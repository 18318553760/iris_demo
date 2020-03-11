# 概述

分布式系统即将一个系统解耦成多个系统运行，运行在不同的环境下，数据库通用

## 1、Windows下打包go项目

cmd运行

1.打开cmd终端，cd到项目src目录下，执行如下操作

SET CGO_ENABLED=0

SET GOOS=linux

SET GOARCH=amd64

go build main.go

这样在main.go同目录下会生产main二进制文件

2.将main二进制文件上传到服务器

3.修改main二进制文件权限chmod -R 777 main ，直接运行之 

GOOS=linux GOARCH=amd64 go build productMain.go



## 2、部署go项目

新建与项目名称相同的文件夹，把打包的exe文件放在本文件下，把静态文件拷贝在当前项目同名的问价夹下，运行查看效果，linux上传文件到服务器要把赋予权限,后台执行命令

nohup  ./main > run.log 2>&1 &

ps aux |grep "test.sh"  #a:显示所有程序  u:以用户为主的格式来显示   x:显示所有程序，不以终端机来区分
ps -ef |grep "test.sh"  #-e显示所有进程。-f全格式。

kill 1001
kill  -9 1001  #-9表示强制关闭

### 1、模板静态化，利用cdn加速静态文件，建立cdn域名，通过cname映射在ip上，绑定

```
/**
* @program: Go
*
* @description:
*
* @author: Mr.chen
*
* @create: 2020-03-06 15:38
**/
package home
import (
	"github.com/kataras/iris"
	"github.com/kataras/iris/mvc"
	"github.com/kataras/iris/sessions"
	"iris_demo/datamodels"
	"iris_demo/services"
	"os"
	"path/filepath"
	"strconv"
	"text/template"
)


type ProductController struct {
	Ctx            iris.Context
	ProductService services.IProductService
	OrderService   services.IOrderService
	Session        *sessions.Session
}
var (
	//生成的Html保存目录
	htmlOutPath = "./web/views/home/htmlProductShow/"
	//静态文件模版目录
	templatePath = "./web/views/home/template/"
)

func (p *ProductController) GetGenerateHtml() {
	productString := p.Ctx.URLParam("productID")
	productID,err:=strconv.Atoi(productString)
	if err !=nil {
		p.Ctx.Application().Logger().Debug(err)
	}


	//1.获取模版
	contenstTmp,err:=template.ParseFiles(filepath.Join(templatePath,"product.html"))
	if err !=nil {
		p.Ctx.Application().Logger().Debug(err)
	}
	//2.获取html生成路径
	fileName:=filepath.Join(htmlOutPath,"htmlProduct_"+strconv.Itoa(productID)+".html")

	//3.获取模版渲染数据
	product,err:=p.ProductService.GetProductByID(int64(productID))
	if err !=nil {
		p.Ctx.Application().Logger().Debug(err)
	}
	//4.生成静态文件
	generateStaticHtml(p.Ctx,contenstTmp,fileName,product)
}

//生成html静态文件
func generateStaticHtml(ctx iris.Context,template *template.Template,fileName string,product *datamodels.Product)  {
	//1.判断静态文件是否存在
	if exist(fileName) {
		err:=os.Remove(fileName)
		if err !=nil {
			ctx.Application().Logger().Error(err)
		}
	}
	//2.生成静态文件
	file,err := os.OpenFile(fileName,os.O_CREATE|os.O_WRONLY,os.ModePerm)
	if err !=nil {
		ctx.Application().Logger().Error(err)
	}
	defer file.Close()
	template.Execute(file,&product)
}

//判断文件是否存在
func exist(fileName string) bool  {
	_,err:=os.Stat(fileName)
	return err==nil || os.IsExist(err)
}

func (p *ProductController) GetDetail() mvc.View {
	product, err := p.ProductService.GetProductByID(4)
	if err != nil {
		p.Ctx.Application().Logger().Error(err)
	}

	return mvc.View{
		Layout: "home/shared/productLayout.html",
		Name:   "home/product/view.html",
		Data: iris.Map{
			"product": product,
		},
	}
}

func (p *ProductController) GetOrder() mvc.View {
	productString := p.Ctx.URLParam("productID")
	userString := p.Ctx.GetCookie("uid")
	productID, err := strconv.Atoi(productString)
	if err != nil {
		p.Ctx.Application().Logger().Debug(err)
	}
	product, err := p.ProductService.GetProductByID(int64(productID))
	if err != nil {
		p.Ctx.Application().Logger().Debug(err)
	}
	var orderID int64
	showMessage := "抢购失败！"
	//判断商品数量是否满足需求
	if product.ProductNum > 0 {
		//扣除商品数量
		product.ProductNum -= 1
		err := p.ProductService.UpdateProduct(product)
		if err != nil {
			p.Ctx.Application().Logger().Debug(err)
		}
		//创建订单
		userID, err := strconv.Atoi(userString)
		if err != nil {
			p.Ctx.Application().Logger().Debug(err)
		}

		order := &datamodels.Order{
			UserId:      int64(userID),
			ProductId:   int64(productID),
			OrderStatus: datamodels.OrderSuccess,
		}
		//新建订单
		orderID, err = p.OrderService.InsertOrder(order)
		if err != nil {
			p.Ctx.Application().Logger().Debug(err)
		} else {
			showMessage = "抢购成功！"
		}
	}

	return mvc.View{
		Layout: "home/shared/productLayout.html",
		Name:   "home/product/result.html",
		Data: iris.Map{
			"orderID":     orderID,
			"showMessage": showMessage,
		},
	}

}


```

### 2、利用cookie来来代替session集群

```
/**
* @program: Go
*
* @description:
*
* @author: Mr.chen
*
* @create: 2020-03-06 14:10
**/
package home
import (
	"fmt"
	"github.com/kataras/iris"
	"github.com/kataras/iris/mvc"
	"github.com/kataras/iris/sessions"
	"iris_demo/datamodels"
	"iris_demo/encrypt"
	"iris_demo/services"
	"iris_demo/tool"
	"strconv"
)

type UserController struct {
	Ctx     iris.Context
	Service services.IUserService
	Session *sessions.Session
}

func (c *UserController) GetRegister() mvc.View {
	return mvc.View{
		Name: "/home/user/register.html",
	}
}

func (c *UserController) PostRegister() {
	var (
		nickName = c.Ctx.FormValue("nickName")
		userName = c.Ctx.FormValue("userName")
		password = c.Ctx.FormValue("password")
	)
	//ozzo-validation
	user := &datamodels.User{
		UserName:     userName,
		NickName:     nickName,
		HashPassword: password,
	}

	_, err := c.Service.AddUser(user)
	c.Ctx.Application().Logger().Debug(err)
	if err != nil {
		c.Ctx.Redirect("/user/error")
		return
	}
	c.Ctx.Redirect("/user/login")
	return
}

func (c *UserController) GetLogin() mvc.View {
	return mvc.View{
		Name: "/home/user/login.html",
	}
}

func (c *UserController) PostLogin() mvc.Response {
	//1.获取用户提交的表单信息
	var (
		userName = c.Ctx.FormValue("userName")
		password = c.Ctx.FormValue("password")

	)
	//2、验证账号密码正确
	user, isOk := c.Service.IsPwdSuccess(userName, password)
	if !isOk {
		return mvc.Response{
			Path: "/user/login",
		}
	}

	//3、写入用户ID到cookie中
	//tool.GlobalCookie(c.Ctx, "uid", strconv.FormatInt(user.ID, 10))
	//c.Session.Set("userID",strconv.FormatInt(user.ID,10))

	//3、写入用户ID到cookie中 用cookie代替session集群
	tool.GlobalCookie(c.Ctx, "uid", strconv.FormatInt(user.ID, 10))
	uidByte := []byte(strconv.FormatInt(user.ID, 10))
	uidString, err := encrypt.EnPwdCode(uidByte)
	if err != nil {
		fmt.Println(err)
	}
	//写入用户浏览器
	tool.GlobalCookie(c.Ctx, "sign", uidString)

	return mvc.Response{
		Path: "/product/detail",
	}

}


```

### tool文件

```
/**
* @program: Go
*
* @description:
*
* @author: Mr.chen
*
* @create: 2020-03-06 14:13
**/
package tool
import (
	"github.com/kataras/iris"
	"net/http"
)
//设置全局cookie
func GlobalCookie(ctx iris.Context,name string,value string)  {
	ctx.SetCookie(&http.Cookie{Name:name,Value:value,Path:"/"})
}

```

### encrypt

```
/**
* @program: Go
*
* @description:aes加密
*
* @author: Mr.chen
*
* @create: 2020-03-07 14:04
**/
package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

//高级加密标准（Adevanced Encryption Standard ,AES）

//16,24,32位字符串的话，分别对应AES-128，AES-192，AES-256 加密方法
//key不能泄露
var PwdKey = []byte("DIS**#KKKDJJSKDI")

//PKCS7 填充模式
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	//Repeat()函数的功能是把切片[]byte{byte(padding)}复制padding个，然后合并成新的字节切片返回
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

//填充的反向操作，删除填充字符串
func PKCS7UnPadding(origData []byte) ([]byte, error) {
	//获取数据长度
	length := len(origData)
	if length == 0 {
		return nil, errors.New("加密字符串错误！")
	} else {
		//获取填充字符串长度
		unpadding := int(origData[length-1])
		//截取切片，删除填充字节，并且返回明文
		return origData[:(length - unpadding)], nil
	}
}

//实现加密
func AesEcrypt(origData []byte, key []byte) ([]byte, error) {
	//创建加密算法实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//获取块的大小
	blockSize := block.BlockSize()
	//对数据进行填充，让数据长度满足需求
	origData = PKCS7Padding(origData, blockSize)
	//采用AES加密方法中CBC加密模式
	blocMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	//执行加密
	blocMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

//实现解密
func AesDeCrypt(cypted []byte, key []byte) ([]byte, error) {
	//创建加密算法实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//获取块大小
	blockSize := block.BlockSize()
	//创建加密客户端实例
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(cypted))
	//这个函数也可以用来解密
	blockMode.CryptBlocks(origData, cypted)
	//去除填充字符串
	origData, err = PKCS7UnPadding(origData)
	if err != nil {
		return nil, err
	}
	return origData, err
}

//加密base64
func EnPwdCode(pwd []byte) (string, error) {
	result, err := AesEcrypt(pwd, PwdKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(result), err
}

//解密
func DePwdCode(pwd string) ([]byte, error) {
	//解密base64字符串
	pwdByte, err := base64.StdEncoding.DecodeString(pwd)
	if err != nil {
		return nil, err
	}
	//执行AES解密
	return AesDeCrypt(pwdByte, PwdKey)

}


```

### 中间件middleware/auth

```
/**
* @program: Go
*
* @description:
*
* @author: Mr.chen
*
* @create: 2020-03-06 15:42
**/
package middleware
import "github.com/kataras/iris"

func AuthConProduct(ctx iris.Context) {

	uid := ctx.GetCookie("uid")
	if uid == "" {
		ctx.Application().Logger().Debug("必须先登录!")
		ctx.Redirect("/user/login")

		return
	}
	ctx.Application().Logger().Debug("已经登陆")
	ctx.Next()
}


```

## 3、服务端优化

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\1.png)

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\2.png)



![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\4.png)

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\5.png)

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\6.png)

### 1、建立拦截器

#### common/filter.go

```
/**
* @program: Go
*
* @description:拦截器
*
* @author: Mr.chen
*
* @create: 2020-03-07 15:10
**/
package common

import (
	"net/http"
)

//声明一个新的数据类型（函数类型）
type FilterHandle func(rw http.ResponseWriter, req *http.Request) error

//拦截器结构体
type Filter struct {
	//用来存储需要拦截的URI
	filterMap map[string]FilterHandle
}

//Filter初始化函数
func NewFilter() *Filter {
	return &Filter{filterMap: make(map[string]FilterHandle)}
}

//注册拦截器
func (f *Filter) RegisterFilterUri(uri string, handler FilterHandle) {
	f.filterMap[uri] = handler
}

//根据Uri获取对应的handle
func (f *Filter) GetFilterHandle(uri string) FilterHandle {
	return f.filterMap[uri]
}

//声明新的函数类型
type WebHandle func(rw http.ResponseWriter, req *http.Request)

//执行拦截器，返回函数类型
func (f *Filter) Handle(webHandle WebHandle) func(rw http.ResponseWriter, r *http.Request) {
	return func(rw http.ResponseWriter, r *http.Request) {
		for path, handle := range f.filterMap {
			if path == r.RequestURI {
				//执行拦截业务逻辑
				err := handle(rw, r)  // 进入拦截器的处理
				if err != nil {
					rw.Write([]byte(err.Error()))
					return
				}
				//跳出循环
				break
			}
		}
		//执行正常注册的函数
		webHandle(rw, r)
	}
}


```

#### main.go

```
/**
* @program: Go
*
* @description:分布式验证，拦截器的使用
*
* @author: Mr.chen
*
* @create: 2020-03-07 15:23
**/
package main
import (
	//"errors"
	"fmt"
	"iris_demo/common"
	"net/http"
)
func Auth(rw http.ResponseWriter,r *http.Request)  error {
	fmt.Println("执行验证！")
	return nil
	//return errors.New("错误！")
}
//执行正常业务逻辑
func Check(w http.ResponseWriter, r *http.Request) {
	//执行正常业务逻辑
	fmt.Println("执行check！")
}
func main() {
	filter := common.NewFilter()
	filter.RegisterFilterUri("/check",Auth) // 注册函数，把url放在拦截器，访问/check会被拦截
	http.HandleFunc("/check",filter.Handle(Check)) // 处理拦截器
	http.ListenAndServe(":8083", nil)
}
```

#### main.go实践

```
/**
* @program: Go
*
* @description:分布式验证，拦截器的使用
*
* @author: Mr.chen
*
* @create: 2020-03-07 15:23
**/
package main
import (
	"errors"
	"fmt"
	"iris_demo/common"
	"iris_demo/encrypt"
	"net/http"
)
func Auth(rw http.ResponseWriter,r *http.Request)  error {
	fmt.Println("执行验证！")
	//添加基于cookie的权限验证
	err := CheckUserInfo(r)
	if err != nil {
		return err
	}
	return nil
	//return errors.New("错误！")
}
//身份校验函数
func CheckUserInfo(r *http.Request) error {
	//获取Uid，cookie
	uidCookie, err := r.Cookie("uid")
	if err != nil {
		return errors.New("用户UID Cookie 获取失败！")
	}
	//获取用户加密串
	signCookie, err := r.Cookie("sign")
	if err != nil {
		return errors.New("用户加密串 Cookie 获取失败！")
	}

	//对信息进行解密
	signByte, err := encrypt.DePwdCode(signCookie.Value)
	if err != nil {
		return errors.New("加密串已被篡改！")
	}

	//fmt.Println("结果比对")
	//fmt.Println("用户ID：" + uidCookie.Value)
	//fmt.Println("解密后用户ID：" + string(signByte))
	if checkInfo(uidCookie.Value, string(signByte)) {
		return nil
	}
	//return errors.New("身份校验失败！")
	return nil
}

//自定义逻辑判断
func checkInfo(checkStr string, signStr string) bool {
	if checkStr == signStr {
		return true
	}
	return false
}

//执行正常业务逻辑
func Check(w http.ResponseWriter, r *http.Request) {
	//执行正常业务逻辑
	fmt.Println("执行check！")
}
func main() {
	filter := common.NewFilter()
	filter.RegisterFilterUri("/check",Auth) // 注册函数，把url放在拦截器，访问/check会被拦截
	http.HandleFunc("/check",filter.Handle(Check)) // 处理拦截器
	http.ListenAndServe(":9999", nil)
}
```

### 2、一致哈希算法

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\11.png)

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\12.png)

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\13.png)

slb负载均衡采用一致性哈希算法

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\14.png)

### 3、wrk

#### a、安装wrk

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\15.png)

make之后生成了wrk,直接在当前的目录运行wrk

#### b、wrk命令

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\16.png)

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\17.png)

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\18.png)

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\19.png)

#### c、wrk实践

##### getOne.go

```
/**
* @program: Go
*
* @description:秒杀设计原型
*
* @author: Mr.chen
*
* @create: 2020-03-09 13:46
**/
//./wrk -t80 -c200 -d30s --latency  http://127.0.0.1:8084/getOne
//
//./wrk -t80 -c2000 -d30s --latency  http://127.0.0.1:8084/getOne
//
//./wrk -t80 -c20000 -d30s --latency  http://127.0.0.1:8084/getOne
package main
import (
	"fmt"
	"log"
	"net/http"
	"sync"
)

var sum int64 = 0

//预存商品数量
var productNum int64 = 1000000

//互斥锁
var mutex sync.Mutex

//计数
var count int64 = 0

//获取秒杀商品
func GetOneProduct() bool {
	//加锁
	mutex.Lock()
	defer mutex.Unlock()
	count += 1
	//判断数据是否超限
	if count%100 == 0 {
		if sum < productNum {
			sum += 1
			fmt.Println(sum)
			return true
		}
	}
	return false

}

func GetProduct(w http.ResponseWriter, req *http.Request) {
	if GetOneProduct() {
		w.Write([]byte("true"))
		return
	}
	w.Write([]byte("false"))
	return
}

func main() {
	http.HandleFunc("/getOne", GetProduct)
	err := http.ListenAndServe(":8084", nil)
	if err != nil {
		log.Fatal("Err:", err)
	}
}


```



### 4、引入rabbitmq

#### a、redis详解

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\20.png)

#### b、redis单机版

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\21.png)

#### c、redis集群版，单个商品访问比较集群服务器数据比较分散，会存在瓶颈

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\22.png)

#### d、rabbitmq实践

##### rabbitmq/rabbitmq

```
package rabbitmq

import (
	"fmt"
	"github.com/streadway/amqp"
	"log"
	"encoding/json"
	"iris_demo/datamodels"
	"iris_demo/services"
	"sync"
)

//连接信息
//const MQURL = "amqp://imoocuser:imoocuser@172.31.96.59:5672/imooc"
const MQURL = "amqp://mqUser:mqUser@129.204.49.177:5672/mq"

//rabbitMQ结构体
type RabbitMQ struct {
	conn    *amqp.Connection
	channel *amqp.Channel
	//队列名称
	QueueName string
	//交换机名称
	Exchange string
	//bind Key 名称
	Key string
	//连接信息
	Mqurl string
	sync.Mutex
}

//创建结构体实例
func NewRabbitMQ(queueName string, exchange string, key string) *RabbitMQ {
	return &RabbitMQ{QueueName: queueName, Exchange: exchange, Key: key, Mqurl: MQURL}
}

//断开channel 和 connection
func (r *RabbitMQ) Destory() {
	r.channel.Close()
	r.conn.Close()
}

//错误处理函数
func (r *RabbitMQ) failOnErr(err error, message string) {
	if err != nil {
		log.Fatalf("%s:%s", message, err)
		panic(fmt.Sprintf("%s:%s", message, err))
	}
}

//创建简单模式下RabbitMQ实例
func NewRabbitMQSimple(queueName string) *RabbitMQ {
	//创建RabbitMQ实例
	rabbitmq := NewRabbitMQ(queueName, "", "")
	var err error
	//获取connection
	rabbitmq.conn, err = amqp.Dial(rabbitmq.Mqurl)
	rabbitmq.failOnErr(err, "failed to connect rabb"+
		"itmq!")
	//获取channel
	rabbitmq.channel, err = rabbitmq.conn.Channel()
	rabbitmq.failOnErr(err, "failed to open a channel")
	return rabbitmq
}

//直接模式队列生产
func (r *RabbitMQ) PublishSimple(message string) error {
	r.Lock()
	defer r.Unlock()
	//1.申请队列，如果队列不存在会自动创建，存在则跳过创建
	_, err := r.channel.QueueDeclare(
		r.QueueName,
		//是否持久化
		false,
		//是否自动删除
		false,
		//是否具有排他性
		false,
		//是否阻塞处理
		false,
		//额外的属性
		nil,
	)
	if err != nil {
		return err
	}
	//调用channel 发送消息到队列中
	r.channel.Publish(
		r.Exchange,
		r.QueueName,
		//如果为true，根据自身exchange类型和routekey规则无法找到符合条件的队列会把消息返还给发送者
		false,
		//如果为true，当exchange发送消息到队列后发现队列上没有消费者，则会把消息返还给发送者
		false,
		amqp.Publishing{
			ContentType: "text/plain",
			Body:        []byte(message),
		})
	return nil
}

//simple 模式下消费者
func (r *RabbitMQ) ConsumeSimple(orderService services.IOrderService,productService services.IProductService) {
	//1.申请队列，如果队列不存在会自动创建，存在则跳过创建
	q, err := r.channel.QueueDeclare(
		r.QueueName,
		//是否持久化
		false,
		//是否自动删除
		false,
		//是否具有排他性
		false,
		//是否阻塞处理
		false,
		//额外的属性
		nil,
	)
	if err != nil {
		fmt.Println(err)
	}

	//消费者流控，autoAck设置为false
	r.channel.Qos(
		1, //当前消费者一次能接受的最大消息数量
		0, //服务器传递的最大容量（以八位字节为单位）
		false, //如果设置为true 对channel可用
	)

	//接收消息
	msgs, err := r.channel.Consume(
		q.Name, // queue
		//用来区分多个消费者
		"", // consumer
		//是否自动应答
		//这里要改掉，我们用手动应答
		false, // auto-ack ，如果没有手动断掉，会一直存在，存在不断的重复消费
		//是否独有
		false, // exclusive
		//设置为true，表示 不能将同一个Conenction中生产者发送的消息传递给这个Connection中 的消费者
		false, // no-local
		//列是否阻塞
		false, // no-wait
		nil,   // args
	)
	if err != nil {
		fmt.Println(err)
	}

	forever := make(chan bool)
	//启用协程处理消息
	go func() {
		for d := range msgs {
			//消息逻辑处理，可以自行设计逻辑
			log.Printf("Received a message: %s", d.Body)
			message := &datamodels.Message{}
			err :=json.Unmarshal([]byte(d.Body),message)
			if err !=nil {
				fmt.Println(err)
			}
			//插入订单
			_,err=orderService.InsertOrderByMessage(message)
			if err !=nil {
				fmt.Println(err)
			}

			//扣除商品数量
			err = productService.SubNumberOne(message.ProductID)
			if err !=nil {
				fmt.Println(err)
			}
			//如果为true表示确认所有未确认的消息，
			//为false表示确认当前消息
			d.Ack(false) // 断掉ack，删除对列
		}
	}()

	log.Printf(" [*] Waiting for messages. To exit press CTRL+C")
	<-forever

}

```

##### public.go

```
func (p *ProductController) GetOrder() []byte {
	productString := p.Ctx.URLParam("productID")
	userString := p.Ctx.GetCookie("uid")
	productID, err := strconv.ParseInt(productString,10,64)
	if err != nil {
		p.Ctx.Application().Logger().Debug(err)
	}
	userID ,err :=strconv.ParseInt(userString,10,64)
	if err !=nil {
		p.Ctx.Application().Logger().Debug(err)
	}

	//创建消息体
	message :=datamodels.NewMessage(userID,productID)
	//类型转化
	byteMessage,err :=json.Marshal(message)
	if err !=nil {
		p.Ctx.Application().Logger().Debug(err)
	}
	rabbitmq := rabbitmq.NewRabbitMQSimple("" +
		"mqSimpleProduct")
	err = rabbitmq.PublishSimple(string(byteMessage))
	defer rabbitmq.Destory()
	//err = p.RabbitMQ.PublishSimple(string(byteMessage))
	if err !=nil {
		p.Ctx.Application().Logger().Debug(err)
	}

	return []byte("true")


}

```

##### message

```
/**
* @program: Go
*
* @description:
*
* @author: Mr.chen
*
* @create: 2020-03-09 09:52
**/
package datamodels
//简单的消息体
type Message struct {
	ProductID int64
	UserID    int64
}

//创建结构体
func NewMessage(userId int64,productId int64) *Message  {
	return &Message{UserID:userId,ProductID:productId}
}

```

##### consume.go

```
/**
* @program: Go
*
* @description:消费单列模式的对列,生成订单
*
* @author: Mr.chen
*
* @create: 2020-03-09 11:31
**/


package main

import (
	"iris_demo/common"
	"fmt"
	"iris_demo/repositories"
	"iris_demo/services"
	"iris_demo/rabbitmq"
)

func main()  {
	db,err:=common.NewMysqlConn()
	if err !=nil {
		fmt.Println(err)
	}
	//创建product数据库操作实例
	product := repositories.NewProductManager("product",db)
	//创建product serivce
	productService:=services.NewProductService(product)
	//创建Order数据库实例
	order := repositories.NewOrderMangerRepository("order",db)
	//创建order Service
	orderService := services.NewOrderService(order)

	rabbitmqConsumeSimple :=rabbitmq.NewRabbitMQSimple("" +
		"mqSimpleProduct")
	rabbitmqConsumeSimple.ConsumeSimple(orderService,productService)
}


```



### 5、基于cookie的分布式验证

```
/**
* @program: Go
*
* @description:分布式验证获取用户信息，拦截器的使用,一致哈希法，内存操作要加锁，读的加读写锁,比如根据数组的下标读写，其他加普通锁
*
* @author: Mr.chen
*
* @create: 2020-03-07 15:23
**/
package main
import (
   "errors"
   "fmt"
   "io/ioutil"
   "iris_demo/common"
   "iris_demo/encrypt"
   "net/http"
   "strconv"
   "time"

   "sync"
)
//设置集群地址，最好内外IP,利用同一个ip，不同端口的cookie一样
var hostArray= []string{"192.168.1.190","192.168.1.190"} // 本机的内网ip,通过common.GetIntranceIp()可以获取
var localHost = "" // 本机ip
//var hostArray= []string{"127.0.0.1","127.0.0.1"} // 本机的内网ip,通过common.GetIntranceIp()可以获取
//var localHost = "127.0.0.1" // 本机ip

var port = "8081"

var hashConsistent *common.Consistent

//用来存放控制信息，
type AccessControl struct {
   //用来存放用户想要存放的信息
   sourcesArray map[int]interface{}
   sync.RWMutex
}
type BlackList struct {
   // 用于存放uid,加入黑名单
   listArray map[int]bool
   sync.RWMutex
}
func (m *BlackList) GetBlackListByID(uid int) bool {
   m.RLock()
   defer m.RUnlock()
   data:=m.listArray[uid]
   return data
}
func (m *BlackList) SetBlackListByID(uid int) bool {
   m.Lock()
   defer m.Unlock()
   m.listArray[uid] = true
   return true
}
//创建全局变量
var accessControl = &AccessControl{sourcesArray:make(map[int]interface{})}
var blacklist = &BlackList{listArray:make(map[int]bool)}
//获取制定的数据
func (m *AccessControl) GetNewRecord(uid int) interface{} {
   m.RWMutex.RLock()
   defer m.RWMutex.RUnlock()
   data:=m.sourcesArray[uid]
   return data
}

//设置记录
func (m *AccessControl) SetNewRecord(uid int) {
   m.RWMutex.Lock()
   m.sourcesArray[uid] = time.Now()
   m.RWMutex.Unlock()
}

func (m *AccessControl) GetDistributedRight(req *http.Request) bool {
   //获取用户UID
   uid ,err := req.Cookie("uid")
   if err !=nil {
      return false
   }
   //采用一致性hash算法，根据用户ID，判断获取具体机器
   hostRequest,err:=hashConsistent.Get(uid.Value) // 得到数据在哪个机器的ip上192.168.1.190

   if err !=nil {
      return false
   }

   //判断是否为本机
   if hostRequest == localHost {
      //执行本机数据读取和校验
      return m.GetDataFromMap(uid.Value)
   } else {
      //不是本机充当代理访问数据返回结果
      return GetDataFromOtherMap(hostRequest,req)
   }

}

//获取本机map，并且处理业务逻辑，返回的结果类型为bool类型
func (m *AccessControl) GetDataFromMap(uid string) (isOk bool) {

   uidInt,err := strconv.Atoi(uid)
   if err !=nil {
      return false
   }
   //data:=m.GetNewRecord(uidInt)
   //
   ////执行逻辑判断
   //if data !=nil {
   // return true
   //}
   //return

   if blacklist.GetBlackListByID(uidInt) {
      return false
   }
   return true
}
func CheckRight(w http.ResponseWriter,r *http.Request)  {
   right := accessControl.GetDistributedRight(r)
   if !right {
      w.Write([]byte("false"))
      return
   }
   w.Write([]byte("true"))
   return
}
//获取其它节点处理结果
func GetDataFromOtherMap(host string,request *http.Request) bool  {
   hostUrl:="http://"+host+":"+port+"/checkRight"
   response,body,err:=GetCurl(hostUrl,request)
   if err !=nil {
      return false
   }
   //判断状态
   if response.StatusCode == 200 {
      if string(body) == "true" {
         return true
      } else {
         return false
      }
   }
   return false
}
//模拟请求
func GetCurl(hostUrl string,request *http.Request)(response *http.Response,body []byte,err error)  {
   //获取Uid
   uidPre,err := request.Cookie("uid")
   if err !=nil {
      return
   }
   //获取sign
   uidSign,err:=request.Cookie("sign")
   if err !=nil {
      return
   }

   //模拟接口访问，
   client :=&http.Client{}
   req,err:= http.NewRequest("GET",hostUrl,nil)
   if err !=nil {
      return
   }

   //手动指定，排查多余cookies
   cookieUid :=&http.Cookie{Name:"uid",Value:uidPre.Value,Path:"/"}
   cookieSign :=&http.Cookie{Name:"sign",Value:uidSign.Value,Path:"/"}
   //添加cookie到模拟的请求中
   req.AddCookie(cookieUid)
   req.AddCookie(cookieSign)

   //获取返回结果
   response,err =client.Do(req)
   defer response.Body.Close()
   if err !=nil {
      return
   }
   body,err =ioutil.ReadAll(response.Body)
   return
}

func Auth(rw http.ResponseWriter,r *http.Request)  error {
   fmt.Println("执行验证！")
   //添加基于cookie的权限验证
   err := CheckUserInfo(r)
   if err != nil {
      return err
   }
   return nil
   //return errors.New("错误！")
}
//身份校验函数
func CheckUserInfo(r *http.Request) error {
   //获取Uid，cookie
   uidCookie, err := r.Cookie("uid")
   fmt.Println(uidCookie)
   if err != nil {
      return errors.New("用户UID Cookie 获取失败！")
   }
   //获取用户加密串
   signCookie, err := r.Cookie("sign")
   if err != nil {
      return errors.New("用户加密串 Cookie 获取失败！")
   }

   //对信息进行解密
   signByte, err := encrypt.DePwdCode(signCookie.Value)
   if err != nil {
      return errors.New("加密串已被篡改！")
   }

   //fmt.Println("结果比对")
   //fmt.Println("用户ID：" + uidCookie.Value)
   //fmt.Println("解密后用户ID：" + string(signByte))
   if checkInfo(uidCookie.Value, string(signByte)) {
      return nil
   }
   //return errors.New("身份校验失败！")
   return nil
}

//自定义逻辑判断
func checkInfo(checkStr string, signStr string) bool {
   if checkStr == signStr {
      return true
   }
   return false
}

//执行正常业务逻辑
func Check(w http.ResponseWriter, r *http.Request) {
   //执行正常业务逻辑
   fmt.Println("执行check！")
}
func main() {
   //负载均衡器设置
   //采用一致性哈希算法
   hashConsistent = common.NewConsistent()
   //采用一致性hash算法，添加节点
   for _,v :=range hostArray {
      hashConsistent.Add(v)
   }
   localIp,err:=common.GetIntranceIp()
   if err!=nil {
      fmt.Println(err)
   }
   localHost=localIp

   filter := common.NewFilter()
   filter.RegisterFilterUri("/check",Auth) // 注册函数，把url放在拦截器，访问/check会被拦截
   http.HandleFunc("/check",filter.Handle(Check)) // 处理拦截器
   filter.RegisterFilterUri("/checkRight",Auth)
   http.HandleFunc("/checkRight",filter.Handle(CheckRight))
   http.ListenAndServe(":8083", nil)
}
```
## 4、项目实践

cmd可以用go build打包方法，解决模板路径问题，直接在idea编辑器则需要设置打包路径，如图所示

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\23.png)

分别运行skill.go,main.go,getOne.go,consume.go查看效果

访问<http://127.0.0.1:8083/html/product.html> ，需要登录，获取cookie

![](C:\Users\Administrator\Desktop\go语言\go\go项目\images\24.png)

skill.go

```


/**
* @program: Go
*
* @description:分布式验证获取用户信息，拦截器的使用,一致哈希法，内存操作要加锁，读的加读写锁,比如根据数组的下标读写，其他加普通锁
*
* @author: Mr.chen
*
* @create: 2020-03-07 15:23
**/
package main
import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"iris_demo/common"
	"iris_demo/datamodels"
	"iris_demo/encrypt"
	"iris_demo/rabbitmq"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)
//设置集群地址，最好内外IP,利用同一个ip，不同端口的cookie一样
//var hostArray= []string{"192.168.1.190","192.168.1.190"} // 本机的内网ip,通过common.GetIntranceIp()可以获取
//var localHost = "" // 本机ip
var hostArray= []string{"127.0.0.1","192.168.1.190"} // 本机的内网ip,通过common.GetIntranceIp()可以获取
var localHost = "" // 本机ip

var port = "8083"

//数量控制接口服务器内网IP，或者getone的SLB内网IP
var GetOneIp = "127.0.0.1"

var GetOnePort = "8084"

//rabbitmq
var rabbitMqValidate *rabbitmq.RabbitMQ

var hashConsistent *common.Consistent
// 时间间隔
var interval = 10
//用来存放控制信息，
type AccessControl struct {
	//用来存放用户想要存放的信息
	sourcesArray map[int]time.Time
	sync.RWMutex
}
type BlackList struct {
	// 用于存放uid,加入黑名单
	listArray map[int]bool
	sync.RWMutex
}
func (m *BlackList) GetBlackListByID(uid int) bool {
	m.RLock()
	defer m.RUnlock()
	data:=m.listArray[uid]
	return data
}
func (m *BlackList) SetBlackListByID(uid int) bool {
	m.Lock()
	defer m.Unlock()
	m.listArray[uid] = true
	return true
}
//创建全局变量
var accessControl = &AccessControl{sourcesArray:make(map[int]time.Time)}
var blacklist = &BlackList{listArray:make(map[int]bool)}
//获取制定的数据
func (m *AccessControl) GetNewRecord(uid int) time.Time {
	m.RWMutex.RLock()
	defer m.RWMutex.RUnlock()
	data:=m.sourcesArray[uid]
	return data
}

//设置记录
func (m *AccessControl) SetNewRecord(uid int) {
	m.RWMutex.Lock()
	m.sourcesArray[uid] = time.Now()
	m.RWMutex.Unlock()
}

func (m *AccessControl) GetDistributedRight(req *http.Request) bool {
	//获取用户UID
	uid ,err := req.Cookie("uid")

	if err !=nil {
		fmt.Println("uid不存在")
		return false
	}
	//采用一致性hash算法，根据用户ID，判断获取具体机器
	hostRequest,err:=hashConsistent.Get(uid.Value) // 得到数据在哪个机器的ip上192.168.1.190
	fmt.Println(hostRequest,localHost)
	if err !=nil {
		return false
	}

	//判断是否为本机
	if hostRequest == localHost {
		fmt.Println("本机访问")
		//执行本机数据读取和校验
		return m.GetDataFromMap(uid.Value)
	} else {
		fmt.Println("不是本机访问")
		//不是本机充当代理访问数据返回结果
		return GetDataFromOtherMap(hostRequest,req)
	}

}

//获取本机map，并且处理业务逻辑，返回的结果类型为bool类型
func (m *AccessControl) GetDataFromMap(uid string) (isOk bool) {

	uidInt,err := strconv.Atoi(uid)

	if err !=nil {
		return false
	}
	dataRecord:=m.GetNewRecord(uidInt)
	fmt.Println(dataRecord)
	//执行逻辑判断
	if !dataRecord.IsZero()  { // 判断时间有没有赋值,没有指定
		// 业务逻辑，是否在直接指定之后
		if dataRecord.Add(time.Duration(interval)*time.Second).After(time.Now()){
			return false
		}
	}
	if blacklist.GetBlackListByID(uidInt) {
		return false
	}
	m.SetNewRecord(uidInt)
	return true
}
func CheckRight(w http.ResponseWriter,r *http.Request)  {
	right := accessControl.GetDistributedRight(r)
	if !right {
		w.Write([]byte("false"))
		return
	}
	w.Write([]byte("true"))
	return
}
//获取其它节点处理结果
//获取其它节点处理结果
func GetDataFromOtherMap(host string,request *http.Request) bool  {
	hostUrl:="http://"+host+":"+port+"/checkRight"
	fmt.Println(hostUrl)
	response,body,err:=GetCurl(hostUrl,request)
	if err !=nil {
		return false
	}
	//判断状态
	if response.StatusCode == 200 {
		if string(body) == "true" {
			return true
		} else {
			return false
		}
	}
	return false
}

//模拟请求
func GetCurl(hostUrl string,request *http.Request)(response *http.Response,body []byte,err error)  {
	//获取Uid
	uidPre,err := request.Cookie("uid")
	if err !=nil {
		return
	}
	//获取sign
	uidSign,err:=request.Cookie("sign")
	if err !=nil {
		return
	}

	//模拟接口访问，
	client :=&http.Client{}

	req,err:= http.NewRequest("GET",hostUrl,nil)
	if err !=nil {
		return
	}

	//手动指定，排查多余cookies
	cookieUid :=&http.Cookie{Name:"uid",Value:uidPre.Value,Path:"/"}
	cookieSign :=&http.Cookie{Name:"sign",Value:uidSign.Value,Path:"/"}
	//添加cookie到模拟的请求中
	req.AddCookie(cookieUid)
	req.AddCookie(cookieSign)

	//获取返回结果
	response,err =client.Do(req)
	defer response.Body.Close()
	if err !=nil {
		return
	}
	body,err =ioutil.ReadAll(response.Body)
	return
}

//统一验证拦截器，每个接口都需要提前验证
func Auth(w http.ResponseWriter, r *http.Request) error {

	//w.Header().Set("Access-Control-Allow-Origin", "*")
	//添加基于cookie的权限验证
	err := CheckUserInfo(r)
	if err != nil {
		return err
	}
	return nil
}

//身份校验函数
func CheckUserInfo(r *http.Request) error {
	//获取Uid，cookie
	uidCookie, err := r.Cookie("uid")
	if err != nil {
		return errors.New("用户UID Cookie 获取失败！")
	}
	//获取用户加密串
	signCookie, err := r.Cookie("sign")
	if err != nil {
		return errors.New("用户加密串 Cookie 获取失败！")
	}

	//对信息进行解密
	signByte, err := encrypt.DePwdCode(signCookie.Value)
	if err != nil {
		return errors.New("加密串已被篡改！")
	}

	//fmt.Println("结果比对")
	//fmt.Println("用户ID：" + uidCookie.Value)
	//fmt.Println("解密后用户ID：" + string(signByte))
	if checkInfo(uidCookie.Value, string(signByte)) {
		return nil
	}
	return errors.New("身份校验失败！")
	//return nil
}

//自定义逻辑判断
func checkInfo(checkStr string, signStr string) bool {
	if checkStr == signStr {
		return true
	}
	return false
}

//执行正常业务逻辑
func Check(w http.ResponseWriter,r *http.Request)  {
	//w.Header().Set("Access-Control-Allow-Origin", "*")
	//执行正常业务逻辑
	fmt.Println("执行check！")
	queryForm,err:=url.ParseQuery(r.URL.RawQuery)

	if err !=nil || len(queryForm["productID"])<=0 {
		w.Write([]byte("false"))
		return
	}
	productString :=queryForm["productID"][0]

	//获取用户cookie
	userCookie,err:=r.Cookie("uid")
	if err !=nil {
		fmt.Println("uid不存在")
		w.Write([]byte("false"))
		return
	}
	//1.分布式权限验证
	right:=accessControl.GetDistributedRight(r)
	if right == false{
		w.Write([]byte("false"))
		return
	}
	//2.获取数量控制权限，防止秒杀出现超卖现象
	hostUrl :="http://"+GetOneIp+":"+GetOnePort+"/getOne"
	responseValidate,validateBody,err:=GetCurl(hostUrl,r)
	if err !=nil {
		w.Write([]byte("false"))
		return
	}
	//判断数量控制接口请求状态
	if responseValidate.StatusCode == 200 {
		if string(validateBody)=="true" {
			//整合下单
			//1.获取商品ID
			productID,err :=strconv.ParseInt(productString,10,64)
			if err !=nil {

				w.Write([]byte("false"))
				return
			}
			//2.获取用户ID
			userID,err := strconv.ParseInt(userCookie.Value,10,64)
			if err !=nil {

				w.Write([]byte("false"))
				return
			}

			//3.创建消息体
			message :=datamodels.NewMessage(userID,productID)
			//类型转化
			byteMessage,err :=json.Marshal(message)
			if err !=nil {
				w.Write([]byte("false"))
				return
			}
			//4.生产消息
			err = rabbitMqValidate.PublishSimple(string(byteMessage))
			if err !=nil {
				w.Write([]byte("false"))
				return
			}
			w.Write([]byte("true"))
			return
		}
	}
	w.Write([]byte("false"))
	return
}
func main() {
	//负载均衡器设置
	//采用一致性哈希算法
	hashConsistent = common.NewConsistent()
	//采用一致性hash算法，添加节点
	for _,v :=range hostArray {
		hashConsistent.Add(v)
	}
	localIp,err:=common.GetIntranceIp()
	if err!=nil {
		fmt.Println(err)
	}
	localHost=localIp

	fmt.Println(localHost)

	rabbitMqValidate =rabbitmq.NewRabbitMQSimple("" +"mqSimpleProduct")
	defer rabbitMqValidate.Destory()

	// 设置静态文件
	http.Handle("/html/",http.StripPrefix("/html/",http.FileServer(http.Dir("./web/views/home/htmlProductShow"))))
	http.Handle("/public/",http.StripPrefix("/public",http.FileServer(http.Dir("./web/views/home/public"))))

	filter := common.NewFilter()
	filter.RegisterFilterUri("/check",Auth) // 注册函数，把url放在拦截器，访问/check会被拦截
	http.HandleFunc("/check",filter.Handle(Check)) // 处理拦截器
	filter.RegisterFilterUri("/checkRight",Auth)
	http.HandleFunc("/checkRight",filter.Handle(CheckRight))
	http.ListenAndServe(":8083", nil)
}

```

getOne.go

```
/**
* @program: Go
*
* @description:秒杀设计原型
*
* @author: Mr.chen
*
* @create: 2020-03-09 13:46
**/
//./wrk -t80 -c200 -d30s --latency  http://127.0.0.1:8084/getOne
//
//./wrk -t80 -c2000 -d30s --latency  http://127.0.0.1:8084/getOne
//
//./wrk -t80 -c20000 -d30s --latency  http://127.0.0.1:8084/getOne
package main
import (
	"fmt"
	"log"
	"net/http"

	"sync"
)

var sum int64 = 0

//预存商品数量
var productNum int64 = 1000000

//互斥锁
var mutex sync.Mutex

//计数
var count int64 = 0

//获取秒杀商品
func GetOneProduct() bool {
	//加锁
	mutex.Lock()
	defer mutex.Unlock()
	count += 1
	//判断数据是否超限
	//fmt.Println("==============")
	//fmt.Println(count%100)
	//fmt.Println("==============")
	//if count%100 == 0 {
		if sum < productNum {
			sum += 1
			fmt.Println(sum)
			return true
		}
	//}
	return false

}

func GetProduct(w http.ResponseWriter, req *http.Request) {
	if GetOneProduct() {
		w.Write([]byte("true"))
		return
	}
	w.Write([]byte("false"))
	return
}

func main() {
	http.HandleFunc("/getOne", GetProduct)
	err := http.ListenAndServe(":8084", nil)
	if err != nil {
		log.Fatal("Err:", err)
	}
}


```

consume.go

```
/**
* @program: Go
*
* @description:消费单列模式的对列,生成订单
*
* @author: Mr.chen
*
* @create: 2020-03-09 11:31
**/


package main

import (
	"iris_demo/common"
	"fmt"
	"iris_demo/repositories"
	"iris_demo/services"
	"iris_demo/rabbitmq"
)

func main()  {
	db,err:=common.NewMysqlConn()
	if err !=nil {
		fmt.Println(err)
	}
	//创建product数据库操作实例
	product := repositories.NewProductManager("product",db)
	//创建product serivce
	productService:=services.NewProductService(product)
	//创建Order数据库实例
	order := repositories.NewOrderMangerRepository("order",db)
	//创建order Service
	orderService := services.NewOrderService(order)

	rabbitmqConsumeSimple :=rabbitmq.NewRabbitMQSimple("" +
		"mqSimpleProduct")
	rabbitmqConsumeSimple.ConsumeSimple(orderService,productService)
}


```

main.go

```
/**
* @program: Go
*
* @description:iris入口文件
*
* @author: Mr.chen
*
* @create: 2020-03-05 09:34
**/
package main
import (
	"context"
	"github.com/kataras/iris"
	"github.com/kataras/iris/mvc"
	//"github.com/kataras/iris/sessions"
	"github.com/opentracing/opentracing-go/log"
	"iris_demo/common"
	"iris_demo/repositories"
	"iris_demo/services"
	"iris_demo/web/controllers/admin"
	"iris_demo/web/controllers/home"
	"iris_demo/web/middleware"
	//"time"
)

func main()  {
	//1.创建iris 实例
	app:=iris.New()
	//2.设置错误模式，在mvc模式下提示错误
	app.Logger().SetLevel("debug" )
	//3.注册模板
	tmplate := iris.HTML("./web/views",".html").Reload(true)
	app.RegisterView(tmplate)
	//出现异常跳转到指定页面

	// 5.设置异常页面
	app.OnAnyErrorCode(func(ctx iris.Context) {
		ctx.ViewData("Message",ctx.Values().GetStringDefault("message","访问页面出错"))
		//ctx.ViewData("Message", "访问页面出错")
		ctx.ViewLayout("")
		ctx.View("admin/shared/error.html")
	})

	//连接数据库
	db,err :=common.NewMysqlConn()
	if err !=nil {
		log.Error(err)
	}
	ctx,cancel := context.WithCancel(context.Background())
	defer cancel()
	//5.注册控制器
	//productRepository := repositories.NewProductManager("product",db)
	//productSerivce :=services.NewProductService(productRepository)
	//productParty := app.Party("/product")
	//product := mvc.New(productParty)
	//product.Register(ctx,productSerivce)
	//product.Handle(new(controllers.ProductController))
	adminroute := app.Party("/admin")
	{
		//4.设置模板目标
		app.StaticWeb("/assets","./web/assets")
		adminroute.Layout("admin/shared/layout.html")
		productRepository := repositories.NewProductManager("product",db)
		productSerivce :=services.NewProductService(productRepository)
		productParty := adminroute.Party("/product")
		product := mvc.New(productParty)
		product.Register(ctx,productSerivce)
		product.Handle(new(admin.ProductController))
		orderRepository := repositories.NewOrderMangerRepository("product",db)
		orderSerivce :=services.NewOrderService(orderRepository)
		orderParty := adminroute.Party("/order")
		order := mvc.New(orderParty)
		order.Register(ctx,orderSerivce)
		order.Handle(new(admin.OrderController))
	}
	homeroute := app.Party("/")
	{
		homeroute.Layout("home/shared/layout.html")
		app.Handle("GET", "/", func(ctx iris.Context) {
			ctx.HTML("<h1> Hello iris </h1>")
		})
		//4.设置模板目标
		app.StaticWeb("/public", "./web/views/home/public")
		app.StaticWeb("/html", "./web/views/home/htmlProductShow")
		// 使用cookie验证，去掉
		//sess := sessions.New(sessions.Config{
		//	Cookie:"AdminCookie",
		//	Expires:600*time.Minute,
		//})
		//注册user控制器
		user := repositories.NewUserRepository("user", db)
		userService := services.NewService(user)
		userPro := mvc.New(homeroute.Party("/user"))
		userPro.Register(userService)
		//userPro.Register(userService, ctx,sess.Start)
		userPro.Handle(new(home.UserController))


		//注册product控制器
		product := repositories.NewProductManager("product", db)
		productService := services.NewProductService(product)
		order := repositories.NewOrderMangerRepository("order", db)
		orderService := services.NewOrderService(order)
		proProduct := homeroute.Party("/product")
		pro := mvc.New(proProduct)
		proProduct.Use(middleware.AuthConProduct)
		pro.Register(productService, orderService)
		pro.Handle(new(home.ProductController))

	}
	//6.启动服务
	app.Run(
		iris.Addr("0.0.0.0:80"),
		iris.WithoutServerError(iris.ErrServerClosed),
		iris.WithOptimizations,
	)

}
```

product.html

```
<!DOCTYPE html>
<html lang="en">
<head>
    <title>商品详情</title>
    <meta charset="utf-8">
    <!--[if IE]><meta http-equiv='X-UA-Compatible' content='IE=edge,chrome=1'><![endif]-->
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <meta name="description" content="">

    <!-- Google Fonts -->
    <link href='http://fonts.googleapis.com/css?family=Questrial:400%7CMontserrat:300,400,700,700i' rel='stylesheet'>

    <!-- Css -->
    <link rel="stylesheet" href="/public/css/bootstrap.min.css" />
    <link rel="stylesheet" href="/public/css/font-icons.css" />
    <link rel="stylesheet" href="/public/css/style.css" />
    <link rel="stylesheet" href="/public/css/color.css" />

</head>

<body>

<!-- Preloader -->
<div class="loader-mask">
    <div class="loader">
        <div></div>
    </div>
</div>


<!-- Mobile Sidenav -->
<header class="sidenav" id="sidenav">
    <!-- Search -->
    <div class="sidenav__search-mobile">
        <form method="get" class="sidenav__search-mobile-form">
            <input type="search" class="sidenav__search-mobile-input" placeholder="Search..." aria-label="Search input">
            <button type="submit" class="sidenav__search-mobile-submit" aria-label="Submit search">
                <i class="ui-search"></i>
            </button>
        </form>
    </div>

    <nav>
        <ul class="sidenav__menu" role="menubar">
            <li>
                <a href="#" class="sidenav__menu-link">Men</a>
                <button class="sidenav__menu-toggle" aria-haspopup="true" aria-label="Open dropdown"><i class="ui-arrow-down"></i></button>
                <ul class="sidenav__menu-dropdown">
                    <li><a href="#" class="sidenav__menu-link">T-shirt</a></li>
                    <li><a href="#" class="sidenav__menu-link">Hoodie &amp; Jackets</a></li>
                    <li><a href="#" class="sidenav__menu-link">Suits</a></li>
                    <li><a href="#" class="sidenav__menu-link">Shorts</a></li>
                </ul>
            </li>

            <li>
                <a href="#" class="sidenav__menu-link">Women</a>
                <button class="sidenav__menu-toggle" aria-haspopup="true" aria-label="Open dropdown"><i class="ui-arrow-down"></i></button>
                <ul class="sidenav__menu-dropdown">
                    <li><a href="#" class="sidenav__menu-link">Underwear</a></li>
                    <li><a href="#" class="sidenav__menu-link">Hipster</a></li>
                    <li><a href="#" class="sidenav__menu-link">Dress</a></li>
                    <li><a href="#" class="sidenav__menu-link">Hoodie &amp; Jackets</a></li>
                    <li><a href="#" class="sidenav__menu-link">Tees</a></li>
                </ul>
            </li>

            <li>
                <a href="#" class="sidenav__menu-link">Accessories</a>
                <button class="sidenav__menu-toggle" aria-haspopup="true" aria-label="Open dropdown"><i class="ui-arrow-down"></i></button>
                <ul class="sidenav__menu-dropdown">
                    <li>
                        <a href="#" class="sidenav__menu-link">All accessories</a>
                        <button class="sidenav__menu-toggle" aria-haspopup="true" aria-label="Open dropdown"><i class="ui-arrow-down"></i></button>
                        <ul class="sidenav__menu-dropdown">
                            <li>
                                <a href="#" class="sidenav__menu-link">Wallets</a>
                            </li>
                            <li>
                                <a href="#" class="sidenav__menu-link">Scarfs</a>
                            </li>
                            <li>
                                <a href="#" class="sidenav__menu-link">Shirt</a>
                            </li>
                            <li>
                                <a href="#" class="sidenav__menu-link">Shoes</a>
                            </li>
                        </ul>
                    </li>

                    <li>
                        <a href="#" class="sidenav__menu-link">for her</a>
                        <button class="sidenav__menu-toggle" aria-haspopup="true" aria-label="Open dropdown"><i class="ui-arrow-down"></i></button>
                        <ul class="sidenav__menu-dropdown">
                            <li>
                                <a href="#" class="sidenav__menu-link">Underwear</a>
                            </li>
                            <li>
                                <a href="#" class="sidenav__menu-link">Hipster</a>
                            </li>
                            <li>
                                <a href="#" class="sidenav__menu-link">Dress</a>
                            </li>
                            <li>
                                <a href="#" class="sidenav__menu-link">Hoodie &amp; Jackets</a>
                            </li>
                            <li>
                                <a href="#" class="sidenav__menu-link">Tees</a>
                            </li>
                        </ul>
                    </li>

                    <li>
                        <a href="#" class="sidenav__menu-link">for him</a>
                        <button class="sidenav__menu-toggle" aria-haspopup="true" aria-label="Open dropdown"><i class="ui-arrow-down"></i></button>
                        <ul class="sidenav__menu-dropdown">
                            <li>
                                <a href="#" class="sidenav__menu-link">T-shirt</a>
                            </li>
                            <li>
                                <a href="#" class="sidenav__menu-link">Hoodie &amp; Jackets</a>
                            </li>
                            <li>
                                <a href="#" class="sidenav__menu-link">Dress</a>
                            </li>
                            <li>
                                <a href="#" class="sidenav__menu-link">Suits</a>
                            </li>
                            <li>
                                <a href="#" class="sidenav__menu-link">Shorts</a>
                            </li>
                        </ul>
                    </li>

                    <li>
                        <a href="#" class="sidenav__menu-link">Watches</a>
                        <button class="sidenav__menu-toggle" aria-haspopup="true" aria-label="Open dropdown"><i class="ui-arrow-down"></i></button>
                        <ul class="sidenav__menu-dropdown">
                            <li>
                                <a href="#" class="sidenav__menu-link">Smart Watches</a>
                            </li>
                            <li>
                                <a href="#" class="sidenav__menu-link">Diving Watches</a>
                            </li>
                            <li>
                                <a href="#" class="sidenav__menu-link">Sport Watches</a>
                            </li>
                            <li>
                                <a href="#" class="sidenav__menu-link">Classic Watches</a>
                            </li>
                        </ul>
                    </li>

                </ul>
            </li>

            <li>
                <a href="#" class="sidenav__menu-link">News</a>
                <button class="sidenav__menu-toggle" aria-haspopup="true" aria-label="Open dropdown"><i class="ui-arrow-down"></i></button>
                <ul class="sidenav__menu-dropdown">
                    <li><a href="#" class="sidenav__menu-link">Blog Standard</a></li>
                    <li><a href="#" class="sidenav__menu-link">Single Post</a></li>
                </ul>
            </li>

            <li>
                <a href="#" class="sidenav__menu-link">Pages</a>
                <button class="sidenav__menu-toggle" aria-haspopup="true" aria-label="Open dropdown"><i class="ui-arrow-down"></i></button>
                <ul class="sidenav__menu-dropdown">
                    <li><a href="catalog.html" class="sidenav__menu-link">Catalog</a></li>
                    <li><a href="single-product.html" class="sidenav__menu-link">Single Product</a></li>
                    <li><a href="#" class="sidenav__menu-link">Cart</a></li>
                    <li><a href="#" class="sidenav__menu-link">Checkout</a></li>
                    <li><a href="#" class="sidenav__menu-link">About</a></li>
                    <li><a href="#" class="sidenav__menu-link">Contact</a></li>
                    <li><a href="#" class="sidenav__menu-link">Login</a></li>
                    <li><a href="#" class="sidenav__menu-link">FAQ</a></li>
                    <li><a href="#" class="sidenav__menu-link">404</a></li>
                </ul>
            </li>

            <li>
                <a href="#" class="sidenav__menu-link">Sign In</a>
            </li>
        </ul>
    </nav>
</header> <!-- end mobile sidenav -->


<main class="main oh" id="main">

    <!-- Navigation -->
    <header class="nav" xmlns="http://www.w3.org/1999/html">

        <div class="nav__holder nav--sticky">
            <div class="container relative">
                <!-- Top Bar -->
                <div class="top-bar d-none d-lg-flex">
                    <!-- Currency / Language -->
                    <ul class="top-bar__currency-language">
                        <li class="top-bar__language">
                            <a href="#">English</a>
                            <div class="top-bar__language-dropdown">
                                <ul>
                                    <li><a href="#">English</a></li>
                                    <li><a href="#">Spanish</a></li>
                                    <li><a href="#">German</a></li>
                                    <li><a href="#">Chinese</a></li>
                                </ul>
                            </div>
                        </li>
                        <li class="top-bar__currency">
                            <a href="#">USD</a>
                            <div class="top-bar__currency-dropdown">
                                <ul>
                                    <li><a href="#">USD</a></li>
                                    <li><a href="#">EUR</a></li>
                                </ul>
                            </div>
                        </li>
                    </ul>

                    <!-- Promo -->
                    <p class="top-bar__promo text-center">Free shipping on orders over $50</p>
                    <!-- Sign in / Wishlist / Cart -->
                    <div class="top-bar__right">

                        <!-- Sign In -->
                        <a href="#" class="top-bar__item top-bar__sign-in" id="top-bar__sign-in"><i class="ui-user"></i>Sign
                            In</a>

                        <!-- Wishlist -->
                        <a href="#" class="top-bar__item"><i class="ui-heart"></i></a>

                        <div class="top-bar__item nav-cart">
                            <a href="#">
                                <i class="ui-bag"></i>(2)
                            </a>
                            <div class="nav-cart__dropdown">
                                <div class="nav-cart__items">

                                    <div class="nav-cart__item clearfix">
                                        <div class="nav-cart__img">
                                            <a href="#">
                                                <img src="/public/img/shop/cart_small_1.jpg" alt="">
                                            </a>
                                        </div>
                                        <div class="nav-cart__title">
                                            <a href="#">
                                                Classic White Tailored Shirt
                                            </a>
                                            <div class="nav-cart__price">
                                                <span>1 x</span>
                                                <span>19.99</span>
                                            </div>
                                        </div>
                                        <div class="nav-cart__remove">
                                            <a href="#"><i class="ui-close"></i></a>
                                        </div>
                                    </div>

                                    <div class="nav-cart__item clearfix">
                                        <div class="nav-cart__img">
                                            <a href="#">
                                                <img src="/public/img/shop/cart_small_2.jpg" alt="">
                                            </a>
                                        </div>
                                        <div class="nav-cart__title">
                                            <a href="#">
                                                Sport Hi Adidas
                                            </a>
                                            <div class="nav-cart__price">
                                                <span>1 x</span>
                                                <span>29.00</span>
                                            </div>
                                        </div>
                                        <div class="nav-cart__remove">
                                            <a href="#"><i class="ui-close"></i></a>
                                        </div>
                                    </div>

                                </div> <!-- end cart items -->

                                <div class="nav-cart__summary">
                                    <span>Cart Subtotal</span>
                                    <span class="nav-cart__total-price">$1799.00</span>
                                </div>

                                <div class="nav-cart__actions mt-20">
                                    <a href="shop-#" class="btn btn-md btn-light"><span>View Cart</span></a>
                                    <a href="shop-#" class="btn btn-md btn-color mt-10"><span>Proceed to Checkout</span></a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div> <!-- end top bar -->

                <div class="flex-parent">
                    <!-- Mobile Menu Button -->
                    <button class="nav-icon-toggle" id="nav-icon-toggle" aria-label="Open mobile menu">
              <span class="nav-icon-toggle__box">
                <span class="nav-icon-toggle__inner"></span>
              </span>
                    </button> <!-- end mobile menu button -->
                    <!-- Logo -->
                    <a href="index.html" class="logo">
                        <img class="logo__img" src="/public/img/logo_light.png" alt="logo">
                    </a>
                    <!-- Nav-wrap -->
                    <nav class="flex-child nav__wrap d-none d-lg-block">
                        <ul class="nav__menu">

                            <li class="nav__dropdown active">
                                <a href="catalog.html">Men</a>
                                <ul class="nav__dropdown-menu">
                                    <li><a href="#">T-shirt</a></li>
                                    <li><a href="#">Hoodie &amp; Jackets</a></li>
                                    <li><a href="#">Suits</a></li>
                                    <li><a href="#">Shorts</a></li>
                                </ul>
                            </li>

                            <li class="nav__dropdown">
                                <a href="catalog.html">Women</a>
                                <ul class="nav__dropdown-menu">
                                    <li><a href="#">Underwear</a></li>
                                    <li><a href="#">Hipster</a></li>
                                    <li><a href="#">Dress</a></li>
                                    <li><a href="#">Hoodie &amp; Jackets</a></li>
                                    <li><a href="#">Tees</a></li>
                                </ul>
                            </li>

                            <li class="nav__dropdown">
                                <a href="catalog.html">Accessories</a>
                                <ul class="nav__dropdown-menu nav__megamenu">
                                    <li>
                                        <div class="nav__megamenu-wrap">
                                            <div class="row">

                                                <div class="col nav__megamenu-item">
                                                    <a href="#" class="nav__megamenu-title">All accessories</a>
                                                    <ul class="nav__megamenu-list">
                                                        <li><a href="#">Wallets</a></li>
                                                        <li><a href="#">Scarfs</a></li>
                                                        <li><a href="#">Belts</a></li>
                                                        <li><a href="#">Shoes</a></li>
                                                    </ul>
                                                </div>

                                                <div class="col nav__megamenu-item">
                                                    <a href="#" class="nav__megamenu-title">for her</a>
                                                    <ul class="nav__megamenu-list">
                                                        <li><a href="#">Underwear</a></li>
                                                        <li><a href="#">Hipster</a></li>
                                                        <li><a href="#">Dress</a></li>
                                                        <li><a href="#">Hoodie &amp; Jackets</a></li>
                                                        <li><a href="#">Tees</a></li>
                                                    </ul>
                                                </div>

                                                <div class="col nav__megamenu-item">
                                                    <a href="#" class="nav__megamenu-title">for him</a>
                                                    <ul class="nav__megamenu-list">
                                                        <li><a href="#">T-shirt</a></li>
                                                        <li><a href="#">Hoodie &amp; Jackets</a></li>
                                                        <li><a href="#">Suits</a></li>
                                                        <li><a href="#">Shorts</a></li>
                                                    </ul>
                                                </div>

                                                <div class="col nav__megamenu-item">
                                                    <a href="#" class="nav__megamenu-title">watches</a>
                                                    <ul class="nav__megamenu-list">
                                                        <li><a href="#">Smart Watches</a></li>
                                                        <li><a href="#">Diving Watches</a></li>
                                                        <li><a href="#">Sport Watches</a></li>
                                                        <li><a href="#">Classic Watches</a></li>
                                                    </ul>
                                                </div>

                                                <div class="col nav__megamenu-item">
                                                    <a href="#"><img src="/public/img/shop/megamenu_banner.png" alt=""></a>
                                                </div>

                                            </div>
                                        </div>
                                    </li>
                                </ul>
                            </li>

                            <li class="nav__dropdown">
                                <a href="#">News</a>
                                <ul class="nav__dropdown-menu">
                                    <li><a href="#">Blog Standard</a></li>
                                    <li><a href="#">Single Post</a></li>
                                </ul>
                            </li>

                            <li class="nav__dropdown">
                                <a href="#">Pages</a>
                                <ul class="nav__dropdown-menu">
                                    <li><a href="catalog.html">Catalog</a></li>
                                    <li><a href="single-product.html">Single Product</a></li>
                                    <li><a href="#">Cart</a></li>
                                    <li><a href="#">Checkout</a></li>
                                    <li><a href="#">About</a></li>
                                    <li><a href="#">Contact</a></li>
                                    <li><a href="#">FAQ</a></li>
                                    <li><a href="#">404</a></li>
                                </ul>
                            </li>

                        </ul> <!-- end menu -->

                    </nav> <!-- end nav-wrap -->

                    <!-- Search -->
                    <div class="flex-child nav__search d-none d-lg-block">
                        <form method="get" class="nav__search-form">
                            <input type="search" class="nav__search-input" placeholder="Search">
                            <button type="submit" class="nav__search-submit">
                                <i class="ui-search"></i>
                            </button>
                        </form>
                    </div>


                    <!-- Mobile Wishlist -->
                    <a href="#" class="nav__mobile-wishlist d-lg-none" aria-label="Mobile wishlist">
                        <i class="ui-heart"></i>
                    </a>

                    <!-- Mobile Cart -->
                    <a href="#" class="nav__mobile-cart d-lg-none">
                        <i class="ui-bag"></i>
                        <span class="nav__mobile-cart-amount">(2)</span>
                    </a>


                </div> <!-- end flex-parent -->
            </div> <!-- end container -->

        </div>
    </header> <!-- end navigation -->

    <!-- Single Product -->
    <section class="section-wrap pb-20 product-single">
        <div class="container">

            <!-- Breadcrumbs -->
            <ol class="breadcrumbs">
                <li>
                    <a href="index.html">Home</a>
                </li>
                <li>
                    <a href="index.html">Women</a>
                </li>
                <li class="active">
                    Casual Jacket
                </li>
            </ol>

            <div class="row">

                <div class="col-md-6 product-slider mb-50">

                    <div class="flickity flickity-slider-wrap mfp-hover" id="gallery-main">

                        <div class="gallery-cell">
                            <a href="/public/img/shop/item_lg_1.jpg" class="lightbox-img">
                                <img src="https://img.alicdn.com/imgextra/i3/1743582420/O1CN01WErpbo1TkP277GHs8_!!0-item_pic.jpg_430x430q90.jpg" alt=""/>
                            </a>
                        </div>
                        <div class="gallery-cell">
                            <a href="/public/img/shop/item_lg_2.jpg" class="lightbox-img">
                                <img src="/public/img/shop/item_lg_2.jpg" alt=""/>
                            </a>
                        </div>
                        <div class="gallery-cell">
                            <a href="/public/img/shop/item_lg_3.jpg" class="lightbox-img">
                                <img src="/public/img/shop/item_lg_3.jpg" alt=""/>
                            </a>
                        </div>
                        <div class="gallery-cell">
                            <a href="/public/img/shop/item_lg_4.jpg" class="lightbox-img">
                                <img src="/public/img/shop/item_lg_4.jpg" alt=""/>
                            </a>
                        </div>
                        <div class="gallery-cell">
                            <a href="/public/img/shop/item_lg_5.jpg" class="lightbox-img">
                                <img src="/public/img/shop/item_lg_5.jpg" alt=""/>
                            </a>
                        </div>
                    </div> <!-- end gallery main -->

                    <div class="gallery-thumbs" id="gallery-thumbs">
                        <div class="gallery-cell">
                            <img src="/public/img/shop/item_thumb_1.jpg" alt=""/>
                        </div>
                        <div class="gallery-cell">
                            <img src="/public/img/shop/item_thumb_2.jpg" alt=""/>
                        </div>
                        <div class="gallery-cell">
                            <img src="/public/img/shop/item_thumb_3.jpg" alt=""/>
                        </div>
                        <div class="gallery-cell">
                            <img src="/public/img/shop/item_thumb_4.jpg" alt=""/>
                        </div>
                        <div class="gallery-cell">
                            <img src="/public/img/shop/item_thumb_5.jpg" alt=""/>
                        </div>
                    </div> <!-- end gallery thumbs -->

                </div> <!-- end col img slider -->

                <div class="col-md-6 product-single">
                    <h1 class="product-single__title uppercase">测试，由html控制器生成 化妆品</h1>

                    <div class="rating">
                        <a href="#">101 Reviews</a>
                    </div>

                    <span class="product-single__price">
              <ins>
                <span class="amount">$117.99</span>
              </ins>
              <del>
                <span>$300.00</span>
              </del>
            </span>

                    <form action="/product/get" method="post" id="productFrom">
                        <div class="colors clearfix">
                        <span class="colors__label">Color: <span
                                    class="colors__label-selected">Fadaed Blue</span></span>
                            <input name="color" id="color" value="Fadaed Blue" type="hidden">
                            <a href="#" class="colors__item colors__item--selected blue"></a>
                        </div>

                        <div class="size-quantity clearfix">

                            <div class="quantity">
                                <label>Quantity:</label>
                                46
                            </div>
                        </div>

                        <div class="row row-10 product-single__actions clearfix">
                            <div class="col">

                                <input type="hidden" id="productId" value="4" >
                                <input type="button" value="立即抢购" id="getButton" onclick="rushToBuy()" />
                            </div>
                            <div class="col">
                                <a href="#" class="btn btn-lg btn-dark product-single__add-to-wishlist">
                                    <i class="ui-heart"></i>
                                    <span>Wishlist</span>
                                </a>
                            </div>
                        </div>
                    </form>

                    <div class="product_meta">
                        <ul>
                            <li>
                                <span class="product-code">Product Code: <span>111763</span></span>
                            </li>
                            <li>
                                <span class="product-material">Material: <span>Cotton 100%</span></span>
                            </li>
                            <li>
                                <span class="product-country">Country: <span>Made in Canada</span></span>
                            </li>
                        </ul>
                    </div>

                    <!-- Accordion -->
                    <div class="accordion mb-50" id="accordion">
                        <div class="accordion__panel">
                            <div class="accordion__heading" id="headingOne">
                                <a data-toggle="collapse" href="#collapseOne" class="accordion__link accordion--is-open"
                                   aria-expanded="true" aria-controls="collapseOne">Description<span
                                            class="accordion__toggle">&nbsp;</span>
                                </a>
                            </div>
                            <div id="collapseOne" class="collapse show" data-parent="#accordion" role="tabpanel"
                                 aria-labelledby="headingOne">
                                <div class="accordion__body">
                                    Namira is a very slick and clean e-commerce template with endless possibilities.
                                    Creating an awesome clothes store with this Theme is easy than you can imagine.
                                </div>
                            </div>
                        </div>

                        <div class="accordion__panel">
                            <div class="accordion__heading" id="headingTwo">
                                <a data-toggle="collapse" href="#collapseTwo" class="accordion__link accordion--is-closed"
                                   aria-expanded="false" aria-controls="collapseTwo">Information<span
                                            class="accordion__toggle">&nbsp;</span>
                                </a>
                            </div>
                            <div id="collapseTwo" class="collapse" data-parent="#accordion" role="tabpanel"
                                 aria-labelledby="headingTwo">
                                <div class="accordion__body">
                                    <table class="table shop_attributes">
                                        <tbody>
                                        <tr>
                                            <th>Size:</th>
                                            <td>EU 41 (US 8), EU 42 (US 9), EU 43 (US 10), EU 45 (US 12)</td>
                                        </tr>
                                        <tr>
                                            <th>Colors:</th>
                                            <td>Violet, Black, Blue</td>
                                        </tr>
                                        <tr>
                                            <th>Fabric:</th>
                                            <td>Cotton (100%)</td>
                                        </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>

                        <div class="accordion__panel">
                            <div class="accordion__heading" id="headingThree">
                                <a data-toggle="collapse" href="#collapseThree" class="accordion__link accordion--is-closed"
                                   aria-expanded="false" aria-controls="collapseThree">Reviews<span
                                            class="accordion__toggle">&nbsp;</span>
                                </a>
                            </div>
                            <div id="collapseThree" class="collapse" data-parent="#accordion" role="tabpanel"
                                 aria-labelledby="headingThree">
                                <div class="accordion__body">
                                    <div class="reviews">
                                        <ul class="reviews__list">
                                            <li class="reviews__list-item">
                                                <div class="reviews__body">
                                                    <div class="reviews__content">
                                                        <p class="reviews__author"><strong>Alexander Samokhin</strong> - May
                                                            6, 2017 at 12:48 pm</p>
                                                        <div class="rating">
                                                            <a href="#"></a>
                                                        </div>
                                                        <p>This template is so awesome. I didn’t expect so many features
                                                            inside. E-commerce pages are very useful, you can launch your
                                                            online store in few seconds. I will rate 5 stars.</p>
                                                    </div>
                                                </div>
                                            </li>

                                            <li class="reviews__list-item">
                                                <div class="reviews__body">
                                                    <div class="reviews__content">
                                                        <p class="reviews__author"><strong>Christopher Robins</strong> - May
                                                            7, 2014 at 12:48 pm</p>
                                                        <div class="rating">
                                                            <a href="#"></a>
                                                        </div>
                                                        <p>This template is so awesome. I didn’t expect so many features
                                                            inside. E-commerce pages are very useful, you can launch your
                                                            online store in few seconds. I will rate 5 stars.</p>
                                                    </div>
                                                </div>
                                            </li>

                                        </ul>
                                    </div> <!--  end reviews -->
                                </div>
                            </div>
                        </div>
                    </div> <!-- end accordion -->

                </div> <!-- end col product description -->
            </div> <!-- end row -->

        </div> <!-- end container -->
    </section> <!-- end single product -->


    <!-- Related Products -->
    <section class="section-wrap pt-0 pb-40">
        <div class="container">
            <div class="heading-row">
                <div class="text-center">
                    <h2 class="heading bottom-line">
                        Shop the look
                    </h2>
                </div>
            </div>

            <div class="row row-8">

                <div class="col-lg-2 col-sm-4 product">
                    <div class="product__img-holder">
                        <a href="single-product.html" class="product__link">
                            <img src="/public/img/shop/product_1.jpg" alt="" class="product__img">
                            <img src="/public/img/shop/product_back_1.jpg" alt="" class="product__img-back">
                        </a>
                        <div class="product__actions">
                            <a href="#" class="product__quickview">
                                <i class="ui-eye"></i>
                                <span>Quick View</span>
                            </a>
                            <a href="#" class="product__add-to-wishlist">
                                <i class="ui-heart"></i>
                                <span>Wishlist</span>
                            </a>
                        </div>
                    </div>

                    <div class="product__details">
                        <h3 class="product__title">
                            <a href="single-product.html">Joeby Tailored Trouser</a>
                        </h3>
                    </div>

                    <span class="product__price">
              <ins>
                <span class="amount">$17.99</span>
              </ins>
            </span>
                </div> <!-- end product -->

                <div class="col-lg-2 col-sm-4 product">
                    <div class="product__img-holder">
                        <a href="single-product.html" class="product__link">
                            <img src="/public/img/shop/product_9.jpg" alt="" class="product__img">
                            <img src="/public/img/shop/product_back_9.jpg" alt="" class="product__img-back">
                        </a>
                        <div class="product__actions">
                            <a href="#" class="product__quickview">
                                <i class="ui-eye"></i>
                                <span>Quick View</span>
                            </a>
                            <a href="#" class="product__add-to-wishlist">
                                <i class="ui-heart"></i>
                                <span>Wishlist</span>
                            </a>
                        </div>
                    </div>

                    <div class="product__details">
                        <h3 class="product__title">
                            <a href="single-product.html">Men’s Belt</a>
                        </h3>
                    </div>

                    <span class="product__price">
              <ins>
                <span class="amount">$9.90</span>
              </ins>
            </span>
                </div> <!-- end product -->

                <div class="col-lg-2 col-sm-4 product">
                    <div class="product__img-holder">
                        <a href="single-product.html" class="product__link">
                            <img src="/public/img/shop/product_10.jpg" alt="" class="product__img">
                            <img src="/public/img/shop/product_back_10.jpg" alt="" class="product__img-back">
                        </a>
                        <div class="product__actions">
                            <a href="#" class="product__quickview">
                                <i class="ui-eye"></i>
                                <span>Quick View</span>
                            </a>
                            <a href="#" class="product__add-to-wishlist">
                                <i class="ui-heart"></i>
                                <span>Wishlist</span>
                            </a>
                        </div>
                    </div>

                    <div class="product__details">
                        <h3 class="product__title">
                            <a href="single-product.html">Sport Hi Adidas</a>
                        </h3>
                    </div>

                    <span class="product__price">
              <ins>
                <span class="amount">$29.00</span>
              </ins>
            </span>
                </div> <!-- end product -->

                <div class="col-lg-2 col-sm-4 product">
                    <div class="product__img-holder">
                        <a href="single-product.html" class="product__link">
                            <img src="/public/img/shop/product_2.jpg" alt="" class="product__img">
                            <img src="/public/img/shop/product_back_2.jpg" alt="" class="product__img-back">
                        </a>
                        <div class="product__actions">
                            <a href="#" class="product__quickview">
                                <i class="ui-eye"></i>
                                <span>Quick View</span>
                            </a>
                            <a href="#" class="product__add-to-wishlist">
                                <i class="ui-heart"></i>
                                <span>Wishlist</span>
                            </a>
                        </div>
                    </div>

                    <div class="product__details">
                        <h3 class="product__title">
                            <a href="single-product.html">Denim Hooded</a>
                        </h3>
                    </div>

                    <span class="product__price">
              <ins>
                <span class="amount">$30.00</span>
              </ins>
            </span>
                </div> <!-- end product -->

                <div class="col-lg-2 col-sm-4 product">
                    <div class="product__img-holder">
                        <a href="single-product.html" class="product__link">
                            <img src="/public/img/shop/product_3.jpg" alt="" class="product__img">
                            <img src="/public/img/shop/product_back_3.jpg" alt="" class="product__img-back">
                        </a>
                        <div class="product__actions">
                            <a href="#" class="product__quickview">
                                <i class="ui-eye"></i>
                                <span>Quick View</span>
                            </a>
                            <a href="#" class="product__add-to-wishlist">
                                <i class="ui-heart"></i>
                                <span>Wishlist</span>
                            </a>
                        </div>
                    </div>

                    <div class="product__details">
                        <h3 class="product__title">
                            <a href="single-product.html">Mint Maxi Dress</a>
                        </h3>
                    </div>

                    <span class="product__price">
              <ins>
                <span class="amount">$17.99</span>
              </ins>
              <del>
                <span>$30.00</span>
              </del>
            </span>
                </div> <!-- end product -->

                <div class="col-lg-2 col-sm-4 product">
                    <div class="product__img-holder">
                        <a href="single-product.html" class="product__link">
                            <img src="/public/img/shop/product_4.jpg" alt="" class="product__img">
                            <img src="/public/img/shop/product_back_4.jpg" alt="" class="product__img-back">
                        </a>
                        <div class="product__actions">
                            <a href="#" class="product__quickview">
                                <i class="ui-eye"></i>
                                <span>Quick View</span>
                            </a>
                            <a href="#" class="product__add-to-wishlist">
                                <i class="ui-heart"></i>
                                <span>Wishlist</span>
                            </a>
                        </div>
                    </div>

                    <div class="product__details">
                        <h3 class="product__title">
                            <a href="single-product.html">White Flounce Dress</a>
                        </h3>
                    </div>

                    <span class="product__price">
              <ins>
                <span class="amount">$15.99</span>
              </ins>
              <del>
                <span>$27.00</span>
              </del>
            </span>
                </div> <!-- end product -->

            </div> <!-- end row -->
        </div> <!-- end container -->
    </section> <!-- end related products -->

    <script>
        // var startTime = "Mon Jun 18 2018 19:34:20 GMT+0800 (CST)" //秒杀开始时间
        // //求时间差秒级别
        // function contrastTime(begin, end) {
        //     var difference = (Date.parse(end) - Date.parse(begin)) / 1000; //利用时间戳算出相差的时间
        //     return difference;
        // }
        //
        // //判断时间是否可以
        // function isTimeOk() {
        //     var d = new Date();
        //     var ret = contrastTime(d, startTime);//获取返回值
        //     //判断开始时间是否大于当前时间，秒为单位
        //     if (ret >= 0) {
        //         //大于则无法够买
        //         return false
        //     }
        //     return true
        // }
        // //判断是否开始抢购,这里可以改成其它方式
        // if (isTimeOk() == true) {
        //     document.getElementById('add').style="";
        // } else {
        //     document.getElementById('add').style="display:none";
        //     //一秒判断一次
        // }
        //
        // //点击按钮后10秒不允许提交,也可以变成其它样式
        // document.getElementById('add').onclick=function(){
        //     this.style= "display:none";
        //     setTimeout(function (){
        //         document.getElementById('add').style="";
        //     },3000);
        // }
        // //表单提交
        // function doSubmitForm() {
        //     var form = document.getElementById('productFrom');
        //     form.submit();
        // }
        // 抢购按钮
        var rushButtonId = "getButton"
        // 跳转地址
        var redirectUrl = "/user/login"
        // 时间间隔
        var interval =  10
        // 计数器
        var count = interval
        // 定时器
        var inter
        function getCookie(name) {
            var arr,reg=new RegExp("(^| )"+name+"=([^;]*)(;|$)");
            if(arr=document.cookie.match(reg)) {
                return unescape(arr[2]);
            }else{
                return null;
            }
        }
        function timeSub(){
            inter = setInterval("timeFuc()",1000)
        }
        function timeFuc() {
            count--;
            if (count<=0){
                count = interval;
                document.getElementById(rushButtonId).removeAttribute("disabled");
                document.getElementById(rushButtonId).value = "立即抢购";
                clearInterval(inter)

            }else{
                document.getElementById(rushButtonId).value = "抢购等待"+count+"秒"
            }
        }
        if (getCookie("uid")==null) {
            location.href = "http://127.0.0.1"+redirectUrl;
        }
        function rushToBuy() {
            var productId = document.getElementById("productId").value;
            // 设置按钮不可用
            document.getElementById(rushButtonId).setAttribute("disabled",true)
            // 开始倒计时
            timeSub()
            // 发送异步请求
            var xmlHttp;
            if (window.XMLHttpRequest){
                 xmlHttp = new XMLHttpRequest();
            }else{
                // ie6,ie5
                xmlHttp = new ActiveXObject("Microsoft.XMLHTTP");
            }
            request_url = "http://127.0.0.1:8083/check?productID="+productId
            //request_url = "http://129.204.49.177:8083/check?procuctID="+productId

            xmlHttp.onreadystatechange = function(){

                if(xmlHttp.readyState == 4){
                    if (xmlHttp.status === 200) {
                        var result = xmlHttp.responseText;
                        console.log(result)
                        if (result=="true"){
                            alert('抢购成功！');
                        }else{
                            alert('抢购失败，请重试！');

                        }
                    }
                }

            }
            xmlHttp.onerror = function(e) {
                alert('请求失败')
            }
            xmlHttp.open('GET', request_url);

            xmlHttp.send();


        }
    </script>
    <script>

    </script>



</main> <!-- end main-wrapper -->

<!-- Footer -->
<footer class="footer">
    <div class="container">
        <div class="footer__widgets">
            <div class="row">

                <div class="col-lg-4 col-md-6">
                    <div class="widget widget__about">
                        <h4 class="widget-title white">about us</h4>
                        <p class="widget__about-text">Namira is a very slick and clean e-commerce template with endless possibilities.</p>
                    </div>
                </div>

                <div class="col-lg-4 col-md-6">
                    <div class="widget widget__newsletter">
                        <h4 class="widget-title white">get exclusive offers &amp; updates</h4>

                        <form class="mc4wp-form">
                            <div class="mc4wp-form-fields">
                                <p><input type="email" placeholder="Please enter your email address"></p>
                                <p><input type="submit" value="Subscribe"></p>
                            </div>
                        </form>

                        <div class="socials socials--white mt-20">
                            <a href="#" class="facebook"><i class="ui-facebook"></i></a>
                            <a href="#" class="twitter"><i class="ui-twitter"></i></a>
                            <a href="#" class="snapchat"><i class="ui-snapchat"></i></a>
                            <a href="#" class="instagram"><i class="ui-instagram"></i></a>
                            <a href="#" class="pinterest"><i class="ui-pinterest"></i></a>
                        </div>
                    </div>
                </div>

                <div class="col-lg-2 col-md-6">
                    <div class="widget widget_nav_menu">
                        <h4 class="widget-title white">help</h4>
                        <ul>
                            <li><a href="#">Contact Us</a></li>
                            <li><a href="#">Tract Order</a></li>
                            <li><a href="#">Returns &amp; Refunds</a></li>
                            <li><a href="#">Private Policy</a></li>
                            <li><a href="#">Shipping Info</a></li>
                            <li><a href="#">FAQ</a></li>
                        </ul>
                    </div>
                </div>

                <div class="col-lg-2 col-md-6">
                    <div class="widget widget_nav_menu">
                        <h4 class="widget-title white">information</h4>
                        <ul>
                            <li><a href="#">Our Stores</a></li>
                            <li><a href="#">Careers</a></li>
                            <li><a href="#">Delivery Info</a></li>
                            <li><a href="#">Terms &amp; Conditions</a></li>
                            <li><a href="#">Site Map</a></li>
                            <li><a href="#">Namira Reviews</a></li>
                        </ul>
                    </div>
                </div>

            </div>
        </div>
    </div> <!-- end container -->

    <div class="footer__bottom">
        <div class="container">
            <div class="row">
                <div class="col-md-6 text-sm-center">
              <span class="copyright">
                Copyright &copy; 2018.Company name All rights reserved.<a target="_blank" href="http://sc.chinaz.com/moban/">&#x7F51;&#x9875;&#x6A21;&#x677F;</a>
              </span>
                </div>

                <div class="col-md-6 footer__payment-systems text-right text-sm-center mt-sml-10">
                    <i class="ui-paypal"></i>
                    <i class="ui-visa"></i>
                    <i class="ui-mastercard"></i>
                    <i class="ui-discover"></i>
                    <i class="ui-amex"></i>
                </div>
            </div>
        </div>
    </div> <!-- end bottom footer -->
</footer> <!-- end footer -->



<!-- jQuery Scripts -->
<script type="text/javascript" src="/public/js/jquery.min.js"></script>
<script type="text/javascript" src="/public/js/bootstrap.min.js"></script>
<script type="text/javascript" src="/public/js/easing.min.js"></script>
<script type="text/javascript" src="/public/js/jquery.magnific-popup.min.js"></script>
<script type="text/javascript" src="/public/js/owl-carousel.min.js"></script>
<script type="text/javascript" src="/public/js/flickity.pkgd.min.js"></script>
<script type="text/javascript" src="/public/js/modernizr.min.js"></script>
<script type="text/javascript" src="/public/js/scripts.js"></script>

</body>
</html>

```

项目地址：

<https://github.com/18318553760/iris_demo> 