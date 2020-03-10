# 概述

分布式系统即将一个系统解耦成多个系统运行，运行在不同的环境下，数据库通用

## 1、Windows下打包go项目

cmd运行

GOOS=linux GOARCH=amd64 go build productMain.go

## 2、部署go项目

新建与项目名称相同的文件夹，把打包的exe文件放在本文件下，把静态文件拷贝在当前项目同名的问价夹下，运行查看效果

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