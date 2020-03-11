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
var hostArray= []string{"172.16.0.3","172.16.0.13"} // 本机的内网ip,通过common.GetIntranceIp()可以获取
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
	//	return true
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
	fmt.Println("机器访问2")
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
	fmt.Println(localHost)

	filter := common.NewFilter()
	filter.RegisterFilterUri("/check",Auth) // 注册函数，把url放在拦截器，访问/check会被拦截
	http.HandleFunc("/check",filter.Handle(Check)) // 处理拦截器
	filter.RegisterFilterUri("/checkRight",Auth)
	http.HandleFunc("/checkRight",filter.Handle(CheckRight))
	http.ListenAndServe(":8083", nil)
}