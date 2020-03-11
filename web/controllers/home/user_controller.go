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

//func (c *UserController) PostLogin() mvc.Response {
//	//1.获取用户提交的表单信息
//	var (
//		userName = c.Ctx.FormValue("userName")
//		password = c.Ctx.FormValue("password")
//
//	)
//	//2、验证账号密码正确
//	user, isOk := c.Service.IsPwdSuccess(userName, password)
//	if !isOk {
//		return mvc.Response{
//			Path: "/user/login",
//		}
//	}
//
//	//3、写入用户ID到cookie中
//	//tool.GlobalCookie(c.Ctx, "uid", strconv.FormatInt(user.ID, 10))
//	//c.Session.Set("userID",strconv.FormatInt(user.ID,10))
//
//	//3、写入用户ID到cookie中 用cookie代替session集群
//	tool.GlobalCookie(c.Ctx, "uid", strconv.FormatInt(user.ID, 10))
//	uidByte := []byte(strconv.FormatInt(user.ID, 10))
//	uidString, err := encrypt.EnPwdCode(uidByte)
//	if err != nil {
//		fmt.Println(err)
//	}
//	//写入用户浏览器
//	tool.GlobalCookie(c.Ctx, "sign", uidString)
//
//	return mvc.Response{
//		Path: "/product/detail",
//	}
//
//}
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
	tool.GlobalCookie(c.Ctx, "uid", strconv.FormatInt(user.ID, 10))
	uidByte := []byte(strconv.FormatInt(user.ID, 10))
	uidString, err := encrypt.EnPwdCode(uidByte)
	if err != nil {
		fmt.Println(err)
	}
	//写入用户浏览器
	tool.GlobalCookie(c.Ctx, "sign", uidString)

	return mvc.Response{
		Path: "/html/product.html",
	}

}

