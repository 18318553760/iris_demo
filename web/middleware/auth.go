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

