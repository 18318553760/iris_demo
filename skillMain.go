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
	"github.com/kataras/iris"
)

func main()  {
	//1.创建iris 实例
	app:=iris.New()
	//2.设置错误模式，在mvc模式下提示错误
	app.Logger().SetLevel("debug" )
	app.Handle("GET", "/", func(ctx iris.Context) {
		ctx.HTML("<h1> Hello nginx2 </h1>")
	})
	//4.设置模板目标
	app.StaticWeb("/public", "./web/views/home/public")
	app.StaticWeb("/html", "./web/views/home/htmlProductShow")
	//6.启动服务
	app.Run(
		iris.Addr("0.0.0.0:9081"),
		iris.WithoutServerError(iris.ErrServerClosed),
		iris.WithOptimizations,
	)

}