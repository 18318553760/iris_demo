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
		iris.Addr("0.0.0.0:8080"),
		iris.WithoutServerError(iris.ErrServerClosed),
		iris.WithOptimizations,
	)

}