/**
* @program: Go
*
* @description:
*
* @author: Mr.chen
*
* @create: 2020-03-06 10:54
**/
package admin

import (
	"github.com/kataras/iris"
	"github.com/kataras/iris/mvc"
	"iris_demo/services"
)

type OrderController struct {
	Ctx iris.Context
	OrderService services.IOrderService
}

func (o *OrderController) Get() mvc.View {
	orderArray,err:=o.OrderService.GetAllOrderInfo()
	if err !=nil {
		o.Ctx.Application().Logger().Debug("查询订单信息失败")
	}

	return mvc.View{
		Name:"/admin/order/view.html",
		Data:iris.Map{
			"order":orderArray,
		},
	}

}
