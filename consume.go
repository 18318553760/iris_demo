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

