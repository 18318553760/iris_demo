/**
* @program: Go
*
* @description:
*
* @author: Mr.chen
*
* @create: 2020-03-06 10:42
**/
package services
import (
	"iris_demo/datamodels"
	"iris_demo/repositories"
)
// 定义接口
type IOrderService interface {
	GetOrderByID(int64) (*datamodels.Order,error)
	DeleteOrderByID(int64) bool
	UpdateOrder(*datamodels.Order) error
	InsertOrder(*datamodels.Order) (int64 ,error)
	GetAllOrder()([]*datamodels.Order,error)
	GetAllOrderInfo()(map[int]map[string]string,error)
	InsertOrderByMessage(message *datamodels.Message)(int64,error)
}
// 定义结构太，实现接口，定义变量，获取其他接口
type OrderService struct {
	OrderRepository repositories.IOrderRepository
}
// 初始化
func NewOrderService(repository repositories.IOrderRepository ) IOrderService  {
	return &OrderService{OrderRepository:repository}
}

// 根据订单ID获取信息
func (o *OrderService) GetOrderByID(orderID int64) (order *datamodels.Order,err error)  {
	return o.OrderRepository.SelectByKey(orderID)
}


// 根据订单ID删除信息
func (o *OrderService) DeleteOrderByID(orderID int64) (isOk bool)  {
	isOk = o.OrderRepository.Delete(orderID)
	return
}
// 根据订单信息更新订单信息
func (o *OrderService) UpdateOrder(order *datamodels.Order) error{
	return o.OrderRepository.Update(order)
}
// 插入
func (o *OrderService) InsertOrder(order *datamodels.Order) (orderID int64,err error)  {
	return o.OrderRepository.Insert(order)
}
// 获取所有订单
func (o *OrderService) GetAllOrder()([]*datamodels.Order,error) {
	return o.OrderRepository.SelectAll()
}
// 获取所有订单信息
func (o *OrderService) GetAllOrderInfo()(map[int]map[string]string,error) {
	return o.OrderRepository.SelectAllWithInfo()
}
//根据消息创建订单
func (o *OrderService) InsertOrderByMessage(message *datamodels.Message) (orderID int64 ,err error) {
	order :=&datamodels.Order{
		UserId:message.UserID,
		ProductId:message.ProductID,
		OrderStatus:datamodels.OrderSuccess,
	}
	return o.InsertOrder(order)


}