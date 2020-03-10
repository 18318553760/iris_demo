/**
* @program: Go
*
* @description:
*
* @author: Mr.chen
*
* @create: 2020-03-06 09:30
**/
package repositories
import (
	"database/sql"

	"iris_demo/common"
	"iris_demo/datamodels"
	"strconv"
)

//第一步，先开发对应的接口
//第二步，实现定义的接口
type IOrderRepository interface {
	//连接数据
	Conn()(error)
	Insert(*datamodels.Order)(int64,error)
	Delete(int64) bool
	Update(*datamodels.Order) error
	SelectByKey(int64)(*datamodels.Order,error)
	SelectAll()([]*datamodels.Order,error)
	SelectAllWithInfo()(map[int]map[string]string,error)
}

type OrderMangerRepository struct {
	table string
	mysqlConn *sql.DB
}

func NewOrderMangerRepository(table string,db *sql.DB) IOrderRepository  {
	return &OrderMangerRepository{table:table,mysqlConn:db}
}



//数据连接
func (o *OrderMangerRepository) Conn()(err error)  {
	if o.mysqlConn == nil {
		mysql,err := common.NewMysqlConn()
		if err !=nil {
			return err
		}
		o.mysqlConn = mysql
	}
	if o.table == "" {
		o.table = "order"
	}
	return
}

//插入
func (o *OrderMangerRepository) Insert(order *datamodels.Order) (orderId int64,err error) {
	//1.判断连接是否存在
	if err=o.Conn();err != nil{
		return
	}

	//2.准备sql
	sql := "INSERT `order` SET userID=?,productID=?,orderStatus=?"

	stmt, errStmt := o.mysqlConn.Prepare(sql)
	if errStmt != nil {
		return orderId, errStmt
	}
	//3.传入参数
	result, errStmt := stmt.Exec(order.UserId, order.ProductId, order.OrderStatus)
	if errStmt !=nil {
		return 0,errStmt
	}
	return result.LastInsertId()
}
//订单的删除
func (o *OrderMangerRepository) Delete(orderID int64) bool  {
	//1.判断连接是否存在
	if err:=o.Conn();err != nil{
		return false
	}
	sql := "delete from "+o.table+" where ID=?"
	stmt,err := o.mysqlConn.Prepare(sql)
	if err!= nil {
		return false
	}
	_,err = stmt.Exec(strconv.FormatInt(orderID,10))
	if err !=nil {
		return false
	}
	return true
}

//订单的更新
func (o *OrderMangerRepository) Update(order *datamodels.Order) error {
	//1.判断连接是否存在
	if err:=o.Conn();err != nil{
		return err
	}

	sql := "Update "+ o.table + " set userID=?,productID=?,orderStatus=? where ID="+strconv.FormatInt(order.ID,10)
	stmt,err := o.mysqlConn.Prepare(sql)
	if err !=nil {
		return err
	}
	_,err = stmt.Exec(order.UserId,order.ProductId,order.OrderStatus)
	if err !=nil {
		return err
	}
	return nil
}

//根据订单ID查询订单
func (o *OrderMangerRepository) SelectByKey(orderID int64) (productResult *datamodels.Order,err error) {
	//1.判断连接是否存在
	if err=o.Conn();err != nil{
		return &datamodels.Order{},err
	}
	sql := "Select * from "+o.table+" where ID ="+strconv.FormatInt(orderID,10)
	row,errRow :=o.mysqlConn.Query(sql)
	defer row.Close()
	if errRow !=nil {
		return &datamodels.Order{},errRow
	}
	result := common.GetResultRow(row)
	if len(result)==0{
		return &datamodels.Order{},nil
	}
	productResult = &datamodels.Order{}
	common.DataToStructByTagSql(result,productResult)
	return
}

//获取所有订单
func (o *OrderMangerRepository) SelectAll()(orderArray []*datamodels.Order,err error){
	//1.判断连接是否存在
	if err:=o.Conn();err!= nil{
		return nil,err
	}
	sql := "Select * from "+o.table
	rows,err := o.mysqlConn.Query(sql)
	defer  rows.Close()
	if err !=nil {
		return nil ,err
	}

	result:= common.GetResultRows(rows)
	if len(result)==0{
		return nil,nil
	}

	for _,v :=range result{
		order := &datamodels.Order{}
		common.DataToStructByTagSql(v,order)
		orderArray=append(orderArray, order)
	}
	return
}
// 查询订单与商品的详细信息
func (o *OrderMangerRepository) SelectAllWithInfo() (orderMap map[int]map[string]string,err error){
	if errConn := o.Conn(); errConn != nil {
		return nil, errConn
	}
	sql := "Select o.ID,p.productName,o.orderStatus From order as o left join product as p on o.productID=p.ID"
	rows, errRows := o.mysqlConn.Query(sql)
	if errRows != nil {
		return nil, errRows
	}
	return common.GetResultRows(rows), err
}