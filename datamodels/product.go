/**
* @program: Go
*
* @description:
*
* @author: Mr.chen
*
* @create: 2020-03-05 09:34
**/
package datamodels

type Product struct {
	ID           int64  `json:"id" sql:"ID" iris:"ID"`
	ProductName  string `json:"ProductName" sql:"productName" iris:"ProductName"`
	ProductNum   int64  `json:"ProductNum" sql:"productNum" iris:"ProductNum"`
	ProductImage string `json:"ProductImage" sql:"productImage" iris:"ProductImage"`
	ProductUrl   string `json:"ProductUrl" sql:"productUrl" iris:"ProductUrl"`
}
