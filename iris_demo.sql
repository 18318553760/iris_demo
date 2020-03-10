/*
Navicat MySQL Data Transfer

Source Server         : localhost
Source Server Version : 50553
Source Host           : localhost:3306
Source Database       : iris_blog

Target Server Type    : MYSQL
Target Server Version : 50553
File Encoding         : 65001

Date: 2020-03-10 10:55:31
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for order
-- ----------------------------
DROP TABLE IF EXISTS `order`;
CREATE TABLE `order` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `userID` int(11) DEFAULT NULL,
  `productID` int(11) DEFAULT NULL,
  `orderStatus` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=24 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of order
-- ----------------------------
INSERT INTO `order` VALUES ('20', '2', '4', '1');
INSERT INTO `order` VALUES ('21', '2', '4', '1');
INSERT INTO `order` VALUES ('22', '2', '4', '1');
INSERT INTO `order` VALUES ('23', '2', '4', '1');

-- ----------------------------
-- Table structure for product
-- ----------------------------
DROP TABLE IF EXISTS `product`;
CREATE TABLE `product` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `productName` varchar(255) DEFAULT NULL,
  `productNum` int(11) DEFAULT NULL,
  `productImage` varchar(255) DEFAULT NULL,
  `productUrl` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of product
-- ----------------------------
INSERT INTO `product` VALUES ('4', '化妆品', '31', 'https://img.alicdn.com/imgextra/i3/1743582420/O1CN01WErpbo1TkP277GHs8_!!0-item_pic.jpg_430x430q90.jpg', 'https://detail.tmall.com/item.htm?spm=a211oj.13994892.6992705520.1.704a310fyd8LsH&id=601612495516&scm=1007.12144.115311.9599069_0_0&pvid=2470739c-625a-4c4a-b820-c0796d229b13&sku_properties=20509:28383');

-- ----------------------------
-- Table structure for user
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `ID` int(11) NOT NULL AUTO_INCREMENT,
  `nickName` varchar(255) DEFAULT NULL,
  `userName` varchar(255) DEFAULT NULL,
  `passWord` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of user
-- ----------------------------
INSERT INTO `user` VALUES ('1', 'test', 'test', '$2a$10$RI.dnbCsEP/6CzF68au9/.y3m7LtfNN.Eqr0.cukRls0Zs54qeX5i');
INSERT INTO `user` VALUES ('2', 'test', 'admin', '$2a$10$5rfXWpzgERh6YQ9IoE3l/./5JdzGMOAaH/gcV2QhtliMj9N5/FzRu');
