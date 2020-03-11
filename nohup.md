# 概述

# [使程序在Linux下后台运行](https://www.cnblogs.com/andylhc/p/9721705.html)

 

[![复制代码](https://common.cnblogs.com/images/copycode.gif)](javascript:void(0);)

```
#后台执行程序
nohup  python dingding_for_safe.py > run.log 2>&1 &

#查看后台程序
ps aux |grep "test.sh"  #a:显示所有程序  u:以用户为主的格式来显示   x:显示所有程序，不以终端机来区分
ps -ef |grep "test.sh"  #-e显示所有进程。-f全格式。

#关闭后台程序
kill 1001
kill  -9 1001  #-9表示强制关闭
 
```

[![复制代码](https://common.cnblogs.com/images/copycode.gif)](javascript:void(0);)

 

**1. 在终端输入命令，使程序后台执行：**

nohup  ./pso > pso.log 2>&1 &

解释：nohup就是不挂起的意思，将pso直接放在后台运行，并把终端输出存放在当前

目录下的pso.log文件中。当客户端关机后重新登陆服务器后，直接查看pso.log文件就可看执行结果（命令：#cat pso.file）。

 

# [使程序在Linux下后台运行 （关掉终端继续让程序运行的方法）](https://blog.csdn.net/zxh2075/article/details/52932885)

 

## **2. 关闭当前后台运行的命令**，可进入当前目录执行

​       **ps命令** 功能：查看当前的所有进程

​          ![img](https://img-blog.csdn.net/20170630162114394)![img]()

​      **kill命令：结束进程**

​     （1）通过jobs命令查看jobnum，然后执行   kill  jobnum

​     （2）通过ps命令查看进程号PID，然后执行  kill PID

​       如果是前台进程的话，直接执行 Ctrl+c 就可以终止了

​           ------- 作者：求知之人 来源：[CSDN 原文](https://blog.csdn.net/u013846293/article/details/74003051/) 

 

### 3. linux后台运行命令nohup和&的区别

1.   &的意思是在后台运行， 什么意思呢？  意思是说， 当你在执行 ./a.out & 的时候， 即使你用ctrl C,  那么a.out照样运行（因为对SIGINT信号免疫）。 但是要注意， 如果你直接关掉shell后， 那么， a.out进程同样消失。 可见， &的后台并不硬（因为对SIGHUP信号不免疫）。

2.   nohup的意思是忽略SIGHUP信号， 所以当运行nohup ./a.out的时候， 关闭shell, 那么a.out进程还是存在的（对SIGHUP信号免疫）。 但是， 要注意， 如果你直接在shell中用Ctrl C, 那么, a.out进程也是会消失的（因为对SIGINT信号不免疫）

3.   所以， &和nohup没有半毛钱的关系， 要让进程真正不受shell中Ctrl C和shell关闭的影响， 那该怎么办呢？ 那就用nohua ./a.out &吧， 两全其美。

 

来源：https://blog.csdn.net/stpeace/article/details/76389073     https://blog.csdn.net/u011095110/article/details/78666833