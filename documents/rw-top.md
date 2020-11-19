##  rw-top
本功能监控一段时间内执行文件写的进程和文件。

###  查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools rw-top --help
```
结果如下：
```
    rw-top usage:
        --help rw-top help info
        --activate
          verbose VERBOSE
          top how many items to dump
          shm set 1 if want dump shm
          perf set 1 if want perf detail
        --deactivate
        --report dump log with text.
        --log
          sls=/tmp/1.log store in file
          syslog=1 store in syslog.
```
###  安装KO
参见《安装和卸载KO》一节

###  激活功能
激活本功能的命令是：
```
diagnose-tools rw-top --activate
```
在激活本功能时，可用参数为：
* verbose 设置输出信息的详细程度
* top 设置输出列表的长度，默认值是20。
* shm 如果设置为1,将只监控对共享内存文件的读写。

例如，如下命令设置输出列表长度为100：
```
diagnose-tools rw-top --activate='top=100'
```
如果成功，将输出：
```
功能设置成功，返回值：0
    TOP：100
    SHM：0
    PERF: 0
    输出级别：0
```
如果失败，将输出：
```
功能设置失败，返回值：-16
    TOP：100
    SHM：0
    PERF: 0
    输出级别：0
```

###  测试用例
运行如下命令启动本功能的测试用例：
```
sh /usr/diagnose-tools/test.sh rw-top
```
 
###  查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools rw-top --settings
```
结果如下：
```
功能设置：
    是否激活：×
    TOP：0
    SHM：0
    PERF1
    输出级别：1
```
###  查看结果
执行如下命令查看本功能的输出结果：
```
diagnose-tools rw-top --report
```
输出结果示例如下：
```
  序号           R-SIZE            W-SIZE          MAP-SIZE           RW-SIZE        文件名
    1                 0             66375                 0             66375        /apsarapangu/tmp.txt 
```
输出结果中，包含了写数量排名前100名的文件名/读写长度。
###  关闭功能
通过如下命令关闭本功能：
```
diagnose-tools rw-top --deactivate
```
如果成功，将输出：
```
rw-top is not activated
```
如果失败，将输出：
```
deactivate rw-top fail, ret is -1
```
关闭功能后，本功能将不会对系统带来性能影响。
