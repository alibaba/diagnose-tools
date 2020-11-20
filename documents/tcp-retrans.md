## tcp-retrans
本功能统计内核态一段时间内，各个TCP连接上面的重传计数。
###  查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools tcp-retrans --help
```
结果如下：
```
    tcp-retrans usage:
        --help tcp-retrans help info
        --activate
          verbose VERBOSE
          source-addr source addr you want monitor
          source-port source port you want monitor
          dest-addr dest addr you want monitor
          dest-port dest port you want monitor
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
diagnose-tools tcp-retrans --activate
```
在激活本功能时，可用的参数有：
* verbose 该参数设置输出级别，暂时未用。
例如，如下命令设置输出级别为1：
```
diagnose-tools tcp-retrans --activate='verbose=1'
```
如果成功，将输出:
```
功能设置成功，返回值：0
    输出级别：1
```

如果失败，将输出：
```
功能设置失败，返回值：-16
    输出级别：1
```

###  测试用例
运行如下命令启动本功能的测试用例：
sh /usr/diagnose-tools/test.sh tcp-retrans

###  查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools tcp-retrans --settings
```
结果如下：
```
功能设置：
    是否激活：√
    输出级别：1
```
###  查看结果
执行如下命令查看本功能的输出结果：
```
diagnose-tools tcp-retrans --report
```
可以在report的时候，指定ignore参数，这样就不会打印重传数量较少的五元组，如：
```
diagnose-tools tcp-retrans --report="ignore=5"
```
这样，重传次数在5次以下的将被忽略。
输出结果示例如下：
```
TCP重传调试统计：：
    分配次数：0
    tcp_retransmit_skb调用次数：10
    tcp_rtx_synack调用次数：0
    tcp_dupack调用次数：15
    tcp_send_dupack调用次数：0
    源地址： 10.0.2.15[703]， 目的地址： 180.101.49.12[9999]， SYNC重传次数: 0, 报文重传次数： 4
    源地址： 10.0.2.15[14498]， 目的地址： 180.101.49.11[9999]， SYNC重传次数: 0, 报文重传次数： 6
```
输出结果中包含一些调试统计值，以及每个连接上的重传统计。包含sync重传和报文重传统计。
每次输出结果后，历史数据将被清空。
###  关闭功能
通过如下命令关闭本功能：
```
diagnose-tools tcp-retrans --deactivate
```
如果成功，将输出：
```
tcp-retrans is not activated
```
如果失败，将输出：
```
deactivate tcp-retrans fail, ret is -1
```
关闭功能后，本功能将不会对系统带来性能影响。
