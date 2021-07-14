## ping-delay

本功能追踪ping包的时间延迟。

###  查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools ping-delay --help
```
结果如下：
```
    ping-delay usage:
        --help ping_delay help info
        --activate
          verbose VERBOSE
          addr filtered ipv4 address.
        --deactivate
        --settings dump settings
        --report dump log with text.
        --log
          sls=/tmp/1.log store in file
          syslog=1 store in syslog
```

###  安装KO
参见《安装和卸载KO》一节
###  激活功能
激活本功能的命令是：
```
  diagnose-tools ping-delay --activate
```
在激活本功能时，可用参数为：
* verbose 该参数设置输出级别，当该值为1时，输出详细的报文信息。
* addr 设置要过滤的IP地址。
例如，如下命令设置输出级别为1：
```
diagnose-tools ping-delay --activate='verbose=1'
```
如果成功，将输出：
```
功能设置成功，返回值：0
    输出级别：1
    过滤地址：0.0.0.0
```
如果失败，将输出：
```
功能设置失败，返回值：-16
    输出级别：1
    过滤地址：0.0.0.0
```

###  测试用例
运行如下命令运行测试用例，以查看本功能是否正常：
```
sh /usr/diagnose-tools/test.sh ping-delay
```

###  查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools ping-delay --settings
```
结果如下：
```
功能设置：
    是否激活：×
    输出级别：0
    过滤地址：0.0.0.0
```
###  查看结果

执行如下命令查看本功能的输出结果：
```
diagnose-tools ping-delay --report
```

输出结果示例如下：
```
PING延时信息, 源IP：[172.16.241.166], 目的IP：[172.16.241.167], ID：2529, SEQ: 1, 时间：[1626250570:568878]
                       PD_ETH_RECV:         272296490950
                       PD_GRO_RECV:         272296491246
                   PD_GRO_RECV_ERR:                    0
                       PD_RECV_SKB:         272296492201
                  PD_RECV_SKB_DROP:                    0
                         PD_IP_RCV:         272296493223
                  PD_IP_RCV_FINISH:         272296493815
                      PD_DST_INPUT:         272296494982
                  PD_LOCAL_DELIVER:         272296495129
           PD_LOCAL_DELIVER_FINISH:         272296495186
                       PD_ICMP_RCV:         272296497254
                        PD_IP_SEND:         272296181957
                     PD_QUEUE_XMIT:         272296238226
                       PD_DEV_XMIT:         272296241068
```

输出结果中包含ping报文在各个阶段的时间，以ns为单位。
每次输出结果后，历史数据将被清空。

###  关闭功能
通过如下命令关闭本功能：
diagnose-tools ping-delay --deactivate
关闭功能后，本功能将不会对系统带来性能影响。
