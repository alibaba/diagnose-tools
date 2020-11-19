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
          addr filtered ip address.
        --deactivate
        --settings dump settings
        --report dump log with text.
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
PING延时信息, 源IP：[10.0.2.15], 目的IP：[180.101.49.12], ID：6074, SEQ: 2, 时间：[1589802125:725029]
                       PD_ETH_RECV:       14277527179528
                       PD_GRO_RECV:       14277527180325
                   PD_GRO_RECV_ERR:                    0
                       PD_RECV_SKB:       14277527181863
                  PD_RECV_SKB_DROP:                    0
                         PD_IP_RCV:                    0
                  PD_IP_RCV_FINISH:                    0
                      PD_DST_INPUT:       14277527220383
                  PD_LOCAL_DELIVER:       14277527220563
           PD_LOCAL_DELIVER_FINISH:       14277527220652
                       PD_ICMP_RCV:       14277527234109
                       PD_SEND_SKB:       14277491867008
```

输出结果中包含ping报文在各个阶段的时间，以ns为单位。
每次输出结果后，历史数据将被清空。

###  关闭功能
通过如下命令关闭本功能：
diagnose-tools ping-delay --deactivate
关闭功能后，本功能将不会对系统带来性能影响。
