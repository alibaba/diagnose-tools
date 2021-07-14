## ping-delay6

本功能追踪ping包的时间延迟。

###  查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools ping-delay6 --help
```
结果如下：
```
    ping-delay6 usage:
        --help ping_delay6 help info
        --activate
          verbose VERBOSE
          addr filtered ipv6 address.
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
  diagnose-tools ping-delay6 --activate
```
在激活本功能时，可用参数为：
* verbose 该参数设置输出级别，当该值为1时，输出详细的报文信息。
* addr 设置要过滤的IPv6地址。
例如，如下命令设置输出级别为1：
```
diagnose-tools ping-delay6 --activate='verbose=1'
```
如果成功，将输出：
```
功能设置成功，返回值：0
    输出级别：1
    过滤地址：[::]
```
如果失败，将输出：
```
功能设置失败，返回值：-17
    输出级别：1
    过滤地址：[::]
```

###  测试用例
运行如下命令运行测试用例，以查看本功能是否正常：
```
sh /usr/diagnose-tools/test.sh ping-delay6
```

###  查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools ping-delay6 --settings
```
结果如下：
```
功能设置：
    是否激活：√
    输出级别：0
    过滤地址：[::]
```
###  查看结果

执行如下命令查看本功能的输出结果：
```
diagnose-tools ping-delay6 --report
```

输出结果示例如下：
```
PING延时信息, 源IP：[2408:4005:300:ca37:a99b:f077:569d:9d68], 目的IP：[2408:4005:300:ca37:a99b:f077:569d:9d67], ID：3021, SEQ: 1, 时间：[1626226587:921229]
                       PD_ETH_RECV:         714722193211
                       PD_GRO_RECV:         714744840881
                   PD_GRO_RECV_ERR:                    0
                       PD_RECV_SKB:         714744852021
                  PD_RECV_SKB_DROP:                    0
                        PD_IP6_RCV:         714744853906
                 PD_IP6_RCV_FINISH:         714744854487
                      PD_DST_INPUT:         714744858704
                      PD_IP6_INPUT:         714744858946
                      PD_ICMP6_RCV:         714744864966
                     PD_DST_OUTPUT:         714721932149
                     PD_QUEUE_XMIT:         714721933764
                       PD_DEV_XMIT:         714721935491
```

输出结果中包含ping报文在各个阶段的时间，以ns为单位。
每次输出结果后，历史数据将被清空。

###  关闭功能
通过如下命令关闭本功能：
diagnose-tools ping-delay6 --deactivate
关闭功能后，本功能将不会对系统带来性能影响。
