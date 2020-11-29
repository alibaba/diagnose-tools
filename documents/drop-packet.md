## drop-packet
本功能统计内核态一段时间内，在各个TCP/UDP连接上，各个环节的报文数量。统计丢包发生的位置。
###  查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools drop-packet --help
```
结果如下：
```
    drop-packet usage:
        --help drop-packet help info
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

### 安装KO
参见《安装和卸载KO》一节
### 激活功能
激活本功能的命令是：
```
diagnose-tools drop-packet --activate
```
在激活本功能时，可用参数为：
* verbose 该参数设置输出级别，暂时未用。
* source-addr 要监控的源地址，可以不设置。
* source-port 要监控的源端口，可以不设置。
* dest-addr 要监控的目的地址，可以不设置。
* dest-port 要监控的目的端口，可以不设置。
例如，如下命令设置输出级别为1：
```
diagnose-tools drop-packet --activate='verbose=1'
```
如果成功，将输出：
```
功能设置成功，返回值：0
    输出级别：1
```
如果失败，将输出：
```
功能设置失败，返回值：-16
    输出级别：1
```
### 测试用例
运行如下命令启动本功能的测试用例：
```
sh /usr/diagnose-tools/test.sh drop-packet
```
### 查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools drop-packet --settings
```
结果如下：
```
功能设置：
    是否激活：√
    输出级别：0
```

### 查看结果
执行如下命令查看本功能的输出结果：
```
diagnose-tools drop-packet --report
```
输出结果示例如下：
```
协议类型：UDP, 源IP：10.0.2.15, 源端口：54578, 目的IP：30.14.128.1, 目的端口：53
                ETH_RECV: pkg-count:            1, true-size:          896, len:          194, datalen:            0
                GRO_RECV: pkg-count:            1, true-size:          896, len:          180, datalen:            0
            GRO_RECV_ERR: pkg-count:            0, true-size:            0, len:            0, datalen:            0
                RECV_SKB: pkg-count:            1, true-size:          896, len:          180, datalen:            0
           RECV_SKB_DROP: pkg-count:            0, true-size:            0, len:            0, datalen:            0
                  IP_RCV: pkg-count:            0, true-size:            0, len:            0, datalen:            0
           IP_RCV_FINISH: pkg-count:            0, true-size:            0, len:            0, datalen:            0
               DST_INPUT: pkg-count:            1, true-size:          896, len:          180, datalen:            0
           LOCAL_DELIVER: pkg-count:            1, true-size:          896, len:          180, datalen:            0
    LOCAL_DELIVER_FINISH: pkg-count:            1, true-size:          896, len:          180, datalen:            0
                 UDP_RCV: pkg-count:            1, true-size:          896, len:          160, datalen:            0
              TCP_V4_RCV: pkg-count:            0, true-size:            0, len:            0, datalen:            0
                SEND_SKB: pkg-count:            1, true-size:          768, len:           85, datalen:            0
```
输出结果中，包含了报文在各个阶段被接收/发送的次数。
每次输出结果后，历史数据将被清空。
### 关闭功能
通过如下命令关闭本功能：
diagnose-tools drop-packet --deactivate
如果成功，将输出：
drop-packet is not activated
如果失败，将输出：
deactivate drop-packet fail, ret is -1
关闭功能后，本功能将不会对系统带来性能影响。
