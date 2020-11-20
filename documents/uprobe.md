##  uprobe
###  查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools uprobe --help
```
结果如下：
```
    uprobe usage:
        --help uprobe help info
        --activate launch file and offset
          verbose VERBOSE
          tgid process group that monitored
          pid thread id that monitored
          comm comm that monitored
          cpu cpu-list that monitored
        --deactivate
        --settings dump settings
        --report dump log with text.
```
###  安装KO
参见《安装和卸载KO》一节
###  激活功能
激活本功能的命令是：
```
diagnose-tools uprobe --activate
```
在激活本功能时，需要指定激活参数：
* file参数指定在哪个文件中设置探针
* offset参数指定在文件中什么位置设置探针
命令示例：
```
diagnose-tools uprobe --activate='verbose=1 file=/usr/diagnose-tools/bin/uprobe.out offset=1875'
```
同时，可以指定其他一些参数：
本命令可用参数为：
* tgid 要探测的进程ID
* pid 要探测的线程ID
* comm 要探测的进程名称
* cpu cpus 要探测的CPU列表，如0-16,23这样的格式
例如，如下命令限制仅对进程1234进行探测：
```
diagnose-tools uprobe --activate='verbose=1 file=/usr/diagnose-tools/bin/uprobe.out offset=1875,tgid=1234'
```

如果成功，将输出：
```
功能设置成功，返回值：0
    进程ID：1234
    线程ID：0
    进程名称：
    CPUS：
    输出级别：1
    文件名：
    偏移：1875
```

如果失败，将输出：
```
功能设置失败，返回值：-16
    进程ID：1234
    线程ID：0
    进程名称：
    CPUS：
    输出级别：1
    文件名：
    偏移：1875
```
###  测试用例
运行如下命令测试本功能：
```
sh /usr/diagnose-tools/test.sh uprobe
```
###  查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools uprobe --settings
```
结果如下：
```
功能设置：
    是否激活：√
    进程ID：1234
    线程ID：0
    进程名称：
    CPUS：0-1
    输出级别：1
    文件名：/usr/diagnose-tools/bin/uprobe.out
    偏移：1875
```

###  查看结果
执行如下命令查看本功能的输出结果：
```
diagnose-tools uprobe --report
```
输出结果示例如下：
```
UPROBE命中：PID： 9215[run-trace.out]，时间：[1587959184:307057]
##CGROUP:[/]  9215      [001]  UPROBE命中，时间：[1587959184:307057]
    用户态堆栈：
#~        0x400773 mytest ([symbol])
#~        0x7fdc46516495 __libc_start_main ([symbol])
#*        0xffffffffffffff run-trace.out (UNKNOWN)
    进程链信息：
#^        0xffffffffffffff /usr/diagnose-tools/bin/run-trace.out  (UNKNOWN)
#^        0xffffffffffffff sh test.sh uprobe  (UNKNOWN)
#^        0xffffffffffffff /bin/bash  (UNKNOWN)
#^        0xffffffffffffff sudo -s  (UNKNOWN)
#^        0xffffffffffffff bash  (UNKNOWN)
#^        0xffffffffffffff /usr/libexec/gnome-terminal-server  (UNKNOWN)
#^        0xffffffffffffff /usr/lib/systemd/systemd --switched-root --system --deserialize 22  (UNKNOWN)
##
```

输出结果中，包含uprobe命中的线程PID/名称，线程所在CGROUP组，内核态堆栈，用户态堆栈，进程链等信息。
每次输出结果后，历史数据将被清空。
###  输出火焰图
可以将输出结果转储到文件中，然后使用diagnose-tools的flame命令生成火焰图。
###  关闭功能
通过如下命令关闭本功能：
```
diagnose-tools uprobe --deactivate 
```
如果成功，将输出：
```
uprobe is not activated
```
如果失败，将输出：
```
deactivate uprobe fail, ret is -1
```
关闭功能后，本功能将不会对系统带来性能影响。
