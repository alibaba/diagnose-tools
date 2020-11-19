## sched-delay
### 查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools sched-delay --help
```
结果如下：
```
    sched-delay usage:
        --help sched-delay help info
        --activate
          verbose VERBOSE
          threshold THRESHOLD(MS)
          tgid process group monitored
          pid thread id that monitored
          comm comm that monitored
        --deactivate
        --report dump log with text.
```
### 安装KO
参见《安装和卸载KO》一节
### 激活功能
激活本功能的命令是：
```
diagnose-tools sched-delay --activate
```

在激活本功能时，可用参数为：
* verbose：该参数控制输出的详细程度，可以是任意整数。此参数目前未使用。
* threshold：配置监控的阀值，当调度延迟超过该阀值将引起警告信息输出。时间单位是ms。
* tgid 设置要监控的进程PID
* pid 设置要监控的线程TID
* comm 设置要监控的进程名称
例如，如下命令会将检测阀值设置为80ms。一旦系统有超过80ms的调度延迟，将输出其调用链：
```
diagnose-tools sched-delay --activate=”threshold=80”
```
如果成功，该命令在控制台上的输出如下：
```
功能设置成功，返回值：0
    进程ID：	0
    线程ID：	0
    进程名称：	
    监控阈值(ms)：	80
    输出级别：	0
```
如果失败，该命令在控制台上的输出如下：
```
功能设置失败，返回值：-38
    进程ID：	0
    线程ID：	0
    进程名称：	
    监控阈值(ms)：	80
    输出级别：	0
```


### 测试用例
执行如下命令触发测试用例：
```
sh /usr/diagnose-tools/test.sh sched-delay
```

### 查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools sched-delay --settings
```
结果如下：
```
功能设置：
    是否激活：	√
    进程ID：	0
    线程ID：	0
    进程名称：	
    监控阈值(ms)：	80
    输出级别：	0
```

### 查看结果
系统会记录一段时间内调度延迟的调用链。执行如下命令查看本功能的输出结果：
```
diagnose-tools sched-delay --report
```
输出结果示例如下：
```
警告：调度被延迟 14 ms，NOW: 2065771, QUEUED: 2065757, 当前时间：[1584599791:768101]
##CGROUP:[/]  3868      [001]  采样命中
    内核态堆栈：
#@        0xffffffff8129b58b ep_poll  ([kernel.kallsyms])
#@        0xffffffff8129c53e SyS_epoll_wait  ([kernel.kallsyms])
#@        0xffffffff81003c04 do_syscall_64  ([kernel.kallsyms])
#@        0xffffffff81741c8e entry_SYSCALL_64_after_swapgs  ([kernel.kallsyms])
    用户态堆栈：
no address in memory maps
find vma failed
#~        0x7f4a0573538d UNKNOWN ([symbol])
#*        0xffffffffffffff X (UNKNOWN)
    进程链信息：
#^        0xffffffffffffff  (UNKNOWN)
#^        0xffffffffffffff  (UNKNOWN)
#^        0xffffffffffffff  (UNKNOWN)
##
	CPU 0，nr_running:16
	CPU 1，nr_running:14
```

输出结果中包含引起调度延迟的调用链，以及每个CPU调度队列上的线程数量最大值。
每次输出结果后，历史数据将被清空。
### 关闭功能
通过如下命令关闭本功能：
```
diagnose-tools sched-delay --deactivate
```
如果成功，将输出：
```
sched-delay is not activated
```
关闭功能后，本功能将不会对系统带来性能影响。
