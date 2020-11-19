# diagnose-tools 2.0 功能使用说明

本文档介绍diagnose-tools-2.0版本的使用方法。

## 支持的版本

目前的版本支持Centos 7.5 / 7.6

经过验证，工具也支持如下版本，相应的代码会陆续合入：
* Centos 5.x / 6.x
* Ubuntu
* Linux 4.19

## 编译

推荐在centos 7.6中编译
```
make devel //安装编译环境
make deps  //编译三方开源包
make module  //编译内核模块
make tools  //编译用户态工具
make rpm    //制作rpm包
```

## 安装和卸载KO

在使用模块功能之前，需要用如下命令安装KO模块：
```
diagnose-tools install
```
安装成功后，控制台有如下提示：
```
installed successfully
```

在使用完模块功能后，需要用如下命令卸载KO模块：
```
diagnose-tools uninstall
```
卸载成功后，控制台有如下提示：
```
uninstalled successfully
```

## 2.0正式版本的功能

目前，diagnose-tools-2.0正式发布的版本有如下几个功能：

* [实用小工具pupil](./pupil.md)：按照tid查询特定线程在主机上的PID/进程名称/进程链/堆栈等等。
* [sys-delay](./sys-delay.md)：监控syscall长时间运行引起调度不及时。间接引起系统Load高、业务RT高。
* [sys-cost](./sys-cost.md)：统计系统调用的次数及时间。
* [sched-delay](./sched-delay.md) : 监控系统调度延迟。找到引起调度延迟的进程。
* [irq-delay](./irq-delay.md)：监控中断被延迟的时间。
* [irq-stats](./irq-stats.md)：统计中断/软中断执行次数及时间。
* [irq-trace](./irq-trace.md)：跟踪系统中IRQ/定时器的执行。
* [load-monitor](./load-monitor.md)：监控系统Load值。每10ms查看一下系统当前Load，超过特定值时，输出任务堆栈。这个功能多次在线上抓到重大BUG。可以分别监控Load/Load.R/Load.D/Task.D等指标。
* [run-trace](./run-trace.md)：监控进程在某一段时间段内，在用户态/内核态运行情况。
* [perf](./perf.md): 对线程/进程进行性能采样，抓取用户态/内核态调用链。
* [kprobe](./kprobe.md)：在内核任意函数中，利用kprobe监控其执行，并输出火焰图。
* [uprobe](./uprobe.md)：在用户态应用程序中使用探针，在应用中挂接钩子。
* [utilization](./utilization.md)：监控系统资源利用率，找到CPU被哪些野进程干扰，以及进程对内存的使用情况。
* [exit-monitor](./exit-monitor.md)：监控任务退出。在退出时，打印任务的用户态堆栈信息。
* [mutex-monitor](./mutex-monitor.md)：监控长时间持有mutex的流程。
* [exec-monitor](./exec-monitor.md): 监控进程调用exec系统调用创建新进程。
* [alloc-top](./alloc-top.md)：统计内存分配数量，按序输出内存分配多的进程
* [high-order](./high-order.md)：监控分配大内存的调用链
* [drop-packet](./drop-packet.md)：监控内核TCP/IP各个流程中的丢包。
* [tcp-retrans](./tcp-retrans.md)：监控TCP/IP套接字上的重传。
* [ping-delay](./ping-delay.md)：监控ping报文在内核中的路径，确认影响报文延迟的原因。
* [rw-top](./rw-top.md)：监控写文件。找到突发引起文件读写的进程/调用链。
* [fs-shm](./fs-shm.md)：本功能监控当前打开的SHM文件。
* [fs-orphan](./fs-orphan.md)：导出文件系统孤儿节点。
* [fs-cache](./fs-cache.md)：监控文件系统缓存占用情况，统计每个文件占用的缓存数量。
* [reboot](./reboot.md)：监控系统重启信息，打印出调用sys_reboot系统调用的进程名称以及进程链。

## 测试命令

* [test-md5](./test-md5.md): 一个测试CPU速率的小工具
* [test-pi](./test-pi.md): 另一个测试CPU速率的小工具
* [test-memcpy](./test-memcpy.md):这是一个测试内存速率的小工具。
* [test-run-trace]()
* [test-run-trace-java]()
* [test-presure-java]()


## 实验版本的功能

目前，diagnose-tools-2.0实验版本有如下几个功能：
* [kern-demo]()：展示如何在diagnose-tools中添加一个功能，供开发同学使用。
* [sys-broken]()：监控系统调用被中断/软中断/定时器打断的时间。
* [mm-leak](./mm-leak.md)：统计内核态一段时间内，分配了但是没有释放的内存。并输出分配这些内存的调用链，以及泄漏次数。



##  btrace和uprobe
###  btrace

* [btrace](./btrace.md)：btrace类似arthas，但是由于btrace可以定义脚本，所以在使用上相对arthas更加灵活，在某些arthas无法解决的场景，可以考虑使用btrace进行定位
