## exit-monitor
有时候，进程莫名其妙的退出了。很难找到是被kill还是程序自身异常引起。特别是某些三方库会调用abort/exit直接退出系统。
exit-monitor可以监控特定进程退出时的调用链。
###  查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools exit-monitor --help
```
结果如下：
```
    exit-monitor usage:
        --help exit-monitor help info
        --activate
          verbose VERBOSE
          tgid process group that monitored
          comm comm that monitored
        --deactivate
        --report dump log with text.
        --test testcase for exit-monitor.
        --log
          sls=/tmp/1.log store in file
          syslog=1 store in syslog
```

###  安装KO
参见《安装和卸载KO》一节
###  激活功能
激活本功能的命令是：
```
diagnose-tools exit-monitor --activate 
```
在激活本功能时，可用参数有：
本功能可用参数为：
* tgid 设置要监控的进程pid
* comm 设置要监控的进程名称
* verbose 设置输出级别，目前未用。
例如：
```
diagnose-tools exit-monitor --activate="comm=sleep"
```
如果设置成功，该命令在控制台中会有如下输出：
```
功能设置成功，返回值：0
    进程ID：0
    进程名称：sleep
    输出级别：0
```
如果设置失败，该命令在控制台中会有如下输出：
```
功能设置失败，返回值：-16
    进程ID：0
    进程名称：sleep
    输出级别：0
```
###  查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools exit-monitor --settings
```
结果如下：
```
功能设置：
    是否激活：√
    线程ID：0
    进程名称：sleep
    输出级别：0
```
###  测试用例
执行如下命令触发测试用例：
```
sh /usr/diagnose-tools/test.sh exit-monitor
```
###  查看结果
激活本功能后，一旦被监控的进程退出，就会记录下日志。执行如下命令查看本功能的输出结果：
```
diagnose-tools exit-monitor --report
```
输出结果示例如下：
```
线程退出，PID： 13796[sleep]，退出时间：[1580733810:211866]
        0xffffffff8103ddff,        save_stack_trace_tsk 
        0xffffffffa0656409,        diagnose_save_stack_trace	[diagnose] 
        0xffffffffa0658631,        ali_diag_task_kern_stack	[diagnose] 
        0xffffffffa065d444,        kprobe_do_exit_pre	[diagnose] 
        0xffffffff810657b3,        kprobe_ftrace_handler 
        0xffffffff8115ecb1,        ftrace_ops_assist_func 
        0xffffffffa06470d5,        cleanup_module	[isofs] 
        0xffffffff8108f9a5,        do_exit 
        0xffffffff81090583,        do_group_exit 
        0xffffffff81090604,        SyS_exit_group 
        0xffffffff81003c04,        do_syscall_64 
        0xffffffff81741c8e,        entry_SYSCALL_64_after_swapgs 
    用户态堆栈：
        0x00007fcc5f832359,no address in memory maps
```
###  关闭功能
通过如下命令关闭本功能：
```
diagnose-tools exit-monitor --deactivate 
```
如果执行成功，控制台将会有如下输出：
```
exit-monitor is not activated
```
如果执行失败，控制台将会有如下输出：
```
deactivate exit-monitor fail, ret is -1
```
关闭功能后，本功能将不会对系统带来性能影响。不过本功能对系统性能的影响很小。

