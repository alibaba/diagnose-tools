## sys-delay

sys-delay功能抓取在syscall中长时间执行，导致调度被延迟的情况。
本工具的原理，是在定时器中监控当前任务的cond_resched和schedule调用情况。如果在一段时间范围内都没有进行调度，说明在内核中有长时间执行的流程。这样的流程对业务RT和系统load都是有影响的。应当及时优化掉。

###  查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools sys-delay --help
```
结果如下：
```
    sys-delay usage:
        --help sys-delay help info
        --activate
            verbose VERBOSE
            threshold THRESHOLD(MS)
            style dump style: 0 - common, 1 - process chains
        --deactivate
        --settings print settings.
        --report dump log with text.
        --test loop in sys for 100ms, so triger this monitor.
        --log  format:"sls=1.log[ syslog=1]" to store in file or syslog.
```
###	 安装KO
参见《安装和卸载KO》一节
### 激活功能
激活本功能的命令是：
```
diagnose-tools sys-delay --activate
```
在激活本功能时，可以指定如下参数：

* threshold 设置监控阀值，单位是ms。默认值是50。
* style如果为1，输出进程链。其他值不输出。需在—activate激活前设置style为1，才能输出进程链；
* verbose 设置输出级别，目前未用。

例如，使用如下命令，可以：
1. 监控阀值修改为60ms。当在syscall中执行时间超过60ms，就会在系统中记录下异常信息
2. 将输出级别修改为1。目前该参数无实际意义

```
diagnose-tools sys-delay --activate="threshold=60 verbose=1"
```

如果激活功能成功，将打印如下信息：
```
功能设置成功，返回值：0
    阀值(ms)：	60
    输出级别：	1
    STYLE：	0
```

如果不能成功激活功能，将打印如下信息：
```
功能设置失败，返回值：-16
    阀值(ms)：	60
    输出级别：	1
STYLE：	0
```

### 查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools sys-delay --settings
```
结果如下：
```
功能设置：
    是否激活：	√
    阀值(ms)：	60
    输出级别：	1
    STYLE：	0
```

###  测试用例
执行如下命令触发测试用例：
```
sh /usr/diagnose-tools/test.sh sys-delay
```
	
### 查看结果
执行如下命令查看本功能的输出结果：
```
diagnose-tools sys-delay --report
```
输出结果示例如下：
```
抢占关闭, 时长： 55(ms).
    时间：[1584003506:277464].
    进程信息： [/ / diagnose-tools]， PID： 79757 / 79757
##CGROUP:[/]  79757      [001]  采样命中
    内核态堆栈：
#@        0xffffffff81025022 save_stack_trace_tsk  ([kernel.kallsyms])
#@        0xffffffffa16483e9 diagnose_save_stack_trace	[diagnose]  ([kernel.kallsyms])
#@        0xffffffffa1648d5e ali_diag_task_kern_stack	[diagnose]  ([kernel.kallsyms])
#@        0xffffffffa16510ed syscall_timer	[diagnose]  ([kernel.kallsyms])
#@        0xffffffffa164db09 hrtimer_handler	[diagnose]  ([kernel.kallsyms])
#@        0xffffffff810aa0d2 __hrtimer_run_queues  ([kernel.kallsyms])
#@        0xffffffff810aa670 hrtimer_interrupt  ([kernel.kallsyms])
#@        0xffffffff8104cbf7 local_apic_timer_interrupt  ([kernel.kallsyms])
#@        0xffffffff81664cdf smp_apic_timer_interrupt  ([kernel.kallsyms])
#@        0xffffffff81660432 apic_timer_interrupt  ([kernel.kallsyms])
#@        0xffffffff81317dc8 __const_udelay  ([kernel.kallsyms])
#@        0xffffffffa16512f6 sys_delay_syscall	[diagnose]  ([kernel.kallsyms])
#@        0xffffffffa1649bdb trace_sys_enter_hit	[diagnose]  ([kernel.kallsyms])
#@        0xffffffff81023ec6 syscall_trace_enter  ([kernel.kallsyms])
#@        0xffffffff8165f331 tracesys  ([kernel.kallsyms])
    用户态堆栈：
#~        0x50f199 syscall ([symbol])
#~        0x4ace24 generic_start_main ([symbol])
#*        0xffffffffffffff diagnose-tools (UNKNOWN)
    进程链信息：
#^        0xffffffffffffff diagnose-tools sys-delay --test  (UNKNOWN)
#^        0xffffffffffffff -bash  (UNKNOWN)
#^        0xffffffffffffff /usr/sbin/sshd -D -R  (UNKNOWN)
#^        0xffffffffffffff /usr/sbin/sshd -D  (UNKNOWN)
#^        0xffffffffffffff /usr/lib/systemd/systemd --switched-root --system --deserialize 21  (UNKNOWN)
##
```

这是一个引起内核长时间运行的调用链。通过这个调用链，内核开发同学可以方便的找到问题原因。
###  生成火焰图
可以用如下命令获取结果并生成火焰图：
```
diagnose-tools sys-delay --report > sys-delay.log
diagnose-tools flame --input=sys-delay.log --output=sys-delay.svg
```
###  关闭功能
通过如下命令关闭本功能：
```
diagnose-tools sys-delay --deactivate
```
关闭成功后，将会有如下打印输出信息：
```
sys-delay is not activated
```
如果关闭失败，将会有如下打印：
```
deactivate sys-delay fail, ret is -1
```
关闭功能后，本功能将不会对系统带来性能影响。
