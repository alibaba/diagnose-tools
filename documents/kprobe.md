## kprobe
本功能监控任意内核函数的执行情况，并生成火焰图。
### 查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools kprobe --help
```
结果如下：
```
    kprobe usage:
        --help kprobe help info
        --activate
            verbose VERBOSE
            tgid process group that monitored
            pid thread id that monitored
            comm comm that monitored
            cpu cpu-list that monitored
            probe function that monitored
            dump-style dump style for kprobe. dump to dmesg if it is 1.
        --deactivate
        --report dump log with text.
        --settings dump settings.
```
###  安装KO
参见《安装和卸载KO》一节
###  激活功能
激活本功能的命令是：
```
diagnose-tools kprobe --activate
```
在激活本功能时，可用参数为：
* verbose VERBOSE该参数设置输出级别，暂时未用
* tgid 要采样的进程PID
* pid 要采样的线程TID
* comm 要采样的进程名称
* cpu cpus 要采样的CPU列表，如0-16,23这样的格式d
* probe 要监控的函数名称
* dump-style 输出格式，如果为1,表示输出到dmesg中
例如，如下命令表示监控hrtimer_interrupt函数：
```
diagnose-tools kprobe --activate='probe=hrtimer_interrupt'
```
如果成功，将输出：
```
功能设置成功，返回值：0
    进程ID：0
    线程ID：0
    进程名称：
    函数名称：hrtimer_interrupt
    CPUS：
    输出级别：0
```

如果失败，将输出：
```
功能设置失败，返回值：-16
    进程ID：0
    线程ID：0
    进程名称：
    函数名称：hrtimer_interrupt
    CPUS：
    输出级别：0
```
###  测试用例
运行如下命令，将启动本功能的测试用例：
```
sh /usr/diagnose-tools/test.sh kprobe
```
###  查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools kprobe --settings
```
结果如下：
```
功能设置：
    是否激活：×
    进程ID：0
    线程ID：0
    进程名称：
    函数名称：hrtimer_interrupt
    CPUS：0-1
    输出级别：0
```

###  查看结果
执行如下命令查看本功能的输出结果：
```
diagnose-tools kprobe --report
```
输出结果示例如下：
```
KPROBE命中：PID： 106526[h2o]，时间：[1584004225:651374]
##CGROUP:[h2o]  106526      [4564]  KPROBE命中，时间：[1584004225:651374]
    内核态堆栈：
#@        0xffffffff81025022 save_stack_trace_tsk  ([kernel.kallsyms])
#@        0xffffffffa141f419 diagnose_save_stack_trace  [diagnose]  ([kernel.kallsyms])
#@        0xffffffffa141fd8e ali_diag_task_kern_stack   [diagnose]  ([kernel.kallsyms])
#@        0xffffffffa142eaab kprobe_pre [diagnose]  ([kernel.kallsyms])
#@        0xffffffff81659e1c kprobe_ftrace_handler  ([kernel.kallsyms])
#@        0xffffffff8113559e ftrace_ops_list_func  ([kernel.kallsyms])
#@        0xffffffff81663d44 ftrace_regs_call  ([kernel.kallsyms])
#@        0xffffffff81664cdf smp_apic_timer_interrupt  ([kernel.kallsyms])
#@        0xffffffff81660432 apic_timer_interrupt  ([kernel.kallsyms])
    用户态堆栈：
#~        0xcbf32d _ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4findEPKcmm ([symbol])
#*        0xffffffffffffff h2o (UNKNOWN)
    进程链信息：
#^        0xffffffffffffff h2o (UNKNOWN)
#^        0xffffffffffffff auditd (UNKNOWN)
#^        0xffffffffffffff systemd (UNKNOWN)
##
```
输出结果中，包含kprobe命中的线程PID/名称，线程所在CGROUP组，内核态堆栈，用户态堆栈，进程链等信息。
每次输出结果后，历史数据将被清空。

###  输出火焰图
执行如下命令生成火焰图：
```
diagnose-tools kprobe --report > kprobe.log
diagnose-tools flame --input=kprobe.log --output=kprobe.svg
```
###  关闭功能
通过如下命令关闭本功能：
```
diagnose-tools kprobe --deactivate 
```
如果成功，将输出：
```
kprobe is not activated
```
如果失败，将输出：
```
deactivate kprobe fail, ret is -1
```
关闭功能后，本功能将不会对系统带来性能影响。
