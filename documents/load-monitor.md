##  load-monitor
load-monitor功能实时抓取系统Load值，一旦Load值超过设置的阀值，就输出系统中所有处于Running/Uninterruptale状态的线程调用链。
### 查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools load-monitor --help
```
结果如下：
```
    load-monitor usage:
        --help load-monitor help info
        --activate
            verbose VERBOSE
            style dump style: 0 - common, 1 - process chains
            load threshold for load(ms)
            load.r threshold for load.r(ms)
            load.d threshold for load.d(ms)
            task.d threshold for task.d(ms)
        --settings print settings.
        --deactivate
        --report dump log with text.
        --sls save detail into sls files.
```
### 安装KO
参见《安装和卸载KO》一节
### 激活功能
激活本功能的命令是：
```
diagnose-tools load-monitor --activate
```
激活本功能时，可用的参数为：
* verbose 设置输出级别，目前未用。
* style如果为1，输出进程链。其他值不输出。
* load设置监控阀值，一旦Load值超过此值，就触发Load报警输出。默认值是0，表示不监控此值。
* load.r 设置监控阀值，一旦Load.R值超过此值，就触发Load.R报警输出。默认值是0，表示不监控此值。
* load.d 设置监控阀值，一旦Load.D值超过此值，就触发Load.D报警输出。默认值是0，表示不监控此值。
* task.d 设置监控阀值，一旦Task.D值超过此值，就触发Task.D报警输出。默认值是0，表示不监控此值。

Load/Load.R/Load.D/Task.d分别代表几个被监控的负载值。

* Load: 系统load值
* Load.R: 正在运行的任务引起的Load
* Load.D: D状态任务引起的Load
* Task.D: 当前处于D状态的任务数量

一般情况下，仅仅需要监控Load指标即可。如：
```
diagnose-tools load-monitor --activate="load=50"
```
该命令会将Load监控值设置为50,一旦系统Load超过50就输出调用链。
如果成功，将会在控制台输出：
```
功能设置成功，返回值：0
    Load：	50
    Load.R：	0
    Load.D：	0
    Task.D：	0
    输出级别：	0
    STYLE：	0
```
如果失败，将会在控制台输出：
```
功能设置失败，返回值：-16
    Load：	50
    Load.R：	0
    Load.D：	0
    Task.D：	0
    输出级别：	0
STYLE：	0
```
### 测试用例
运行如下命令运行测试用例，以查看本功能是否正常：
```
sh /usr/diagnose-tools/test.sh load-monitor
```

### 查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools load-monitor --settings
```
结果如下：
```
功能设置：
    是否激活：	√
    Load：	50
    Load.R：	0
    Load.D：	0
    Task.D：	0
    输出级别：	0
    STYLE：	0
```
### 查看结果
激活本功能后，一旦系统负载超过阀值，就会记录下日志。执行如下命令查看本功能的输出结果：
```
diagnose-tools load-monitor --report
```
输出结果示例如下：
```
Load飙高：[1583992747:970548]
	Load: 6.10, 6.14, 6.14
	Load.R: 6.08, 6.12, 6.09
	Load.D: 0.01, 0.02, 0.04
##CGROUP:[/]  156654      [022]  采样命中[R]
    内核态堆栈：
#@        0xffffffff81025022 save_stack_trace_tsk  ([kernel.kallsyms])
#@        0xffffffffa0fc0419 diagnose_save_stack_trace	[diagnose]  ([kernel.kallsyms])
#@        0xffffffffa0fc0d8e ali_diag_task_kern_stack	[diagnose]  ([kernel.kallsyms])
#@        0xffffffffa0fc70a0 ali_diagnose_load_timer	[diagnose]  ([kernel.kallsyms])
#@        0xffffffffa0fc5b41 hrtimer_handler	[diagnose]  ([kernel.kallsyms])
#@        0xffffffff810aa0d2 __hrtimer_run_queues  ([kernel.kallsyms])
#@        0xffffffff810aa670 hrtimer_interrupt  ([kernel.kallsyms])
#@        0xffffffff8104cbf7 local_apic_timer_interrupt  ([kernel.kallsyms])
#@        0xffffffff81664cdf smp_apic_timer_interrupt  ([kernel.kallsyms])
#@        0xffffffff81660432 apic_timer_interrupt  ([kernel.kallsyms])
#*        0xffffffffffffff yes (UNKNOWN)
    进程链信息：
#^        0xffffffffffffff yes  (UNKNOWN)
#^        0xffffffffffffff -bash  (UNKNOWN)
#^        0xffffffffffffff sshd: root@pts/6      (UNKNOWN)
#^        0xffffffffffffff /usr/sbin/sshd -D  (UNKNOWN)
#^        0xffffffffffffff /usr/lib/systemd/systemd --switched-root --system --deserialize 21  (UNKNOWN)
##
```
内核开发同学根据这些调用链，就能知道引起系统Load高的原因。

### 生成火焰图
可以用如下命令获取结果并生成火焰图：
```
diagnose-tools load-monitor --report > load-monitor.log
diagnose-tools flame --input=load-monitor.log --output=load-monitor.svg
```
该命令将生成的火焰图保存到load-monitor.svg中。
### 关闭功能
通过如下命令关闭本功能：
```
diagnose-tools load-monitor --deactivate 
```
如果执行成功，控制台将输出如下内容：
```
load-monitor is not activated
```
如果执行失败，控制台将输出如下内容：
```
deactivate load-monitor fail, ret is -1
```
关闭功能后，本功能将不会对系统带来性能影响。不过本功能对系统性能的影响很小。
