## mutex-monitor
本功能监控内核中长时间持有mutex的情况。
###  查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools mutex-monitor --help
```
结果如下：
```
    mutex-monitor usage:
        --help mutex-monitor help info
        --activate
            verbose VERBOSE
            threshold threshold(ms)
            style dump style: 0 - common, 1 - process chains
        --deactivate
        --settings dump settings with text.
        --report dump log with text.
        --test testcase for mutex-monitor.
        --log
          sls=/tmp/1.log store in file
          syslog=1 store in syslog.
```

###  安装KO
参见《安装和卸载KO》一节
###  激活功能
激活本功能的命令是：
```
diagnose-tools mutex-monitor --activate 
```
激活本功能时，可用参数为：
* verbose 本参数目前未用。
* style如果为1，输出进程链。
* threshold 该参数设置监控阀值，单位是ms。默认值是1000。当某个函数持有mutex超过1000 ms时，就会打印这个函数的调用链。
例如，如下命令将监控阀值设置为900ms：
```
diagnose-tools mutex-monitor --activate="threshold=900"
```
如果成功，将输出如下：
```
功能设置成功，返回值：0
    阀值(ms)：	900
    输出级别：	0
    STYLE：	0
```

如果失败，将输出如下：
```
功能设置失败，返回值：-16
    阀值(ms)：	900
    输出级别：	0
    STYLE：	0
```

###  测试用例
运行如下命令运行测试用例，以查看本功能是否正常：
```
sh /usr/diagnose-tools/test.sh mutex-monitor
```
###  查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools mutex-monitor --settings
```
结果如下：
```
功能设置：
    是否激活：	×
    阀值(ms)：	0
    输出级别：	0
    STYLE：	1
```
###  查看结果
```
执行如下命令查看本功能的输出结果：
diagnose-tools mutex-monitor --report
预期结果如下：
MUTEX延迟： 0xffffffffa0fd80c0，PID： 183817[diagnose-tools]， 1503 ms, 时间：[1583993176:208214]
    时间：[1583993176:208214].
    进程信息： [/ / diagnose-tools]， PID： 183817 / 183817
    内核态堆栈：
#@        0xffffffff81025022 save_stack_trace_tsk  ([kernel.kallsyms])
......
```
结果中包含延迟时间/造成延迟的锁名称/造成延迟的调用链。
每次输出结果后，历史数据将被清空。
###  关闭功能
通过如下命令关闭本功能：
```
diagnose-tools mutex-monitor --deactivate
```
如果成功，将输出：
```
mutex-monitor is not activated
```
如果失败，将输出：
```
deactivate mutex-monitor fail, ret is -1
```
关闭功能后，本功能将不会对系统带来性能影响。
