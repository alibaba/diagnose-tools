##  irq-delay
### 查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools irq-delay --help
```
结果如下：
```
    irq-delay usage:
        --help irq-delay help info
        --activate
            verbose VERBOSE
            threshold threshold(ms)
        --deactivate
        --settings dump settings with text.
        --report dump log with text.
        --test testcase for irq-delay.
```
### 安装KO
参见《安装和卸载KO》一节
### 激活功能
激活本功能的命令是：
```
diagnose-tools irq-delay --activate
```
在激活本功能时，可用参数为：
* verbose：该参数控制输出的详细程度，可以是任意整数。当前未用。
* threshold：配置长时间关中断的阀值，超过该阀值将引起警告信息输出。时间单位是ms。
例如，如下命令会将检测阀值设置为80ms。一旦系统有超过80ms的关中断代码，将输出其调用链：
```
diagnose-tools irq-delay --activate="threshold=80"
```
如果成功，将在控制台输出如下：
```
功能设置成功，返回值：0
    阀值(ms)：	80
    输出级别：	0
```
如果失败，将在控制台输出如下：
```
功能设置失败，返回值：-16
    阀值(ms)：	80
    输出级别：	0
```
### 测试用例
执行如下命令触发测试用例：
```
sh /usr/diagnose-tools/test.sh irq-delay
```

### 查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools irq-delay --settings
```
结果如下：
```
功能设置：
    是否激活：√
    阀值(ms)：80
    输出级别：0
```
### 查看结果
系统会记录一段时间内中断被延迟的调用链。执行如下命令查看本功能的输出结果：
```
diagnose-tools irq-delay --report
```
输出结果示例如下：
```
中断延迟，PID： 164390[diagnose-tools]， CPU：39, 96 ms, 时间：[1583993047:186455]
    时间：[1583993047:186455].
    进程信息： [/ / diagnose-tools]， PID： 164390 / 164390
##CGROUP:[/]  164390      [001]  采样命中
    内核态堆栈：
#@        0xffffffff81025022 save_stack_trace_tsk  ([kernel.kallsyms])
```
每次输出结果后，历史数据将被清空。

### 生成火焰图
可以用如下命令获取结果并生成火焰图：
```
diagnose-tools irq-delay --report > irq-delay.log
diagnose-tools flame --input=irq-delay.log --output=irq-delay.svg
```
该命令将生成的火焰图保存到irq-delay.svg中。

### 关闭功能
通过如下命令关闭本功能：
```
diagnose-tools irq-delay --deactivate
```
如果成功，控制台打印如下：
```
irq-delay is not activated
```
如果失败，控制台打印如下：
```
deactivate irq-delay fail, ret is -1
```
关闭功能后，本功能将不会对系统带来性能影响。
