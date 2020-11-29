## irq-trace

### 查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools irq-trace --help
```
结果如下：
```
    irq-trace usage:
        --help irq-trace help info
        --activate
            verbose VERBOSE
            irq set irq threshold(ms)
            sirq set soft-irq threshold(ms)
            timer set timer threshold(ms)
        --deactivate
        --report dump log with text.
```
### 安装KO
参见《安装和卸载KO》一节
### 激活功能
激活本功能的命令是：
```
diagnose-tools irq-trace --activate
```
激活本功能时，可用参数为：
* verbose：该参数控制输出的详细程度，可以是任意整数。当值大于等于0时，会在日志文件中输出每次中断/软中断/定时器的执行时刻、类型、函数名称。
* irq：设置中断监控阈值(ms)
* sirq：设置软中断监控阈值(ms)
* timer：设置定时器监控阈值(ms)

如下命令监控超过1ms的IRQ，超过5ms的软中断／定时器：
```
diagnose-tools irq-trace --activate='irq=1 sirq=5 timer=5'
```
如果成功，将输出如下信息：
```
功能设置成功，返回值：0
    输出级别：0
    IRQ：1(ms)
    SIRQ：5(ms)
    TIMER：5(ms)
```
如果失败，将输出如下信息：
```
功能设置失败，返回值：-16
    输出级别：0
    IRQ：1(ms)
    SIRQ：5(ms)
    TIMER：5(ms)
```
### 测试用例
运行如下命令运行测试用例，以查看本功能是否正常：
```
sh /usr/diagnose-tools/test.sh irq-trace
```
### 查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools irq-trace --settings
```
结果如下：
```
功能设置：
    是否激活：×
    输出级别：0
    IRQ：1(ms)
    SIRQ：5(ms)
    TIMER：5(ms)
```
### 查看结果
执行如下命令查看本功能的输出结果：
```
diagnose-tools irq-trace --report
```
如果系统中有长时间执行的中断/软中断/定时器，工具将输出相应函数的名称，以及执行时长，异常时间点。
每次输出结果后，历史数据将被清空。
### 关闭功能
通过如下命令关闭本功能：
```
diagnose-tools irq-trace --deactivate
```
如果成功，将输出如下：
```
irq-trace is not activated
```
如果失败，将输出如下：
```
deactivate irq-trace fail, ret is -1
```
关闭功能后，本功能将不会对系统带来性能影响。

