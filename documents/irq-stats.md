##  irq-stats
### 查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools irq-stats --help
```
结果如下：
```
    irq-stats usage:
        --help irq-stats help info
        --activate
            verbose VERBOSE
        --deactivate
        --report dump log with text.
```
### 安装KO
参见《安装和卸载KO》一节
### 激活功能
激活本功能的命令是：
```
diagnose-tools irq-stats --activate
```
在激活本功能时，有如下可供设置的参数：
* verbose，该参数控制输出的详细程度，可以是任意整数。当值大于等于0时，会输出每个中断在每个核上面执行的次数/时间。
通过如下命令设置verbose参数为1,以打印详细的信息：
```
diagnose-tools irq-stats --activate="verbose=1"
```
如果激活成功，控制台将会输出如下：
```
功能设置成功，返回值：0
    输出级别：1
```
如果失败，控制台将会输出如下：
```
功能设置失败，返回值：-16
    输出级别：1
```

### 测试用例
执行如下命令运行本功能的测试用例：
```
sh /usr/diagnose-tools/test.sh irq-stats
```
### 查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools irq-stats --settings
```
结果如下：
```
功能设置：
    是否激活：×
    输出级别：1
```
### 查看结果
系统会记录一段时间内中断/软中断执行次数/执行时间。执行如下命令查看本功能的输出结果：
```
diagnose-tools irq-stats --report
```
输出结果示例如下：
```
中断统计：[1580784677:664146]
    core0    2558       125155482            21         971594    
    core1    106        8753619              21         1425487   
    IRQ: core0    irq:    1, handler: 0xffffffff815809b0, runtime(ns):      395 /    7867442
    IRQ: core0    irq:   15, handler: 0xffffffffa006a750, runtime(ns):       72 /    1217346
    IRQ: core0    irq:   19, handler: 0xffffffffa00a6480, runtime(ns):       92 /    1600734
    IRQ: core0    irq:   21, handler: 0xffffffffa00cbef0, runtime(ns):        9 /    1192626
    IRQ: core0    irq:   20, handler: 0xffffffffa03277f0, runtime(ns):     1990 /  113277334
    IRQ: core1    irq:   21, handler: 0xffffffffa00cbef0, runtime(ns):      106 /    8753619
    SOFT-IRQ: core0    soft-irq:    0, count:        0 /          0, runtime(ns):        0 /          0
    SOFT-IRQ: core0    soft-irq:    1, count:    33396 /   22587824, runtime(ns):       39 /      70468
    SOFT-IRQ: core0    soft-irq:    2, count:        0 /          0, runtime(ns):        0 /          0
    SOFT-IRQ: core0    soft-irq:    3, count:       92 /    6564714, runtime(ns):        6 /      45302
```
每次输出结果后，历史数据将被清空。
### 关闭功能
通过如下命令关闭本功能：
```
diagnose-tools irq-stats --deactivate
```
如果执行成功，控制台将打印如下：
```
irq-stats is not activated
```
如果执行失败，控制台将打印如下：
```
deactivate irq-stats fail, ret is -1
```
关闭功能后，本功能将不会对系统带来性能影响。
