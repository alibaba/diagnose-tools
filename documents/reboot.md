## reboot
###  查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools reboot --help
```
结果如下：
```
    reboot usage:
        --help reboot help info
        --activate
        --deactivate
        --verbose VERBOSE
        --settings dump settings
```
###  安装KO
参见《安装和卸载KO》一节
###  激活功能
激活本功能的命令是：
```
diagnose-tools reboot --activate
```
如果成功，将输出:
```
reboot  activated
```
如果失败，将输出：
```
reboot is not activated, ret 0
```
###  设置参数
本功能可用参数为：
* -v, --verbose 该参数设置输出级别，暂时未用。
例如，如下命令设置输出级别为1：
```
diagnose-tools reboot --verbose=1
```
如果成功，将输出：
```
set verbose for reboot: 1, ret is 0
```
如果输出，将输出：
```
set verbose for reboot: 1, ret is -1
```
###  测试用例
无
###  查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools reboot --settings
```
结果如下：
```
功能设置：
    是否激活：√
    输出级别：1
```
###  查看结果
在复位后，通过串口日志查看本命令的输出结果。
###  关闭功能
通过如下命令关闭本功能：
```
diagnose-tools reboot --deactivate
```
如果成功，将输出：
```
reboot is not activated
```
如果失败，将输出：
```
deactivate reboot fail, ret is -1
```
关闭功能后，本功能将不会对系统带来性能影响。
