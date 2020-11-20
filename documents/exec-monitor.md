##  exec-monitor
本功能监控进程创建过程。对于那些引起系统抖动的小脚本，例如ps -eL命令，能抓到调用这些命令的进程组。
###  查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools exec-monitor --help
```
结果如下：
```
    exec-monitor usage:
        --help exec-monitor help info
        --activate
            verbose VERBOSE
        --deactivate
        --report dump log with text.
        --log
          sls=/tmp/1.log store in file
          syslog=1 store in syslog.
```
###  安装KO
参见《安装和卸载KO》一节
###  激活功能
激活本功能的命令是：
```
diagnose-tools exec-monitor --activate
```
激活本功能时，本命令可用参数为：
* verbose 该参数设置输出级别，暂时未用。
如下命令，将设置verbose参数为1：
```
diagnose-tools exec-monitor --activate="verbose=1"
```
如果成功，将输出：
```
功能设置成功，返回值：0
    输出级别：1
```
如果失败，将输出：
```
功能设置失败，返回值：-16
    输出级别：1
```
###  测试用例
运行如下命令启动测试用例：
```
sh /usr/diagnose-tools/test.sh exec-monitor
```
###  查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools exec-monitor --settings
```
结果如下：
```
功能设置：
    是否激活：×
    输出级别：0
```
### 查看结果
执行如下命令查看本功能的输出结果：
```
diagnose-tools exec-monitor --report
```
输出结果示例如下：
```
创建进程： [./diagnose-tools]，CGROUP：[/], 当前进程：10493[diagnose-tools], tgid： 10493，当前时间：[1580804064:266908]
    进程链信息：
        ./diagnose-tools exec-monitor --report 
        /bin/bash 
        sudo -s 
        bash 
        /usr/libexec/gnome-terminal-server 
```
输出结果中，包含了被创建进程的名称/启动参数，所在CGROUP组，父进程/祖父进程的名称。
每次输出结果后，历史数据将被清空。
### 关闭功能
通过如下命令关闭本功能：
```
diagnose-tools exec-monitor --deactivate
```
如果成功，将输出：
```
exec-monitor is not activated
```
如果失败，将输出：
```
deactivate exec-monitor fail, ret is -1
```
关闭功能后，本功能将不会对系统带来性能影响。
