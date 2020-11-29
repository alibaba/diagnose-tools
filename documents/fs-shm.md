##  fs-shm

本功能监控当前打开的SHM文件。

###  查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools fs-shm --help
```
结果如下：
```
    fs-shm usage:
        --help fs-shm help info
        --activate
          verbose VERBOSE
          top how many items to dump
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
diagnose-tools fs-shm --activate
```
在激活本功能时，可用的参数有：
* verbose 设置输出信息的详细程度
* top 设置输出列表的长度，默认值是20。
例如，如下命令设置输出列表长度为100：
```
diagnose-tools fs-shm --activate='top=100'
```
如果成功，将输出：
```
功能设置成功，返回值：0
    TOP：100
    输出级别：0
```

如果失败，将输出：
```
功能设置失败，返回值：-16
    TOP：100
    输出级别：0
```

###  测试用例
运行如下命令将启动本功能的测试用例：
```
sh /usr/diagnose-tools/test.sh fs-shm
```
###  查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools fs-shm --settings
```
结果如下：
```
功能设置：
    是否激活：×
    TOP：100
    输出级别：0
```

###  查看结果
执行如下命令查看本功能的输出结果：
```
diagnose-tools fs-shm --report
```
输出结果示例如下：
```
序号           FILE-SIZE     容器                  PID         进程名               文件名
    0           8388608        /                     1584        systemd-journal      /run/log/journal/aebdf2677ae545de8ce26bb89f163484/system.journal
    1           8388608        /                     3458        rsyslogd             /run/log/journal/aebdf2677ae545de8ce26bb89f163484/system.journal
    2               132        /                     4794        gdm                  /run/gdm/auth-for-baoyou.xie-oaCIhg/database      
    3               132        /                     4794        gdm                  /run/gdm/auth-for-gdm-RhBRA1/database             
    4                 5        /                     4831        VBoxService          /run/vboxadd-service.sh                           
    5                 5        /                     3480        atd                  /run/atd.pid                                      
    6                 5        /                     2969        abrtd                /run/abrt/abrtd.pid                               
    7                 5        /                     3484        crond                /run/crond.pid                                    
    8                 5        /                     1608        lvmetad              /run/lvmetad.pid                                  
    9                 4        /                     3471        libvirtd             /run/libvirtd.pid                                 
   10                 0        /                     3471        libvirtd             /run/libvirt/network/nwfilter.leases              
   11                 0        /                     2962        rpcbind              /run/rpcbind.lock       
```

输出结果中，包含了写数量排名前50名的SHM文件。
每次输出结果后，历史数据将被清空。

### 关闭功能
通过如下命令关闭本功能：
```
diagnose-tools fs-shm --deactivate
```
如果成功，将输出：
```
fs-shm is not activated
```
如果失败，将输出：
```
deactivate fs-shm fail, ret is -1
```
关闭功能后，本功能将不会对系统带来性能影响。
