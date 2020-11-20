##  fs-orphan
输出ext4文件系统下的孤儿节点信息，只适配了v3.10与v4.9版本的内核。
### 查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools fs-orphan--help
```
结果如下：
```
    fs-orphan usage:
        --help fs-orphan help info
        --activate
        --deactivate
        --settings print settings.
        --report dump log with text.
        --verbose VERBOSE
        --dev devname that monitored, for instance dba
```

###  安装KO
参见《安装和卸载KO》一节
###  激活功能
激活本功能的命令是：
```
diagnose-tools fs-orphan --activate
```
激活本功能时，可用参数为：
* verbose VERBOSE该参数设置输出级别，暂时未用
* dev 要分析的设备，如sda
例如，如下命令设置要分析的磁盘设备名称为sda：
```
diagnose-tools fs-orphan --activate='dev=sda'
```

如果成功，将输出：
```
功能设置成功，返回值：0
    输出级别：0
    DEV：sda
```

如果失败，将输出：
```
功能设置失败，返回值：-16
    输出级别：0
    DEV：sda
```

###  测试用例
运行如下命令运行测试用例，以查看本功能是否正常：
```
sh /usr/diagnose-tools/test.sh fs-orphan
```
###  查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools fs-orphan --settings
```
结果如下：
```
功能设置：
    是否激活：√
    输出级别：0
    DEV：sda
```

### 查看结果
执行如下命令查看本功能的输出结果：
```
diagnose-tools fs-orphan --report
```
每次输出结果后，历史数据将被清空。
###  输出火焰图
理论上，可以输出孤儿节点相关的火焰图，但是目前还未实现此功能。
### 关闭功能
通过如下命令关闭本功能：
```
diagnose-tools fs-orphan --deactivate 
```
如果成功，将输出：
```
deactivate fs-orphan
```
如果失败，将输出：
```
deactivate fs-orphan fail, ret is -1
```
关闭功能后，本功能将不会对系统带来性能影响。
