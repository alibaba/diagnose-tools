## alloc-top
本功能统计一段时间内，进程分配的内存数量（不统计释放数量），并按照分配数量按序输出。
###  查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools alloc-top --help
```
结果如下：
```
    alloc-top usage:
        --help alloc-top help info
        --activate
          verbose VERBOSE
          top max count in top list
        --deactivate
        --report dump log with text.
        --settins dump settings with text.
        --test testcase for alloc-top.
        --log
          sls=/tmp/1.log store in file
          syslog=1 store in syslog.
```
### 安装KO
参见《安装和卸载KO》一节
### 激活功能
激活本功能的命令是：
```
diagnose-tools alloc-top --activate
```
在激活本功能时，可用参数为：
verbose 输出级别，目前未用。
top 设置输出结果的行数。
例如，下面的命令将输出行数限制为20行：
```
diagnose-tools alloc-top --activate='top=20'
```
如果成功，将输出：
功能设置成功，返回值：0
    TOP-N：20
    输出级别：0

如果失败，将输出：
功能设置失败，返回值：-16
    TOP-N：20
    输出级别：0

###  测试用例
使用如下命令将启动本功能的测试用例：
```
sh /usr/diagnose-tools/test.sh alloc-top
```
###  查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools alloc-top --settings
```
结果如下：
功能设置：
    是否激活：×
    TOP-N：20
    输出级别：0
### 查看结果
执行如下命令查看本功能的输出结果：
```
diagnose-tools alloc-top --report
```
结果示例如下：
```
 序号     TGID                COMM    PG-COUNT              CGROUP
    1      3883                   X     2443251                               /
  序号     TGID                COMM    PG-COUNT              CGROUP
    1      4959         gnome-shell      201975                               /
```

这几列数据分别代表：序号/进程号/进程名称/分配页面数量/进程所在CGROUP名称。

### 关闭功能
通过如下命令关闭本功能：
```
diagnose-tools alloc-top --deactivate 
```
如果成功，将输出：
```
alloc-top is not activated
```
如果失败，将输出：
```
deactivate alloc-top fail, ret is -1
```
关闭功能后，本功能将不会对系统带来任何影响。
