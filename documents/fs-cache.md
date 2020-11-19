##  fs-cache
### 查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools fs-cache --help
```
结果如下：
```
    fs-cache usage:
        --help fs-cache help info
        --activate
          verbose VERBOSE
          top how many items to dump
          size filter size
        --deactivate
        --report dump log with text.
        --drop invalid file cache
```
###  安装KO
参见《安装和卸载KO》一节
### 激活功能
激活本功能的命令是：
```
diagnose-tools df-du --activate
```
在激活本功能时，可用参数为：
* verbose VERBOSE该参数设置输出级别，暂时未用
* top 指定输出数据的数量
* size 当指定此参数时，只考虑那些缓存大小超过此值的文件。
例如：
```
diagnose-tools fs-cache -activate='top=100'
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

### 测试用例
使用如下命令测试本功能：
```
sh /usr/diagnose-tools/test.sh fs-cache
```
 
###  删除文件缓存
使用如下命令删除特定文件的缓存
```
diagnose-tools fs-cache --drop='inode=$ADDR'
```
其中$ADDR是inode节点的内核地址，例如 18446612134122553728
### 查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools fs-cache --settings
```
结果如下：
```
功能设置：
    是否激活：√
    TOP：100
    输出级别：0
```

### 查看结果
执行如下命令查看本功能的输出结果：
```
diagnose-tools fs-cache --report
```
每次输出结果后，历史数据将被清空。
### 关闭功能
通过如下命令关闭本功能：
```
diagnose-tools fs-cache --deactivate 
```
如果成功，将输出：
```
fs-cache is not activated
```
如果失败，将输出：
```
deactivate fs-cache fail, ret is -1
```
关闭功能后，本功能将不会对系统带来性能影响。
