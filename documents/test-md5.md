### test-md5
这是一个测试CPU速率的小工具。
使用方法：
```
diagnose-tools test-md5
```
该命令默认执行1000,0000次md5计算。
也可以使用-c参数指定计算次数，如：
```
[root@localhost diagnoise-tool]# diagnose-tools test-md5 -c 5000000
加密前:admin
加密后:21232f297a57a5a743894a0e4a801fc3
real	0m3.600s
user	0m3.581s
sys	0m0.006s
```
