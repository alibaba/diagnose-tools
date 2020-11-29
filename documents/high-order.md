## high-order
###  查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools high-order --help
```
结果如下：
```
    high-order usage:
        --help high-order help info
        --activate
          verbose VERBOSE
          order threshold value
        --deactivate
        --settins dump settings with text.
        --report dump log with text.
        --test testcase for high-order.
```

###  安装KO
参见《安装和卸载KO》一节
###  激活功能
激活本功能的命令是：
```
diagnose-tools alloc-top --activate
```
在激活本功能时，可用参数为：
* verbose 输出级别，目前未用。
* order只有当分配的内存阶数高于此值才输出。
例如，下面的命令将分配阶数设置为2：
```
diagnose-tools high-order --activate='order=2'
```
如果成功，将输出：
```
功能设置成功，返回值：0
    ORDER：2
    输出级别：0
```

如果失败，将输出：
```
功能设置失败，返回值：-16
    ORDER：2
    输出级别：0
```

###  测试用例
使用如下命令将启动本功能的测试用例：
```
sh /usr/diagnose-tools/test.sh high-order
```
###  查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools high-order --settings
```
结果如下：
```
功能设置：
    是否激活：×
    ORDER：2
    输出级别：0
```
###  查看结果
执行如下命令查看本功能的输出结果：
```
diagnose-tools high-order --report
```
结果示例如下：
```
##CGROUP:[/]  5180      [48191]  采样命中[3]
    内核态堆栈：
#@        0xffffffff8103ddef save_stack_trace_tsk  ([kernel.kallsyms])
#@        0xffffffffa1b49289 diagnose_save_stack_trace	[diagnose]  ([kernel.kallsyms])
#@        0xffffffffa1b49bae ali_diag_task_kern_stack	[diagnose]  ([kernel.kallsyms])
#@        0xffffffffa1b5d232 trace_mm_page_alloc_hit	[diagnose]  ([kernel.kallsyms])
#@        0xffffffff811d20ac __alloc_pages_nodemask  ([kernel.kallsyms])
#@        0xffffffff81229ba5 alloc_pages_current  ([kernel.kallsyms])
#@        0xffffffff81629889 alloc_skb_with_frags  ([kernel.kallsyms])
#@        0xffffffff816249d0 sock_alloc_send_pskb  ([kernel.kallsyms])
#@        0xffffffff816fdf17 unix_stream_sendmsg  ([kernel.kallsyms])
#@        0xffffffff8161ea48 sock_sendmsg  ([kernel.kallsyms])
#@        0xffffffff8161eae5 sock_write_iter  ([kernel.kallsyms])
#@        0xffffffff81262f89 do_iter_readv_writev  ([kernel.kallsyms])
#@        0xffffffff8126499e do_readv_writev  ([kernel.kallsyms])
#@        0xffffffff81264c8c vfs_writev  ([kernel.kallsyms])
#@        0xffffffff81264d01 do_writev  ([kernel.kallsyms])
#@        0xffffffff81265ee0 SyS_writev  ([kernel.kallsyms])
#@        0xffffffff81003c04 do_syscall_64  ([kernel.kallsyms])
#@        0xffffffff817691ce entry_SYSCALL_64_after_swapgs  ([kernel.kallsyms])
    用户态堆栈：
#~        0x7efef7266b80 __writev ([symbol])
#*        0xffffffffffffff gnome-shell (UNKNOWN)
    进程链信息：
#^        0xffffffffffffff /usr/bin/gnome-shell  (UNKNOWN)
#^        0xffffffffffffff /usr/libexec/gnome-session-binary --session gnome-classic  (UNKNOWN)
#^        0xffffffffffffff gdm-session-worker [pam/gdm-password]  (UNKNOWN)
#^        0xffffffffffffff /usr/sbin/gdm  (UNKNOWN)
#^        0xffffffffffffff /usr/lib/systemd/systemd --switched-root --system --deserialize 22  (UNKNOWN)
##
```

###  关闭功能
通过如下命令关闭本功能：
```
diagnose-tools high-order --deactivate 
```
如果成功，将输出：
```
high-order is not activated
```
如果失败，将输出：
```
deactivate high-order fail, ret is -1
```
关闭功能后，本功能将不会对系统带来任何影响。
