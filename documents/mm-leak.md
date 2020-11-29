## mm-leak
本功能统计内核态一段时间内，分配了但是没有释放的内存。并输出分配这些内存的调用链，以及泄漏次数。

### 查看帮助信息
通过如下命令查看本功能的帮助信息：
```
diagnose-tools mm-leak --help
```

结果如下：
```
    mm-leak usage:
        --help mm-leak help info
        --activate
        --deactivate
        --verbose VERBOSE
        --report dump log with text.
```
### 安装KO
参见《安装和卸载KO》一节

### 激活功能
激活本功能的命令是：
```
diagnose-tools mm-leak --activate
```
如果成功，将输出：
```
mm-leak activated
```

### 设置参数
本功能可用参数为：
-v, --verbose 该参数设置输出级别，暂时未用。
例如，如下命令设置输出级别为1：
```
diagnose-tools mm-leak --verbose=1
```
该命令在控制台会输出如下结果：
```
set verbose for mm-leak: 1, ret is 0
```

###  测试用例
无
### 查看设置参数
使用如下命令查看本功能的设置参数：
```
diagnose-tools mm-leak --settings
```
结果如下：
```
功能设置：
    是否激活：√
    输出级别：1
```

###  查看结果
执行如下命令查看本功能的输出结果：
```
diagnose-tools mm-leak --report
```
输出结果示例如下：
```
内存泄漏，次数：25337
    内核态堆栈：
#@        0xffffffff8103ddef save_stack_trace_tsk  ([kernel.kallsyms])
#@        0xffffffffa1b09289 diagnose_save_stack_trace	[diagnose]  ([kernel.kallsyms])
#@        0xffffffffa1b0d7cf ali_stack_desc_find_alloc	[diagnose]  ([kernel.kallsyms])
#@        0xffffffffa1b24461 trace_kmem_cache_alloc_hit	[diagnose]  ([kernel.kallsyms])
#@        0xffffffff812264f7 kmem_cache_alloc  ([kernel.kallsyms])
#@        0xffffffff8128c141 alloc_buffer_head  ([kernel.kallsyms])
#@        0xffffffff8128c467 alloc_page_buffers  ([kernel.kallsyms])
#@        0xffffffff8128c4de create_empty_buffers  ([kernel.kallsyms])
#@        0xffffffff8128c621 create_page_buffers  ([kernel.kallsyms])
#@        0xffffffff8128e9aa __block_write_begin_int  ([kernel.kallsyms])
#@        0xffffffff812bb631 iomap_write_begin  ([kernel.kallsyms])
#@        0xffffffff812bb8c8 iomap_write_actor  ([kernel.kallsyms])
#@        0xffffffff812bbf31 iomap_apply  ([kernel.kallsyms])
#@        0xffffffff812bc020 iomap_file_buffered_write  ([kernel.kallsyms])
#@        0xffffffffa017144c xfs_file_buffered_aio_write	[xfs]  ([kernel.kallsyms])
#@        0xffffffffa0171743 xfs_file_write_iter	[xfs]  ([kernel.kallsyms])
#@        0xffffffff8125251e new_sync_write  ([kernel.kallsyms])
#@        0xffffffff812526c6 __vfs_write  ([kernel.kallsyms])
#@        0xffffffff81252ce5 vfs_write  ([kernel.kallsyms])
#@        0xffffffff812541a5 SyS_write  ([kernel.kallsyms])
#@        0xffffffff81003c04 do_syscall_64  ([kernel.kallsyms])
#@        0xffffffff8174bfce entry_SYSCALL_64_after_swapgs  ([kernel.kallsyms])
内存泄漏，次数：13562
```
每次输出结果后，历史数据将被清空。

### 关闭功能
通过如下命令关闭本功能：
```
diagnose-tools mm-leak --deactivate
```
如果成功，将输出：
```
mm-leak is not activated
```
关闭功能后，本功能将不会对系统带来性能影响。
