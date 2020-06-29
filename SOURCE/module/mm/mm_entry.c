/*
 * Linux内核诊断工具--内核态内存功能入口
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/timex.h>
#include <linux/tracepoint.h>
#include <trace/events/irq.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <trace/events/napi.h>
#include <linux/rtc.h>
#include <linux/time.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/crc32.h>
#include <linux/fs.h>

#if !defined(DIAG_ARM64)
#include <asm/asm-offsets.h>
#endif

#include "internal.h"
#include "mm_internal.h"

int diag_mm_init(void)
{
    struct proc_dir_entry *pe;
    int ret = 0;

    pe = diag_proc_mkdir("ali-linux/diagnose/mm", NULL);

	ret = diag_alloc_page_init();
	if (ret)
		goto out_alloc;

	ret = diag_memory_leak_init();
	if (ret)
		goto out_memory_leak;

	ret = diag_mm_page_fault_init();
	if (ret)
		goto out_page_fault;

   	ret = diag_alloc_top_init();
	if (ret)
		goto out_alloc_top;

   	ret = diag_high_order_init();
	if (ret)
		goto out_high_order;

	return 0;

out_high_order:
	diag_alloc_top_exit();
out_alloc_top:
	diag_mm_page_fault_exit();
out_page_fault:
	diag_memory_leak_exit();
out_memory_leak:
	diag_alloc_page_exit();
out_alloc:
	return ret;
}

void diag_mm_exit(void)
{
	diag_high_order_exit();
	diag_alloc_page_exit();
	diag_memory_leak_exit();
	diag_mm_page_fault_exit();
	diag_alloc_top_exit();
    //remove_proc_entry("ali-linux/diagnose/mm", NULL);
}

