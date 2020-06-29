/*
 * Alibaba's bio trace module
 *
 * Copyright (C) 2018 Alibaba Ltd.
 *
 * Author: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
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
/*
 * Linux内核诊断工具--内核态io功能入口
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/bio.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
#include <linux/blk-mq.h>
#endif
#include <linux/crc32.h>
#include <linux/fs.h>

#if !defined(DIAG_ARM64)
#include <asm/asm-offsets.h>
#endif


#include "internal.h"
#include "io_internal.h"

int diag_io_init(void)
{
	struct proc_dir_entry *pe;
	int ret;

	pe = diag_proc_mkdir("ali-linux/diagnose/io", NULL);

	ret = diag_bio_init();
	if (ret)
		goto out_bio;

	ret = diag_blk_dev_init();
	if (ret)
		goto out_blk_dev;

	ret = diag_vfs_init();
	if (ret)
		goto out_vfs;

	ret = diag_nvme_init();
	if (ret)
		goto out_nvme;

	return 0;

out_nvme:
	diag_vfs_exit();
out_vfs:
	diag_blk_dev_exit();
out_blk_dev:
	diag_bio_exit();
out_bio:
	return ret;
}

void diag_io_exit(void)
{
	diag_bio_exit();
	diag_blk_dev_exit();
	diag_vfs_exit();
	diag_nvme_exit();

	//remove_proc_entry("ali-linux/diagnose/io", NULL);
}
