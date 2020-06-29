/*
 * Linux内核诊断工具--内核态alloc-page功能
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/gfp.h>
#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/timex.h>
#include <trace/events/sched.h>
#include <trace/events/irq.h>
#include <linux/init.h>
#include <linux/tracepoint.h>
#include <linux/proc_fs.h>
#include <trace/events/napi.h>

#include "internal.h"

int sysctl_alloc_cost[MAX_TEST_ORDER + 1];

static u64 alloc_page_test(unsigned int order)
{
	ktime_t time_start, time_stop, time;
	struct timespec timespec;
	struct page *ret;

	time_start = ktime_get();

	ret = alloc_pages_current(GFP_KERNEL, order);
	if (!ret)
		return 0;

	time_stop = ktime_get();
	time = ktime_sub(time_stop, time_start);
	timespec = ktime_to_timespec(time);

	__free_pages(ret, order);

	return timespec.tv_sec * 1000000000 + timespec.tv_nsec;
}

static void stress_alloc_page(void)
{
	long alloc_ns = 0;
	int order;

	for (order = 0; order <= MAX_TEST_ORDER; order++)
	{
		alloc_ns = alloc_page_test(order);

		sysctl_alloc_cost[order] = alloc_ns;
	}
}

static int alloc_show(struct seq_file *m, void *v)
{
	int order;

	seq_printf(m, "order  ");
	for (order = 0; order <= MAX_TEST_ORDER; order++)
		seq_printf(m, "%10d", order);

	seq_printf(m, "\n");

	seq_printf(m, "time:ns");
	for (order = 0; order <= MAX_TEST_ORDER; order++)
		seq_printf(m, "%10d", sysctl_alloc_cost[order]);

	seq_printf(m, "\n");

	return 0;
}

static int alloc_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, alloc_show, NULL);
}

static ssize_t alloc_write(struct file *file, const char __user *buf,
						   size_t count, loff_t *offs)
{
	if (count < 1 || count >= 255 || *offs)
		return -EINVAL;

	stress_alloc_page();

	return count;
}

const struct file_operations alloc_fops = {
	.open = alloc_open,
	.read = seq_read,
	.write = alloc_write,
	.llseek = seq_lseek,
	.release = single_release,
};

int diag_alloc_page_init(void)
{
	struct proc_dir_entry *pe;

	pe = proc_create("ali-linux/diagnose/mm/alloc",
					 S_IFREG | 0444,
					 NULL,
					 &alloc_fops);
	if (!pe)
		return -ENOMEM;

	return 0;
}

void diag_alloc_page_exit(void)
{
	remove_proc_entry("ali-linux/diagnose/mm/alloc", NULL);

	return;
}
