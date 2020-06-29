/*
 * Linux内核诊断工具--内核态测试用例
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
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/random.h>
//#include <linux/printk.h>
#include <linux/cgroup.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/sort.h>
#include <linux/net.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <net/sock.h>
#include <linux/connector.h>
#ifdef CENTOS_7U
#include <linux/rhashtable.h>
#endif

#include <asm/kdebug.h>

#include "internal.h"
#include "mm_tree.h"
#include "pub/trace_file.h"
#include "pub/kprobe.h"
#include "pub/cgroup.h"
#include "pub/fs_utils.h"

static struct diag_trace_file xby_test_file;

static void *test_cb_file(struct task_struct *tsk, struct file *file, void *data)
{
	unsigned long flags;
	char path_name[DIAG_PATH_LEN];

	diag_get_file_path(file, path_name, DIAG_PATH_LEN);
	diag_trace_file_spin_lock(&xby_test_file, flags);
	diag_trace_file_printk_nolock(&xby_test_file, "测试for_each_files_task函数：\n");
	diag_trace_file_printk_nolock(&xby_test_file, "    进程名称：%s\n", tsk->comm);
	diag_trace_file_printk_nolock(&xby_test_file, "    文件名：  [%p]%s\n", file, path_name);
	diag_trace_file_spin_unlock(&xby_test_file, flags);

	return NULL;
}

static void test_for_each_files_task(void)
{
	struct task_struct *tsk;
	struct radix_tree_root proc_tree;
	struct task_struct *batch[NR_BATCH];
	int nr_found;
	unsigned long pos;
	int i;

	INIT_RADIX_TREE(&proc_tree, GFP_ATOMIC);
	for_each_process(tsk) {
		radix_tree_insert(&proc_tree, (unsigned long)tsk, tsk);
		get_task_struct(tsk);
	}

	pos = 0;
	do {
		nr_found = radix_tree_gang_lookup(&proc_tree, (void **)batch, pos, NR_BATCH);
		for (i = 0; i < nr_found; i++) {
			tsk = batch[i];
			radix_tree_delete(&proc_tree, (unsigned long)tsk);
			pos = (unsigned long)tsk + 1;
			for_each_files_task(tsk, test_cb_file, NULL);
			put_task_struct(tsk);
		}
	} while (nr_found > 0);
}

static ssize_t xby_test_file_read(struct diag_trace_file *trace_file,
		struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	return 0;
}

static ssize_t xby_test_file_write(struct diag_trace_file *trace_file,
		struct file *file, const char __user *buf, size_t count,
		loff_t *offs)
{
	int ret;
	char cmd[255];
	char chr[256];

	if (count < 1 || count >= 255 || *offs)
		return -EINVAL;

	if (copy_from_user(chr, buf, 256))
		return -EFAULT;
	chr[255] = 0;

	ret = sscanf(chr, "%s", cmd);
	if (ret != 1) {
		return -EINVAL;
	}

	if (strcmp(cmd, "fs-utils") == 0) {
		unsigned int id;

		ret = sscanf(chr, "%s %d", cmd, &id);
		if (ret == 2) {
			test_for_each_files_task();
		}
	}

	return count;
}

int diag_xby_test_init(void)
{
	int ret;

	ret = init_diag_trace_file(&xby_test_file,
		"ali-linux/diagnose/test",
		4 * 1024 * 1024,
		xby_test_file_read,
		xby_test_file_write);
	if (ret)
		goto out_trace_file;

	return 0;

out_trace_file:
	return ret;
}

void diag_xby_test_exit(void)
{
	destroy_diag_trace_file(&xby_test_file);
}

