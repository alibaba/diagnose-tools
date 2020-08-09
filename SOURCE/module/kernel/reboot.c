/*
 * Linux内核诊断工具--内核态reboot功能
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
#include <linux/cpu.h>
#include <linux/syscalls.h>
#include <linux/bitmap.h>
#include <linux/reboot.h>
#include <net/sock.h>

#include <asm/irq_regs.h>

#include "internal.h"
#include "mm_tree.h"
#include "pub/trace_file.h"

#include "uapi/reboot.h"

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
static unsigned int reboot_activated;
static unsigned int reboot_verbose;

static void __maybe_unused clean_data(void)
{
	//
}

static int need_trace(struct task_struct *tsk)
{
	return 1;
}

static int hook_reboot(void)
{
	static struct reboot_detail detail;

	atomic64_inc_return(&diag_nr_running);
	if (!need_trace(current)) {
		atomic64_dec_return(&diag_nr_running);
		return 0;
	}

	detail.et_type = et_reboot_detail;
	do_gettimeofday(&detail.tv);
	detail.proc_chains.chains[0][0] = 0;
	dump_proc_chains_simple(current, &detail.proc_chains);
	diag_task_brief(current, &detail.task);
	diag_task_kern_stack(current, &detail.kern_stack);
	diag_task_user_stack(current, &detail.user_stack);
	
	printk_task_brief(&detail.task);
	dump_stack();
	printk_task_user_stack(&detail.user_stack);
	printk_process_chains(&detail.proc_chains);

	atomic64_dec_return(&diag_nr_running);
	return 0;
}

static int diag_notify_sys(struct notifier_block *this,
					unsigned long code, void *unused)
{
	hook_reboot();

	return NOTIFY_DONE;
}

static struct notifier_block diag_notifier = {
	.notifier_call = diag_notify_sys,
};

static int __activate_reboot(void)
{
	int ret = 0;

	ret = register_reboot_notifier(&diag_notifier);
	if (ret != 0) {
		pr_err("cannot register reboot notifier (err=%d)\n", ret);
		goto out;
	}

	return 1;
out:
	return 0;
}

static void __deactivate_reboot(void)
{
	unregister_reboot_notifier(&diag_notifier);

	synchronize_sched();
	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0)
		msleep(20);

	clean_data();
}

int activate_reboot(void)
{
	if (!reboot_activated)
		reboot_activated = __activate_reboot();

	return reboot_activated;
}

int deactivate_reboot(void)
{
	if (reboot_activated)
		__deactivate_reboot();
	reboot_activated = 0;

	return 0;
}

static int lookup_syms(void)
{
	return 0;
}

static void jump_init(void)
{
}

int reboot_syscall(struct pt_regs *regs, long id)
{
	unsigned int verbose;
	int ret = 0;
	struct diag_reboot_settings settings;
	void __user *buf;
	size_t size;

	switch (id) {
	case DIAG_REBOOT_VERBOSE:
		verbose = (unsigned int)SYSCALL_PARAM1(regs);
		reboot_verbose = verbose;
		break;
	case DIAG_REBOOT_SETTINGS:
		buf = (void __user *)SYSCALL_PARAM1(regs);
		size = (size_t)SYSCALL_PARAM2(regs);

		memset(&settings, 0, sizeof(settings));
		if (size != sizeof(struct diag_reboot_settings)) {
			ret = -EINVAL;
		} else {
			settings.activated = reboot_activated;
			settings.verbose = reboot_verbose;
			ret = copy_to_user(buf, &settings, size);
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_reboot(unsigned int cmd, unsigned long arg)
{
	unsigned int verbose;
	int ret = 0;
	struct diag_reboot_settings settings;
	printk("xby-debugs: %d\n", cmd);
	switch (cmd) {
	case CMD_REBOOT_VERBOSE:
		ret = copy_from_user(&verbose, (void *)arg, sizeof(unsigned int));
		if (!ret) {
			reboot_verbose = verbose;
		}
		break;
	case CMD_REBOOT_SETTINGS:
		settings.activated = reboot_activated;
		settings.verbose = reboot_verbose;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_reboot_settings));
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_reboot_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	jump_init();

	if (reboot_activated)
		reboot_activated = __activate_reboot();

	return 0;
}

void diag_reboot_exit(void)
{
	if (reboot_activated)
		deactivate_reboot();
	reboot_activated = 0;

	msleep(10);
	synchronize_sched();
}
