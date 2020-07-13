/*
 * Alibaba's exec monitor module
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
/*
 * Linux内核诊断工具--内核态exec-monitor功能
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <trace/events/napi.h>
#include <linux/rtc.h>
#include <linux/time.h>
#include <linux/rbtree.h>
#include <linux/cpu.h>
#include <linux/syscalls.h>
#include <trace/events/sched.h>
#include <linux/highmem.h>
#include <linux/namei.h>
#include <linux/binfmts.h>

#include <asm/irq_regs.h>

#include "internal.h"
#include "mm_tree.h"
#include "pub/trace_file.h"
#include "pub/trace_point.h"

#include "uapi/exec_monitor.h"

#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
__maybe_unused static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_exec_monitor_settings exec_monitor_settings;

__maybe_unused static int exec_monitor_alloced = 0;

static struct diag_variant_buffer exec_monitor_variant_buffer;

static struct mm_tree mm_tree;

static void hook_exec(const char * filename, struct mm_struct *mm)
{
	char buf[256];
	struct exec_monitor_detail *detail;
	unsigned long flags;

	if (!exec_monitor_settings.activated)
		return;

	if (!mm)
		return;

	get_argv_from_mm(mm, buf, 255);
	
	detail = kmalloc(sizeof(struct exec_monitor_detail), GFP_KERNEL);
	if (detail) {
		detail->et_type = et_exec_monitor_detail;
		do_gettimeofday(&detail->tv);
		diag_task_brief(current, &detail->task);
		strncpy(detail->filename, filename, 255);
		dump_proc_chains_argv(1, &mm_tree, current, &detail->proc_chains);
		diag_variant_buffer_spin_lock(&exec_monitor_variant_buffer, flags);
		diag_variant_buffer_reserve(&exec_monitor_variant_buffer, sizeof(struct exec_monitor_detail));
		diag_variant_buffer_write_nolock(&exec_monitor_variant_buffer, detail, sizeof(struct exec_monitor_detail));
		diag_variant_buffer_seal(&exec_monitor_variant_buffer);
		diag_variant_buffer_spin_unlock(&exec_monitor_variant_buffer, flags);
		kfree(detail);
	}

}

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
__maybe_unused static void trace_sched_process_exec_hit(void *__data,
		struct task_struct *tsk,
		pid_t old_pid,
		struct linux_binprm *bprm)
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
__maybe_unused static void trace_sched_process_exec_hit(void *__data,
		struct task_struct *tsk,
		pid_t old_pid,
		struct linux_binprm *bprm)
#endif
{
	struct mm_struct *mm = NULL;

	atomic64_inc_return(&diag_nr_running);
	diag_hook_exec(bprm, &mm_tree);

	if (bprm->mm)
	{
		mm = bprm->mm;
	}
	else
	{
		mm = bprm->vma ? bprm->vma->vm_mm : NULL;
	}
	hook_exec(bprm->filename, mm);
	
	atomic64_dec_return(&diag_nr_running);
}

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
__maybe_unused static void trace_sched_process_exit_hit(void *__data, struct task_struct *tsk)
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
__maybe_unused static void trace_sched_process_exit_hit(void *__data, struct task_struct *tsk)
#else
__maybe_unused static void trace_sched_process_exit_hit(struct task_struct *tsk)
#endif
{
	diag_hook_process_exit_exec(tsk, &mm_tree);
}

int __activate_exec_monitor(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&exec_monitor_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	exec_monitor_alloced = 1;

	cleanup_mm_tree(&mm_tree);

	hook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
	hook_tracepoint("sched_process_exec", trace_sched_process_exec_hit, NULL);
#endif
	//get_argv_processes(&mm_tree);

	return 1;
out_variant_buffer:
	return 0;
}

void __deactivate_exec_monitor(void)
{
	unhook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
	unhook_tracepoint("sched_process_exec", trace_sched_process_exec_hit, NULL);
#endif

	synchronize_sched();
	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0)
	{
		msleep(10);
	}
	cleanup_mm_tree(&mm_tree);
}

int activate_exec_monitor(void)
{
	if (!exec_monitor_settings.activated)
		exec_monitor_settings.activated = __activate_exec_monitor();

	return exec_monitor_settings.activated;
}

int deactivate_exec_monitor(void)
{
	if (exec_monitor_settings.activated)
		__deactivate_exec_monitor();
	exec_monitor_settings.activated = 0;

	return 0;
}

static int lookup_syms(void)
{
	return 0;
}

static void jump_init(void)
{
}

int exec_monitor_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_exec_monitor_settings settings;

	switch (id) {
	case DIAG_EXEC_MONITOR_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_exec_monitor_settings)) {
			ret = -EINVAL;
		} else if (exec_monitor_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				exec_monitor_settings = settings;
			}
		}
		break;
	case DIAG_EXEC_MONITOR_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_exec_monitor_settings)) {
			ret = -EINVAL;
		} else {
			settings = exec_monitor_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_EXEC_MONITOR_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!exec_monitor_alloced) {
			ret = -EINVAL;
		} else {
			ret = copy_to_user_variant_buffer(&exec_monitor_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("exec-monitor");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_exec_monitor(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

int diag_exec_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&exec_monitor_variant_buffer, 1 * 1024 * 1024);
	jump_init();
	init_mm_tree(&mm_tree);


	if (exec_monitor_settings.activated)
		exec_monitor_settings.activated = __activate_exec_monitor();

	return 0;
}

void diag_exec_exit(void)
{
	if (exec_monitor_settings.activated)
		deactivate_exec_monitor();
	exec_monitor_settings.activated = 0;
	destroy_diag_variant_buffer(&exec_monitor_variant_buffer);
}
#else
int diag_exec_init(void)
{
	return 0;
}

void diag_exec_exit(void)
{
	//
}
#endif
