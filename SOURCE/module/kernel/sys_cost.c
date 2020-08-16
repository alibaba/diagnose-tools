/*
 * Linux内核诊断工具--内核态sys-cost功能
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
#include <linux/percpu_counter.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#include <linux/context_tracking.h>
#endif
#include <linux/sort.h>

#include <asm/irq_regs.h>
#include <asm/unistd.h>

#if !defined(DIAG_ARM64)
#include <asm/asm-offsets.h>
#endif

//#include <asm/traps.h>

#include "internal.h"
#include "pub/trace_file.h"
#include "pub/trace_point.h"
#include "pub/kprobe.h"

#include "uapi/sys_cost.h"

#if !defined(CENTOS_3_10_123_9_3)
struct diag_sys_cost_settings sys_cost_settings;

static unsigned int sys_cost_alloced;
static struct diag_variant_buffer sys_cost_variant_buffer;

static void do_clean(void *info)
{
	struct diag_percpu_context *context;

	context = get_percpu_context();
	memset(&context->sys_cost, 0, sizeof(context->sys_cost));
}

static void clean_data(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		if (cpu == smp_processor_id()) {
			do_clean(NULL);
		} else {
			smp_call_function_single(cpu, do_clean, NULL, 1);
		}
	}
}

static int need_trace(struct task_struct *tsk)
{
	int cpu;

	if (!sys_cost_settings.activated)
		return 0;

	cpu = smp_processor_id();
	if (orig_idle_task && orig_idle_task(cpu) == tsk)
		return 0;

	if (sys_cost_settings.tgid) {
		if (tsk->tgid != sys_cost_settings.tgid)
			return 0;
	}

	if (sys_cost_settings.pid) {
		if (tsk->pid != sys_cost_settings.pid)
			return 0;
	}

	if (sys_cost_settings.comm[0]) {
		struct task_struct *leader = tsk->group_leader ? tsk->group_leader : tsk;

		if (strcmp(leader->comm, sys_cost_settings.comm) != 0)
			return 0;
	}

	return 1;
}

static void start_trace_syscall(struct task_struct *tsk)
{
	struct diag_percpu_context *context;
	struct pt_regs *regs = task_pt_regs(tsk);
	unsigned long id;

	if (!need_trace(current))
		return;
	if (regs == NULL)
		return;

	id = SYSCALL_NO(regs);
	if (id >= NR_syscalls_virt)
		return;

	context = get_percpu_context();
	context->sys_cost.start_time = sched_clock();
}

static void stop_trace_syscall(struct task_struct *tsk)
{
	unsigned long id;
	struct pt_regs *regs = task_pt_regs(tsk);
	struct diag_percpu_context *context;
	u64 start;
	u64 now;
	u64 delta_ns;

	context = get_percpu_context();
	start = context->sys_cost.start_time;
	context->sys_cost.start_time = 0;

	if (!need_trace(current))
		return;

	if (regs == NULL)
		return;

	id = SYSCALL_NO(regs);
	if (id >= NR_syscalls_virt)
		return;

	
	if (start == 0)
		return;

	now = sched_clock();
	if (now > start)
		delta_ns = now - start;
	else
		delta_ns = 0;

	context->sys_cost.count[id]++;
	context->sys_cost.cost[id] += delta_ns;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
static void trace_sys_enter_hit(struct pt_regs *regs, long id)
#else
static void trace_sys_enter_hit(void *__data, struct pt_regs *regs, long id)
#endif
{
	if (!need_trace(current))
		return;

	start_trace_syscall(current);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
static void trace_sched_switch(struct rq *rq, struct task_struct *prev, struct task_struct *next)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
static void trace_sched_switch(void *__data,
		struct task_struct *prev, struct task_struct *next)
#else
static void trace_sched_switch(void *__data, bool preempt,
		struct task_struct *prev, struct task_struct *next)
#endif
{
	stop_trace_syscall(prev);
	start_trace_syscall(next);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
static void trace_sys_exit_hit(struct pt_regs *regs, long ret)
#else
static void trace_sys_exit_hit(void *__data, struct pt_regs *regs, long ret)
#endif
{
	stop_trace_syscall(current);
}

static int __activate_sys_cost(void)
{
	int ret;

	ret = alloc_diag_variant_buffer(&sys_cost_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	sys_cost_alloced = 1;

	clean_data();

	hook_tracepoint("sys_enter", trace_sys_enter_hit, NULL);
	hook_tracepoint("sys_exit", trace_sys_exit_hit, NULL);
	hook_tracepoint("sched_switch", trace_sched_switch, NULL);

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_sys_cost(void)
{
	unhook_tracepoint("sys_enter", trace_sys_enter_hit, NULL);
	unhook_tracepoint("sys_exit", trace_sys_exit_hit, NULL);
	unhook_tracepoint("sched_switch", trace_sched_switch, NULL);

	synchronize_sched();
}

int activate_sys_cost(void)
{
	if (!sys_cost_settings.activated)
		sys_cost_settings.activated = __activate_sys_cost();

	return sys_cost_settings.activated;
}

int deactivate_sys_cost(void)
{
	if (sys_cost_settings.activated)
		__deactivate_sys_cost();
	sys_cost_settings.activated = 0;

	return 0;
}

static void do_dump(void *info)
{
	struct diag_percpu_context *context;
	struct sys_cost_detail *detail;
	unsigned long flags;
	int i;

	context = get_percpu_context();
	detail = &context->sys_cost.detail;
	memset(detail, 0, sizeof(struct sys_cost_detail));
	
	detail->et_type = et_sys_cost_detail;
	do_gettimeofday(&detail->tv);
	detail->cpu = smp_processor_id();
	for (i = 0; i < NR_syscalls_virt && i < USER_NR_syscalls_virt; i++) {
		detail->count[i] = context->sys_cost.count[i];
		detail->cost[i] = context->sys_cost.cost[i];

		context->sys_cost.count[i] = 0;
		context->sys_cost.cost[i] = 0;
	}

	diag_variant_buffer_spin_lock(&sys_cost_variant_buffer, flags);
	diag_variant_buffer_reserve(&sys_cost_variant_buffer, sizeof(struct sys_cost_detail));
	diag_variant_buffer_write_nolock(&sys_cost_variant_buffer, detail, sizeof(struct sys_cost_detail));
	diag_variant_buffer_seal(&sys_cost_variant_buffer);
	diag_variant_buffer_spin_unlock(&sys_cost_variant_buffer, flags);
}

int sys_cost_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_sys_cost_settings settings;
	int cpu;

	switch (id) {
	case DIAG_SYS_COST_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_sys_cost_settings)) {
			ret = -EINVAL;
		} else if (sys_cost_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				sys_cost_settings = settings;
			}
		}
		break;
	case DIAG_SYS_COST_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		memset(&settings, 0, sizeof(settings));
		if (user_buf_len != sizeof(struct diag_sys_cost_settings)) {
			ret = -EINVAL;
		} else {
			settings = sys_cost_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_SYS_COST_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		for_each_possible_cpu(cpu) {
			if (cpu == smp_processor_id()) {
				do_dump(NULL);
			} else {
				smp_call_function_single(cpu, do_dump, NULL, 1);
			}
		}
		
		if (!sys_cost_alloced) {
			ret = -EINVAL;
		} else {
			ret = copy_to_user_variant_buffer(&sys_cost_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("sys-cost");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_sys_cost(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_sys_cost_settings settings;
	struct diag_ioctl_dump_param dump_param;
	int cpu;

	switch (cmd) {
	case CMD_SYS_COST_SET:
		if (sys_cost_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_sys_cost_settings));
			if (!ret) {
				sys_cost_settings = settings;
			}
		}
		break;
	case CMD_SYS_COST_SETTINGS:
		settings = sys_cost_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_sys_cost_settings));
		break;
	case CMD_SYS_COST_DUMP:
		for_each_possible_cpu(cpu) {
			if (cpu == smp_processor_id()) {
				do_dump(NULL);
			} else {
				smp_call_function_single(cpu, do_dump, NULL, 1);
			}
		}
		
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));
		if (!sys_cost_alloced) {
			ret = -EINVAL;
		} else if (!ret){
			ret = copy_to_user_variant_buffer(&sys_cost_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("sys-cost");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_sys_cost_init(void)
{
	init_diag_variant_buffer(&sys_cost_variant_buffer, 1 * 1024 * 1024);

	if (sys_cost_settings.activated)
		sys_cost_settings.activated = __activate_sys_cost();

	return 0;
}

void diag_sys_cost_exit(void)
{
	if (sys_cost_settings.activated)
		deactivate_sys_cost();
	sys_cost_settings.activated = 0;

	msleep(20);
	destroy_diag_variant_buffer(&sys_cost_variant_buffer);
}
#endif
