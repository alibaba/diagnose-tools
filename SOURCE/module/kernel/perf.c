/*
 * Linux内核诊断工具--内核态perf功能
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
#include <linux/nmi.h>

#include <asm/irq_regs.h>

#include "internal.h"
#include "mm_tree.h"
#include "pub/trace_file.h"
#include "pub/trace_point.h"

#include "uapi/perf.h"

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);

struct diag_perf_settings perf_settings;

static unsigned int perf_alloced;
static struct cpumask perf_cpumask;
static unsigned long perf_id;
static unsigned long perf_seq;

static struct diag_variant_buffer perf_variant_buffer;
static struct mm_tree mm_tree;

static void __maybe_unused clean_data(void)
{
	cleanup_mm_tree(&mm_tree);
}

static int need_trace(struct task_struct *tsk)
{
	int cpu;

	if (!perf_settings.activated)
		return 0;

	cpu = smp_processor_id();
	if (!perf_settings.idle && orig_idle_task && orig_idle_task(cpu) == tsk)
		return 0;

	if (perf_settings.sys) {
		struct pt_regs *regs = get_irq_regs();

		if (regs && user_mode(regs))
			return 0;
	}

	if (!cpumask_test_cpu(cpu, &perf_cpumask))
		return 0;

	if (!perf_settings.bvt && diag_get_task_type(tsk) < 0)
		return 0;

	if (perf_settings.tgid) {
		struct task_struct *leader = tsk->group_leader ? tsk->group_leader : tsk;

		if (leader->pid != perf_settings.tgid)
			return 0;
	}

	if (perf_settings.pid) {
		if (tsk->pid != perf_settings.pid)
			return 0;
	}

	if (perf_settings.comm[0]) {
		struct task_struct *leader = tsk->group_leader ? tsk->group_leader : tsk;

		if (!strstr(leader->comm, perf_settings.comm))
			return 0;
	}

	return 1;
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

void perf_timer(struct diag_percpu_context *context)
{
	unsigned long flags;
	struct perf_detail *detail;

	if (!need_trace(current)) {
		return;
	}

	detail = &diag_percpu_context[smp_processor_id()]->perf_detail;
	if (detail) {
		detail->et_type = et_perf_detail;
		detail->id = perf_id;
		detail->seq = perf_seq;
		do_gettimeofday(&detail->tv);
		diag_task_brief(current, &detail->task);
		diag_task_kern_stack(current, &detail->kern_stack);
		diag_task_user_stack(current, &detail->user_stack);
		detail->proc_chains.chains[0][0] = 0;
		dump_proc_chains_argv(perf_settings.style, &mm_tree, current, &detail->proc_chains);
		diag_variant_buffer_spin_lock(&perf_variant_buffer, flags);
		diag_variant_buffer_reserve(&perf_variant_buffer, sizeof(struct perf_detail));
		diag_variant_buffer_write_nolock(&perf_variant_buffer, detail, sizeof(struct perf_detail));
		diag_variant_buffer_seal(&perf_variant_buffer);
		diag_variant_buffer_spin_unlock(&perf_variant_buffer, flags);
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
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
{
	atomic64_inc_return(&diag_nr_running);
	diag_hook_exec(bprm, &mm_tree);
	atomic64_dec_return(&diag_nr_running);
}
#endif

static int __activate_perf(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&perf_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	perf_alloced = 1;

	clean_data();
	perf_id = get_cycles();
	perf_seq = 0;
	if (perf_settings.style == 1) {
		hook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
		hook_tracepoint("sched_process_exec", trace_sched_process_exec_hit, NULL);
#endif
		//get_argv_processes(&mm_tree);
	}
	
	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_perf(void)
{
	if (perf_settings.style == 1) {
		unhook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
		unhook_tracepoint("sched_process_exec", trace_sched_process_exec_hit, NULL);
#endif
	}

	synchronize_sched();
	/**
	 * 在JUMP_REMOVE和atomic64_read之间存在微妙的竞态条件
	 * 因此这里的msleep并非多余的。
	 */
	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0)
		msleep(20);

	clean_data();
}

int activate_perf(void)
{
	if (!perf_settings.activated)
		perf_settings.activated = __activate_perf();

	return perf_settings.activated;
}

int deactivate_perf(void)
{
	if (perf_settings.activated)
		__deactivate_perf();
	perf_settings.activated = 0;

	return 0;
}

static int lookup_syms(void)
{
	return 0;
}

static void jump_init(void)
{
}

long diag_ioctl_perf(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	static struct diag_perf_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_PERF_SET:
		if (perf_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_perf_settings));
			if (!ret) {
				if (settings.cpus[0]) {
					str_to_cpumask(settings.cpus, &perf_cpumask);
				} else {
					perf_cpumask = *cpu_possible_mask;
				}
				
				perf_settings = settings;
			}
		}
		break;
	case CMD_PERF_SETTINGS:
		settings = perf_settings;
		cpumask_to_str(&perf_cpumask, settings.cpus, 512);
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_perf_settings));
		break;
	case CMD_PERF_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));

		if (!perf_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			perf_seq++;
			ret = copy_to_user_variant_buffer(&perf_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("perf");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_kern_perf_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&perf_variant_buffer, 50 * 1024 * 1024);
	jump_init();

	init_mm_tree(&mm_tree);

	perf_cpumask = *cpu_possible_mask;

	if (perf_settings.activated)
		perf_settings.activated = __activate_perf();

	return 0;
}

void diag_kern_perf_exit(void)
{
	if (perf_settings.activated)
		deactivate_perf();
	perf_settings.activated = 0;

	msleep(10);
	synchronize_sched();

	destroy_diag_variant_buffer(&perf_variant_buffer);
}
