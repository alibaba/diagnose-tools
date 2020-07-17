/*
 * Linux内核诊断工具--内核态load-monitor功能
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

#include <asm/irq_regs.h>

#include "internal.h"
#include "mm_tree.h"
#include "pub/trace_file.h"
#include "pub/variant_buffer.h"
#include "pub/trace_point.h"

#include "uapi/load_monitor.h"

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);

struct diag_load_monitor_settings load_monitor_settings;

static unsigned int load_monitor_alloced;

static struct mm_tree mm_tree;

unsigned long *orig_avenrun_r;
unsigned long *orig_avenrun;

static struct diag_variant_buffer load_monitor_variant_buffer;

static void __maybe_unused clean_data(void)
{
	cleanup_mm_tree(&mm_tree);
}

#ifndef FSHIFT
#define FSHIFT		11		/* nr of bits of precision */
#endif
#ifndef FIXED_1
#define FIXED_1		(1<<FSHIFT)	/* 1.0 as fixed-point */
#endif
#ifndef LOAD_INT
#define LOAD_INT(x) ((x) >> FSHIFT)
#endif
#ifndef LOAD_FRAC
#define LOAD_FRAC(x) LOAD_INT(((x) & (FIXED_1-1)) * 100)
#endif

#if defined(UPSTREAM_4_19_32)
void diag_load_timer(struct diag_percpu_context *context)
{
	return;
}
#else
void diag_load_timer(struct diag_percpu_context *context)
{
	static ktime_t last;
	u64 ms;
	bool scare = false;
	unsigned long load_d;
	struct task_struct *g, *p;

	if (!load_monitor_settings.activated)
		return;
	if (!load_monitor_settings.threshold_load && !load_monitor_settings.threshold_load_r && !load_monitor_settings.threshold_load_d
		&& !load_monitor_settings.threshold_task_d)
		return;
	if (smp_processor_id() != 0)
		return;

	if (load_monitor_settings.threshold_load && orig_avenrun
			&& LOAD_INT(orig_avenrun[0]) >= load_monitor_settings.threshold_load)
		scare = true;
	if (load_monitor_settings.threshold_load_r && orig_avenrun_r
			&& LOAD_INT(orig_avenrun_r[0]) >= load_monitor_settings.threshold_load_r)
		scare = true;
	if (load_monitor_settings.threshold_load_d && orig_avenrun && orig_avenrun_r) {
		load_d = LOAD_INT(orig_avenrun[0] - orig_avenrun_r[0]);

		if (load_d >= load_monitor_settings.threshold_load_d && load_d < 999999)
			scare = true;
	}
	if (load_monitor_settings.threshold_task_d) {
		int nr_uninterrupt = 0;
		struct task_struct *g, *p;

		rcu_read_lock();

		do_each_thread(g, p) {
			if (p->state & TASK_UNINTERRUPTIBLE)
				nr_uninterrupt++;
		} while_each_thread(g, p);

		rcu_read_unlock();

		if (nr_uninterrupt >= load_monitor_settings.threshold_task_d)
			scare = true;
	}

	if (scare) {
		unsigned long flags;
		static struct load_monitor_detail detail;
		static struct load_monitor_task tsk_info;
		unsigned long event_id;

		ms = ktime_to_ms(ktime_sub(ktime_get(), last));
		if (ms < 10 * 1000)
			return;

		last = ktime_get();
		
		if (orig_avenrun) {
			detail.load_1_1 = LOAD_INT(orig_avenrun[0]);
			detail.load_1_2 = LOAD_FRAC(orig_avenrun[0]);
			detail.load_5_1 = LOAD_INT(orig_avenrun[1]);
			detail.load_5_2 = LOAD_FRAC(orig_avenrun[1]);
			detail.load_15_1 = LOAD_INT(orig_avenrun[2]);
			detail.load_15_2 = LOAD_FRAC(orig_avenrun[2]);
		}
		if (orig_avenrun && orig_avenrun_r) {
			unsigned long l1, l2, l3;

			detail.load_r_1_1 = LOAD_INT(orig_avenrun_r[0]);
			detail.load_r_1_2 = LOAD_FRAC(orig_avenrun_r[0]);
			detail.load_r_5_1 = LOAD_INT(orig_avenrun_r[1]);
			detail.load_r_5_2 = LOAD_FRAC(orig_avenrun_r[1]);
			detail.load_r_15_1 = LOAD_INT(orig_avenrun_r[2]);
			detail.load_r_15_2 = LOAD_FRAC(orig_avenrun_r[2]);
			l1 = orig_avenrun[0] - orig_avenrun_r[0];
			l2 = orig_avenrun[1] - orig_avenrun_r[1];
			l3 = orig_avenrun[2] - orig_avenrun_r[2];
			detail.load_d_1_1 = LOAD_INT(l1);
			detail.load_d_1_2 = LOAD_FRAC(l1);
			detail.load_d_5_1 = LOAD_INT(l2);
			detail.load_d_5_2 = LOAD_FRAC(l2);
			detail.load_d_15_1 = LOAD_INT(l3);
			detail.load_d_15_2 = LOAD_FRAC(l3);
		}

		event_id = get_cycles();
		detail.id = event_id;
		detail.et_type = et_load_monitor_detail;
		do_gettimeofday(&detail.tv);

		rcu_read_lock();
		diag_variant_buffer_spin_lock(&load_monitor_variant_buffer, flags);
		diag_variant_buffer_reserve(&load_monitor_variant_buffer, sizeof(struct load_monitor_detail));
		diag_variant_buffer_write_nolock(&load_monitor_variant_buffer, &detail, sizeof(struct load_monitor_detail));
		diag_variant_buffer_seal(&load_monitor_variant_buffer);
		diag_variant_buffer_spin_unlock(&load_monitor_variant_buffer, flags);
		do_each_thread(g, p) {
			if ((p->state == TASK_RUNNING)
				|| (p->state & TASK_UNINTERRUPTIBLE)) {
				tsk_info.et_type = et_load_monitor_task;
				tsk_info.id = event_id;
				tsk_info.tv = detail.tv;
				diag_task_brief(p, &tsk_info.task);
				diag_task_kern_stack(p, &tsk_info.kern_stack);
				dump_proc_chains_argv(load_monitor_settings.style, &mm_tree, p, &tsk_info.proc_chains);
				diag_variant_buffer_spin_lock(&load_monitor_variant_buffer, flags);
				diag_variant_buffer_reserve(&load_monitor_variant_buffer, sizeof(struct load_monitor_task));
				diag_variant_buffer_write_nolock(&load_monitor_variant_buffer,
					&tsk_info, sizeof(struct load_monitor_task));
				diag_variant_buffer_seal(&load_monitor_variant_buffer);
				diag_variant_buffer_spin_unlock(&load_monitor_variant_buffer, flags);
			}
		} while_each_thread(g, p);
		rcu_read_unlock();
	}
}
#endif

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

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
static void trace_sched_process_exit_hit(void *__data, struct task_struct *tsk)
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
static void trace_sched_process_exit_hit(void *__data, struct task_struct *tsk)
#else
static void trace_sched_process_exit_hit(struct task_struct *tsk)
#endif
{
	diag_hook_process_exit_exec(tsk, &mm_tree);
}

static int __activate_load_monitor(void)
{
	int ret = 0;

	clean_data();

	ret = alloc_diag_variant_buffer(&load_monitor_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	load_monitor_alloced = 1;

	if (load_monitor_settings.style == 1) {
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
		hook_tracepoint("sched_process_exec", trace_sched_process_exec_hit, NULL);
#endif
		hook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);
	}
	//get_argv_processes(&mm_tree);

	return 1;
out_variant_buffer:
	return 0;
}

int activate_load_monitor(void)
{
	if (!load_monitor_settings.activated)
		load_monitor_settings.activated = __activate_load_monitor();

	return load_monitor_settings.activated;
}

static void __deactivate_load_monitor(void)
{
	if (load_monitor_settings.style == 1) {
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
		unhook_tracepoint("sched_process_exec", trace_sched_process_exec_hit, NULL);
#endif
		unhook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);
	}

	synchronize_sched();
	msleep(10);
	while (atomic64_read(&diag_nr_running) > 0) {
		msleep(10);
	}

	clean_data();

	load_monitor_settings.verbose = 0;
	load_monitor_settings.threshold_load = 0;
	load_monitor_settings.threshold_load_r = 0;
	load_monitor_settings.threshold_load_d = 0;
	load_monitor_settings.threshold_task_d = 0;
}

int deactivate_load_monitor(void)
{
	if (load_monitor_settings.activated)
		__deactivate_load_monitor();
	load_monitor_settings.activated = 0;

	return load_monitor_settings.activated;
}

long diag_ioctl_load_monitor(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_load_monitor_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_LOAD_MONITOR_SET:
		if (load_monitor_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_load_monitor_settings));
			if (!ret) {
				load_monitor_settings = settings;
			}
		}
		break;
	case CMD_LOAD_MONITOR_SETTINGS:
		settings = load_monitor_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_load_monitor_settings));
		break;
	case CMD_LOAD_MONITOR_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));
		if (!load_monitor_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			ret = copy_to_user_variant_buffer(&load_monitor_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("load-monitor");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_load_init(void)
{
	orig_avenrun_r = (void *)__kallsyms_lookup_name("avenrun_r");
	orig_avenrun = (void *)__kallsyms_lookup_name("avenrun");

	init_mm_tree(&mm_tree);
	init_diag_variant_buffer(&load_monitor_variant_buffer, 1 * 1024 * 1024);
	if (load_monitor_settings.activated)
		load_monitor_settings.activated = __activate_load_monitor();

	return 0;
}

void diag_load_exit(void)
{
	if (load_monitor_settings.activated)
		deactivate_load_monitor();
	load_monitor_settings.activated = 0;
	destroy_diag_variant_buffer(&load_monitor_variant_buffer);
}
