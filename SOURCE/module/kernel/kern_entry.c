/*
 * Linux内核诊断工具--内核态kernel功能入口
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
#include <linux/timex.h>
#include <linux/cpu.h>

#if !defined(DIAG_ARM64)
#include <asm/asm-offsets.h>
#endif

#include "internal.h"
#include "kern_internal.h"

static enum hrtimer_restart hrtimer_handler(struct hrtimer *hrtimer)
{
	enum hrtimer_restart ret = HRTIMER_RESTART;
	u64 now, expected;
	struct diag_percpu_context *context = get_percpu_context();

	now = sched_clock();
	expected = context->timer_info.timer_expected_time;

	if (in_irq()) {
		irq_delay_timer(context);
		syscall_timer(context);
		diag_load_timer(context);
		sys_loop_timer(context);
		perf_timer(context);
		utilization_timer(context);
		task_monitor_timer(context);
	}

	if (diag_timer_period > 0 && diag_timer_period < 100)
		timer_sampling_period_ms = diag_timer_period;
	expected = now + timer_sampling_period_ms * 1000 * 1000;
	context->timer_info.timer_expected_time = expected;
	hrtimer_forward_now(hrtimer, __ms_to_ktime(timer_sampling_period_ms));

	return ret;
}

static void start_timer(void *info)
{
	int cpu = smp_processor_id();
	struct diag_percpu_context *context = get_percpu_context_cpu(cpu);
	struct hrtimer *timer;

	if (context->timer_info.timer_started)
		return;

	/* start per-cpu hrtimer */
	timer = &context->timer_info.timer;
	hrtimer_init(timer, CLOCK_MONOTONIC, HRTIMER_MODE_PINNED);
	timer->function = hrtimer_handler;
	context->timer_info.timer_started = 1;
	context->timer_info.timer_expected_time =
		sched_clock() + timer_sampling_period_ms * 1000 * 1000;
	hrtimer_start_range_ns(timer,
			__ms_to_ktime(timer_sampling_period_ms),
			0,
			HRTIMER_MODE_REL_PINNED /*HRTIMER_MODE_PINNED*/);
}

static int start_timer_cpu(void *info)
{
	start_timer(info);

	return 0;
}
static int diag_cpu_notifier(struct notifier_block *nfb,
				    unsigned long action, void *v)
{
	unsigned int cpu = (unsigned long)v;
	struct hrtimer *timer;
	struct diag_percpu_context *percpu_context;

	switch (action) {
	case CPU_ONLINE:
		if (cpu == smp_processor_id()) {
			start_timer_cpu(NULL);
		} else {
			smp_call_function_single(cpu, start_timer, NULL, 1);
		}
#if defined(XBY_DEBUG_KERN_ENTRY)
		atomic64_inc(&xby_debug_counter4);
#endif
		break;
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		percpu_context = get_percpu_context_cpu(cpu);
		if (percpu_context->timer_info.timer_started)
		{
			timer = &percpu_context->timer_info.timer;
			hrtimer_cancel(timer);
			percpu_context->timer_info.timer_started = 0;
		}
#if defined(XBY_DEBUG_KERN_ENTRY)
		atomic64_inc(&xby_debug_counter5);
#endif
		break;
	}
	return NOTIFY_OK;
}

__maybe_unused static struct notifier_block diag_cpu_nb = {
	.notifier_call = diag_cpu_notifier,
};

int diag_kernel_init(void)
{
	struct proc_dir_entry *pe;
	int ret;

	pe = diag_proc_mkdir("ali-linux/diagnose/kern", NULL);

	ret = diag_irq_stats_init();
	if (ret)
		goto out;

	ret = diag_irq_delay_init();
	if (ret)
		goto out_irq_delay;

	ret = diag_sched_delay_init();
	if (ret)
		goto out_sched;

	ret = diag_rcu_init();
	if (ret)
		goto out_rcu;

	ret = diag_sys_loop_init();
	if (ret)
		goto out_sys_loop;

	ret = diag_mutex_init();
	if (ret)
		goto out_mutex;

	ret = diag_load_init();
	if (ret)
		goto out_load;

	ret = diag_exit_init();
	if (ret)
		goto out_exit;

	ret = diag_sys_cost_init();
	if (ret)
		goto out_syscall_cpu_cost;

	ret = diag_task_time_init();
	if (ret)
		goto out_task_time;

	ret = diag_sys_delay_init();
	if (ret)
		goto out_syscall;

	ret = diag_timer_init();
	if (ret)
		goto out_timer;

	ret = diag_exec_init();
	if (ret)
		goto out_exec;

	ret = diag_runq_info_init();
	if (ret)
		goto out_runq_info;

	ret = diag_kern_demo_init();
	if (ret)
		goto out_kern_demo;

	ret = diag_task_runs_init();
	if (ret)
		goto out_task_runs;

	ret = diag_kern_perf_init();
	if (ret)
		goto out_perf;

	ret = diag_run_trace_init();
	if (ret)
		goto out_run_trace;

	ret = diag_lock_init();
	if (ret)
		goto out_lock;

	ret = diag_irq_trace_init();
	if (ret)
		goto out_irq_trace;

	ret = diag_sys_broken_init();
	if (ret)
		goto out_sys_broken;

	ret = diag_kprobe_init();
	if (ret)
		goto out_kprobe;

	ret = diag_utilization_init();
	if (ret)
		goto out_utilization;

	ret = diag_reboot_init();
	if (ret)
		goto out_reboot;

	ret = diag_uprobe_init();
	if (ret)
		goto out_uprobe;

	ret = diag_sig_info_init();
	if (ret)
		goto out_sig_info;

	ret = diag_task_monitor_init();
	if (ret)
		goto out_task_monitor;

	on_each_cpu(start_timer, NULL, 1);

#if !defined(XBY_UBUNTU_1604) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	register_hotcpu_notifier(&diag_cpu_nb);
#endif

	return 0;

out_task_monitor:
	diag_sig_info_exit();
out_sig_info:
	diag_uprobe_exit();
out_uprobe:
	diag_reboot_exit();
out_reboot:
	diag_utilization_exit();
out_utilization:
	diag_kprobe_exit();
out_kprobe:
	diag_sys_broken_exit();
out_sys_broken:
	diag_irq_trace_exit();
out_irq_trace:
	diag_lock_exit();
out_lock:
	diag_run_trace_exit();
out_run_trace:
	diag_kern_perf_exit();
out_perf:
	diag_task_runs_exit();
out_task_runs:
	diag_kern_demo_exit();
out_kern_demo:
	diag_runq_info_exit();
out_runq_info:
	diag_exec_exit();
out_exec:
	diag_timer_exit();
out_timer:
	diag_sys_delay_exit();
out_syscall:
	diag_task_time_exit();
out_task_time:
	diag_sys_cost_exit();
out_syscall_cpu_cost:
	diag_exit_exit();
out_exit:
	diag_load_exit();
out_load:
	diag_mutex_exit();
out_mutex:
	diag_sys_loop_exit();
out_sys_loop:
	diag_rcu_exit();
out_rcu:
	diag_sched_delay_exit();
out_sched:
	diag_irq_delay_exit();
out_irq_delay:
	diag_irq_stats_exit();
out:
	return ret;
}

void diag_kernel_exit(void)
{
	int cpu;
	struct diag_percpu_context *percpu_context;
	struct hrtimer *timer;

#if !defined(XBY_UBUNTU_1604) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
	unregister_hotcpu_notifier(&diag_cpu_nb);
#endif
	/* cancel per-cpu hrtimer */
	for_each_possible_cpu(cpu)
	{
		percpu_context = get_percpu_context_cpu(cpu);
		if (percpu_context->timer_info.timer_started)
		{
			timer = &percpu_context->timer_info.timer;
			hrtimer_cancel(timer);
			percpu_context->timer_info.timer_started = 0;
		}
	}

	diag_task_monitor_exit();
	diag_sig_info_exit();
	diag_uprobe_exit();
	diag_reboot_exit();
	diag_utilization_exit();
	diag_kprobe_exit();
	diag_sys_broken_exit();
	diag_irq_trace_exit();
	diag_lock_exit();
	diag_run_trace_exit();
	diag_kern_perf_exit();
	diag_task_runs_exit();
	diag_kern_demo_exit();
	diag_runq_info_exit();
	diag_exec_exit();
	diag_timer_exit();
	diag_task_time_exit();
	diag_sys_cost_exit();
	diag_sys_delay_exit();
	diag_exit_exit();
	diag_load_exit();
	diag_mutex_exit();
	diag_sys_loop_exit();
	diag_rcu_exit();
	diag_sched_delay_exit();
	diag_irq_delay_exit();
	diag_irq_stats_exit();

	//remove_proc_entry("ali-linux/diagnose/kern", NULL);
}
