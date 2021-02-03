/*
 * Linux内核诊断工具--内核态task-monitor功能
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Wen Yang <simon.wy@linux.alibaba.com>
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

#include "uapi/task_monitor.h"

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_task_monitor_settings task_monitor_settings;
static unsigned int task_monitor_alloced;
static struct mm_tree mm_tree;
static struct diag_variant_buffer task_monitor_variant_buffer;

static bool (*orig_task_in_nonroot_cpuacct)(struct task_struct *) = NULL;
static void (*orig_get_tsk_cpu_allowed)(struct task_struct *, struct cpumask *) = NULL;
static unsigned long (*orig_task_ca_running)(struct task_struct *, int) = NULL;
static unsigned long (*orig_nr_running)(void) = NULL;

static void __maybe_unused clean_data(void)
{
	cleanup_mm_tree(&mm_tree);
}

static bool my_read_lock(rwlock_t *lock)
{
	int max_times = 1000;

	while(max_times-- > 0) {
		if (read_trylock(lock))
			return true;
		udelay(1);
	}
	return false;
}

static unsigned int nr_running_tasks(void)
{
    unsigned long nr_r = 0;
    struct cpumask cpus_allowed;
    int i;

    rcu_read_lock();
    if (orig_task_in_nonroot_cpuacct(current) &&
        in_noninit_pid_ns(current)) {
        struct task_struct *init_tsk;

		if (!my_read_lock(orig_tasklist_lock)) {
			printk(KERN_ERR "lock tasklist failed\n");
			return -EBUSY;
		}
        init_tsk = task_active_pid_ns(current)->child_reaper;
        get_task_struct(init_tsk);
        read_unlock(orig_tasklist_lock);

        cpumask_copy(&cpus_allowed, cpu_possible_mask);
#ifdef CONFIG_CPUSETS
        if (task_css(init_tsk, cpuset_cgrp_id)) {
            memset(&cpus_allowed, 0, sizeof(cpus_allowed));
            orig_get_tsk_cpu_allowed(init_tsk, &cpus_allowed);
        }
#endif
        for_each_cpu_and(i, cpu_possible_mask, &cpus_allowed) {
            nr_r += orig_task_ca_running(init_tsk, i);
		}
        put_task_struct(init_tsk);
    } else {
        nr_r = orig_nr_running();
    }
    rcu_read_unlock();

	return nr_r;
}

#if defined(UPSTREAM_4_19_32)
void task_monitor_timer(struct diag_percpu_context *context)
{
	return;
}
#else
void task_monitor_timer(struct diag_percpu_context *context)
{
	struct task_struct *g, *p;
	unsigned long nr_d = 0;
	unsigned long nr_r;
	bool scare = false;
	static ktime_t last;
	u64 ms;

	if (!task_monitor_settings.activated)
		return;

	if (!task_monitor_settings.threshold_task_a 
			&& !task_monitor_settings.threshold_task_r
			&& !task_monitor_settings.threshold_task_d)
		return;

	if (smp_processor_id() != 0)
		return;

	ms = ktime_to_ms(ktime_sub(ktime_get(), last));
	if (ms < task_monitor_settings.interval)
		return;

	last = ktime_get();
	do {
		/* fast path */
		nr_r = nr_running_tasks();
		if (nr_r >= task_monitor_settings.threshold_task_r || 
				nr_r >= task_monitor_settings.threshold_task_a) {
			scare = true;
			break;
		}

		nr_r = 0;
		nr_d = 0;
		rcu_read_lock();
		do_each_thread(g, p) {
			if (p->state & TASK_UNINTERRUPTIBLE)
				nr_d++;
			if (p->state & TASK_RUNNING)
				nr_r++;
		} while_each_thread(g, p);
		rcu_read_unlock();

		if (nr_d >= task_monitor_settings.threshold_task_d ||
				nr_r >= task_monitor_settings.threshold_task_r || 
				(nr_r + nr_d) >= task_monitor_settings.threshold_task_a)
			scare = true;
	}while (0);

	if (scare) {
		unsigned long flags;
		static struct task_monitor_summary summary;
		static struct task_monitor_detail detail;
		unsigned long event_id;

		event_id = get_cycles();
		summary.id = event_id;
		summary.et_type = et_task_monitor_summary;
		do_gettimeofday(&summary.tv);
		nr_r = nr_d = 0;

		rcu_read_lock();

		do_each_thread(g, p) {
			if ((p->state == TASK_RUNNING)
				|| (p->state & TASK_UNINTERRUPTIBLE)) {
				p->state = TASK_RUNNING ? nr_r++ : nr_d++;
				detail.et_type = et_task_monitor_detail;
				detail.id = event_id;
				detail.tv = summary.tv;
				diag_task_brief(p, &detail.task);
				diag_task_kern_stack(p, &detail.kern_stack);
				dump_proc_chains_argv(task_monitor_settings.style, &mm_tree,
						p, &detail.proc_chains);
				diag_variant_buffer_spin_lock(&task_monitor_variant_buffer,
						flags);
				diag_variant_buffer_reserve(&task_monitor_variant_buffer,
						sizeof(struct task_monitor_detail));
				diag_variant_buffer_write_nolock(&task_monitor_variant_buffer,
						&detail, sizeof(struct task_monitor_detail));
				diag_variant_buffer_seal(&task_monitor_variant_buffer);
				diag_variant_buffer_spin_unlock(&task_monitor_variant_buffer, flags);
			}
		} while_each_thread(g, p);

		summary.task_a = nr_r + nr_d;
		summary.task_r = nr_r;
		summary.task_d = nr_d;
		diag_variant_buffer_spin_lock(&task_monitor_variant_buffer, flags);
		diag_variant_buffer_reserve(&task_monitor_variant_buffer,
				sizeof(struct task_monitor_summary));
		diag_variant_buffer_write_nolock(&task_monitor_variant_buffer,
				&summary, sizeof(struct task_monitor_summary));
		diag_variant_buffer_seal(&task_monitor_variant_buffer);
		diag_variant_buffer_spin_unlock(&task_monitor_variant_buffer, flags);

		rcu_read_unlock();
	}
}
#endif

static int __activate_task_monitor(void)
{
	int ret = 0;

	clean_data();

	ret = alloc_diag_variant_buffer(&task_monitor_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	task_monitor_alloced = 1;

	return 1;
out_variant_buffer:
	return 0;
}

int activate_task_monitor(void)
{
	if (!task_monitor_settings.activated)
		task_monitor_settings.activated = __activate_task_monitor();

	return task_monitor_settings.activated;
}

static void __deactivate_task_monitor(void)
{
	synchronize_sched();
	msleep(10);
	while (atomic64_read(&diag_nr_running) > 0) {
		msleep(10);
	}

	clean_data();
	task_monitor_settings.verbose = 0;
	task_monitor_settings.threshold_task_a = 0;
	task_monitor_settings.threshold_task_r = 0;
	task_monitor_settings.threshold_task_d = 0;
}

int deactivate_task_monitor(void)
{
	if (task_monitor_settings.activated)
		__deactivate_task_monitor();
	task_monitor_settings.activated = 0;

	return task_monitor_settings.activated;
}

int task_monitor_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_task_monitor_settings settings;

	switch (id) {
	case DIAG_TASK_MONITOR_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_task_monitor_settings)) {
			ret = -EINVAL;
		} else if (task_monitor_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				task_monitor_settings = settings;
			}
		}
		break;
	case DIAG_TASK_MONITOR_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_task_monitor_settings)) {
			ret = -EINVAL;
		} else {
			settings = task_monitor_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_TASK_MONITOR_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!task_monitor_alloced) {
			ret = -EINVAL;
		} else {
			ret = copy_to_user_variant_buffer(&task_monitor_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("task-monitor");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_task_monitor(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_task_monitor_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_TASK_MONITOR_SET:
		if (task_monitor_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_task_monitor_settings));
			if (!ret) {
				task_monitor_settings = settings;
			}
		}
		break;
	case CMD_TASK_MONITOR_SETTINGS:
		settings = task_monitor_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_task_monitor_settings));
		break;
	case CMD_TASK_MONITOR_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));
		if (!task_monitor_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			ret = copy_to_user_variant_buffer(&task_monitor_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("task-monitor");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

static int lookup_syms(void)
{
	LOOKUP_SYMS(task_in_nonroot_cpuacct);
	LOOKUP_SYMS(get_tsk_cpu_allowed);
	LOOKUP_SYMS(task_ca_running);
	LOOKUP_SYMS(nr_running);
	return 0;
}

int diag_task_monitor_init(void)
{ 

	if (lookup_syms())
		return -EINVAL;

	init_mm_tree(&mm_tree);
	init_diag_variant_buffer(&task_monitor_variant_buffer, 1 * 1024 * 1024);
	if (task_monitor_settings.activated)
		task_monitor_settings.activated = __activate_task_monitor();

	return 0;
}

void diag_task_monitor_exit(void)
{
	if (task_monitor_settings.activated)
		deactivate_task_monitor();

	task_monitor_settings.activated = 0;
	destroy_diag_variant_buffer(&task_monitor_variant_buffer);
}
