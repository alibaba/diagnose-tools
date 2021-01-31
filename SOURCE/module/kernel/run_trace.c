/*
 * Linux内核诊断工具--内核态run-trace功能
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
#include <linux/uaccess.h>

#include <asm/irq_regs.h>

#include "internal.h"
#include "pub/trace_file.h"
#include "pub/variant_buffer.h"
#include "pub/trace_point.h"
#include "pub/uprobe.h"

#include "uapi/run_trace.h"

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);

struct diag_run_trace_settings run_trace_settings = {
	.threshold_us = 500000,  /* 500ms */

};

static unsigned int run_trace_alloced;

static struct radix_tree_root run_trace_tree;
static DEFINE_SPINLOCK(tree_lock);

static struct radix_tree_root monitor_tree;
static DEFINE_SPINLOCK(monitor_lock);

static DECLARE_RWSEM(run_trace_sem);

static struct diag_variant_buffer run_trace_variant_buffer;
static struct diag_trace_file run_trace_settings_file;

static atomic64_t settings_syscall_count = ATOMIC64_INIT(0);
static atomic64_t settings_threads_count = ATOMIC64_INIT(0);

struct task_info {
	struct rcu_head rcu_head;
	struct task_struct *tsk;
	struct diag_variant_buffer buffer;
	pid_t pid;
	int seq;
	unsigned long id;
	unsigned int threshold_ms;
	char comm[TASK_COMM_LEN];
	struct timeval start_tv;
	u64 start_monitor;
	u64 last_event;
	int traced;
	int stop_on_exit_syscall;
};

struct monitor_info {
	struct task_struct *tsk;
	pid_t pid;
	char comm[TASK_COMM_LEN];
	int syscall_threshold_ms[NR_syscalls_virt];
};

static unsigned long run_trace_uprobe_tgid = 0;
static struct diag_uprobe diag_uprobe_start;
static struct diag_uprobe diag_uprobe_stop;

static void destroy_task_info(struct task_info *task_info)
{
	if (!task_info)
		return;

	destroy_diag_variant_buffer(&task_info->buffer);
	kfree(task_info);
}

static struct task_info *find_task_info(struct task_struct *tsk)
{
	struct task_info *info;

	if (tsk == NULL)
		return NULL;

	info = radix_tree_lookup(&run_trace_tree, (unsigned long)tsk);

	return info;
}

static struct task_info *find_alloc_task_info(struct task_struct *tsk)
{
	struct task_info *info;
	int ret;

	if (tsk == NULL)
		return NULL;

	info = radix_tree_lookup(&run_trace_tree, (unsigned long)tsk);
	if (!info) {
		info = kmalloc(sizeof(struct task_info), GFP_ATOMIC | __GFP_ZERO);
		ret = 0;
		if (info) {
			int buf_size = run_trace_settings.buf_size_k * 1024;

			if (buf_size < 200 * 1024) {
				buf_size = 200 * 1024;
			}
			if (buf_size > 10 * 1024 * 1024) {
				buf_size = 10 * 1024 * 1024;
			}

			init_diag_variant_buffer(&info->buffer, buf_size);
			ret = alloc_diag_variant_buffer(&info->buffer);
		}
		if (ret) {
			kfree(info);
			info = NULL;
		}

		if (info) {
			unsigned long flags;
			struct task_info *tmp;

			spin_lock_irqsave(&tree_lock, flags);
			tmp = radix_tree_lookup(&run_trace_tree, (unsigned long)tsk);
			if (tmp) {
				destroy_task_info(info);
				info = tmp;
			} else {
				info->pid = tsk->pid;
				info->tsk = tsk;
				strncpy(info->comm, tsk->comm, TASK_COMM_LEN);
				info->comm[TASK_COMM_LEN - 1] = 0;
				radix_tree_insert(&run_trace_tree, (unsigned long)tsk, info);
				atomic64_inc_return(&settings_threads_count);
			}
			spin_unlock_irqrestore(&tree_lock, flags);
		}
	}

	return info;
}

__maybe_unused static struct task_info *takeout_task_info(struct task_struct *tsk)
{
	unsigned long flags;
	struct task_info *info = NULL;

	spin_lock_irqsave(&tree_lock, flags);
	info = radix_tree_delete(&run_trace_tree, (unsigned long)tsk);
	if (info)
		atomic64_dec_return(&settings_threads_count);
	spin_unlock_irqrestore(&tree_lock, flags);

	return info;
}

static struct monitor_info *find_monitor_info(struct task_struct *tsk)
{
	struct monitor_info *info;

	if (tsk == NULL)
		return NULL;

	info = radix_tree_lookup(&monitor_tree, (unsigned long)tsk);

	return info;
}

static struct monitor_info *find_alloc_monitor_info(struct task_struct *tsk)
{
	struct monitor_info *info;

	if (tsk == NULL)
		return NULL;

	info = radix_tree_lookup(&monitor_tree, (unsigned long)tsk);
	if (!info) {
		info = kmalloc(sizeof(struct monitor_info), GFP_ATOMIC | __GFP_ZERO);

		if (info) {
			unsigned long flags;
			struct monitor_info *tmp;

			spin_lock_irqsave(&monitor_lock, flags);
			tmp = radix_tree_lookup(&monitor_tree, (unsigned long)tsk);
			if (tmp) {
				kfree(info);
				info = tmp;
			} else {
				info->tsk = tsk;
				info->pid = tsk->pid;
				strncpy(info->comm, tsk->comm, TASK_COMM_LEN);
				info->comm[TASK_COMM_LEN - 1] = 0;
				radix_tree_insert(&monitor_tree, (unsigned long)tsk, info);
				atomic64_inc_return(&settings_syscall_count);
			}
			spin_unlock_irqrestore(&monitor_lock, flags);
		}
	}

	return info;
}

__maybe_unused static struct monitor_info *takeout_monitor_info(struct task_struct *tsk)
{
	unsigned long flags;
	struct monitor_info *info = NULL;

	spin_lock_irqsave(&monitor_lock, flags);
	info = radix_tree_delete(&monitor_tree, (unsigned long)tsk);
	if (info)
		atomic64_dec_return(&settings_syscall_count);
	spin_unlock_irqrestore(&monitor_lock, flags);

	return info;
}

int start_run_trace(struct task_struct *tsk, unsigned int threshold_ms, int stop_on_exit_syscall)
{
	struct task_info *task_info;
	unsigned long flags;
	struct event_start event;

	task_info = find_alloc_task_info(tsk);
	if (!task_info)
		return -EINVAL;

	task_info->id = get_cycles();
	task_info->seq = 1;
	task_info->threshold_ms = threshold_ms;
	task_info->start_monitor = task_info->last_event = sched_clock();
	do_gettimeofday(&task_info->start_tv);
	task_info->traced = 1;
	task_info->stop_on_exit_syscall = stop_on_exit_syscall;
	discard_diag_variant_buffer(&task_info->buffer);

	event.header.et_type = et_start;
	event.header.id = task_info->id;
	event.header.seq = task_info->seq;
	task_info->seq++;
	diag_task_brief(tsk, &event.header.task);
	event.header.tv = task_info->start_tv;
	event.header.start_tv = task_info->start_tv;
	diag_variant_buffer_spin_lock(&task_info->buffer, flags);
	diag_variant_buffer_reserve(&task_info->buffer, sizeof(event));
	diag_variant_buffer_write_nolock(&task_info->buffer, &event, sizeof(event));
	diag_variant_buffer_seal(&task_info->buffer);
	diag_variant_buffer_spin_unlock(&task_info->buffer, flags);

	return 0;
}

static void stop_run_trace(struct task_struct *tsk, int stop_on_sys_exit)
{
	struct task_info *task_info;
	int et_type;

	task_info = find_task_info(tsk);
	if (!task_info)
		return;

	task_info->traced = 0;
	task_info->stop_on_exit_syscall = 0;
	
	if (task_info->start_monitor > 0) {
		u64 now = sched_clock();
		u64 delta_ns = now - task_info->last_event;
		u64 duration_ns = now - task_info->start_monitor;
		unsigned int threshold_us = 0;

		task_info->start_monitor = 0;
		if (task_info->threshold_ms) {
			threshold_us = task_info->threshold_ms * 1000;
		} else {
			threshold_us = run_trace_settings.threshold_us;
		}

		if (duration_ns >= (u64)threshold_us * 1000) {
			static struct event_stop_raw_stack event_raw_stack;
			static struct event_stop event;
			unsigned long flags;

			if (stop_on_sys_exit) {
				diag_variant_buffer_spin_lock(&task_info->buffer, flags);
				event_raw_stack.header.et_type = et_stop_raw_stack;
				event_raw_stack.header.id = task_info->id;
				event_raw_stack.header.seq = task_info->seq;
				task_info->seq++;
				event_raw_stack.header.start_tv = task_info->start_tv;
				diag_task_brief(tsk, &event_raw_stack.header.task);
				diag_task_raw_stack(tsk, &event_raw_stack.raw_stack);
				do_gettimeofday(&event_raw_stack.header.tv);
				event_raw_stack.header.delta_ns = delta_ns;
				event_raw_stack.duration_ns = duration_ns;
				diag_variant_buffer_reserve(&task_info->buffer,
					sizeof(event_raw_stack));
				diag_variant_buffer_write_nolock(&task_info->buffer,
					&event_raw_stack, sizeof(event_raw_stack));
				diag_variant_buffer_seal(&task_info->buffer);
				diag_variant_buffer_spin_unlock(&task_info->buffer, flags);
			} else {
				diag_variant_buffer_spin_lock(&task_info->buffer, flags);
				event.header.et_type = et_stop;
				event.header.id = task_info->id;
				event.header.seq = task_info->seq;
				task_info->seq++;
				event.header.start_tv = task_info->start_tv;
				diag_task_brief(tsk, &event.header.task);
				do_gettimeofday(&event.header.tv);
				event.header.delta_ns = delta_ns;
				event.duration_ns = duration_ns;
				diag_variant_buffer_reserve(&task_info->buffer, sizeof(event));
				diag_variant_buffer_write_nolock(&task_info->buffer, &event, sizeof(event));
				diag_variant_buffer_seal(&task_info->buffer);
				diag_variant_buffer_spin_unlock(&task_info->buffer, flags);
			}

			backup_diag_variant_buffer(&task_info->buffer);

			diag_variant_buffer_spin_lock(&run_trace_variant_buffer, flags);
			diag_variant_buffer_reserve(&run_trace_variant_buffer,
				sizeof(int) + task_info->buffer.product.len);
			et_type = et_run_trace;
			diag_variant_buffer_write_nolock(&run_trace_variant_buffer, &et_type, sizeof(int));
			diag_variant_buffer_write_nolock(&run_trace_variant_buffer,
				task_info->buffer.product.data,
				task_info->buffer.product.len);
			diag_variant_buffer_seal(&run_trace_variant_buffer);
			diag_variant_buffer_spin_unlock(&run_trace_variant_buffer, flags);
		}
	}

	task_info->start_monitor = 0;
}

static void __maybe_unused clean_data(void)
{
	struct task_info *tasks[NR_BATCH];
	struct task_info *task_info;
	struct monitor_info *monitors[NR_BATCH];
	struct monitor_info *monitor_info;
	int nr_found;
	unsigned long pos = 0;
	int i;

	down_write(&run_trace_sem);
	rcu_read_lock();

	do {
		nr_found = radix_tree_gang_lookup(&run_trace_tree, (void **)tasks, pos, NR_BATCH);
		for (i = 0; i < nr_found; i++) {
			task_info = tasks[i];
			radix_tree_delete(&run_trace_tree, (unsigned long)task_info->tsk);
			pos = (unsigned long)task_info->tsk + 1;
			destroy_task_info(task_info);
		}
	} while (nr_found > 0);

	pos = 0;
	do {
		nr_found = radix_tree_gang_lookup(&monitor_tree, (void **)monitors, pos, NR_BATCH);
		for (i = 0; i < nr_found; i++) {
			monitor_info = monitors[i];
			radix_tree_delete(&monitor_tree, (unsigned long)monitor_info->tsk);
			pos = (unsigned long)monitor_info->tsk + 1;
			kfree(monitor_info);
		}
	} while (nr_found > 0);

	rcu_read_unlock();
	up_write(&run_trace_sem);

	atomic64_set(&settings_syscall_count, 0);
	atomic64_set(&settings_threads_count, 0);
}

static inline void __maybe_unused
hook_sched_switch(struct task_struct *prev, struct task_struct *next)
{
	struct task_info *task_info;
	unsigned long flags;

	task_info = find_task_info(prev);
	if (task_info && task_info->traced) {
		struct event_sched_out event;
		u64 now = sched_clock();
		u64 delta_ns = now - task_info->last_event;

		task_info->last_event = now;
		event.header.et_type = et_sched_out;
		event.header.id = task_info->id;
		event.header.seq = task_info->seq;
		event.header.start_tv = task_info->start_tv;
		do_gettimeofday(&event.header.tv);
		task_info->seq++;
		diag_task_brief(current, &event.header.task);
		event.header.delta_ns = delta_ns;
		diag_task_kern_stack(current, &event.kern_stack);
		diag_variant_buffer_spin_lock(&task_info->buffer, flags);
		diag_variant_buffer_reserve(&task_info->buffer, sizeof(event));
		diag_variant_buffer_write_nolock(&task_info->buffer, &event, sizeof(event));
		diag_variant_buffer_seal(&task_info->buffer);
		diag_variant_buffer_spin_unlock(&task_info->buffer, flags);
	}

	task_info = find_task_info(next);
	if (task_info && task_info->traced) {
		struct event_sched_in event;
		u64 now = sched_clock();
		u64 delta_ns = now - task_info->last_event;

		task_info->last_event = now;
		event.header.et_type = et_sched_in;
		event.header.id = task_info->id;
		event.header.seq = task_info->seq;
		event.header.start_tv = task_info->start_tv;
		do_gettimeofday(&event.header.tv);
		task_info->seq++;
		diag_task_brief(next, &event.header.task);
		event.header.delta_ns = delta_ns;
		diag_task_kern_stack(current, &event.kern_stack);
		diag_variant_buffer_spin_lock(&task_info->buffer, flags);
		diag_variant_buffer_reserve(&task_info->buffer, sizeof(event));
		diag_variant_buffer_write_nolock(&task_info->buffer, &event, sizeof(event));
		diag_variant_buffer_seal(&task_info->buffer);
		diag_variant_buffer_spin_unlock(&task_info->buffer, flags);
	}
}

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
static void trace_sched_switch_hit(void *__data, bool preempt,
		struct task_struct *prev, struct task_struct *next)
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
static void trace_sched_switch_hit(void *__data,
		struct task_struct *prev, struct task_struct *next)
#else
static void trace_sched_switch_hit(struct rq *rq, struct task_struct *prev,
		struct task_struct *next)
#endif
{
	hook_sched_switch(prev, next);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
static void trace_sys_enter_hit(struct pt_regs *regs, long id)
#else
static void trace_sys_enter_hit(void *__data, struct pt_regs *regs, long id)
#endif
{
	struct task_info *task_info;
	struct monitor_info *monitor_info;
	struct task_struct *leader;
	unsigned long flags;

	leader = current->group_leader ? current->group_leader : current;
	monitor_info = find_monitor_info(leader);
	if (monitor_info && id < NR_syscalls_virt && monitor_info->syscall_threshold_ms[id]) {
		/**
		 * 注意这里的读锁
		 */
		down_read(&run_trace_sem);
		start_run_trace(current, monitor_info->syscall_threshold_ms[id], 1);
		up_read(&run_trace_sem);
	}

	task_info = find_task_info(current);
	if (task_info && task_info->traced) {
		u64 now = sched_clock();
		u64 delta_ns = now - task_info->last_event;
		if (run_trace_settings.raw_stack) {
			struct event_sys_enter_raw *event;
			event = &diag_percpu_context[smp_processor_id()]->event_sys_enter_raw;

			task_info->last_event = now;
			event->header.et_type = et_sys_enter_raw;
			event->header.id = task_info->id;
			event->header.seq = task_info->seq;
			event->header.start_tv = task_info->start_tv;
			do_gettimeofday(&event->header.tv);
			task_info->seq++;
			diag_task_brief(current, &event->header.task);
			event->syscall_id = id;
			event->header.delta_ns = delta_ns;
			diag_task_raw_stack(current, &event->raw_stack);
			diag_variant_buffer_spin_lock(&task_info->buffer, flags);
			diag_variant_buffer_reserve(&task_info->buffer, sizeof(struct event_sys_enter_raw));
			diag_variant_buffer_write_nolock(&task_info->buffer, event, sizeof(struct event_sys_enter_raw));
			diag_variant_buffer_seal(&task_info->buffer);
			diag_variant_buffer_spin_unlock(&task_info->buffer, flags);
		} else {
			struct event_sys_enter event;

			task_info->last_event = now;
			event.header.et_type = et_sys_enter;
			event.header.id = task_info->id;
			event.header.seq = task_info->seq;
			event.header.start_tv = task_info->start_tv;
			do_gettimeofday(&event.header.tv);
			task_info->seq++;
			diag_task_brief(current, &event.header.task);
			event.syscall_id = id;
			event.header.delta_ns = delta_ns;
			diag_task_user_stack(current, &event.user_stack);
			diag_variant_buffer_spin_lock(&task_info->buffer, flags);
			diag_variant_buffer_reserve(&task_info->buffer, sizeof(event));
			diag_variant_buffer_write_nolock(&task_info->buffer, &event, sizeof(event));
			diag_variant_buffer_seal(&task_info->buffer);
			diag_variant_buffer_spin_unlock(&task_info->buffer, flags);
		}
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
static void trace_sys_exit_hit(struct pt_regs *regs, long ret)
#else
static void trace_sys_exit_hit(void *__data, struct pt_regs *regs, long ret)
#endif
{
	struct task_info *task_info;
	unsigned long flags;

	task_info = find_task_info(current);
	if (task_info && task_info->traced) {
		struct event_sys_exit event;
		u64 now = sched_clock();
		u64 delta_ns = now - task_info->last_event;

		task_info->last_event = now;
		event.header.et_type = et_sys_exit;
		event.header.id = task_info->id;
		event.header.seq = task_info->seq;
		event.header.start_tv = task_info->start_tv;
		do_gettimeofday(&event.header.tv);
		task_info->seq++;
		diag_task_brief(current, &event.header.task);
		event.header.delta_ns = delta_ns;
		diag_variant_buffer_spin_lock(&task_info->buffer, flags);
		diag_variant_buffer_reserve(&task_info->buffer, sizeof(event));
		diag_variant_buffer_write_nolock(&task_info->buffer, &event, sizeof(event));
		diag_variant_buffer_seal(&task_info->buffer);
		diag_variant_buffer_spin_unlock(&task_info->buffer, flags);
	}

	if (task_info && task_info->stop_on_exit_syscall) {
		stop_run_trace(current, 1);
	}
}

__maybe_unused static void free_task_info(struct rcu_head *head)
{
	struct task_info *task_info = container_of(head, struct task_info, rcu_head);

	destroy_task_info(task_info);
}

static inline void __maybe_unused hook_sched_process_exit(struct task_struct *tsk)
{
	struct task_info *task_info;
	struct monitor_info *monitor_info;

	task_info = takeout_task_info(tsk);
	if (task_info) {
		destroy_task_info(task_info);
	}

	monitor_info = takeout_monitor_info(tsk);
	if (monitor_info) {
		kfree(monitor_info);
	}
}

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
static void trace_sched_process_exit_hit(void *__data, struct task_struct *tsk)
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
static void trace_sched_process_exit_hit(void *__data, struct task_struct *tsk)
#else
static void trace_sched_process_exit_hit(struct task_struct *tsk)
#endif
{
	hook_sched_process_exit(tsk);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_irq_handler_entry_hit(int irq,
		struct irqaction *action)
#else
static void trace_irq_handler_entry_hit(void *ignore, int irq,
                struct irqaction *action)
#endif
{
	struct task_info *task_info;
	unsigned long flags;

	task_info = find_task_info(current);
	if (task_info && task_info->traced) {
		struct event_irq_handler_entry event;
		u64 now = sched_clock();
		u64 delta_ns = now - task_info->last_event;

		task_info->last_event = now;
		event.header.et_type = et_irq_handler_entry;
		event.header.id = task_info->id;
		event.header.seq = task_info->seq;
		event.header.start_tv = task_info->start_tv;
		do_gettimeofday(&event.header.tv);
		task_info->seq++;
		event.irq = irq;
		diag_task_brief(current, &event.header.task);
		event.header.delta_ns = delta_ns;
		diag_variant_buffer_spin_lock(&task_info->buffer, flags);
		diag_variant_buffer_reserve(&task_info->buffer, sizeof(event));
		diag_variant_buffer_write_nolock(&task_info->buffer, &event, sizeof(event));
		diag_variant_buffer_seal(&task_info->buffer);
		diag_variant_buffer_spin_unlock(&task_info->buffer, flags);
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_irq_handler_exit_hit(int irq,
		struct irqaction *action, int ret)
#else
static void trace_irq_handler_exit_hit(void *ignore, int irq,
                struct irqaction *action, int ret)
#endif
{
	struct task_info *task_info;
	unsigned long flags;

	task_info = find_task_info(current);
	if (task_info && task_info->traced) {
		struct event_irq_handler_exit event;
		u64 now = sched_clock();
		u64 delta_ns = now - task_info->last_event;

		task_info->last_event = now;
		event.header.et_type = et_irq_handler_exit;
		event.header.id = task_info->id;
		event.header.seq = task_info->seq;
		event.header.start_tv = task_info->start_tv;
		do_gettimeofday(&event.header.tv);
		task_info->seq++;
		event.irq = irq;
		diag_task_brief(current, &event.header.task);
		event.header.delta_ns = delta_ns;
		diag_variant_buffer_spin_lock(&task_info->buffer, flags);
		diag_variant_buffer_reserve(&task_info->buffer, sizeof(event));
		diag_variant_buffer_write_nolock(&task_info->buffer, &event, sizeof(event));
		diag_variant_buffer_seal(&task_info->buffer);
		diag_variant_buffer_spin_unlock(&task_info->buffer, flags);
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_softirq_entry_hit(struct softirq_action *h,
	struct softirq_action *softirq_vec)
#else
static void trace_softirq_entry_hit(void *ignore, unsigned long nr_sirq)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	unsigned long nr_sirq = h - softirq_vec;
#endif
	struct task_info *task_info;
	unsigned long flags;

	if (nr_sirq >= NR_SOFTIRQS)
		return;

	task_info = find_task_info(current);
	if (task_info && task_info->traced) {
		struct event_softirq_entry event;
		u64 now = sched_clock();
		u64 delta_ns = now - task_info->last_event;

		task_info->last_event = now;
		event.header.et_type = et_softirq_entry;
		event.header.id = task_info->id;
		event.header.seq = task_info->seq;
		event.header.start_tv = task_info->start_tv;
		do_gettimeofday(&event.header.tv);
		task_info->seq++;
		event.nr_sirq = nr_sirq;
		diag_task_brief(current, &event.header.task);
		event.header.delta_ns = delta_ns;
		diag_variant_buffer_spin_lock(&task_info->buffer, flags);
		diag_variant_buffer_reserve(&task_info->buffer, sizeof(event));
		diag_variant_buffer_write_nolock(&task_info->buffer, &event, sizeof(event));
		diag_variant_buffer_seal(&task_info->buffer);
		diag_variant_buffer_spin_unlock(&task_info->buffer, flags);
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_softirq_exit_hit(struct softirq_action *h,
	struct softirq_action *softirq_vec)
#else
static void trace_softirq_exit_hit(void *ignore, unsigned long nr_sirq)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	unsigned long nr_sirq = h - softirq_vec;
#endif
	struct task_info *task_info;
	unsigned long flags;

	if (nr_sirq >= NR_SOFTIRQS)
		return;

	task_info = find_task_info(current);
	if (task_info && task_info->traced) {
		struct event_softirq_exit event;
		u64 now = sched_clock();
		u64 delta_ns = now - task_info->last_event;

		task_info->last_event = now;
		event.header.et_type = et_softirq_exit;
		event.header.id = task_info->id;
		event.header.seq = task_info->seq;
		event.header.start_tv = task_info->start_tv;
		do_gettimeofday(&event.header.tv);
		task_info->seq++;
		event.nr_sirq = nr_sirq;
		diag_task_brief(current, &event.header.task);
		event.header.delta_ns = delta_ns;
		diag_variant_buffer_spin_lock(&task_info->buffer, flags);
		diag_variant_buffer_reserve(&task_info->buffer, sizeof(event));
		diag_variant_buffer_write_nolock(&task_info->buffer, &event, sizeof(event));
		diag_variant_buffer_seal(&task_info->buffer);
		diag_variant_buffer_spin_unlock(&task_info->buffer, flags);
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_timer_expire_entry_hit(struct timer_list *timer)
#else
static void trace_timer_expire_entry_hit(void *ignore, struct timer_list *timer)
#endif
{
	void *func = timer->function;
	struct task_info *task_info;
	unsigned long flags;

	task_info = find_task_info(current);
	if (task_info && task_info->traced) {
		struct event_timer_expire_entry event;
		u64 now = sched_clock();
		u64 delta_ns = now - task_info->last_event;

		task_info->last_event = now;
		event.header.et_type = et_timer_expire_entry;
		event.header.id = task_info->id;
		event.header.seq = task_info->seq;
		event.header.start_tv = task_info->start_tv;
		do_gettimeofday(&event.header.tv);
		task_info->seq++;
		event.func = func;
		diag_task_brief(current, &event.header.task);
		event.header.delta_ns = delta_ns;
		diag_variant_buffer_spin_lock(&task_info->buffer, flags);
		diag_variant_buffer_reserve(&task_info->buffer, sizeof(event));
		diag_variant_buffer_write_nolock(&task_info->buffer, &event, sizeof(event));
		diag_variant_buffer_seal(&task_info->buffer);
		diag_variant_buffer_spin_unlock(&task_info->buffer, flags);
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_timer_expire_exit_hit(struct timer_list *timer)
#else
static void trace_timer_expire_exit_hit(void *ignore, struct timer_list *timer)
#endif
{
	void *func = timer->function;
	struct task_info *task_info;
	unsigned long flags;

	task_info = find_task_info(current);
	if (task_info && task_info->traced) {
		struct event_timer_expire_exit event;
		u64 now = sched_clock();
		u64 delta_ns = now - task_info->last_event;

		task_info->last_event = now;
		event.header.et_type = et_timer_expire_exit;
		event.header.id = task_info->id;
		event.header.seq = task_info->seq;
		event.header.start_tv = task_info->start_tv;
		do_gettimeofday(&event.header.tv);
		task_info->seq++;
		event.func = func;
		diag_task_brief(current, &event.header.task);
		event.header.delta_ns = delta_ns;
		diag_variant_buffer_spin_lock(&task_info->buffer, flags);
		diag_variant_buffer_reserve(&task_info->buffer, sizeof(event));
		diag_variant_buffer_write_nolock(&task_info->buffer, &event, sizeof(event));
		diag_variant_buffer_seal(&task_info->buffer);
		diag_variant_buffer_spin_unlock(&task_info->buffer, flags);
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_sched_wakeup_hit(struct rq *rq, struct task_struct *p, int success)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)
static void trace_sched_wakeup_hit(void *ignore, struct task_struct *p, int success)
#else
static void trace_sched_wakeup_hit(void *ignore, struct task_struct *p)
#endif
{
	struct task_info *task_info;
	unsigned long flags;

	task_info = find_task_info(p);
	if (task_info && task_info->traced) {
		struct event_sched_wakeup event;
		u64 now = sched_clock();
		u64 delta_ns = now - task_info->last_event;

		task_info->last_event = now;
		event.header.et_type = et_sched_wakeup;
		event.header.id = task_info->id;
		event.header.seq = task_info->seq;
		event.header.start_tv = task_info->start_tv;
		do_gettimeofday(&event.header.tv);
		task_info->seq++;
		diag_task_brief(p, &event.header.task);
		event.header.delta_ns = delta_ns;
		diag_task_kern_stack(p, &event.kern_stack);
		diag_variant_buffer_spin_lock(&task_info->buffer, flags);
		diag_variant_buffer_reserve(&task_info->buffer, sizeof(event));
		diag_variant_buffer_write_nolock(&task_info->buffer, &event, sizeof(event));
		diag_variant_buffer_seal(&task_info->buffer);
		diag_variant_buffer_spin_unlock(&task_info->buffer, flags);
	}
}


static enum hrtimer_restart hrtimer_handler(struct hrtimer *hrtimer)
{
	enum hrtimer_restart ret = HRTIMER_RESTART;
	u64 now, expected;
	struct diag_percpu_context *context = get_percpu_context();
	struct task_info *task_info;
	unsigned long flags;
	u64 delta_ns;

	task_info = find_task_info(current);
	if (!task_info || !task_info->traced) {
		now = sched_clock();
		expected = now + run_trace_settings.timer_us * 1000;
		context->run_trace.timer_expected_time = expected;
		hrtimer_forward_now(hrtimer, __us_to_ktime(run_trace_settings.timer_us));

		return ret;
	}

	now = sched_clock();
	delta_ns = now - task_info->last_event;
	if(run_trace_settings.raw_stack){
		struct event_run_trace_raw *event;
		event = &diag_percpu_context[smp_processor_id()]->event_run_trace_raw;	

		task_info->last_event = now;
		event->et_type = et_run_trace_raw;
		event->id = task_info->id;
		event->seq = task_info->seq;
		task_info->seq++;
		diag_task_brief(current, &event->task);
		event->delta_ns = delta_ns;
		diag_task_kern_stack(current, &event->kern_stack);
		diag_task_raw_stack(current, &event->raw_stack);
		diag_variant_buffer_spin_lock(&task_info->buffer, flags);
		diag_variant_buffer_reserve(&task_info->buffer, sizeof(struct event_run_trace_raw));
		diag_variant_buffer_write_nolock(&task_info->buffer, event, sizeof(struct event_run_trace_raw));
		diag_variant_buffer_seal(&task_info->buffer);
		diag_variant_buffer_spin_unlock(&task_info->buffer, flags);
	} else {
		struct event_run_trace_perf event;
		task_info->last_event = now;
		event.et_type = et_run_trace_perf;
		event.id = task_info->id;
		event.seq = task_info->seq;
		task_info->seq++;
		diag_task_brief(current, &event.task);
		event.delta_ns = delta_ns;
		diag_task_kern_stack(current, &event.kern_stack);
		diag_task_user_stack(current, &event.user_stack);
		diag_variant_buffer_spin_lock(&task_info->buffer, flags);
		diag_variant_buffer_reserve(&task_info->buffer, sizeof(event));
		diag_variant_buffer_write_nolock(&task_info->buffer, &event, sizeof(event));
		diag_variant_buffer_seal(&task_info->buffer);
		diag_variant_buffer_spin_unlock(&task_info->buffer, flags);
	}

	expected = now + run_trace_settings.timer_us * 1000;
	context->run_trace.timer_expected_time = expected;
	hrtimer_forward_now(hrtimer, __us_to_ktime(run_trace_settings.timer_us));

	return ret;
}

static void start_timer(void *info)
{
	int cpu = smp_processor_id();
	struct diag_percpu_context *context = get_percpu_context_cpu(cpu);
	struct hrtimer *timer;

	if (run_trace_settings.timer_us < 10)
		return;
	if (context->run_trace.timer_started)
		return;

	/* start per-cpu hrtimer */
	timer = &context->run_trace.timer;
	hrtimer_init(timer, CLOCK_MONOTONIC, HRTIMER_MODE_PINNED);
	timer->function = hrtimer_handler;
	context->run_trace.timer_started = 1;
	context->run_trace.timer_expected_time =
		sched_clock() + run_trace_settings.timer_us * 1000;
	hrtimer_start_range_ns(timer,
			__us_to_ktime(run_trace_settings.timer_us),
			0,
			HRTIMER_MODE_REL_PINNED /*HRTIMER_MODE_PINNED*/);
}

static int start_timer_cpu(void *info)
{
	start_timer(info);

	return 0;
}

static int __activate_run_trace(void)
{
	int ret = 0;
	int cpu;
	struct diag_percpu_context *percpu_context;
	struct hrtimer *timer;

	ret = alloc_diag_variant_buffer(&run_trace_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	run_trace_alloced = 1;
	msleep(10);
	hook_tracepoint("sched_switch", trace_sched_switch_hit, NULL);
	hook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);
	hook_tracepoint("sys_enter", trace_sys_enter_hit, NULL);
	hook_tracepoint("sys_exit", trace_sys_exit_hit, NULL);
	hook_tracepoint("sched_wakeup", trace_sched_wakeup_hit, NULL);

	hook_tracepoint("irq_handler_entry", trace_irq_handler_entry_hit, NULL);
	hook_tracepoint("irq_handler_exit", trace_irq_handler_exit_hit, NULL);
	hook_tracepoint("softirq_entry", trace_softirq_entry_hit, NULL);
	hook_tracepoint("softirq_exit", trace_softirq_exit_hit, NULL);
	hook_tracepoint("timer_expire_entry", trace_timer_expire_entry_hit, NULL);
	hook_tracepoint("timer_expire_exit", trace_timer_expire_exit_hit, NULL);

	if (run_trace_settings.timer_us) {
		for_each_online_cpu(cpu) {
			percpu_context = get_percpu_context_cpu(cpu);
			if (percpu_context->run_trace.timer_started == 0)
			{
				timer = &percpu_context->run_trace.timer;
				if (cpu == smp_processor_id()) {
					start_timer_cpu(NULL);
				} else {
					smp_call_function_single(cpu, start_timer, NULL, 1);
				}
			}
		}
	}

	return 1;
out_variant_buffer:
	return 0;
}

int activate_run_trace(void)
{
	if (!run_trace_settings.activated)
		run_trace_settings.activated = __activate_run_trace();

	return run_trace_settings.activated;
}

static int __deactivate_run_trace(void)
{
	int cpu;
	struct diag_percpu_context *percpu_context;
	struct hrtimer *timer;

	if (run_trace_settings.timer_us) {
		for_each_online_cpu(cpu) {
			percpu_context = get_percpu_context_cpu(cpu);
			if (percpu_context->run_trace.timer_started)
			{
				timer = &percpu_context->run_trace.timer;
				hrtimer_cancel(timer);
			}
		}
	}
	run_trace_settings.timer_us = 0;

	msleep(10);

	unhook_uprobe(&diag_uprobe_start);
	unhook_uprobe(&diag_uprobe_stop);
	unhook_tracepoint("sched_switch", trace_sched_switch_hit, NULL);
	unhook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);
	unhook_tracepoint("sys_enter", trace_sys_enter_hit, NULL);
	unhook_tracepoint("sys_exit", trace_sys_exit_hit, NULL);
	unhook_tracepoint("sched_wakeup", trace_sched_wakeup_hit, NULL);

	unhook_tracepoint("irq_handler_entry", trace_irq_handler_entry_hit, NULL);
	unhook_tracepoint("irq_handler_exit", trace_irq_handler_exit_hit, NULL);
	unhook_tracepoint("softirq_entry", trace_softirq_entry_hit, NULL);
	unhook_tracepoint("softirq_exit", trace_softirq_exit_hit, NULL);
	unhook_tracepoint("timer_expire_entry", trace_timer_expire_entry_hit, NULL);
	unhook_tracepoint("timer_expire_exit", trace_timer_expire_exit_hit, NULL);

	synchronize_sched();
	/**
	 * 在JUMP_REMOVE和atomic64_read之间存在微妙的竞态条件
	 * 因此这里的msleep并非多余的。
	 */
	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0)
		msleep(20);

	clean_data();

	return 0;
}

int deactivate_run_trace(void)
{
	if (run_trace_settings.activated)
		__deactivate_run_trace();
	run_trace_settings.activated = 0;

	return 0;
}

int run_trace_set_syscall(unsigned int pid, unsigned int syscall, unsigned int threshold)
{
	struct task_struct *tsk = NULL;
	struct monitor_info *monitor_info;
	int ret = -EINVAL;

	rcu_read_lock();
	if (pid == 0)
		tsk = current;
	else if (orig_find_task_by_vpid)
		tsk = orig_find_task_by_vpid(pid);
	if (tsk) {
		monitor_info = find_alloc_monitor_info(tsk);
		if (monitor_info && syscall < NR_syscalls_virt) {
			monitor_info->syscall_threshold_ms[syscall] = threshold;
			ret = 0;
		}
	}
	rcu_read_unlock();

	return ret;
}

int run_trace_clear_syscall(unsigned int pid)
{
	struct task_struct *tsk = NULL;
	struct monitor_info *monitor_info;
	int ret = -EINVAL;

	rcu_read_lock();
	if (pid == 0)
		tsk = current;
	else if (orig_find_task_by_vpid)
		tsk = orig_find_task_by_vpid(pid);
	if (tsk) {
		monitor_info = takeout_monitor_info(tsk);
		if (monitor_info) {
			kfree(monitor_info);
			ret = 0;
		}
	}
	rcu_read_unlock();

	return ret;
}

__maybe_unused static int uprobe_start_handler(struct uprobe_consumer *self, struct pt_regs *regs)
{
	if (current->tgid != run_trace_uprobe_tgid)
		return 0;

	start_run_trace(current, 0, 0);
	return 0;
}

__maybe_unused static int uprobe_stop_handler(struct uprobe_consumer *self, struct pt_regs *regs)
{
	if (current->tgid != run_trace_uprobe_tgid)
		return 0;

	stop_run_trace(current, 0);
	return 0;
}

static int do_uprobe(unsigned long tgid, unsigned long fd_start, unsigned long offset_start,
	unsigned long fd_stop, unsigned long offset_stop)
{
	int ret = 0;

	run_trace_uprobe_tgid = tgid;
	unhook_uprobe(&diag_uprobe_start);
	unhook_uprobe(&diag_uprobe_stop);
	hook_uprobe(fd_start, offset_start, &diag_uprobe_start);
	hook_uprobe(fd_stop, offset_stop, &diag_uprobe_stop);

	return ret;
}

int run_trace_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_run_trace_settings settings;
	unsigned long offset_start;
	unsigned long offset_stop;
	unsigned long tgid;
	unsigned long fd_start, fd_stop;
	unsigned int threshold;
	int pid;
	unsigned int syscall;

	switch (id) {
	case DIAG_RUN_TRACE_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_run_trace_settings)) {
			ret = -EINVAL;
		} else if (run_trace_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if ((settings.timer_us && settings.timer_us < 10)
				  || (settings.buf_size_k && (settings.buf_size_k < 200 || settings.buf_size_k > 10 * 1024))) {
				ret = -EINVAL;
			}
			if (!ret) {
				run_trace_settings = settings;
			}
		}
		break;
	case DIAG_RUN_TRACE_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_run_trace_settings)) {
			ret = -EINVAL;
		} else {
			settings = run_trace_settings;
			settings.threads_count = atomic64_read(&settings_threads_count);
			settings.syscall_count = atomic64_read(&settings_syscall_count);
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_RUN_TRACE_START:
		threshold = (unsigned int)SYSCALL_PARAM1(regs);
		down_read(&run_trace_sem);
		ret = start_run_trace(current, threshold, 0);
		up_read(&run_trace_sem);
		break;
	case DIAG_RUN_TRACE_STOP:
		stop_run_trace(current, 0);
		ret = 0;
		break;
	case DIAG_RUN_TRACE_MONITOR_SYSCALL:
		pid = (unsigned int)SYSCALL_PARAM1(regs);
		syscall = (unsigned int)SYSCALL_PARAM2(regs);
		threshold = (unsigned int)SYSCALL_PARAM3(regs);
		ret = run_trace_set_syscall(pid, syscall, threshold);
		break;
	case DIAG_RUN_TRACE_CLEAR_SYSCALL:
		pid = (unsigned int)SYSCALL_PARAM1(regs);
		ret = run_trace_clear_syscall(pid);
		break;
	case DIAG_RUN_TRACE_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);
		if (!run_trace_alloced) {
			ret = -EINVAL;
		} else {
			ret = copy_to_user_variant_buffer(&run_trace_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("run-trace");
		}
		
		break;
	case DIAG_RUN_TRACE_UPROBE:
		tgid = SYSCALL_PARAM1(regs);
		fd_start = SYSCALL_PARAM2(regs);
		offset_start = SYSCALL_PARAM3(regs);
		fd_stop = SYSCALL_PARAM4(regs);
		offset_stop = SYSCALL_PARAM5(regs);

		ret = do_uprobe(tgid, fd_start, offset_start, fd_stop, offset_stop);
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_run_trace(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	int pid;
	unsigned int threshold;
	struct diag_run_trace_settings settings;
	struct diag_ioctl_dump_param dump_param;
	struct diag_run_trace_monitor_syscall monitor_syscall;
	struct diag_run_trace_uprobe uprobe;

	switch (cmd) {
	case CMD_RUN_TRACE_SET:
		if (run_trace_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_run_trace_settings));
			if ((settings.timer_us && settings.timer_us < 10)
				  || (settings.buf_size_k && (settings.buf_size_k < 200 || settings.buf_size_k > 10 * 1024))) {
				ret = -EINVAL;
			}
			if (!ret) {
				run_trace_settings = settings;
			}
		}
		break;
	case CMD_RUN_TRACE_SETTINGS:
		settings = run_trace_settings;
		settings.threads_count = atomic64_read(&settings_threads_count);
		settings.syscall_count = atomic64_read(&settings_syscall_count);
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_run_trace_settings));
		break;
	case CMD_RUN_TRACE_START:
		ret = copy_from_user(&threshold, (void *)arg, sizeof(int));
		if (!ret) {
			down_read(&run_trace_sem);
			ret = start_run_trace(current, threshold, 0);
			up_read(&run_trace_sem);
		}
		break;
	case CMD_RUN_TRACE_STOP:
		stop_run_trace(current, 0);
		ret = 0;
		break;
	case CMD_RUN_TRACE_MONITOR_SYSCALL:
		ret = copy_from_user(&monitor_syscall, (void *)arg,
			sizeof(struct diag_run_trace_monitor_syscall));
		if (!ret) {
			ret = run_trace_set_syscall(monitor_syscall.pid,
				monitor_syscall.syscall, monitor_syscall.threshold);
		}
		break;
	case CMD_RUN_TRACE_CLEAR_SYSCALL:
		ret = copy_from_user(&pid, (void *)arg, sizeof(int));
		if (!ret) {
			ret = run_trace_clear_syscall(pid);
		}
		break;
	case CMD_RUN_TRACE_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));
		if (!run_trace_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			ret = copy_to_user_variant_buffer(&run_trace_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("run-trace");
		}

		break;
	case CMD_RUN_TRACE_UPROBE:
		ret = copy_from_user(&uprobe, (void *)arg, sizeof(struct diag_run_trace_uprobe));
		if (!ret) {
			ret = do_uprobe(uprobe.tgid, uprobe.fd_start,
				uprobe.offset_start, uprobe.fd_stop, uprobe.offset_stop);
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

ssize_t run_trace_settings_file_write(struct diag_trace_file *trace_file,
		struct file *file, const char __user *buf, size_t count,
		loff_t *offs)
{
	int ret;
	char cmd[255];
	char chr[256];
	int len;

	if (count < 1 || count >= 255 || *offs)
		return -EINVAL;

	len = min_t(unsigned long, count, 255);
	if (copy_from_user(chr, buf, len))
		return -EFAULT;
	chr[255] = 0;

	ret = sscanf(chr, "%255s", cmd);
	if (ret <= 0)
		return count;

	if (strcmp(cmd, "start") == 0) {
		unsigned int id;
		struct task_struct *tsk = NULL;

		ret = sscanf(chr, "%s %d", cmd, &id);
		if (ret == 2) {
			unsigned int threshold_ms = 0;

			ret = sscanf(chr, "%s %d %d", cmd, &id, &threshold_ms);
			rcu_read_lock();
			if (ret == 3) {
				if (orig_find_task_by_vpid)
					tsk = orig_find_task_by_vpid(id);
				if (tsk) { 
					start_run_trace(tsk, threshold_ms, 0);
				}
			} else {
				start_run_trace(current, id, 0);
			}
			rcu_read_unlock();
		} else {
			start_run_trace(current, 0, 0);
		}
	} else if (strcmp(cmd, "stop") == 0) {
		unsigned int id;
		struct task_struct *tsk = NULL;

		ret = sscanf(chr, "%s %d", cmd, &id);
		if (ret == 2) {
			rcu_read_lock();
			if (orig_find_task_by_vpid)
				tsk = orig_find_task_by_vpid(id);
			if (tsk) {
				stop_run_trace(tsk, 0);
			}
			rcu_read_unlock();
		} else {
			stop_run_trace(current, 0);
		}
	} else if (strcmp(cmd, "threshold") == 0) {
		int threshold;

		ret = sscanf(chr, "%255s %d", cmd, &threshold);
		if (ret != 2)
			return -EINVAL;
		run_trace_settings.threshold_us = threshold * 1000;
	} else if (strcmp(cmd, "set-syscall") == 0) {
		unsigned int pid, syscall, threshold;

		ret = sscanf(chr, "%255s %d %d %d", cmd, &pid, &syscall, &threshold);
		if (ret != 4)
			return -EINVAL;

		run_trace_set_syscall(pid, syscall, threshold);
	} else if (strcmp(cmd, "clear-syscall") == 0) {
		unsigned int pid;

		ret = sscanf(chr, "%255s %d", cmd, &pid);
		if (ret != 2)
			return -EINVAL;

		run_trace_clear_syscall(pid);
	}

	return count;
}

static ssize_t run_trace_settings_file_read(struct diag_trace_file *trace_file,
		struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	return 0;
}

static int lookup_syms(void)
{
	return 0;
}

static void jump_init(void)
{
}

int diag_run_trace_init(void)
{
	int ret = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	diag_uprobe_start.uprobe_consumer.handler = uprobe_start_handler;
	diag_uprobe_stop.uprobe_consumer.handler = uprobe_stop_handler;
#endif

	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&run_trace_variant_buffer, 5 * 1024 * 1024);
	INIT_RADIX_TREE(&run_trace_tree, GFP_ATOMIC);
	jump_init();

	ret = init_diag_trace_file(&run_trace_settings_file,
		"ali-linux/diagnose/kern/run-trace-settings",
		20 * 1024,
		run_trace_settings_file_read,
		run_trace_settings_file_write);
	if (ret)
		goto out_settings_file;

	if (run_trace_settings.activated)
		run_trace_settings.activated = __activate_run_trace();

	return 0;

out_settings_file:
	return ret;
}

void diag_run_trace_exit(void)
{
	unhook_uprobe(&diag_uprobe_start);
	unhook_uprobe(&diag_uprobe_stop);

	destroy_diag_trace_file(&run_trace_settings_file);

	if (run_trace_settings.activated)
		deactivate_run_trace();
	run_trace_settings.activated = 0;
	destroy_diag_variant_buffer(&run_trace_variant_buffer);
}

