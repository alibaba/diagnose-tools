/*
 * Linux内核诊断工具--内核态irq-stats功能
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

#include "internal.h"
#include "pub/trace_file.h"
#include "pub/variant_buffer.h"
#include "pub/trace_point.h"

#include "uapi/irq_stats.h"

struct diag_irq_stats_settings irq_stats_settings;

static int irq_stats_alloced = 0;

static struct diag_variant_buffer irq_stats_variant_buffer;

static DEFINE_MUTEX(irq_stats_mutex);

static void clean_data(void)
{
	struct irq_func_runtime *func_runtimes[NR_BATCH];
	struct irq_func_runtime *func_runtime;
	int nr_found;
	struct diag_percpu_context *context;
	int cpu;
	unsigned long pos = 0;
	int i;

	for_each_possible_cpu(cpu) {
		context = get_percpu_context_cpu(cpu);

		rcu_read_lock();

		do {
			nr_found = radix_tree_gang_lookup(&context->irq_stats.irq_tree,
					(void **)func_runtimes, pos, NR_BATCH);
			for (i = 0; i < nr_found; i++) {
				func_runtime = func_runtimes[i];
				radix_tree_delete(&context->irq_stats.irq_tree,
							(unsigned long)func_runtime->handler);
				pos = (unsigned long)func_runtime->handler + 1;
				kfree(func_runtime);
			}
		} while (nr_found > 0);

		rcu_read_unlock();

		memset(&context->irq_stats, 0, sizeof(context->irq_stats));
		INIT_RADIX_TREE(&context->irq_stats.irq_tree, GFP_ATOMIC);
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_irq_handler_entry_hit(int irq,
		struct irqaction *action)
#else
static void trace_irq_handler_entry_hit(void *ignore, int irq,
                struct irqaction *action)
#endif
{
	struct irq_runtime *runtime = &get_percpu_context()->irq_stats.irq_runtime;
	u64 now;

	if (hardirq_count() > (1 << HARDIRQ_SHIFT))
		return;

	now = ktime_to_ns(ktime_get());
	runtime->irq = irq;
	runtime->time = now;

	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_irq_handler_exit_hit(int irq,
		struct irqaction *action, int ret)
#else
static void trace_irq_handler_exit_hit(void *ignore, int irq,
                struct irqaction *action, int ret)
#endif
{
	struct irq_runtime *entry_runtime;
	struct irq_result *result;
	struct rtc_time tm_val;
	struct timespec ts;
	unsigned long local_time;
	struct diag_percpu_context *context;

	u64 now = ktime_to_ns(ktime_get());
	u64 delta_ns;

	if (hardirq_count() > (1 << HARDIRQ_SHIFT))
		return;

	context = get_percpu_context();
	entry_runtime = &context->irq_stats.irq_runtime;
	result = &context->irq_stats.irq_result;

	if (ret && (entry_runtime->time > 0))
	{
		struct irq_func_runtime *func_runtime;

		delta_ns = now - entry_runtime->time;

		result->irq_cnt++;
		result->irq_run_total += delta_ns;

		if (delta_ns > result->max_irq.time)
		{
			getnstimeofday(&ts);
			local_time = ts.tv_sec - (sys_tz.tz_minuteswest * 60);
			rtc_time_to_tm(local_time, &tm_val);

			sprintf(result->max_irq.timestamp,
					"%d-%d-%d %02d:%02d:%02d",
					1900 + tm_val.tm_year, 1 + tm_val.tm_mon,
					tm_val.tm_mday, tm_val.tm_hour,
					tm_val.tm_min, tm_val.tm_sec);

			result->max_irq.time = delta_ns;
			result->max_irq.irq = irq;
		}

		if (irq_stats_settings.verbose >= 1) {
			func_runtime = radix_tree_lookup(&context->irq_stats.irq_tree,
									(unsigned long)action->handler);
			if (!func_runtime) {
				func_runtime = kmalloc(sizeof(struct irq_func_runtime), GFP_ATOMIC | __GFP_ZERO);
				if (func_runtime) {
					func_runtime->irq = irq;
					func_runtime->handler = action->handler;
					radix_tree_insert(&context->irq_stats.irq_tree,
									(unsigned long)action->handler, func_runtime);
				}
			}
			if (func_runtime) {
				func_runtime->irq_cnt++;
				func_runtime->irq_run_total += delta_ns;
			}
		}
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
	u64 period;
	struct softirq_runtime *runtime;

	if (nr_sirq >= NR_SOFTIRQS)
		return;

	period = ktime_to_ns(ktime_get());

	runtime = &get_percpu_context()->irq_stats.softirq_runtime;
	runtime->time[nr_sirq] = period;

	return;
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
	u64 period;
	u64 delta_ns;
	struct softirq_runtime *entry_runtime;
	struct irq_result *result;

	if (nr_sirq >= NR_SOFTIRQS)
		return;

	period = ktime_to_ns(ktime_get());

	entry_runtime = &get_percpu_context()->irq_stats.softirq_runtime;
	result = &get_percpu_context()->irq_stats.irq_result;

	if (entry_runtime->time[nr_sirq] > 0)
	{
		delta_ns = period - entry_runtime->time[nr_sirq];

		result->softirq_cnt[nr_sirq]++;
		result->sortirq_run_total[nr_sirq] += delta_ns;
		if (strncmp(current->comm, "ksoftirq", 8) == 0) {
			result->softirq_cnt_d[nr_sirq]++;
			result->sortirq_run_total_d[nr_sirq] += delta_ns;
		}

		if (delta_ns > result->max_softirq.time[nr_sirq])
			result->max_softirq.time[nr_sirq] = delta_ns;
	}

	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_timer_expire_entry_hit(struct timer_list *timer)
#else
static void trace_timer_expire_entry_hit(void *ignore, struct timer_list *timer)
#endif
{
	u64 period;
	struct timer_runtime *runtime;

	period = ktime_to_ns(ktime_get());

	runtime = &get_percpu_context()->irq_stats.timer_runtime;
	runtime->start_time = period;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_timer_expire_exit_hit(struct timer_list *timer)
#else
static void trace_timer_expire_exit_hit(void *ignore, struct timer_list *timer)
#endif
{
	void *func = timer->function;
	u64 period;
	u64 delta_ns;
	struct timer_runtime *entry_runtime;
	struct irq_result *result;

	period = ktime_to_ns(ktime_get());

	entry_runtime = &get_percpu_context()->irq_stats.timer_runtime;
	result = &get_percpu_context()->irq_stats.irq_result;

	if (entry_runtime->start_time > 0)
	{
		delta_ns = period - entry_runtime->start_time;

		result->timer.timer_cnt++;
		result->timer.timer_run_total += delta_ns;

		if (delta_ns > result->max_timer.time) {
			result->max_timer.time = delta_ns;
			result->max_timer.func = func;
		}
	}
}

static int __activate_irq_stats(void)
{
	struct irq_result *result;
	int cpu;
	int ret = 0;

	ret = alloc_diag_variant_buffer(&irq_stats_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	irq_stats_alloced = 1;

	for_each_possible_cpu(cpu)
	{
		result = &get_percpu_context_cpu(cpu)->irq_stats.irq_result;
		memset(result, 0, sizeof(struct irq_result));
		INIT_RADIX_TREE(&get_percpu_context_cpu(cpu)->irq_stats.irq_tree, GFP_ATOMIC);
	}

	hook_tracepoint("irq_handler_entry", trace_irq_handler_entry_hit, NULL);
	hook_tracepoint("irq_handler_exit", trace_irq_handler_exit_hit, NULL);
	hook_tracepoint("softirq_entry", trace_softirq_entry_hit, NULL);
	hook_tracepoint("softirq_exit", trace_softirq_exit_hit, NULL);
	hook_tracepoint("timer_expire_entry", trace_timer_expire_entry_hit, NULL);
	hook_tracepoint("timer_expire_exit", trace_timer_expire_exit_hit, NULL);

	return 1;
out_variant_buffer:
	return 0;
}

int activate_irq_stats(void)
{
	if (!irq_stats_settings.activated)
		irq_stats_settings.activated = __activate_irq_stats();

	return irq_stats_settings.activated;
}

static void __deactivate_irq_stats(void)
{
	unhook_tracepoint("irq_handler_entry", trace_irq_handler_entry_hit, NULL);
	unhook_tracepoint("irq_handler_exit", trace_irq_handler_exit_hit, NULL);
	unhook_tracepoint("softirq_entry", trace_softirq_entry_hit, NULL);
	unhook_tracepoint("softirq_exit", trace_softirq_exit_hit, NULL);
	unhook_tracepoint("timer_expire_entry", trace_timer_expire_entry_hit, NULL);
	unhook_tracepoint("timer_expire_exit", trace_timer_expire_exit_hit, NULL);

	synchronize_sched();
	msleep(10);

	clean_data();
}

int deactivate_irq_stats(void)
{
	if (irq_stats_settings.activated)
		__deactivate_irq_stats();
	irq_stats_settings.activated = 0;

	return 0;
}

static void reset_data(void)
{
	int cpu;
	struct irq_result *result;

	for_each_possible_cpu(cpu) {
		result = &get_percpu_context_cpu(cpu)->irq_stats.irq_result;
		memset(result, 0, sizeof(struct irq_result));
	}
}

static void dump_data(void)
{
	int cpu;
	int softirq;
	struct irq_result *result;
	struct diag_percpu_context *context;
	struct irq_stats_header header;
	struct irq_stats_irq_summary irq_summary;
	struct irq_stats_irq_detail irq_detail;
	struct irq_stats_softirq_summary softirq_summary;
	struct irq_stats_timer_summary timer_summary;
	unsigned long flags;
	unsigned long event_id;

	event_id = get_cycles();
	header.et_type = et_irq_stats_header;
	header.id = event_id;
	do_gettimeofday(&header.tv);
	diag_variant_buffer_spin_lock(&irq_stats_variant_buffer, flags);
	diag_variant_buffer_reserve(&irq_stats_variant_buffer, sizeof(struct irq_stats_header));
	diag_variant_buffer_write_nolock(&irq_stats_variant_buffer, &header, sizeof(struct irq_stats_header));
	diag_variant_buffer_seal(&irq_stats_variant_buffer);
	diag_variant_buffer_spin_unlock(&irq_stats_variant_buffer, flags);

	for_each_online_cpu(cpu)
	{
		context = get_percpu_context_cpu(cpu);
		result = &context->irq_stats.irq_result;

		irq_summary.et_type = et_irq_stats_irq_summary;
		irq_summary.id = event_id;
		irq_summary.cpu = cpu;
		irq_summary.irq_cnt = result->irq_cnt;
		irq_summary.irq_run_total = result->irq_run_total;
		irq_summary.max_irq = result->max_irq.irq;
		irq_summary.max_irq_time = result->max_irq.time;

		diag_variant_buffer_spin_lock(&irq_stats_variant_buffer, flags);
		diag_variant_buffer_reserve(&irq_stats_variant_buffer, sizeof(struct irq_stats_irq_summary));
		diag_variant_buffer_write_nolock(&irq_stats_variant_buffer, &irq_summary, sizeof(struct irq_stats_irq_summary));
		diag_variant_buffer_seal(&irq_stats_variant_buffer);
		diag_variant_buffer_spin_unlock(&irq_stats_variant_buffer, flags);
	}

	if (irq_stats_settings.verbose >= 1) {
		for_each_possible_cpu(cpu) {
			struct irq_func_runtime *func_runtime;
			struct irq_func_runtime *func_runtimes[NR_BATCH];
			int nr_found;
			unsigned long pos = 0;
			int i;

			context = get_percpu_context_cpu(cpu);
			result = &context->irq_stats.irq_result;

			rcu_read_lock();
			do {
				nr_found = radix_tree_gang_lookup(&context->irq_stats.irq_tree,
					(void **)func_runtimes, pos, NR_BATCH);
				rcu_read_unlock();
				for (i = 0; i < nr_found; i++) {
					func_runtime = func_runtimes[i];
					pos = (unsigned long)func_runtime->handler + 1;
					if (func_runtime->irq_cnt) {
						irq_detail.et_type = et_irq_stats_irq_detail;
						irq_detail.id = event_id;
						irq_detail.cpu = cpu;
						irq_detail.irq = func_runtime->irq;
						irq_detail.handler = func_runtime->handler;
						irq_detail.irq_cnt = func_runtime->irq_cnt;
						irq_detail.irq_run_total = func_runtime->irq_run_total;
						diag_variant_buffer_spin_lock(&irq_stats_variant_buffer, flags);
						diag_variant_buffer_reserve(&irq_stats_variant_buffer, sizeof(struct irq_stats_irq_detail));
						diag_variant_buffer_write_nolock(&irq_stats_variant_buffer, &irq_detail, sizeof(struct irq_stats_irq_detail));
						diag_variant_buffer_seal(&irq_stats_variant_buffer);
						diag_variant_buffer_spin_unlock(&irq_stats_variant_buffer, flags);
					}
				}
				rcu_read_lock();
			} while (nr_found == NR_BATCH);
			rcu_read_unlock();
		}
	}

	for_each_online_cpu(cpu)
	{
		context = get_percpu_context_cpu(cpu);
		result = &context->irq_stats.irq_result;

		softirq_summary.et_type = et_irq_stats_softirq_summary;
		softirq_summary.id = event_id;
		softirq_summary.cpu = cpu;
		for (softirq = HI_SOFTIRQ; softirq < DIAG_NR_SOFTIRQS; softirq++)
		{
			softirq_summary.softirq_cnt[softirq] = result->softirq_cnt[softirq];
			softirq_summary.softirq_cnt_d[softirq] = result->softirq_cnt_d[softirq];
			softirq_summary.sortirq_run_total[softirq] = result->sortirq_run_total[softirq];
			softirq_summary.sortirq_run_total_d[softirq] = result->sortirq_run_total_d[softirq];
		}
		diag_variant_buffer_spin_lock(&irq_stats_variant_buffer, flags);
		diag_variant_buffer_reserve(&irq_stats_variant_buffer, sizeof(struct irq_stats_softirq_summary));
		diag_variant_buffer_write_nolock(&irq_stats_variant_buffer, &softirq_summary, sizeof(struct irq_stats_softirq_summary));
		diag_variant_buffer_seal(&irq_stats_variant_buffer);
		diag_variant_buffer_spin_unlock(&irq_stats_variant_buffer, flags);
	}

	for_each_online_cpu(cpu)
	{
		context = get_percpu_context_cpu(cpu);
		result = &context->irq_stats.irq_result;

		timer_summary.et_type = et_irq_stats_timer_summary;
		timer_summary.id = event_id;
		timer_summary.cpu = cpu;
		timer_summary.timer_cnt = result->timer.timer_cnt;
		timer_summary.timer_run_total = result->timer.timer_run_total;
		timer_summary.max_func = result->max_timer.func;
		timer_summary.max_time = result->max_timer.time;

		diag_variant_buffer_spin_lock(&irq_stats_variant_buffer, flags);
		diag_variant_buffer_reserve(&irq_stats_variant_buffer, sizeof(struct irq_stats_timer_summary));
		diag_variant_buffer_write_nolock(&irq_stats_variant_buffer, &timer_summary, sizeof(struct irq_stats_timer_summary));
		diag_variant_buffer_seal(&irq_stats_variant_buffer);
		diag_variant_buffer_spin_unlock(&irq_stats_variant_buffer, flags);
	}

	reset_data();
}

int irq_stats_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_irq_stats_settings settings;

	mutex_lock(&irq_stats_mutex);

	switch (id) {
	case DIAG_IRQ_STATS_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_irq_stats_settings)) {
			ret = -EINVAL;
		} else if (irq_stats_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				irq_stats_settings = settings;
			}
		}
		break;
	case DIAG_IRQ_STATS_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_irq_stats_settings)) {
			ret = -EINVAL;
		} else {
			settings = irq_stats_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_IRQ_STATS_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!irq_stats_alloced) {
			ret = -EINVAL;
		} else {
			dump_data();
			ret = copy_to_user_variant_buffer(&irq_stats_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("irq-stats");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	mutex_unlock(&irq_stats_mutex);
	return ret;
}

long diag_ioctl_irq_stats(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_irq_stats_settings settings;
	struct diag_ioctl_dump_param dump_param;

	mutex_lock(&irq_stats_mutex);

	switch (cmd) {
	case CMD_IRQ_STATS_SET:
		if (irq_stats_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_irq_stats_settings));
			if (!ret) {
				irq_stats_settings = settings;
			}
		}
		break;
	case CMD_IRQ_STATS_SETTINGS:
		settings = irq_stats_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_irq_stats_settings));
		break;
	case CMD_IRQ_STATS_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));
		if (!irq_stats_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			dump_data();
			ret = copy_to_user_variant_buffer(&irq_stats_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("irq-stats");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	mutex_unlock(&irq_stats_mutex);
	return ret;
}

static int lookup_syms(void)
{
	return 0;
}

int diag_irq_stats_init(void)
{
	int cpu;

	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&irq_stats_variant_buffer, 1 * 1024 * 1024);
	//clean_data();
	for_each_possible_cpu(cpu)
	{
		INIT_RADIX_TREE(&get_percpu_context_cpu(cpu)->irq_stats.irq_tree, GFP_ATOMIC);
	}

	if (irq_stats_settings.activated)
		irq_stats_settings.activated = __activate_irq_stats();

	return 0;
}

void diag_irq_stats_exit(void)
{
	if (irq_stats_settings.activated)
		deactivate_irq_stats();
	irq_stats_settings.activated = 0;
	destroy_diag_variant_buffer(&irq_stats_variant_buffer);
}
