/*
 * Linux内核诊断工具--内核态irq-trace功能
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
#include "pub/trace_point.h"

#include "uapi/irq_trace.h"

struct diag_irq_trace_settings irq_trace_settings = {
	.threshold_irq = 5,
	.threshold_sirq = 10,
	.threshold_timer = 10,
};

static int irq_trace_alloced = 0;
static struct softirq_action *orig_softirq_vec;

static struct diag_variant_buffer irq_trace_variant_buffer;

static void clean_data(void)
{
	//
}

static void record_dither(int source, void *func, unsigned long time)
{
	struct irq_trace_detail irq_trace_detail;
	unsigned long flags;

	irq_trace_detail.et_type = et_irq_trace_detail;
	do_gettimeofday(&irq_trace_detail.tv);
	irq_trace_detail.cpu = smp_processor_id();
	irq_trace_detail.source = source;
	irq_trace_detail.func = func;
	irq_trace_detail.time = time;
	diag_variant_buffer_spin_lock(&irq_trace_variant_buffer, flags);
	diag_variant_buffer_reserve(&irq_trace_variant_buffer, sizeof(struct irq_trace_detail));
	diag_variant_buffer_write_nolock(&irq_trace_variant_buffer, &irq_trace_detail, sizeof(struct irq_trace_detail));
	diag_variant_buffer_seal(&irq_trace_variant_buffer);
	diag_variant_buffer_spin_unlock(&irq_trace_variant_buffer, flags);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_irq_handler_entry_hit(int irq,
		struct irqaction *action)
#else
static void trace_irq_handler_entry_hit(void *ignore, int irq,
                struct irqaction *action)
#endif
{
	struct diag_irq_trace *irq_trace;
	struct diag_percpu_context *context;
	u64 now;

	if (hardirq_count() > (1 << HARDIRQ_SHIFT))
		return;

	context = get_percpu_context();
	irq_trace = &context->irq_trace;
	now = ktime_to_ns(ktime_get());
	irq_trace->irq.irq = irq;
	irq_trace->irq.start_time = now;

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
	struct diag_irq_trace *irq_trace;
	struct diag_percpu_context *context;
	u64 now = ktime_to_ns(ktime_get());
	u64 start_time;
	u64 delta_ns;

	if (hardirq_count() > (1 << HARDIRQ_SHIFT))
		return;

	context = get_percpu_context();
	irq_trace = &context->irq_trace;
	start_time = irq_trace->irq.start_time;
	if (ret && (start_time > 0)) {
		delta_ns = now - start_time;

		irq_trace->sum.irq_count++;
		irq_trace->sum.irq_runs += delta_ns;
		if (irq_trace_settings.threshold_irq && (delta_ns >> 20) >= irq_trace_settings.threshold_irq) {
			record_dither(0, action->handler, delta_ns);
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
#else
	struct softirq_action *h;
#endif
	struct diag_irq_trace *irq_trace;
	struct diag_percpu_context *context;
	u64 now = ktime_to_ns(ktime_get());
	void *func;

	if (nr_sirq >= NR_SOFTIRQS)
		return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	h = orig_softirq_vec + nr_sirq;
#endif
	func = h->action;
	context = get_percpu_context();
	irq_trace = &context->irq_trace;

	irq_trace->softirq.sirq = nr_sirq;
	irq_trace->softirq.start_time = now;
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
#else
	struct softirq_action *h;
#endif
	void *func;
	struct diag_irq_trace *irq_trace;
	struct diag_percpu_context *context;
	u64 now = ktime_to_ns(ktime_get());
	u64 start_time;
	u64 delta_ns;

	if (nr_sirq >= NR_SOFTIRQS)
		return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	h = orig_softirq_vec + nr_sirq;
#endif
	func = h->action;

	context = get_percpu_context();
	irq_trace = &context->irq_trace;
	start_time = irq_trace->softirq.start_time;
	if (start_time > 0) {
		delta_ns = now - start_time;

		irq_trace->sum.sirq_count[nr_sirq]++;
		irq_trace->sum.sirq_runs[nr_sirq] += delta_ns;
		if (irq_trace_settings.threshold_sirq && (delta_ns >> 20) >= irq_trace_settings.threshold_sirq) {
			record_dither(1, func, delta_ns);
		}
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_timer_expire_entry_hit(struct timer_list *timer)
#else
static void trace_timer_expire_entry_hit(void *ignore, struct timer_list *timer)
#endif
{
	struct diag_irq_trace *irq_trace;
	struct diag_percpu_context *context;
	u64 now = ktime_to_ns(ktime_get());

	context = get_percpu_context();
	irq_trace = &context->irq_trace;

	irq_trace->timer.start_time = now;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_timer_expire_exit_hit(struct timer_list *timer)
#else
static void trace_timer_expire_exit_hit(void *ignore, struct timer_list *timer)
#endif
{
	void *func = timer->function;
	struct diag_irq_trace *irq_trace;
	struct diag_percpu_context *context;
	u64 now = ktime_to_ns(ktime_get());
	u64 start_time;
	u64 delta_ns;

	context = get_percpu_context();
	irq_trace = &context->irq_trace;
	start_time = irq_trace->timer.start_time;
	if (start_time > 0) {
		delta_ns = now - start_time;

		irq_trace->sum.timer_count++;
		irq_trace->sum.timer_runs += delta_ns;
		if (irq_trace_settings.threshold_timer && (delta_ns >> 20) >= irq_trace_settings.threshold_timer) {
			record_dither(2, func, delta_ns);
		}
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_hrtimer_expire_entry_hit(struct hrtimer *timer, ktime_t *_now)
#else
static void trace_hrtimer_expire_entry_hit(void *ignore, struct hrtimer *timer, ktime_t *_now)
#endif
{
	struct diag_irq_trace *irq_trace;
	struct diag_percpu_context *context;
	u64 now = ktime_to_ns(ktime_get());

	context = get_percpu_context();
	irq_trace = &context->irq_trace;

	irq_trace->timer.start_time = now;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_hrtimer_expire_exit_hit(struct hrtimer *timer)
#else
static void trace_hrtimer_expire_exit_hit(void *ignore, struct hrtimer *timer)
#endif
{
	void *func = timer->function;
	struct diag_irq_trace *irq_trace;
	struct diag_percpu_context *context;
	u64 now = ktime_to_ns(ktime_get());
	u64 start_time;
	u64 delta_ns;

	context = get_percpu_context();
	irq_trace = &context->irq_trace;
	start_time = irq_trace->timer.start_time;
	if (start_time > 0) {
		delta_ns = now - start_time;

		irq_trace->sum.timer_count++;
		irq_trace->sum.timer_runs += delta_ns;
		if (irq_trace_settings.threshold_timer && (delta_ns >> 20) >= irq_trace_settings.threshold_timer) {
			record_dither(2, func, delta_ns);
		}
	}
}

static int __activate_irq_trace(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&irq_trace_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	irq_trace_alloced = 1;

	clean_data();

	hook_tracepoint("irq_handler_entry", trace_irq_handler_entry_hit, NULL);
	hook_tracepoint("irq_handler_exit", trace_irq_handler_exit_hit, NULL);
	hook_tracepoint("softirq_entry", trace_softirq_entry_hit, NULL);
	hook_tracepoint("softirq_exit", trace_softirq_exit_hit, NULL);
	hook_tracepoint("timer_expire_entry", trace_timer_expire_entry_hit, NULL);
	hook_tracepoint("timer_expire_exit", trace_timer_expire_exit_hit, NULL);
	hook_tracepoint("hrtimer_expire_entry", trace_hrtimer_expire_entry_hit, NULL);
	hook_tracepoint("hrtimer_expire_exit", trace_hrtimer_expire_exit_hit, NULL);

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_irq_trace(void)
{
	unhook_tracepoint("irq_handler_entry", trace_irq_handler_entry_hit, NULL);
	unhook_tracepoint("irq_handler_exit", trace_irq_handler_exit_hit, NULL);
	unhook_tracepoint("softirq_entry", trace_softirq_entry_hit, NULL);
	unhook_tracepoint("softirq_exit", trace_softirq_exit_hit, NULL);
	unhook_tracepoint("timer_expire_entry", trace_timer_expire_entry_hit, NULL);
	unhook_tracepoint("timer_expire_exit", trace_timer_expire_exit_hit, NULL);
	unhook_tracepoint("hrtimer_expire_entry", trace_hrtimer_expire_entry_hit, NULL);
	unhook_tracepoint("hrtimer_expire_exit", trace_hrtimer_expire_exit_hit, NULL);

	clean_data();
	synchronize_sched();
}

int activate_irq_trace(void)
{
	if (!irq_trace_settings.activated)
		irq_trace_settings.activated = __activate_irq_trace();

	return irq_trace_settings.activated;
}

int deactivate_irq_trace(void)
{
	if (irq_trace_settings.activated)
		__deactivate_irq_trace();
	irq_trace_settings.activated = 0;

	return 0;
}

static void clear_sum(void *info)
{
	struct diag_percpu_context *context;

	context = get_percpu_context();
	memset(&context->irq_trace.sum, 0, sizeof(struct irq_trace_sum));
}

static void do_dump(void)
{
	struct irq_trace_sum sum;
	struct diag_percpu_context *context;
	int i, j;
	unsigned long flags;

	memset(&sum, 0, sizeof(struct irq_trace_sum));
	sum.et_type = et_irq_trace_sum;

	for (i = 0; i < num_possible_cpus(); i++) {
		context = get_percpu_context_cpu(i);
		sum.irq_count += context->irq_trace.sum.irq_count;
		sum.irq_runs += context->irq_trace.sum.irq_runs;
		for (j = 0; j < DIAG_NR_SOFTIRQS; j++) {
			sum.sirq_count[j] += context->irq_trace.sum.sirq_count[j];
			sum.sirq_runs[j] += context->irq_trace.sum.sirq_runs[j];
		}
		sum.timer_count += context->irq_trace.sum.timer_count;
		sum.timer_runs += context->irq_trace.sum.timer_runs;
	}
	on_each_cpu(clear_sum, NULL, 1);

	do_gettimeofday(&sum.tv);
	diag_variant_buffer_spin_lock(&irq_trace_variant_buffer, flags);
	diag_variant_buffer_reserve(&irq_trace_variant_buffer, sizeof(struct irq_trace_sum));
	diag_variant_buffer_write_nolock(&irq_trace_variant_buffer, &sum, sizeof(struct irq_trace_sum));
	diag_variant_buffer_seal(&irq_trace_variant_buffer);
	diag_variant_buffer_spin_unlock(&irq_trace_variant_buffer, flags);
}

long diag_ioctl_irq_trace(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_irq_trace_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_IRQ_TRACE_SET:
		if (irq_trace_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_irq_trace_settings));
			if (!ret) {
				irq_trace_settings = settings;
			}
		}
		break;
	case CMD_IRQ_TRACE_SETTINGS:
		settings = irq_trace_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_irq_trace_settings));
		break;
	case CMD_IRQ_TRACE_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));

		do_dump();
		if (!irq_trace_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			ret = copy_to_user_variant_buffer(&irq_trace_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("irq-trace");
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
	LOOKUP_SYMS(softirq_vec);

	return 0;
}

int diag_irq_trace_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&irq_trace_variant_buffer, 1 * 1024 * 1024);
	clean_data();

	if (irq_trace_settings.activated)
		irq_trace_settings.activated = __activate_irq_trace();

	return 0;
}

void diag_irq_trace_exit(void)
{
	if (irq_trace_settings.activated)
		deactivate_irq_trace();
	irq_trace_settings.activated = 0;
	destroy_diag_variant_buffer(&irq_trace_variant_buffer);
}
