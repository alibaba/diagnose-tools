/*
 * Linux内核诊断工具--内核态irq-delay功能
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

#include "uapi/irq_delay.h"

struct diag_irq_delay_settings irq_delay_settings = {
	.threshold = 20,
};

static int irq_delay_alloced = 0;
static struct diag_variant_buffer irq_delay_variant_buffer;

static void clean_data(void)
{
	//
}

void irq_delay_timer(struct diag_percpu_context *context)
{
	u64 expected;
	static struct irq_delay_detail *detail;

	if (!irq_delay_settings.activated)
		return;

	expected = context->timer_info.timer_expected_time;
	if (expected <= 0)
		return;

	if (need_dump(irq_delay_settings.threshold,
				&context->irq_delay.max_irq_delay_ms, expected))
	{
		u64 delay_ns = sched_clock() - expected;
		unsigned long flags;

		diag_variant_buffer_spin_lock(&irq_delay_variant_buffer, flags);
		detail = &diag_percpu_context[smp_processor_id()]->irq_delay_detail;
		detail->et_type = et_irq_delay_detail;
		detail->cpu = smp_processor_id();
		detail->delay_ns = delay_ns;
		do_gettimeofday(&detail->tv);
		diag_task_brief(current, &detail->task);
		diag_task_kern_stack(current, &detail->kern_stack);
		diag_task_user_stack(current, &detail->user_stack);

		diag_variant_buffer_reserve(&irq_delay_variant_buffer, sizeof(struct irq_delay_detail));
		diag_variant_buffer_write_nolock(&irq_delay_variant_buffer, detail, sizeof(struct irq_delay_detail));
		diag_variant_buffer_seal(&irq_delay_variant_buffer);
		diag_variant_buffer_spin_unlock(&irq_delay_variant_buffer, flags);
	}
}

static int __activate_irq_delay(void)
{
	int ret = 0;
	ret = alloc_diag_variant_buffer(&irq_delay_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	irq_delay_alloced = 1;

	clean_data();

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_irq_delay(void)
{
	synchronize_sched();
	clean_data();
}

int activate_irq_delay(void)
{
	if (!irq_delay_settings.activated)
		irq_delay_settings.activated = __activate_irq_delay();

	return irq_delay_settings.activated;
}

int deactivate_irq_delay(void)
{
	if (irq_delay_settings.activated)
		__deactivate_irq_delay();
	irq_delay_settings.activated = 0;

	return 0;
}

int irq_delay_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	unsigned long flags;
	int i, ms;
	int ret = 0;
	struct diag_irq_delay_settings settings;

	switch (id) {
	case DIAG_IRQ_DELAY_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_irq_delay_settings)) {
			ret = -EINVAL;
		} else if (irq_delay_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				irq_delay_settings = settings;
			}
		}
		break;
	case DIAG_IRQ_DELAY_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_irq_delay_settings)) {
			ret = -EINVAL;
		} else {
			settings.activated = irq_delay_settings.activated;
			settings.verbose = irq_delay_settings.verbose;
			settings.threshold = irq_delay_settings.threshold;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_IRQ_DELAY_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!irq_delay_alloced) {
			ret = -EINVAL;
		} else {
			ret = copy_to_user_variant_buffer(&irq_delay_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("irq-delay");
		}
		break;
	case DIAG_IRQ_DELAY_TEST:
		ms = SYSCALL_PARAM1(regs);
		
		if (ms <= 0 || ms > 1000) {
			ret = -EINVAL;
		} else {
			local_irq_save(flags);
			for (i = 0; i < ms; i++)
				mdelay(1);
			local_irq_restore(flags);
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_irq_delay(unsigned int cmd, unsigned long arg)
{
	unsigned long flags;
	int i, ms;
	int ret = 0;
	struct diag_irq_delay_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_IRQ_DELAY_SET:
		if (irq_delay_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_irq_delay_settings));
			if (!ret) {
				irq_delay_settings = settings;
			}
		}
		break;
	case CMD_IRQ_DELAY_SETTINGS:
		settings = irq_delay_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_irq_delay_settings));
		break;
	case CMD_IRQ_DELAY_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));
		if (!irq_delay_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			ret = copy_to_user_variant_buffer(&irq_delay_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("irq-delay");
		}
		break;
	case CMD_IRQ_DELAY_TEST:
		ret = copy_from_user(&ms, (void *)arg, sizeof(int));
		if (ret)
			ms = 0;

		if (ms <= 0 || ms > 1000) {
			ret = -EINVAL;
		} else {
			local_irq_save(flags);
			for (i = 0; i < ms; i++)
				mdelay(1);
			local_irq_restore(flags);
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
	return 0;
}

int diag_irq_delay_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&irq_delay_variant_buffer, 1 * 1024 * 1024);
	clean_data();

	if (irq_delay_settings.activated)
		__activate_irq_delay();

	return 0;
}

void diag_irq_delay_exit(void)
{
	if (irq_delay_settings.activated)
		deactivate_irq_delay();
	irq_delay_settings.activated = 0;
	destroy_diag_variant_buffer(&irq_delay_variant_buffer);
}
