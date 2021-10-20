/*
 * Linux内核诊断工具--内核态sched-delay功能
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/module.h>
#include <linux/stacktrace.h>
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
#include <linux/version.h>
#include <linux/net.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <net/tcp.h>
#include <linux/stop_machine.h>

#include <asm/thread_info.h>

#include "internal.h"
#include "mm_tree.h"
#include "kern_internal.h"
#include "pub/trace_file.h"
#include "pub/trace_point.h"

#include "uapi/sched_delay.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32) && \
	LINUX_VERSION_CODE <= KERNEL_VERSION(4, 20, 0) \
	&& !defined(UBUNTU_1604)

#if defined(ALIOS_4000_009)
static unsigned long *get_last_queued_addr(struct task_struct *p)
{
	/**
	 * task_stack_page, but not end_of_stack !!
	 */
	return task_stack_page(p) + sizeof(struct thread_info) + 32;
}
#else
#if  defined(CENTOS_8U)
#define diag_last_queued rh_reserved2
#elif KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
#define diag_last_queued ali_reserved3
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
#define diag_last_queued rh_reserved3
#else
#define diag_last_queued rh_reserved[0]
#endif

static unsigned long *get_last_queued_addr(struct task_struct *p)
{
	return &p->diag_last_queued;
}
#endif

static unsigned long read_last_queued(struct task_struct *p)
{
	unsigned long *ptr = get_last_queued_addr(p);

	if (ptr) {
		return *ptr;
	} else {
		return 0;
	}
}

static void update_last_queued(struct task_struct *p, unsigned long stamp)
{
	unsigned long *ptr = get_last_queued_addr(p);

	if (ptr) {
		*ptr = stamp;
	}
}

__maybe_unused static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_sched_delay_settings sched_delay_settings = {
	.threshold_ms = 50,
};

static int sched_delay_alloced;

static int diag_sched_delay_id;
static int sched_delay_seq;
static struct diag_variant_buffer sched_delay_variant_buffer;

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
static void trace_sched_wakeup_hit(void *__data, struct task_struct *p)
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
static void trace_sched_wakeup_hit(void *__data, struct task_struct *p, bool unused)
#else
static void trace_sched_wakeup_hit(struct rq *rq, struct task_struct *p, bool unused)
#endif
{
	update_last_queued(p, ktime_to_ms(ktime_get()));
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
	unsigned long long t_queued;
	unsigned long long delta = 0;
	unsigned long long delta_ms;
	unsigned long long now = ktime_to_ms(ktime_get());

	struct task_struct *leader = next->group_leader ? next->group_leader : next;

	if (sched_delay_settings.bvt == 0 && diag_get_task_type(next) < 0)
		return;

	if (sched_delay_settings.comm[0] && (strcmp("none", sched_delay_settings.comm) != 0)) {
		if (strcmp(leader->comm, sched_delay_settings.comm) != 0)
			return;
	}

	if (sched_delay_settings.tgid && leader->pid != sched_delay_settings.tgid) {
		return;
	}

	if (sched_delay_settings.pid && next->pid != sched_delay_settings.pid) {
		return;
	}

	t_queued = read_last_queued(next);
	update_last_queued(next, 0);
	if (t_queued <= 0)
		return;

	delta = now - t_queued;
	delta_ms = delta;

	if (delta_ms >= sched_delay_settings.threshold_ms) {
		struct sched_delay_dither *dither;
		unsigned long flags;

		if (strcmp(leader->comm, "qemu-kvm") == 0)
			return;

		dither = &diag_percpu_context[smp_processor_id()]->sched_delay_dither;
		dither->et_type = et_sched_delay_dither;
		dither->id = diag_sched_delay_id;
		do_diag_gettimeofday(&dither->tv);
		dither->seq = sched_delay_seq;
		sched_delay_seq++;
		dither->now	= now;
		dither->queued = t_queued;
		dither->delay_ms = delta_ms;
		diag_task_brief(next, &dither->task);
		diag_task_kern_stack(next, &dither->kern_stack);
		diag_task_user_stack(next, &dither->user_stack);
		dump_proc_chains_simple(next, &dither->proc_chains);

		diag_variant_buffer_spin_lock(&sched_delay_variant_buffer, flags);
		diag_variant_buffer_reserve(&sched_delay_variant_buffer, sizeof(struct sched_delay_dither));
		diag_variant_buffer_write_nolock(&sched_delay_variant_buffer, dither, sizeof(struct sched_delay_dither));
		diag_variant_buffer_seal(&sched_delay_variant_buffer);
		diag_variant_buffer_spin_unlock(&sched_delay_variant_buffer, flags);
	}
}

static int __activate_sched_delay(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&sched_delay_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	sched_delay_alloced = 1;

	hook_tracepoint("sched_switch", trace_sched_switch_hit, NULL);
	hook_tracepoint("sched_wakeup", trace_sched_wakeup_hit, NULL);

	return 1;
out_variant_buffer:
	return 0;
}

int activate_sched_delay(void)
{
	if (!sched_delay_settings.activated)
		sched_delay_settings.activated = __activate_sched_delay();

	return sched_delay_settings.activated;
}

static void __deactivate_sched_delay(void)
{
	unhook_tracepoint("sched_switch", trace_sched_switch_hit, NULL);
	unhook_tracepoint("sched_wakeup", trace_sched_wakeup_hit, NULL);

	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0)
	{
		msleep(10);
	}
}

int deactivate_sched_delay(void)
{
	if (sched_delay_settings.activated)
		__deactivate_sched_delay();
	sched_delay_settings.activated = 0;

	return 0;
}

static int lookup_syms(void)
{
	return 0;
}

static void jump_init(void)
{
}

static void dump_data(void)
{
	struct sched_delay_rq rq;
	unsigned long flags;
	int cpu;

	rq.et_type = et_sched_delay_rq;
	rq.id = diag_sched_delay_id;
	do_diag_gettimeofday(&rq.tv);

	for_each_online_cpu(cpu)
	{
		rq.seq = sched_delay_seq;
		sched_delay_seq++;
		rq.cpu = cpu;

		diag_variant_buffer_spin_lock(&sched_delay_variant_buffer, flags);
		diag_variant_buffer_reserve(&sched_delay_variant_buffer, sizeof(struct sched_delay_rq));
		diag_variant_buffer_write_nolock(&sched_delay_variant_buffer, &rq, sizeof(struct sched_delay_rq));
		diag_variant_buffer_seal(&sched_delay_variant_buffer);
		diag_variant_buffer_spin_unlock(&sched_delay_variant_buffer, flags);
	}
}

int sched_delay_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	static struct diag_sched_delay_settings settings;

	switch (id) {
	case DIAG_SCHED_DELAY_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_sched_delay_settings)) {
			ret = -EINVAL;
		} else if (sched_delay_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				sched_delay_settings = settings;
			}
		}
		break;
	case DIAG_SCHED_DELAY_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_sched_delay_settings)) {
			ret = -EINVAL;
		} else {
			settings = sched_delay_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_SCHED_DELAY_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!sched_delay_alloced) {
			ret = -EINVAL;
		} else {
			dump_data();
			ret = copy_to_user_variant_buffer(&sched_delay_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			diag_sched_delay_id++;
			record_dump_cmd("sched-delay");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_sched_delay(unsigned int cmd, unsigned long arg)
{
	struct diag_ioctl_dump_param dump_param;
	int ret = 0;
	static struct diag_sched_delay_settings settings;

	switch (cmd) {
	case CMD_SCHED_DELAY_SET:
		if (sched_delay_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_sched_delay_settings));
			if (!ret) {
				sched_delay_settings = settings;
			}
		}
		break;
	case CMD_SCHED_DELAY_SETTINGS:
		settings = sched_delay_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_sched_delay_settings));
		break;
	case CMD_SCHED_DELAY_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));
		if (!sched_delay_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			dump_data();
			ret = copy_to_user_variant_buffer(&sched_delay_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			diag_sched_delay_id++;
			record_dump_cmd("sched-delay");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_sched_delay_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&sched_delay_variant_buffer, 4 * 1024 * 1024);
	jump_init();

    if (sched_delay_settings.activated)
		sched_delay_settings.activated = __activate_sched_delay();

    return 0;

}

void diag_sched_delay_exit(void)
{
    if (sched_delay_settings.activated)
        __deactivate_sched_delay();
    sched_delay_settings.activated = 0;

	destroy_diag_variant_buffer(&sched_delay_variant_buffer);
}
#else
int diag_sched_delay_init(void)
{
	return 0;
}

void diag_sched_delay_exit(void)
{

}
#endif
