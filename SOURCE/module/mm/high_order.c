/*
 * Linux内核诊断工具--内核态high-order功能
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
#include "mm_tree.h"

#include "uapi/high_order.h"

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_high_order_settings high_order_settings = {
	.order = 3,
};

static unsigned long high_order_id;
static unsigned long high_order_seq;
static int high_order_alloced;

static struct diag_variant_buffer high_order_variant_buffer;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static void trace_mm_page_alloc_hit(void *ignore, struct page *page,
		unsigned int order, gfp_t gfp_flags, int migratetype)
#else
static void trace_mm_page_alloc_hit(struct page *page,
		unsigned int order, gfp_t gfp_flags, int migratetype)
#endif
{
	unsigned long flags;
	struct high_order_detail *detail;

	if (!high_order_settings.activated)
		return;

	if (order < high_order_settings.order)
		return;

#if 0	
	if (gfp_flags & __GFP_NORETRY)
        return;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 11, 0)
    if ((gfp_flags & __GFP_WAIT) != __GFP_WAIT)
        return;
#else
	if ((gfp_flags & GFP_NOWAIT) == GFP_NOWAIT)
		return;
#endif
#endif

	detail = &diag_percpu_context[smp_processor_id()]->high_order_detail;
	if (detail) {
		detail->et_type = et_high_order_detail;
		detail->id = high_order_id;
		detail->seq = high_order_seq;
		do_gettimeofday(&detail->tv);
		detail->order = order;
		diag_task_brief(current, &detail->task);
		diag_task_kern_stack(current, &detail->kern_stack);
		diag_task_user_stack(current, &detail->user_stack);
		detail->proc_chains.chains[0][0] = 0;
		dump_proc_chains_simple(current, &detail->proc_chains);
		diag_variant_buffer_spin_lock(&high_order_variant_buffer, flags);
		diag_variant_buffer_reserve(&high_order_variant_buffer, sizeof(struct high_order_detail));
		diag_variant_buffer_write_nolock(&high_order_variant_buffer, detail, sizeof(struct high_order_detail));
		diag_variant_buffer_seal(&high_order_variant_buffer);
		diag_variant_buffer_spin_unlock(&high_order_variant_buffer, flags);
		high_order_seq++;
	}
}

static int __activate_high_order(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&high_order_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	high_order_alloced = 1;

	high_order_id = get_cycles();

	hook_tracepoint("mm_page_alloc", trace_mm_page_alloc_hit, NULL);

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_high_order(void)
{
	unhook_tracepoint("mm_page_alloc", trace_mm_page_alloc_hit, NULL);
	synchronize_sched();
	msleep(10);
	while (atomic64_read(&diag_nr_running) > 0) {
		msleep(10);
	}
}

int activate_high_order(void)
{
	if (!high_order_settings.activated)
		high_order_settings.activated = __activate_high_order();

	return high_order_settings.activated;
}

int deactivate_high_order(void)
{
	if (high_order_settings.activated)
		__deactivate_high_order();
	high_order_settings.activated = 0;

	return 0;
}

int high_order_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_high_order_settings settings;
	unsigned long addr;

	switch (id) {
	case DIAG_HIGH_ORDER_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_high_order_settings)) {
			ret = -EINVAL;
		} else if (high_order_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				high_order_settings = settings;
			}
		}
		break;
	case DIAG_HIGH_ORDER_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_high_order_settings)) {
			ret = -EINVAL;
		} else {
			settings = high_order_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_HIGH_ORDER_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!high_order_alloced) {
			ret = -EINVAL;
		} else {
			ret = copy_to_user_variant_buffer(&high_order_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("high-order");
		}
		break;
	case DIAG_HIGH_ORDER_TEST:
		addr = __get_free_pages(GFP_KERNEL, 3);
		if (addr)
			free_pages(addr, 3);
		ret = 0;
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_high_order(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

int diag_high_order_init(void)
{
	init_diag_variant_buffer(&high_order_variant_buffer, 10 * 1024 * 1024);
	if (high_order_settings.activated)
		high_order_settings.activated = __activate_high_order();

	return 0;
}

void diag_high_order_exit(void)
{
	if (high_order_settings.activated)
		deactivate_high_order();
	high_order_settings.activated = 0;

	msleep(20);

	destroy_diag_variant_buffer(&high_order_variant_buffer);
}
