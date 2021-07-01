/*
 * Linux内核诊断工具--内核态rss-monitor功能
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Jiyun Fan <fanjiyun.fjy@alibaba-inc.com>
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
#include <net/sock.h>

#include <asm/irq_regs.h>
#include <asm/unistd.h>

#include "internal.h"
#include "pub/kprobe.h"
#include "uapi/rss_monitor.h"

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_rss_monitor_settings rss_monitor_settings;

static struct kprobe kprobe_do_mmap;

static int rss_monitor_alloced;
static struct diag_variant_buffer rss_monitor_variant_buffer;

static void __maybe_unused clean_data(void)
{
}

static int need_trace(struct task_struct *tsk)
{

	int cpu;

	if (!rss_monitor_settings.activated)
		return 0;

	cpu = smp_processor_id();
	if (orig_idle_task && orig_idle_task(cpu) == tsk)
		return 0;

	if (rss_monitor_settings.tgid) {
                struct task_struct *leader = tsk->group_leader ? tsk->group_leader : tsk;

                if (leader->pid != rss_monitor_settings.tgid)
                        return 0;
        }

        if (rss_monitor_settings.pid) {
                if (tsk->pid != rss_monitor_settings.pid)
                        return 0;
        }

        return 1;
}

static int kprobe_do_mmap_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long flags;

	atomic64_inc_return(&diag_nr_running);
	if (!need_trace(current)) {
		atomic64_dec_return(&diag_nr_running);
		return 0;
	}

	if (rss_monitor_settings.raw_stack) {
		struct rss_monitor_raw_stack_detail *raw_detail;
		raw_detail = &diag_percpu_context[smp_processor_id()]->rss_monitor.rss_monitor_raw_stack_detail;
		raw_detail->et_type = et_rss_monitor_raw_detail;
		do_diag_gettimeofday(&raw_detail->tv);
		diag_task_brief(current, &raw_detail->task);
		//diag_task_kern_stack(current, &raw_detail->kern_stack);
		diag_task_user_stack(current, &raw_detail->user_stack);
		diag_task_raw_stack(current, &raw_detail->raw_stack);

		diag_variant_buffer_spin_lock(&rss_monitor_variant_buffer, flags);
		diag_variant_buffer_reserve(&rss_monitor_variant_buffer, sizeof(struct rss_monitor_raw_stack_detail));
		diag_variant_buffer_write_nolock(&rss_monitor_variant_buffer, raw_detail, sizeof(struct rss_monitor_raw_stack_detail));
		diag_variant_buffer_seal(&rss_monitor_variant_buffer);
		diag_variant_buffer_spin_unlock(&rss_monitor_variant_buffer, flags);
	} else {
		struct rss_monitor_detail *detail;
		detail = &diag_percpu_context[smp_processor_id()]->rss_monitor.rss_monitor_detail;
		detail->et_type = et_rss_monitor_detail;
		do_diag_gettimeofday(&detail->tv);
		diag_task_brief(current, &detail->task);
		//diag_task_kern_stack(current, &detail->kern_stack);
		diag_task_user_stack(current, &detail->user_stack);

		diag_variant_buffer_spin_lock(&rss_monitor_variant_buffer, flags);
		diag_variant_buffer_reserve(&rss_monitor_variant_buffer, sizeof(struct rss_monitor_detail));
		diag_variant_buffer_write_nolock(&rss_monitor_variant_buffer, detail, sizeof(struct rss_monitor_detail));
		diag_variant_buffer_seal(&rss_monitor_variant_buffer);
		diag_variant_buffer_spin_unlock(&rss_monitor_variant_buffer, flags);
	}
	atomic64_dec_return(&diag_nr_running);
	return 0;
}

static int __activate_rss_monitor(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&rss_monitor_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	rss_monitor_alloced = 1;

	unhook_kprobe(&kprobe_do_mmap);

	#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
		hook_kprobe(&kprobe_do_mmap, "do_mmap_pgoff", kprobe_do_mmap_pre, NULL);
	#else
		hook_kprobe(&kprobe_do_mmap, "do_mmap", kprobe_do_mmap_pre, NULL);
	#endif

        return 1;
out_variant_buffer:
        return 0;
}

static void __deactivate_rss_monitor(void)
{
        unhook_kprobe(&kprobe_do_mmap);
        synchronize_sched();

        msleep(20);
        while (atomic64_read(&diag_nr_running) > 0)
                msleep(20);

        clean_data();
}

int activate_rss_monitor(void)
{
	if (!rss_monitor_settings.activated)
		rss_monitor_settings.activated = __activate_rss_monitor();

	return rss_monitor_settings.activated;
}

int deactivate_rss_monitor(void)
{
	if (rss_monitor_settings.activated)
		__deactivate_rss_monitor();
	rss_monitor_settings.activated = 0;

	return 0;
}

static int lookup_syms(void)
{
        return 0;
}

static void jump_init(void)
{
}

int rss_monitor_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_rss_monitor_settings settings;

	switch (id) {
	case DIAG_RSS_MONITOR_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_rss_monitor_settings)) {
			ret = -EINVAL;
		} else if (rss_monitor_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				rss_monitor_settings = settings;
			}
		}
		break;
	case DIAG_RSS_MONITOR_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		memset(&settings, 0, sizeof(settings));
		if (user_buf_len != sizeof(struct diag_rss_monitor_settings)) {
			ret = -EINVAL;
		} else {
			settings = rss_monitor_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_RSS_MONITOR_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!rss_monitor_alloced) {
			ret = -EINVAL;
		} else {
			ret = copy_to_user_variant_buffer(&rss_monitor_variant_buffer,
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

long diag_ioctl_rss_monitor(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_rss_monitor_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_RSS_MONITOR_SET:
		if (rss_monitor_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_rss_monitor_settings));
			if (!ret) {
				rss_monitor_settings = settings;
			}
		}
		break;
	case CMD_RSS_MONITOR_SETTINGS:
		memset(&settings, 0, sizeof(settings));
		settings = rss_monitor_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_rss_monitor_settings));
		break;
	case CMD_RSS_MONITOR_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));
		if (!rss_monitor_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			ret = copy_to_user_variant_buffer(&rss_monitor_variant_buffer,
				dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("rss-monitor");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_rss_monitor_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&rss_monitor_variant_buffer, 10 * 1024 * 1024);
	jump_init();

	if (rss_monitor_settings.activated)
		rss_monitor_settings.activated = __activate_rss_monitor();

	return 0;
}

void diag_rss_monitor_exit(void)
{
	if (rss_monitor_settings.activated)
		deactivate_rss_monitor();
	rss_monitor_settings.activated = 0;

	msleep(10);
	synchronize_sched();

	destroy_diag_variant_buffer(&rss_monitor_variant_buffer);
}
