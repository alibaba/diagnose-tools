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
#include "pub/variant_buffer.h"
#include "uapi/rss_monitor.h"

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_rss_monitor_settings rss_monitor_settings;

static struct kprobe kprobe_mmap_region, kprobe_do_munmap;

static struct radix_tree_root rss_monitor_tree;
static DEFINE_SPINLOCK(tree_lock);

static int rss_monitor_alloced;
static unsigned long last_dump_addr = 0;
static struct diag_variant_buffer rss_monitor_variant_buffer;

struct rss_monitor_info {
	unsigned long addr;
	u64 stamp;
	unsigned long alloc_len;
	struct diag_task_detail task;
	struct diag_user_stack_detail user_stack;
	struct diag_raw_stack_detail raw_stack;
};

static void __maybe_unused clean_data(void)
{
	struct rss_monitor_info *batch[NR_BATCH];
	struct rss_monitor_info *info;
	int nr_found;
	unsigned long pos = 0;
	int i;
	unsigned long flags;

	rcu_read_lock();

	do {
		nr_found = radix_tree_gang_lookup(&rss_monitor_tree, (void **)batch, pos, NR_BATCH);
		for(i = 0; i< nr_found; i++) {
			info = batch[i];
			pos = (unsigned long)info->addr + 1;
			spin_lock_irqsave(&tree_lock, flags);
			radix_tree_delete(&rss_monitor_tree, (unsigned long)info->addr);
			spin_unlock_irqrestore(&tree_lock, flags);
			kfree(info);
		}
	} while (nr_found > 0);

	rcu_read_unlock();
}

static int need_trace(struct task_struct *tsk)
{

	//int cpu;

	if (!rss_monitor_settings.activated)
		return 0;

	//cpu = smp_processor_id();
	//if (orig_idle_task && orig_idle_task(cpu) == tsk)
		//return 0;

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

static struct rss_monitor_info *takeout_rss_monitor_info(unsigned long addr)
{
	unsigned long flags;
	struct rss_monitor_info *info = NULL;

	spin_lock_irqsave(&tree_lock, flags);
	info = radix_tree_delete(&rss_monitor_tree, addr);
	spin_unlock_irqrestore(&tree_lock, flags);

	return info;
}

static struct rss_monitor_info *find_alloc_rss_monitor_info(unsigned long addr, size_t len)
{
	struct rss_monitor_info *info;
	int ret;

	info = radix_tree_lookup(&rss_monitor_tree, addr);
	if (!info) {
		info = kmalloc(sizeof(struct rss_monitor_info), GFP_ATOMIC | __GFP_ZERO);
		ret = 0;

		if (info) {
			unsigned long flags;
			struct rss_monitor_info *tmp;

			info->addr = addr;
			info->alloc_len = len;
			info->stamp = sched_clock();
			diag_task_brief(current, &info->task);
			diag_task_raw_stack(current, &info->raw_stack);
			diag_task_user_stack(current, &info->user_stack);

			spin_lock_irqsave(&tree_lock, flags);
			tmp = radix_tree_lookup(&rss_monitor_tree, addr);
			if (tmp) {
				kfree(info);
				info = tmp;
			} else {
				radix_tree_insert(&rss_monitor_tree, addr, info);
			}
			spin_unlock_irqrestore(&tree_lock, flags);
		}
	}
	return info;
}

static int kprobe_mmap_region_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long flags;
	unsigned long addr;
	struct rss_monitor_info *info;
	unsigned long len = 0;

	atomic64_inc_return(&diag_nr_running);
	if (!need_trace(current)) {
		atomic64_dec_return(&diag_nr_running);
		return 0;
	}

	addr = ORIG_PARAM2(regs);
	len = ORIG_PARAM3(regs);

	local_irq_save(flags);
	info = find_alloc_rss_monitor_info(addr, len);
	local_irq_restore(flags);

	atomic64_dec_return(&diag_nr_running);
	return 0;

}

static int kprobe_do_munmap_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long flags;
	unsigned long addr;
	struct rss_monitor_info *info;

	atomic64_inc_return(&diag_nr_running);
	if (!need_trace(current)) {
		atomic64_dec_return(&diag_nr_running);
		return 0;
	}

	addr = ORIG_PARAM2(regs);
	//len = ORIG_PARAM3(regs);

	local_irq_save(flags);
	info = takeout_rss_monitor_info(addr);
	if (info) {
		kfree(info);
	}

	local_irq_restore(flags);

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

	unhook_kprobe(&kprobe_mmap_region);
	unhook_kprobe(&kprobe_do_munmap);

	hook_kprobe(&kprobe_mmap_region, "mmap_region", kprobe_mmap_region_pre, NULL);
	hook_kprobe(&kprobe_do_munmap, "do_munmap", kprobe_do_munmap_pre, NULL);

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_rss_monitor(void)
{
	unhook_kprobe(&kprobe_mmap_region);
	unhook_kprobe(&kprobe_do_munmap);
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

static void do_dump(void)
{
	unsigned long flags;
	struct rss_monitor_info *batch[NR_BATCH];
	struct rss_monitor_info *info;
	unsigned long pos = last_dump_addr + 1;
	u64 now = sched_clock();
	u64 delta_time;
	int nr_found;
	int i;
	int count = 0;

	rcu_read_lock();

	do {
		nr_found = radix_tree_gang_lookup(&rss_monitor_tree, (void **)batch, pos, NR_BATCH);
		for (i = 0; i < nr_found; i++) {
			info = batch[i];
			last_dump_addr = info->addr;
			pos = info->addr + 1;

			delta_time = now - info->stamp;

			if (delta_time < (u64)rss_monitor_settings.time_threshold * 1000 * 1000 * 1000)
				continue;

			if(rss_monitor_settings.raw_stack) {
				struct rss_monitor_raw_stack_detail *raw_detail;
				raw_detail = &diag_percpu_context[smp_processor_id()]->rss_monitor.rss_monitor_raw_stack_detail;
				raw_detail->et_type = et_rss_monitor_raw_detail;
				raw_detail->addr = info->addr;
				raw_detail->alloc_len = info->alloc_len;
				raw_detail->delta_time = delta_time / (1000 * 1000 * 1000); //s
				do_diag_gettimeofday(&raw_detail->tv);

				raw_detail->task = info->task;
				raw_detail->user_stack = info->user_stack;
				raw_detail->raw_stack = info->raw_stack;

				diag_variant_buffer_spin_lock(&rss_monitor_variant_buffer, flags);
				diag_variant_buffer_reserve(&rss_monitor_variant_buffer,
					sizeof(struct rss_monitor_raw_stack_detail));
				diag_variant_buffer_write_nolock(&rss_monitor_variant_buffer,
					raw_detail, sizeof(struct rss_monitor_raw_stack_detail));
				diag_variant_buffer_seal(&rss_monitor_variant_buffer);
				diag_variant_buffer_spin_unlock(&rss_monitor_variant_buffer, flags);

			} else {
				struct rss_monitor_detail *detail;
				detail = &diag_percpu_context[smp_processor_id()]->rss_monitor.rss_monitor_detail;
				detail->et_type = et_rss_monitor_detail;
				detail->addr = info->addr;
				detail->alloc_len = info->alloc_len;
				detail->delta_time = delta_time / (1000 * 1000 * 1000); //s
				do_diag_gettimeofday(&detail->tv);

				detail->task = info->task;
				detail->user_stack = info->user_stack;

				diag_variant_buffer_spin_lock(&rss_monitor_variant_buffer, flags);
				diag_variant_buffer_reserve(&rss_monitor_variant_buffer,
					sizeof(struct rss_monitor_detail));
				diag_variant_buffer_write_nolock(&rss_monitor_variant_buffer,
					detail, sizeof(struct rss_monitor_detail));
				diag_variant_buffer_seal(&rss_monitor_variant_buffer);
				diag_variant_buffer_spin_unlock(&rss_monitor_variant_buffer, flags);
			}

			spin_lock_irqsave(&tree_lock, flags);
			info = radix_tree_delete(&rss_monitor_tree, info->addr);
			spin_unlock_irqrestore(&tree_lock, flags);
			if (info) {
				kfree(info);
			}

			count++;
			if (count >= 10000)
				goto out;
		}
	} while (nr_found > 0);
out:
	rcu_read_unlock();
}

int rss_monitor_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	unsigned long cycle;
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
		cycle = SYSCALL_PARAM4(regs);

		if (!rss_monitor_alloced) {
			ret = -EINVAL;
		} else {
			if (cycle) {
				last_dump_addr = 0;
			}
			do_dump();
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
	struct diag_ioctl_dump_param_cycle dump_param;

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
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param_cycle));
		if (!rss_monitor_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			if (dump_param.cycle) {
				last_dump_addr = 0;
			}
			do_dump();
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
	INIT_RADIX_TREE(&rss_monitor_tree, GFP_ATOMIC);
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

	clean_data();
	destroy_diag_variant_buffer(&rss_monitor_variant_buffer);
}
