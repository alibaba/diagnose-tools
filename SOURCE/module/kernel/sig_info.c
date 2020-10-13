/*
 * Linux内核诊断工具--内核态sig-info功能
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 * 作者: Wllabs <wllabs@163.com>
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
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <linux/rtc.h>
#include <linux/time.h>
#include <linux/version.h>
#include <linux/cpu.h>
#include <net/xfrm.h>
#include <linux/inetdevice.h>

#include "internal.h"
#include "mm_tree.h"
#include "pub/trace_point.h"
#include "uapi/sig_info.h"

struct diag_sig_info_settings sig_info_settings;
static int sig_info_alloced = 0;

struct sig_info
{
	unsigned long sig_key;
	int signum;
	unsigned long spid;
	unsigned long rpid;
	char scomm[TASK_COMM_LEN];
	char rcomm[TASK_COMM_LEN];

	struct list_head list;
	struct rcu_head rcu_head;
};

static struct radix_tree_root sig_info_tree;
static DEFINE_SPINLOCK(tree_lock);
static DEFINE_MUTEX(sig_mutex);

static struct diag_variant_buffer sig_info_variant_buffer;

__maybe_unused static void move_to_list(struct list_head *sig_list)
{
	int i;
	unsigned long flags;
	struct sig_info *infos[NR_BATCH];
	struct sig_info *sig_info;
	int nr_found;
	unsigned long pos = 0;

	INIT_LIST_HEAD(sig_list);

	mutex_lock(&sig_mutex);
	spin_lock_irqsave(&tree_lock, flags);
	do {
		nr_found = radix_tree_gang_lookup(&sig_info_tree, (void **)infos, pos, NR_BATCH);

		for (i = 0; i < nr_found; i++) {
			sig_info = infos[i];
			radix_tree_delete(&sig_info_tree, (unsigned long)sig_info->sig_key);
			pos = (unsigned long)sig_info->sig_key + 1;
			INIT_LIST_HEAD(&sig_info->list);
			list_add_tail(&sig_info->list, sig_list);
		}
	} while (nr_found > 0);
	spin_unlock_irqrestore(&tree_lock, flags);
	mutex_unlock(&sig_mutex);
}

static void free_sig_info(struct rcu_head *rcu)
{
	struct sig_info *this = container_of(rcu, struct sig_info, rcu_head);

	kfree(this);
}

__maybe_unused static void diag_free_list(struct list_head *sig_list)
{
	while (!list_empty(sig_list))
	{
		struct sig_info *this = list_first_entry(sig_list, struct sig_info, list);

		list_del_init(&this->list);
		call_rcu(&this->rcu_head, free_sig_info);
	}
}

__maybe_unused static void clean_data(void)
{
	struct list_head header;

	move_to_list(&header);

	diag_free_list(&header);
}

__maybe_unused static struct sig_info *find_alloc_desc(int signum,
		const struct task_struct *stask,
		const struct task_struct *rtask)
{
	struct sig_info *info = NULL;
	unsigned long sig_key;

	sig_key =  (unsigned long)stask | rtask->pid;

	info = radix_tree_lookup(&sig_info_tree, sig_key);
	if (!info) {
		info = kmalloc(sizeof(struct sig_info), GFP_ATOMIC | __GFP_ZERO);
		if (info) {
			unsigned long flags;
			struct sig_info *tmp;

			info->sig_key = sig_key;
			info->signum = signum;
			info->spid = stask->pid;
			info->rpid = rtask->pid;
			strncpy(info->scomm, stask->comm, TASK_COMM_LEN);
			info->scomm[TASK_COMM_LEN - 1] = 0;
			strncpy(info->rcomm, rtask->comm, TASK_COMM_LEN);
			info->rcomm[TASK_COMM_LEN - 1] = 0;

			INIT_LIST_HEAD(&info->list);

			spin_lock_irqsave(&tree_lock, flags);
			tmp = radix_tree_lookup(&sig_info_tree, sig_key);
			if (tmp) {
				kfree(info);
				info = tmp;
			} else {
				radix_tree_insert(&sig_info_tree, sig_key, info);
			}
			spin_unlock_irqrestore(&tree_lock, flags);
		}
	}

	return info;
}

static void inspect_signal(int signum, const struct task_struct *rtask)
{
	struct sig_info *signalinfo;
	struct task_struct *stask = current;
	unsigned long flags;

	if (sig_info_settings.spid > 0 && stask->pid != sig_info_settings.spid) {
		return;
	}

	if (sig_info_settings.rpid > 0 && rtask->pid != sig_info_settings.rpid) {
		return;
	}

	signalinfo = find_alloc_desc(signum, stask, rtask);
	if (signalinfo && sig_info_settings.perf) {
		struct sig_info_perf *perf;

		perf = &diag_percpu_context[smp_processor_id()]->sig_info.perf;
		perf->et_type = et_sig_info_perf;
		perf->id = 0;
		perf->seq = 0;
		do_gettimeofday(&perf->tv);
		diag_task_brief(current, &perf->task);
		diag_task_kern_stack(current, &perf->kern_stack);
		diag_task_user_stack(current, &perf->user_stack);
		perf->proc_chains.chains[0][0] = 0;
		dump_proc_chains_simple(current, &perf->proc_chains);
		diag_variant_buffer_spin_lock(&sig_info_variant_buffer, flags);
		diag_variant_buffer_reserve(&sig_info_variant_buffer, sizeof(struct sig_info_perf));
		diag_variant_buffer_write_nolock(&sig_info_variant_buffer, perf, sizeof(struct sig_info_perf));
		diag_variant_buffer_seal(&sig_info_variant_buffer);
		diag_variant_buffer_spin_unlock(&sig_info_variant_buffer, flags);
	}
	return;
}

static int trace_signal_generate_hit(void *ignore, int sig,
		struct siginfo *info, struct task_struct *task,
		int group, int result)
{
	if (!sig_info_settings.activated)
		return 0;

	inspect_signal(sig, task);

	return 0;
}

static int __activate_sig_info(void)
{
	int ret = 1;

	ret = alloc_diag_variant_buffer(&sig_info_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	sig_info_alloced = 1;

	clean_data();

	hook_tracepoint("signal_generate", trace_signal_generate_hit, NULL);

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_sig_info(void)
{
	unhook_tracepoint("signal_generate", trace_signal_generate_hit, NULL);

	synchronize_sched();
	msleep(20);

	clean_data();
}

static int lookup_syms(void)
{
	return 0;
}

int activate_sig_info(void)
{
	if (!sig_info_settings.activated)
		sig_info_settings.activated = __activate_sig_info();

	return sig_info_settings.activated;
}

int deactivate_sig_info(void)
{
	if (sig_info_settings.activated)
		__deactivate_sig_info();
	sig_info_settings.activated = 0;

	return 0;
}

static void do_dump(void)
{
	struct sig_info *this;
	struct list_head header;
	struct sig_info_detail detail;
	unsigned long flags;

	move_to_list(&header);

	list_for_each_entry(this, &header, list)
	{
		detail.et_type = et_sig_info_detail;
		detail.signum = this->signum;
		detail.spid = this->spid;
		detail.rpid = this->rpid;

		strncpy(detail.scomm, this->scomm, TASK_COMM_LEN);
		detail.scomm[TASK_COMM_LEN - 1] = 0;
		strncpy(detail.rcomm, this->rcomm, TASK_COMM_LEN);
		detail.rcomm[TASK_COMM_LEN - 1] = 0;

		diag_variant_buffer_spin_lock(&sig_info_variant_buffer, flags);
		diag_variant_buffer_reserve(&sig_info_variant_buffer, sizeof(struct sig_info_detail));
		diag_variant_buffer_write_nolock(&sig_info_variant_buffer, &detail, sizeof(struct sig_info_detail));
		diag_variant_buffer_seal(&sig_info_variant_buffer);
		diag_variant_buffer_spin_unlock(&sig_info_variant_buffer, flags);
	}

	diag_free_list(&header);
}

int sig_info_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_sig_info_settings settings;

	switch (id) {
	case DIAG_SIG_INFO_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_sig_info_settings)) {
			ret = -EINVAL;
		} else if (sig_info_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				sig_info_settings = settings;
			}
		}
		break;
	case DIAG_SIG_INFO_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_sig_info_settings)) {
			ret = -EINVAL;
		} else {
			settings.activated = sig_info_settings.activated;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_SIG_INFO_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!sig_info_alloced) {
			ret = -EINVAL;
		} else {
			do_dump();
			ret = copy_to_user_variant_buffer(&sig_info_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("sig_info");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_sig_info(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_sig_info_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_SIG_INFO_SET:
		if (sig_info_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_sig_info_settings));
			if (!ret) {
				sig_info_settings = settings;
			}
		}
		break;
	case CMD_SIG_INFO_SETTINGS:
		settings.activated = sig_info_settings.activated;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_sig_info_settings));
		break;
	case CMD_SIG_INFO_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));

		if (!sig_info_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			do_dump();
			ret = copy_to_user_variant_buffer(&sig_info_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("sig_info");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_sig_info_init(void)
{
	INIT_RADIX_TREE(&sig_info_tree, GFP_ATOMIC);

	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&sig_info_variant_buffer, 20 * 1024 * 1024);

	if (sig_info_settings.activated)
		sig_info_settings.activated = __activate_sig_info();

	return 0;
}

void diag_sig_info_exit(void)
{
	if (sig_info_settings.activated)
		deactivate_sig_info();
	sig_info_settings.activated = 0;
	destroy_diag_variant_buffer(&sig_info_variant_buffer);

	return;
}
