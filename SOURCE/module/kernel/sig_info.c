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

static struct diag_variant_buffer sig_info_variant_buffer;

static void clean_data(void)
{
	//
}

static void inspect_signal(int signum, const struct task_struct *rtask)
{
	struct task_struct *stask = current;
	unsigned long flags;
	struct sig_info_detail *detail;

	if (sig_info_settings.spid > 0 && stask->tgid != sig_info_settings.spid) {
		return;
	}

	if (sig_info_settings.rpid > 0 && rtask->tgid != sig_info_settings.rpid) {
		return;
	}

	detail = &diag_percpu_context[smp_processor_id()]->sig_info.detail;
	detail->et_type = et_sig_info_detail;
	detail->id = 0;
	detail->seq = 0;
	detail->sig = signum;
	do_gettimeofday(&detail->tv);
	diag_task_brief(rtask, &detail->receive_task);
	diag_task_brief(current, &detail->task);
	diag_task_kern_stack(current, &detail->kern_stack);
	diag_task_user_stack(current, &detail->user_stack);
	detail->proc_chains.chains[0][0] = 0;
	dump_proc_chains_simple(current, &detail->proc_chains);
	diag_variant_buffer_spin_lock(&sig_info_variant_buffer, flags);
	diag_variant_buffer_reserve(&sig_info_variant_buffer, sizeof(struct sig_info_detail));
	diag_variant_buffer_write_nolock(&sig_info_variant_buffer, detail, sizeof(struct sig_info_detail));
	diag_variant_buffer_seal(&sig_info_variant_buffer);
	diag_variant_buffer_spin_unlock(&sig_info_variant_buffer, flags);
}

#if KERNEL_VERSION(4, 19, 0) <= LINUX_VERSION_CODE
static int trace_signal_generate_hit(void *ignore, int sig,
		struct siginfo *info, struct task_struct *task,
		int type, int result)
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
static int trace_signal_generate_hit(void *ignore, int sig,
		struct siginfo *info, struct task_struct *task,
		int group, int result)
#else
static int trace_signal_generate_hit(int sig,
		struct siginfo *info, struct task_struct *task,
		int group)
#endif
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
