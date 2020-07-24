/*
 * Linux内核诊断工具--内核态kprobe功能
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
#include <linux/bitmap.h>
#include <net/sock.h>

#include <asm/irq_regs.h>

#include "internal.h"
#include "mm_tree.h"
#include "pub/trace_file.h"
#include "pub/kprobe.h"

#include "uapi/kprobe.h"

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);

struct diag_kprobe_settings kprobe_settings;

static unsigned int kprobe_alloced;
static struct cpumask kprobe_cpumask;
enum kern_kprobe_style {
	DIAG_KPROBE_NONE,
	DIAG_KPROBE_TCP_SENDMSG,
	DIAG_KPROBE_DQUOT_SET_DQBLK,
};
static enum kern_kprobe_style kern_kprobe_style;
static struct kprobe diag_kprobe;

static struct diag_variant_buffer kprobe_variant_buffer;

static void __maybe_unused clean_data(void)
{
	//
}

static int need_trace(struct task_struct *tsk, struct pt_regs *regs)
{
	int cpu;

	if (!kprobe_settings.activated)
		return 0;

	cpu = smp_processor_id();
	if (orig_idle_task && orig_idle_task(cpu) == tsk)
		return 0;

	if (!cpumask_test_cpu(cpu, &kprobe_cpumask))
		return 0;

#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE 
	if (kern_kprobe_style == DIAG_KPROBE_TCP_SENDMSG) {
#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
		struct sock *sk = (void *)ORIG_PARAM1(regs);
#else
		struct sock *sk = (void *)ORIG_PARAM2(regs);
#endif
		int saddr = 0;
		int daddr = 0;
		int sport = 0;
		int dport = 0;

		saddr = sk->sk_daddr;
		sport = sk->sk_num;
		daddr = sk->sk_rcv_saddr;
		dport = be16_to_cpu(sk->sk_dport);

		if (dport != 80)
			return 0;
		//printk("%pI4[%d] -> %pI4[%d]\n", &saddr, sport, &daddr, dport);
	}
#endif

	if (kern_kprobe_style == DIAG_KPROBE_DQUOT_SET_DQBLK) {
#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE 
		struct qc_dqblk *di = (void *)ORIG_PARAM3(regs);

		if ((di->d_fieldmask & FS_DQ_BHARD) && (di->d_spc_hardlimit == 0))
			return 1;
		
		return 0;
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
		struct fs_disk_quota *di = (void *)ORIG_PARAM3(regs);

		if ((di->d_fieldmask & FS_DQ_BHARD) && (di->d_blk_hardlimit == 0))
			return 1;
		
		return 0;
#else
		struct if_dqblk *di = (void *)ORIG_PARAM4(regs);

		if((di->dqb_valid & QIF_LIMITS) && (di->dqb_bhardlimit == 0))
			return 1;

		return 0;
#endif
	}

	if (kprobe_settings.tgid) {
		struct task_struct *leader = tsk->group_leader ? tsk->group_leader : tsk;

		if (leader->pid != kprobe_settings.tgid)
			return 0;
	}

	if (kprobe_settings.pid) {
		if (tsk->pid != kprobe_settings.pid)
			return 0;
	}

	if (kprobe_settings.comm[0]) {
		struct task_struct *leader = tsk->group_leader ? tsk->group_leader : tsk;

		if (strcmp(leader->comm, kprobe_settings.comm) != 0)
			return 0;
	}

	return 1;
}

static int kprobe_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long flags;
	int sample = 1;

	atomic64_inc_return(&diag_nr_running);
	if (!need_trace(current, regs)) {
		atomic64_dec_return(&diag_nr_running);
		return 0;
	}

	if (kprobe_settings.sample_step > 0) {
		int count = diag_percpu_context[smp_processor_id()]->kprobe.sample_step;

		if (count <= kprobe_settings.sample_step) {
			count += 1;
			diag_percpu_context[smp_processor_id()]->kprobe.sample_step = count;
			sample = 0;
		}
	}

	if (kprobe_settings.dump_style == 0) {
		if (kprobe_settings.raw_stack) {
			struct kprobe_raw_stack_detail *raw_detail;

			if (sample) {
				raw_detail = &diag_percpu_context[smp_processor_id()]->kprobe.kprobe_raw_stack_detail;
				raw_detail->et_type = et_kprobe_raw_detail;
				do_gettimeofday(&raw_detail->tv);
				raw_detail->proc_chains.chains[0][0] = 0;
				dump_proc_chains_simple(current, &raw_detail->proc_chains);
				diag_task_brief(current, &raw_detail->task);
				diag_task_kern_stack(current, &raw_detail->kern_stack);
				diag_task_user_stack(current, &raw_detail->user_stack);

				diag_task_raw_stack(current, &raw_detail->raw_stack);
				diag_variant_buffer_spin_lock(&kprobe_variant_buffer, flags);

				diag_variant_buffer_spin_unlock(&kprobe_variant_buffer, flags);
			}
		} else {
			struct kprobe_detail *detail;

			if (sample) {
				detail = &diag_percpu_context[smp_processor_id()]->kprobe.kprobe_detail;
				detail->et_type = et_kprobe_detail;
				do_gettimeofday(&detail->tv);
				detail->proc_chains.chains[0][0] = 0;
				dump_proc_chains_simple(current, &detail->proc_chains);
				diag_task_brief(current, &detail->task);
				diag_task_kern_stack(current, &detail->kern_stack);
				diag_task_user_stack(current, &detail->user_stack);

				diag_variant_buffer_spin_lock(&kprobe_variant_buffer, flags);

				diag_variant_buffer_reserve(&kprobe_variant_buffer, sizeof(struct kprobe_raw_stack_detail));
				diag_variant_buffer_write_nolock(&kprobe_variant_buffer, detail, sizeof(struct kprobe_raw_stack_detail));
				diag_variant_buffer_seal(&kprobe_variant_buffer);
				
				diag_variant_buffer_spin_unlock(&kprobe_variant_buffer, flags);
			}
		}
		
		
	} else if (kprobe_settings.dump_style == 1) {
		int i = 0;
		struct kprobe_detail *detail;

		detail = &diag_percpu_context[smp_processor_id()]->kprobe.kprobe_detail;
		detail->et_type = et_kprobe_detail;
		do_gettimeofday(&detail->tv);
		detail->proc_chains.chains[0][0] = 0;
		dump_proc_chains_simple(current, &detail->proc_chains);
		diag_task_brief(current, &detail->task);
		diag_task_kern_stack(current, &detail->kern_stack);
		diag_task_user_stack(current, &detail->user_stack);

		for (i = 0; i < 5000; i++)
			msleep(1);

		printk_task_brief(&detail->task);
		dump_stack();
		printk_task_user_stack(&detail->user_stack);
		printk_process_chains(&detail->proc_chains);
	}

	atomic64_dec_return(&diag_nr_running);
	return 0;
}

static int __activate_kprobe(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&kprobe_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	kprobe_alloced = 1;

	unhook_kprobe(&diag_kprobe);
	if (kprobe_settings.func[0] && (strcmp(kprobe_settings.func, "none") != 0)) {
		if (strcmp(kprobe_settings.func, "TCP_SENDMSG") == 0) {
			hook_kprobe(&diag_kprobe, "tcp_sendmsg",
				kprobe_pre, NULL);
			kern_kprobe_style = DIAG_KPROBE_TCP_SENDMSG;
		} if (strcmp(kprobe_settings.func, "DQUOT_SET_DQBLK") == 0) {
#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE 
			hook_kprobe(&diag_kprobe, "dquot_set_dqblk",
				kprobe_pre, NULL);
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
			hook_kprobe(&diag_kprobe, "dquot_set_dqblk",
				kprobe_pre, NULL);
#else
			hook_kprobe(&diag_kprobe, "vfs_set_dqblk",
				kprobe_pre, NULL);
#endif
			kern_kprobe_style = DIAG_KPROBE_DQUOT_SET_DQBLK;
		} else {
			hook_kprobe(&diag_kprobe, kprobe_settings.func,
				kprobe_pre, NULL);
		}
	}

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_kprobe(void)
{
	unhook_kprobe(&diag_kprobe);
	synchronize_sched();
	kern_kprobe_style = DIAG_KPROBE_NONE;

	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0)
		msleep(20);

	clean_data();
}

int activate_kprobe(void)
{
	if (!kprobe_settings.activated)
		kprobe_settings.activated = __activate_kprobe();

	return kprobe_settings.activated;
}

int deactivate_kprobe(void)
{
	if (kprobe_settings.activated)
		__deactivate_kprobe();
	kprobe_settings.activated = 0;

	return 0;
}

static int lookup_syms(void)
{
	return 0;
}

static void jump_init(void)
{
}

long diag_ioctl_kprobe(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_kprobe_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_KPROBE_SET:
		if (kprobe_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_kprobe_settings));
			if (!ret) {
				if (settings.cpus[0]) {
					str_to_cpumask(settings.cpus, &kprobe_cpumask);
				} else {
					kprobe_cpumask = *cpu_possible_mask;
				}
				kprobe_settings = settings;
			}
		}
		break;
	case CMD_KPROBE_SETTINGS:
		memset(&settings, 0, sizeof(settings));
		settings = kprobe_settings;
		cpumask_to_str(&kprobe_cpumask, settings.cpus, 255);
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_kprobe_settings));
		break;
	case CMD_KPROBE_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));

		if (!kprobe_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			ret = copy_to_user_variant_buffer(&kprobe_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("kprobe");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_kprobe_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&kprobe_variant_buffer, 10 * 1024 * 1024);
	jump_init();

	kprobe_cpumask = *cpu_possible_mask;

	if (kprobe_settings.activated)
		kprobe_settings.activated = __activate_kprobe();

	return 0;
}

void diag_kprobe_exit(void)
{
	if (kprobe_settings.activated)
		deactivate_kprobe();
	kprobe_settings.activated = 0;

	msleep(10);
	synchronize_sched();

	destroy_diag_variant_buffer(&kprobe_variant_buffer);
}
