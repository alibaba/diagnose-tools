/*
 * Linux内核诊断工具--内核态uprobe功能
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
#include "pub/uprobe.h"

#include "uapi/uprobe.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_uprobe_settings uprobe_settings;

static unsigned int kern_uprobe_alloced;
static struct cpumask kern_uprobe_cpumask;
static struct diag_uprobe diag_uprobe;

static int kern_uprobe_raw_stack = 0;

static struct diag_variant_buffer kern_uprobe_variant_buffer;

static void __maybe_unused clean_data(void)
{
	//
}

static int need_trace(struct task_struct *tsk, struct pt_regs *regs)
{
	int cpu;

	if (!uprobe_settings.activated)
		return 0;

	cpu = smp_processor_id();

	if (!cpumask_test_cpu(cpu, &kern_uprobe_cpumask))
		return 0;

	if (uprobe_settings.tgid && tsk->tgid != uprobe_settings.tgid) {
		return 0;
	}

	if (uprobe_settings.pid && tsk->pid != uprobe_settings.pid) {
		return 0;
	}

	if (uprobe_settings.comm[0]) {
		struct task_struct *leader = tsk->group_leader ? tsk->group_leader : tsk;

		if (strcmp(leader->comm, uprobe_settings.comm) != 0)
			return 0;
	}

	return 1;
}

void diag_save_user_params(struct pt_regs *regs,
	struct diag_uprobe_param_define *params,
	struct diag_uprobe_param_value *values)
{
	int i;
	unsigned long param_idx;
	const char __user *buf;
	unsigned long len;

	for (i = 0; i < DIAG_UPROBE_MAX_PARAMS; i++) {
		len = 0;

		values[i].type = params[i].type;

		switch (params[i].type) {
		case 1:
			values[i].int_value = 0;
			param_idx = params[i].param_idx;
			switch (param_idx) {
			case 1:
				values[i].int_value = ORIG_PARAM1(regs);
				break;
			case 2:
				values[i].int_value = ORIG_PARAM2(regs);
				break;
			case 3:
				values[i].int_value = ORIG_PARAM3(regs);
				break;
			case 4:
				values[i].int_value = ORIG_PARAM4(regs);
				break;
			case 5:
				values[i].int_value = ORIG_PARAM5(regs);
				break;
			}
			break;
		case 3:
			/**
			 * fall down
			 */
		case 2:
			param_idx = params[i].param_idx;
			buf = NULL;
			switch (param_idx) {
			case 1:
				buf = (void *)ORIG_PARAM1(regs);
				break;
			case 2:
				buf = (void *)ORIG_PARAM2(regs);
				break;
			case 3:
				buf = (void *)ORIG_PARAM3(regs);
				break;
			case 4:
				buf = (void *)ORIG_PARAM4(regs);
				break;
			case 5:
				buf = (void *)ORIG_PARAM5(regs);
				break;
			}
			if (params[i].type == 2 && buf && params[i].size == -255) {
				len = strnlen_user(buf, 255);
			} else if (params[i].size > 0) {
				len = params[i].size;
			} else {
				param_idx = 0 - params[i].size;
				switch (param_idx) {
				case 1:
					len = ORIG_PARAM1(regs);
					break;
				case 2:
					len = ORIG_PARAM2(regs);
					break;
				case 3:
					len = ORIG_PARAM3(regs);
					break;
				case 4:
					len = ORIG_PARAM4(regs);
					break;
				case 5:
					len = ORIG_PARAM5(regs);
					break;
				}
			}
			if (!copy_from_user(values[i].buf.data, buf, len))
				values[i].buf.len = len;
			else
				values[i].buf.len = 0;
			break;
		default:
			values[i].int_value = 0;
			break;
		}
	}
}

static int kern_uprobe_handler(struct uprobe_consumer *self, struct pt_regs *regs)
{
	unsigned long flags;
	int sample = 1;

	if (!need_trace(current, regs)) {
		return 0;
	}

	atomic64_inc_return(&diag_nr_running);

	if (uprobe_settings.sample_step > 0) {
		int count = diag_percpu_context[smp_processor_id()]->uprobe.sample_step;

		if (count < uprobe_settings.sample_step) {
			count += 1;
			diag_percpu_context[smp_processor_id()]->uprobe.sample_step = count;
			sample = 0;
		} else {
			diag_percpu_context[smp_processor_id()]->uprobe.sample_step = 0;
		}
	}

	if (kern_uprobe_raw_stack) {
		struct uprobe_raw_stack_detail *raw_detail;
	
		if (sample) {
			raw_detail = &diag_percpu_context[smp_processor_id()]->uprobe.uprobe_raw_stack_detail;
			raw_detail->et_type = et_uprobe_raw_detail;
			do_gettimeofday(&raw_detail->tv);
			raw_detail->proc_chains.chains[0][0] = 0;
			dump_proc_chains_simple(current, &raw_detail->proc_chains);
			diag_task_brief(current, &raw_detail->task);
			diag_task_user_stack(current, &raw_detail->user_stack);
			diag_task_raw_stack(current, &raw_detail->raw_stack);
			diag_save_user_params(regs, uprobe_settings.params, raw_detail->values);
	
			diag_variant_buffer_spin_lock(&kern_uprobe_variant_buffer, flags);
			diag_variant_buffer_reserve(&kern_uprobe_variant_buffer, sizeof(struct uprobe_raw_stack_detail));
			diag_variant_buffer_write_nolock(&kern_uprobe_variant_buffer, raw_detail, sizeof(struct uprobe_raw_stack_detail));
			diag_variant_buffer_seal(&kern_uprobe_variant_buffer);
			diag_variant_buffer_spin_unlock(&kern_uprobe_variant_buffer, flags);
		}
	} else {
		struct uprobe_detail *detail;

		if (sample) {
			detail = &diag_percpu_context[smp_processor_id()]->uprobe.uprobe_detail;
			detail->et_type = et_uprobe_detail;
			do_gettimeofday(&detail->tv);
			detail->proc_chains.chains[0][0] = 0;
			dump_proc_chains_simple(current, &detail->proc_chains);
			diag_task_brief(current, &detail->task);
			diag_task_user_stack(current, &detail->user_stack);
			diag_save_user_params(regs, uprobe_settings.params, detail->values);

			diag_variant_buffer_spin_lock(&kern_uprobe_variant_buffer, flags);
			diag_variant_buffer_reserve(&kern_uprobe_variant_buffer, sizeof(struct uprobe_detail));
			diag_variant_buffer_write_nolock(&kern_uprobe_variant_buffer, detail, sizeof(struct uprobe_detail));
			diag_variant_buffer_seal(&kern_uprobe_variant_buffer);
			diag_variant_buffer_spin_unlock(&kern_uprobe_variant_buffer, flags);
		}
	}

	atomic64_dec_return(&diag_nr_running);

	return 0;
}

static int __activate_uprobe(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&kern_uprobe_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	kern_uprobe_alloced = 1;

	unhook_uprobe(&diag_uprobe);
	if (uprobe_settings.fd)
		hook_uprobe(uprobe_settings.fd, uprobe_settings.offset, &diag_uprobe);

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_uprobe(void)
{
	unhook_uprobe(&diag_uprobe);
	synchronize_sched();
	uprobe_settings.fd = 0;
	uprobe_settings.offset = 0;

	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0)
		msleep(20);

	clean_data();
}

int activate_uprobe(void)
{
	if (!uprobe_settings.activated)
		uprobe_settings.activated = __activate_uprobe();

	return uprobe_settings.activated;
}

int deactivate_uprobe(void)
{
	if (uprobe_settings.activated)
		__deactivate_uprobe();
	uprobe_settings.activated = 0;

	return 0;
}

static int lookup_syms(void)
{
	return 0;
}

static void jump_init(void)
{
}

int uprobe_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	static struct diag_uprobe_settings settings;

	switch (id) {
	case DIAG_UPROBE_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_uprobe_settings)) {
			ret = -EINVAL;
		} else if (uprobe_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				if (settings.cpus[0]) {
					str_to_cpumask(settings.cpus, &kern_uprobe_cpumask);
				} else {
					kern_uprobe_cpumask = *cpu_possible_mask;
				}
				uprobe_settings = settings;
			}
		}
		break;
	case DIAG_UPROBE_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		memset(&settings, 0, sizeof(settings));
		if (user_buf_len != sizeof(struct diag_uprobe_settings)) {
			ret = -EINVAL;
		} else {
			settings = uprobe_settings;
			if (diag_uprobe.register_status) {
				settings.offset = diag_uprobe.offset;
				strncpy(settings.file_name, diag_uprobe.file_name, 255);
			}
			cpumask_to_str(&kern_uprobe_cpumask, settings.cpus, 255);
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_UPROBE_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!kern_uprobe_alloced) {
			ret = -EINVAL;
		} else {
			ret = copy_to_user_variant_buffer(&kern_uprobe_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("uprobe");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_uprobe(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	static struct diag_uprobe_settings settings;
	static struct diag_ioctl_dump_param dump_param;
	static DEFINE_MUTEX(lock);

	switch (cmd) {
		case CMD_UPROBE_SET:
			if (uprobe_settings.activated) {
				ret = -EBUSY;
			} else {
				mutex_lock(&lock);
				memset(&settings, 0, sizeof(struct diag_uprobe_settings));
				ret = copy_from_user(&settings, (void *)arg, sizeof(settings));
				if (!ret) {
					if (settings.cpus[0]) {
						str_to_cpumask(settings.cpus, &kern_uprobe_cpumask);
					} else {
						kern_uprobe_cpumask = *cpu_possible_mask;
					}
					uprobe_settings = settings;
				}
				mutex_unlock(&lock);
			}
			break;
		case CMD_UPROBE_SETTINGS:
			mutex_lock(&lock);
			memset(&settings, 0, sizeof(struct diag_uprobe_settings));
			settings = uprobe_settings;
			if (diag_uprobe.register_status) {
				settings.offset = diag_uprobe.offset;
				strncpy(settings.file_name, diag_uprobe.file_name, 255);
			}
			cpumask_to_str(&kern_uprobe_cpumask, settings.cpus, 255);
			ret = copy_to_user((void *)arg, &settings, sizeof(settings));
			mutex_unlock(&lock);
			break;
		case CMD_UPROBE_DUMP:
			mutex_lock(&lock);
			memset(&dump_param, 0, sizeof(struct diag_ioctl_dump_param));
			ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));

			if (!kern_uprobe_alloced) {
				ret = -EINVAL;
			} else if (!ret) {
				ret = copy_to_user_variant_buffer(&kern_uprobe_variant_buffer,
						dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
				record_dump_cmd("uprobe");
			}
			mutex_unlock(&lock);
			break;
		default:
			ret = -ENOSYS;
			break;
	}

	return ret;
}

int diag_uprobe_init(void)
{
	diag_uprobe.uprobe_consumer.handler = kern_uprobe_handler;
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&kern_uprobe_variant_buffer, 10 * 1024 * 1024);
	jump_init();

	kern_uprobe_cpumask = *cpu_possible_mask;

	if (uprobe_settings.activated)
		uprobe_settings.activated = __activate_uprobe();

	return 0;
}

void diag_uprobe_exit(void)
{
	if (uprobe_settings.activated)
		deactivate_uprobe();
	uprobe_settings.activated = 0;

	msleep(10);
	synchronize_sched();

	destroy_diag_variant_buffer(&kern_uprobe_variant_buffer);
}
#endif

