/*
 * Linux内核诊断工具--内核态utilization功能
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/version.h>
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
#if KERNEL_VERSION(4, 19, 0) <= LINUX_VERSION_CODE
#include <linux/sched/mm.h>
#endif
#include <asm/irq_regs.h>

#include "internal.h"
#include "mm_tree.h"
#include "pub/trace_file.h"
#include "pub/variant_buffer.h"
#include "pub/trace_point.h"
#include "pub/cgroup.h"

#include "uapi/utilization.h"

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)) || (KERNEL_VERSION(4, 20, 0) <= LINUX_VERSION_CODE) \
	|| defined(CENTOS_3_10_693) || defined(CENTOS_3_10_957) \
	|| defined(CENTOS_3_10_862) || defined(CENTOS_3_10_1062) \
	|| defined(CENTOS_3_10_1127)
/**
 * 只支持7u
 */
#else

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
#define diag_record_stamp ali_reserved5
#define diag_exec ali_reserved6
#define diag_wild ali_reserved8
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
#define diag_record_stamp rh_reserved5
#define diag_exec rh_reserved6
#define diag_wild rh_reserved8
#endif

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_utilization_settings utilization_settings;

static unsigned long utilization_alloced;
static struct cpumask utilization_cpumask;

static struct mm_tree mm_tree;

#define MAX_TASK_COUNT 300000

static DEFINE_PER_CPU(char [CGROUP_NAME_LEN], isolate_cgroup_name);
static DEFINE_PER_CPU(struct cgroup *, isolate_cgroup_ptr);
static struct diag_variant_buffer utilization_variant_buffer;

static void __maybe_unused clean_data(void)
{
	struct task_struct *tsk;

	rcu_read_lock();

	for_each_process(tsk) {
		tsk->diag_exec = 0;
		tsk->diag_wild = 0;
	}

	rcu_read_unlock();
}

static void dump_task_info(struct task_struct *tsk)
{
	struct utilization_detail *detail;
	unsigned long flags;
	unsigned long exec = 0, pages = 0, wild = 0;
	unsigned long size = 0, resident = 0, shared = 0, text = 0, data = 0;
	struct mm_struct *mm;

	if (!utilization_settings.activated || !utilization_settings.sample) {
		return;
	}
	if (!tsk)
		return;

	detail = &diag_percpu_context[smp_processor_id()]->utilization_detail;

	mm = get_task_mm(tsk);
	if (mm) {
		size = orig_task_statm(mm, &shared, &text, &data, &resident);
		pages = resident;
		mmput(mm);
	}

	exec = xchg(&tsk->diag_exec, 0);
	wild = xchg(&tsk->diag_wild, 0);
	if (exec == 0 && pages == 0 && wild == 0)
		return;

	detail->et_type = et_utilization_detail;
	do_gettimeofday(&detail->tv);
	diag_task_brief(tsk, &detail->task);
		if (utilization_settings.style == 2) {
		dump_proc_chains_simple(tsk, &detail->proc_chains);
	} else {
		dump_proc_chains_argv(utilization_settings.style, &mm_tree, tsk, &detail->proc_chains);
	}
	detail->exec = exec;
	detail->pages = pages;
	detail->wild = wild;

	diag_variant_buffer_spin_lock(&utilization_variant_buffer, flags);
	diag_variant_buffer_reserve(&utilization_variant_buffer, sizeof(struct utilization_detail));
	diag_variant_buffer_write_nolock(&utilization_variant_buffer, detail, sizeof(struct utilization_detail));
	diag_variant_buffer_seal(&utilization_variant_buffer);
	diag_variant_buffer_spin_unlock(&utilization_variant_buffer, flags);
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
	u64 delta_ns = 0;
	u64 now;
	struct task_struct *tsk;
	int cpu = smp_processor_id();
	struct cgroup *isolate = per_cpu(isolate_cgroup_ptr, cpu);
	now = sched_clock();

	if (!utilization_settings.activated || !utilization_settings.sample) {
		prev->diag_record_stamp = next->diag_record_stamp = 0;
		return;
	}

	if (cpumask_test_cpu(cpu, &utilization_cpumask)) {
		tsk = prev;
		if (tsk->diag_record_stamp) {
			delta_ns = now - tsk->diag_record_stamp;
			tsk->diag_record_stamp = 0;
		}
		if (delta_ns > 0) {
			if (!thread_group_leader(tsk)) {
				tsk = rcu_dereference(tsk->group_leader);
			}

			if (tsk) {
				xadd(&tsk->diag_exec, delta_ns);
			}
		}
	} else if (isolate) {
		struct cgroup *cgroup;

		tsk = prev;
		cgroup = diag_cpuacct_cgroup_tsk(tsk);
		if (cgroup != isolate) {
			if (tsk->diag_record_stamp) {
				delta_ns = now - tsk->diag_record_stamp;
				tsk->diag_record_stamp = 0;

				if (!thread_group_leader(tsk)) {
					tsk = rcu_dereference(tsk->group_leader);
				}

				if (tsk) {
					xadd(&tsk->diag_wild, delta_ns);
				}
			}
		}
	}

	tsk = next;
	tsk->diag_record_stamp = now;
}

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
static void trace_sched_process_fork_hit(void *__data, struct task_struct *parent, struct task_struct *child)
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
static void trace_sched_process_fork_hit(void *__data, struct task_struct *parent, struct task_struct *child)
#else
static void trace_sched_process_fork_hit(struct task_struct *parent, struct task_struct *child)
#endif
{
	child->diag_record_stamp = 0;
	child->diag_exec = 0;
	child->diag_wild = 0;
}

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
__maybe_unused static void trace_sched_process_exit_hit(void *__data, struct task_struct *tsk)
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
__maybe_unused static void trace_sched_process_exit_hit(void *__data, struct task_struct *tsk)
#else
__maybe_unused static void trace_sched_process_exit_hit(struct task_struct *tsk)
#endif
{
	if (!tsk)
		return;

	dump_task_info(tsk);

	if (utilization_settings.style == 1) {
		diag_hook_process_exit_exec(tsk, &mm_tree);
	}
}

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
__maybe_unused static void trace_sched_process_exec_hit(void *__data,
	struct task_struct *tsk,
	pid_t old_pid,
	struct linux_binprm *bprm)
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
__maybe_unused static void trace_sched_process_exec_hit(void *__data,
	struct task_struct *tsk,
	pid_t old_pid,
	struct linux_binprm *bprm)
#endif
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
{
	atomic64_inc_return(&diag_nr_running);
	diag_hook_exec(bprm, &mm_tree);
	atomic64_dec_return(&diag_nr_running);
}
#endif

void utilization_timer(struct diag_percpu_context *context)
{
	u64 now = sched_clock();
	u64 delta_ns = 0;
	struct task_struct *tsk = current;
	int cpu;

	if (!utilization_settings.activated || !utilization_settings.sample) {
		tsk->diag_record_stamp = 0;
		return;
	}

	cpu = smp_processor_id();
	if (!cpumask_test_cpu(cpu, &utilization_cpumask))
		return;

	if (tsk->diag_record_stamp) {
		struct task_struct *leader;

		delta_ns = now - tsk->diag_record_stamp;
		leader = rcu_dereference(tsk->group_leader);
		if (leader) {
			xadd(&leader->diag_exec, delta_ns);
		}
	}
	tsk->diag_record_stamp = now;
}

static int __activate_utilization(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&utilization_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	utilization_alloced = 1;

	clean_data();

	hook_tracepoint("sched_switch", trace_sched_switch_hit, NULL);
	hook_tracepoint("sched_process_fork", trace_sched_process_fork_hit, NULL);
	hook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);
	if (utilization_settings.style == 1) {
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
		hook_tracepoint("sched_process_exec", trace_sched_process_exec_hit, NULL);
#endif
	}
	//get_argv_processes(&mm_tree);

	utilization_settings.activated = 1;

	return utilization_settings.activated;
out_variant_buffer:
	return 0;
}

int activate_utilization(void)
{
	int ret = 0;

	if (!utilization_settings.activated)
		ret = __activate_utilization();

	return ret;
}

static int __deactivate_utilization(void)
{
	int ret = 0;

	unhook_tracepoint("sched_switch", trace_sched_switch_hit, NULL);
	unhook_tracepoint("sched_process_fork", trace_sched_process_fork_hit, NULL);
	unhook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);

	if (utilization_settings.style == 1) {
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
		unhook_tracepoint("sched_process_exec", trace_sched_process_exec_hit, NULL);
#endif
	}

	synchronize_sched();
	msleep(10);
	while (atomic64_read(&diag_nr_running) > 0) {
		msleep(10);
	}

	clean_data();

	return ret;
}

int deactivate_utilization(void)
{
	int ret = 0;

	if (utilization_settings.activated) {
		__deactivate_utilization();
	} else {
		ret = -EAGAIN;
	}
	utilization_settings.activated = 0;

	return 0;
}

static int do_dump(void)
{
	static DEFINE_MUTEX(mutex);
	int ret = 0;
	struct task_struct *tsk;

	mutex_lock(&mutex);
	rcu_read_lock();

	for_each_process(tsk) {
		dump_task_info(tsk);
	}

	rcu_read_unlock();
	mutex_unlock(&mutex);

	return ret;
}

long diag_ioctl_utilization(unsigned int cmd, unsigned long arg)
{
	int ret = -EINVAL;
	struct diag_utilization_settings settings;
	struct diag_ioctl_dump_param dump_param;
	struct diag_ioctl_utilization_isolate isolate_param;
	int sample;

	switch (cmd) {
	case CMD_UTILIZATION_SET:
		if (utilization_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_utilization_settings));
			if (!ret) {
				if (settings.cpus[0]) {
					str_to_cpumask(settings.cpus, &utilization_cpumask);
				} else {
					utilization_cpumask = *cpu_possible_mask;
				}
				utilization_settings = settings;
			}
		}
		break;
	case CMD_UTILIZATION_SETTINGS:
		settings = utilization_settings;
		cpumask_to_str(&utilization_cpumask, settings.cpus, 512);
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_utilization_settings));
		break;
	case CMD_UTILIZATION_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));

		if (!utilization_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			do_dump();
			ret = copy_to_user_variant_buffer(&utilization_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("utilization");
		}
		break;
	case CMD_UTILIZATION_ISOLATE:
		ret = copy_from_user(&isolate_param, (void *)arg, sizeof(struct diag_ioctl_utilization_isolate));
		
		if (!ret) {
			if (isolate_param.user_buf_len >= CGROUP_NAME_LEN)
				isolate_param.user_buf_len = CGROUP_NAME_LEN - 1;
			if (isolate_param.cpu >= num_possible_cpus())
				ret = -EINVAL;
			else {
				char *isolate = per_cpu(isolate_cgroup_name, isolate_param.cpu);
				struct cpuacct *cpuacct;
				struct cgroup *cgroup;
				
				ret = copy_from_user(isolate, isolate_param.user_buf, isolate_param.user_buf_len);
				isolate[CGROUP_NAME_LEN - 1] = 0;

				cpuacct = diag_find_cpuacct_name(isolate);
				cgroup = cpuacct_to_cgroup(cpuacct);
				per_cpu(isolate_cgroup_ptr, isolate_param.cpu) = cgroup;
			}
		}
		break;
	case CMD_UTILIZATION_SAMPLE:
		ret = copy_from_user(&sample, (void *)arg, sizeof(int));
		if (!ret) {
			utilization_settings.sample = sample;
		}
		break;
	default:
		break;
	}

	return ret;
}

static int lookup_syms(void)
{
	return 0;
}

static void jump_init(void)
{
}

int diag_utilization_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&utilization_variant_buffer, 5 * 1024 * 1024);
	jump_init();

	utilization_cpumask = *cpu_possible_mask;

	if (utilization_settings.activated)
		utilization_settings.activated = __activate_utilization();

	return 0;
}

void diag_utilization_exit(void)
{
	if (utilization_settings.activated)
		deactivate_utilization();
	utilization_settings.activated = 0;

	destroy_diag_variant_buffer(&utilization_variant_buffer);
}
#endif
