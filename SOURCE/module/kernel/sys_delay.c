/*
 * Linux内核诊断工具--内核态sys-delay功能
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

#include <asm/irq_regs.h>

#include "internal.h"
#include "mm_tree.h"
#include "pub/trace_file.h"
#include "pub/variant_buffer.h"
#include "pub/trace_point.h"
#include "pub/kprobe.h"

#include "uapi/sys_delay.h"

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);

struct diag_sys_delay_settings sys_delay_settings = {
	threshold_ms : 50,
};

static unsigned int sys_delay_alloced;
static struct kprobe kprobe_kvm_check_async_pf_completion;

static struct diag_variant_buffer sys_delay_variant_buffer;
static struct mm_tree mm_tree;

static void __maybe_unused clean_data(void)
{
	cleanup_mm_tree(&mm_tree);
}

static inline void update_sched_time(void)
{
	struct diag_percpu_context *context;
	unsigned long flags;

	if (!sys_delay_settings.activated)
		return;

	local_irq_save(flags);
	context = get_percpu_context();
	context->sys_delay.syscall_start_time = sched_clock();
	context->sys_delay.sys_delay_max_ms = 0;
	local_irq_restore(flags);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
DEFINE_ORIG_FUNC(int, _cond_resched, 1, void *, x);

static void (*orig___cond_resched)(void);
static inline int should_resched(void)
{
	return need_resched() && !(preempt_count() & PREEMPT_ACTIVE);
}

int new__cond_resched(void *x)
{
	update_sched_time();

	if (should_resched()) {
		atomic64_inc_return(&diag_nr_running);
		orig___cond_resched();
		atomic64_dec_return(&diag_nr_running);
		return 1;
	}
	return 0;
}
#else
#include <linux/preempt.h>

#ifndef preempt_disable_notrace
#define preempt_disable_notrace()		barrier()
#endif
#define preempt_enable_no_resched_notrace()	barrier()
#ifndef preempt_enable_notrace
#define preempt_enable_notrace()		barrier()
#endif

static inline void preempt_latency_start(int val) { }
static inline void preempt_latency_stop(int val) { }
static void (*orig___schedule)(bool preempt);

DEFINE_ORIG_FUNC(int, _cond_resched, 1, void *, x);

static void preempt_schedule_common(void)
{
	do {
		/*
		 * Because the function tracer can trace preempt_count_sub()
		 * and it also uses preempt_enable/disable_notrace(), if
		 * NEED_RESCHED is set, the preempt_enable_notrace() called
		 * by the function tracer will call this function again and
		 * cause infinite recursion.
		 *
		 * Preemption must be disabled here before the function
		 * tracer can trace. Break up preempt_disable() into two
		 * calls. One to disable preemption without fear of being
		 * traced. The other to still record the preemption latency,
		 * which can also be traced by the function tracer.
		 */
		preempt_disable_notrace();
		preempt_latency_start(1);
		orig___schedule(true);
		preempt_latency_stop(1);
		preempt_enable_no_resched_notrace();

		/*
		 * Check again in case we missed a preemption opportunity
		 * between schedule and now.
		 */
	} while (need_resched());
}

int new__cond_resched(void *x)
{
	update_sched_time();

#if KERNEL_VERSION(4, 9, 151) <= LINUX_VERSION_CODE && KERNEL_VERSION(4, 10, 10) >= LINUX_VERSION_CODE
	current->cond_resched++;
#endif
	if (should_resched(0)) {
		atomic64_inc_return(&diag_nr_running);
		preempt_schedule_common();
		atomic64_dec_return(&diag_nr_running);
		return 1;
	}
	return 0;
}
#endif

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
	update_sched_time();
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
static void trace_sys_enter_hit(struct pt_regs *regs, long id)
#else
static void trace_sys_enter_hit(void *__data, struct pt_regs *regs, long id)
#endif
{
	update_sched_time();
}

static int task_in_sys_loop(struct diag_percpu_context *context)
{
	int ret = 0;
	int cpu = smp_processor_id();

	if (user_mode(get_irq_regs()))
		return ret;

	if (orig_idle_task(cpu) == current)
		return ret;

	ret = 1;
	return ret;
}

void syscall_timer(struct diag_percpu_context *context)
{
	struct sys_delay_detail *detail;

	if (sys_delay_settings.activated) {
		if (context->sys_delay.sys_delay_in_kvm || user_mode(get_irq_regs()))
			update_sched_time();

		if (!context->sys_delay.sys_delay_in_kvm && task_in_sys_loop(context)) {
			if (need_dump(sys_delay_settings.threshold_ms,
						&context->sys_delay.sys_delay_max_ms, context->sys_delay.syscall_start_time)) {
				unsigned long flags;
				u64 delay_ns = sched_clock() - context->sys_delay.syscall_start_time;

				detail = &diag_percpu_context[smp_processor_id()]->sys_delay_detail;
				detail->et_type = et_sys_delay_detail;
				do_diag_gettimeofday(&detail->tv);
				detail->delay_ns = delay_ns;
				diag_task_brief(current, &detail->task);
				diag_task_kern_stack(current, &detail->kern_stack);
				diag_task_user_stack(current, &detail->user_stack);
				diag_task_raw_stack(current, &detail->raw_stack);
				dump_proc_chains_argv(sys_delay_settings.style, &mm_tree, current, &detail->proc_chains);

				diag_variant_buffer_spin_lock(&sys_delay_variant_buffer, flags);
				diag_variant_buffer_reserve(&sys_delay_variant_buffer, sizeof(struct sys_delay_detail));
				diag_variant_buffer_write_nolock(&sys_delay_variant_buffer, detail, sizeof(struct sys_delay_detail));
				diag_variant_buffer_seal(&sys_delay_variant_buffer);
				diag_variant_buffer_spin_unlock(&sys_delay_variant_buffer, flags);
			}
		} else
			update_sched_time();
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

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
static void trace_sched_process_exit_hit(void *__data, struct task_struct *tsk)
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
static void trace_sched_process_exit_hit(void *__data, struct task_struct *tsk)
#else
static void trace_sched_process_exit_hit(struct task_struct *tsk)
#endif
{
	diag_hook_process_exit_exec(tsk, &mm_tree);
}

struct kvm_vcpu;

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
static void trace_kvm_entry_hit(void *__data, int vcpu_id)
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
static void trace_kvm_entry_hit(void *__data, int vcpu_id)
#else
static void trace_kvm_entry_hit(u32 exit_reason, unsigned long ip)
#endif
{
	struct diag_percpu_context *context = get_percpu_context();

	context->sys_delay.sys_delay_in_kvm = 1;
	update_sched_time();
}

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
static void trace_kvm_exit_hit(void *__data, u32 exit_reason, int vcpu_id, int vmx)
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
static void trace_kvm_exit_hit(void *__data, u32 exit_reason, int vcpu_id, int vmx)
#else
static void trace_kvm_exit_hit(u32 exit_reason, unsigned long ip)
#endif
{
	struct diag_percpu_context *context = get_percpu_context();

	context->sys_delay.sys_delay_in_kvm = 0;
	update_sched_time();
}


static int kprobe_kvm_check_async_pf_completion_pre(struct kprobe *p, struct pt_regs *regs)
{
	update_sched_time();

	return 0;
}

static int __activate_sys_delay(void)
{
	int ret = 0;

	clean_data();

	ret = alloc_diag_variant_buffer(&sys_delay_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	sys_delay_alloced = 1;

	JUMP_CHECK(_cond_resched);

	msleep(10);

	hook_kprobe(&kprobe_kvm_check_async_pf_completion, "kvm_check_async_pf_completion",
				kprobe_kvm_check_async_pf_completion_pre, NULL);
	hook_tracepoint("sys_enter", trace_sys_enter_hit, NULL);
	hook_tracepoint("sched_switch", trace_sched_switch_hit, NULL);
	hook_tracepoint("kvm_entry", trace_kvm_entry_hit, NULL);
	hook_tracepoint("kvm_exit", trace_kvm_exit_hit, NULL);

	if (sys_delay_settings.style == 1) {
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
		hook_tracepoint("sched_process_exec", trace_sched_process_exec_hit, NULL);
#endif
		hook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);
	}
	//get_argv_processes(&mm_tree);

	get_online_cpus();
	mutex_lock(orig_text_mutex);
	JUMP_INSTALL(_cond_resched);
	mutex_unlock(orig_text_mutex);
	put_online_cpus();

	return 1;
out_variant_buffer:
	return 0;
}

int activate_sys_delay(void)
{
	if (!sys_delay_settings.activated)
		sys_delay_settings.activated = __activate_sys_delay();

	return sys_delay_settings.activated;
}

static void __deactivate_sys_delay(void)
{
	msleep(10);

	unhook_tracepoint("sys_enter", trace_sys_enter_hit, NULL);
	unhook_tracepoint("sched_switch", trace_sched_switch_hit, NULL);
	unhook_tracepoint("kvm_entry", trace_kvm_entry_hit, NULL);
	unhook_tracepoint("kvm_exit", trace_kvm_exit_hit, NULL);
	unhook_kprobe(&kprobe_kvm_check_async_pf_completion);

	if (sys_delay_settings.style == 1) {
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
		unhook_tracepoint("sched_process_exec", trace_sched_process_exec_hit, NULL);
#endif
		unhook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);
	}

	get_online_cpus();
	mutex_lock(orig_text_mutex);
	JUMP_REMOVE(_cond_resched);
	mutex_unlock(orig_text_mutex);
	put_online_cpus();

	synchronize_sched();
	msleep(10);
	while (atomic64_read(&diag_nr_running) > 0) {
		msleep(10);
	}

	clean_data();
}

int deactivate_sys_delay(void)
{
	if (sys_delay_settings.activated)
		__deactivate_sys_delay();
	sys_delay_settings.activated = 0;

	return 0;
}

static int do_test(int ms)
{
	int i;

	if (ms > 1000)
		return -EINVAL;

	for (i = 0; i < ms; i++)
		mdelay(1);

	return 0;
}

int sys_delay_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ms = 0;
	int ret = 0;
	struct diag_sys_delay_settings settings;

	switch (id) {
	case DIAG_SYS_DELAY_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_sys_delay_settings)) {
			ret = -EINVAL;
		} else if (sys_delay_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				sys_delay_settings = settings;
			}
		}
		break;
	case DIAG_SYS_DELAY_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_sys_delay_settings)) {
			ret = -EINVAL;
		} else {
			settings = sys_delay_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_SYS_DELAY_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!sys_delay_alloced) {
			ret = -EINVAL;
		} else {
			ret = copy_to_user_variant_buffer(&sys_delay_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("sys-delay");
		}
		break;
	case DIAG_SYS_DELAY_TEST:
		ms = SYSCALL_PARAM1(regs);
		ret = do_test(ms);
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_sys_delay(unsigned int cmd, unsigned long arg)
{
	long ret = -EINVAL;
	struct diag_sys_delay_settings settings;
	struct diag_ioctl_dump_param dump_param;
	int ms = 0;

	switch (cmd) {
	case CMD_SYS_DELAY_SET:
		if (sys_delay_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_sys_delay_settings));
			if (!ret) {
				sys_delay_settings = settings;
			}
		}
		break;
	case CMD_SYS_DELAY_SETTINGS:
		settings = sys_delay_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_sys_delay_settings));
		break;
	case CMD_SYS_DELAY_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));
		if (!sys_delay_alloced) {
			ret = -EINVAL;
		} if (!ret) {
			ret = copy_to_user_variant_buffer(&sys_delay_variant_buffer,
				dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("sys-delay");
		}
		break;
	case CMD_SYS_DELAY_TEST:
		ret = copy_from_user(&ms, (void *)arg, sizeof(int));
		if (!ret) {
			ret = do_test(ms);
		}
		break;
	default:
		break;
	}

	return ret;
}

static int lookup_syms(void)
{
	LOOKUP_SYMS(_cond_resched);
#if KERNEL_VERSION(4, 4, 0) <= LINUX_VERSION_CODE
	LOOKUP_SYMS(__schedule);
#else
	LOOKUP_SYMS(__cond_resched);
#endif

	return 0;
}

static void jump_init(void)
{
	JUMP_INIT(_cond_resched);
}

int diag_sys_delay_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&sys_delay_variant_buffer, 1 * 1024 * 1024);
	jump_init();
	init_mm_tree(&mm_tree);

	if (sys_delay_settings.activated)
		__activate_sys_delay();

	return 0;
}

void diag_sys_delay_exit(void)
{
	if (sys_delay_settings.activated)
		deactivate_sys_delay();
	sys_delay_settings.activated = 0;
	destroy_diag_variant_buffer(&sys_delay_variant_buffer);
}
