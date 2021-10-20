/*
 * Linux内核诊断工具--内核态rw-sem功能
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
#include <linux/mutex.h>
#include <linux/version.h>
#include "mm_tree.h"

#include "internal.h"
#include "pub/trace_file.h"
#include "pub/trace_point.h"
#include "pub/kprobe.h"

#include "uapi/rw_sem.h"

#if defined(UPSTREAM_4_19_32) || defined(XBY_UBUNTU_1604) || defined(UBUNTU_1604)
int diag_rw_sem_init(void)
{
	return 0;
}

void diag_rw_sem_exit(void)
{
}
#else

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_rw_sem_settings rw_sem_settings = {
	.threshold = 200,
};

static int rw_sem_alloced;

static struct diag_variant_buffer rw_sem_variant_buffer;

static struct kprobe kprobe_down_write;
static struct kprobe kprobe_down_write_killable;
static struct kprobe kprobe_up_write;

struct rw_sem_dest {
	struct rw_semaphore *rw_sem;
	u64 lock_time;
	struct list_head list;
};

static struct mm_tree mm_tree;

__maybe_unused static struct radix_tree_root rw_sem_tree;
__maybe_unused static DEFINE_SPINLOCK(tree_lock);
static LIST_HEAD(rw_sem_list);
static DEFINE_MUTEX(mutex_mutex);

static void clean_data(void)
{
	struct rw_sem_dest *desc;
	struct rw_sem_dest *desc_ary[NR_BATCH];
	unsigned long flags;
	int nr_found;
	unsigned long pos = 0;
	int i;

	mutex_lock(&mutex_mutex);
	spin_lock_irqsave(&tree_lock, flags);

	INIT_LIST_HEAD(&rw_sem_list);
	do {
		nr_found = radix_tree_gang_lookup(&rw_sem_tree, (void **)desc_ary, pos, NR_BATCH);

		for (i = 0; i < nr_found; i++) {
			desc = desc_ary[i];
			radix_tree_delete(&rw_sem_tree, (unsigned long)desc->rw_sem);
			pos = (unsigned long)desc->rw_sem + 1;
			INIT_LIST_HEAD(&desc->list);
			list_add_tail(&desc->list, &rw_sem_list);
		}
	} while (nr_found > 0);
	spin_unlock_irqrestore(&tree_lock, flags);

	cleanup_mm_tree(&mm_tree);

	/**
	 * 微妙的并发
	 */
	synchronize_sched();

	while (!list_empty(&rw_sem_list)) {
	struct rw_sem_dest *this = list_first_entry(&rw_sem_list,
										struct rw_sem_dest, list);

		list_del_init(&this->list);
		kfree(this);
		cond_resched();
	}
	mutex_unlock(&mutex_mutex);
}

static __used noinline struct rw_sem_dest *__find_desc(struct rw_semaphore *rw_sem)
{
	struct rw_sem_dest *ret;

	ret = radix_tree_lookup(&rw_sem_tree, (unsigned long)rw_sem);

	return ret;
}

static __used noinline struct rw_sem_dest *find_desc(struct rw_semaphore *rw_sem)
{
	struct rw_sem_dest *ret = NULL;
	unsigned long flags;

	spin_lock_irqsave(&tree_lock, flags);
	ret = __find_desc(rw_sem);
	spin_unlock_irqrestore(&tree_lock, flags);

	return ret;
}

static __used noinline struct rw_sem_dest *find_desc_alloc(struct rw_semaphore *rw_sem)
{
	struct rw_sem_dest *desc;

	if (rw_sem == NULL)
		return NULL;

	desc = radix_tree_lookup(&rw_sem_tree, (unsigned long)rw_sem);
	if (!desc) {
		desc = kmalloc(sizeof(struct rw_sem_dest), GFP_ATOMIC | __GFP_ZERO);
		if (desc) {
			unsigned long flags;
			struct rw_sem_dest *tmp;

			desc->rw_sem = rw_sem;
			INIT_LIST_HEAD(&desc->list);

			spin_lock_irqsave(&tree_lock, flags);
			tmp = radix_tree_lookup(&rw_sem_tree, (unsigned long)rw_sem);
			if (tmp) {
				kfree(desc);
				desc = tmp;
			} else {
				radix_tree_insert(&rw_sem_tree, (unsigned long)rw_sem, desc);
			}
			spin_unlock_irqrestore(&tree_lock, flags);
		}
	}

	return desc;
}

static __used noinline void hook_lock(void *lock)
{
	struct rw_sem_dest *ret;

	ret = find_desc_alloc(lock);
	if (ret) {
		ret->lock_time = sched_clock();
	}
}

static __used noinline void hook_unlock(void *lock, int threshold)
{
	struct rw_sem_dest *tmp;
	u64 delay_ns;
	static struct rw_sem_detail detail;
	u64 now;

	tmp = __find_desc(lock);
	if (!tmp)
		return;
	if (tmp->lock_time == 0)
		return;
	now = sched_clock();
	if (now <= tmp->lock_time)
		return;

	delay_ns = now - tmp->lock_time;
	if (delay_ns > threshold * 1000 * 1000) {
		unsigned long flags;

		diag_variant_buffer_spin_lock(&rw_sem_variant_buffer, flags);
		detail.et_type = et_rw_sem_detail;
		detail.lock = lock;
		detail.delay_ns = delay_ns;
		do_diag_gettimeofday(&detail.tv);
		diag_task_brief(current, &detail.task);
		diag_task_kern_stack(current, &detail.kern_stack);
		diag_task_user_stack(current, &detail.user_stack);
		dump_proc_chains_argv(rw_sem_settings.style, &mm_tree, current, &detail.proc_chains);
		diag_variant_buffer_reserve(&rw_sem_variant_buffer, sizeof(struct rw_sem_detail));
		diag_variant_buffer_write_nolock(&rw_sem_variant_buffer, &detail, sizeof(struct rw_sem_detail));
		diag_variant_buffer_seal(&rw_sem_variant_buffer);
		diag_variant_buffer_spin_unlock(&rw_sem_variant_buffer, flags);
	}
	tmp->lock_time = 0;
}

static int kprobe_down_write_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct rw_semaphore *sem = (void *)ORIG_PARAM1(regs);

	hook_lock(sem);

	return 0;
}

static int kprobe_down_write_killable_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct rw_semaphore *sem = (void *)ORIG_PARAM1(regs);

	hook_lock(sem);

	return 0;
}

static int kprobe_up_write_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct rw_semaphore *sem = (void *)ORIG_PARAM1(regs);

	hook_unlock(sem, rw_sem_settings.threshold);

	return 0;
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

static int __activate_rw_sem(void)
{
	int ret;

	ret = alloc_diag_variant_buffer(&rw_sem_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	rw_sem_alloced = 1;

	if (rw_sem_settings.style == 1) {
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
		hook_tracepoint("sched_process_exec", trace_sched_process_exec_hit, NULL);
#endif
		hook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);
	}

	hook_kprobe(&kprobe_down_write, "down_write",
				kprobe_down_write_pre, NULL);
	hook_kprobe(&kprobe_down_write_killable, "down_write_killable",
				kprobe_down_write_killable_pre, NULL);
	hook_kprobe(&kprobe_up_write, "up_write",
				kprobe_up_write_pre, NULL);

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_rw_sem(void)
{
	if (rw_sem_settings.style == 1) {
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
		unhook_tracepoint("sched_process_exec", trace_sched_process_exec_hit, NULL);
#endif
		unhook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);
	}

	unhook_kprobe(&kprobe_down_write);
	unhook_kprobe(&kprobe_down_write_killable);
	unhook_kprobe(&kprobe_up_write);

	clean_data();

	synchronize_sched();
	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0) {
		msleep(10);
	}
}

int activate_rw_sem(void)
{
	if (!rw_sem_settings.activated)
		rw_sem_settings.activated = __activate_rw_sem();

	return rw_sem_settings.activated;
}

int deactivate_rw_sem(void)
{
	if (rw_sem_settings.activated)
		__deactivate_rw_sem();
	rw_sem_settings.activated = 0;

	return 0;
}

int rw_sem_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int i, ms;
	int ret = 0;
	struct diag_rw_sem_settings settings;
	static DECLARE_RWSEM(sem);

	switch (id) {
	case DIAG_RW_SEM_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_rw_sem_settings)) {
			ret = -EINVAL;
		} else if (rw_sem_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				rw_sem_settings = settings;
			}
		}
		break;
	case DIAG_RW_SEM_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_rw_sem_settings)) {
			ret = -EINVAL;
		} else {
			settings = rw_sem_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_RW_SEM_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!rw_sem_alloced) {
			ret = -EINVAL;
		} else {
			ret = copy_to_user_variant_buffer(&rw_sem_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("rw-sem");
		}
		break;
	case DIAG_RW_SEM_TEST:
		ms = SYSCALL_PARAM1(regs);

		if (ms <= 0 || ms > 20000) {
			ret = -EINVAL;
		} else {
			down_write(&sem);
			for (i = 0; i < ms; i++)
				mdelay(1);
			up_write(&sem);
			down_write(&sem);
			mdelay(1);
			up_write(&sem);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
			ret = down_write_killable(&sem);
			for (i = 0; i < ms; i++)
				mdelay(1);
			up_write(&sem);
#endif
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_rw_sem(unsigned int cmd, unsigned long arg)
{
	int i, ms;
	int ret = 0;
	struct diag_rw_sem_settings settings;
	struct diag_ioctl_dump_param dump_param;
	static DECLARE_RWSEM(sem);

	switch (cmd) {
	case CMD_RW_SEM_SET:
		if (rw_sem_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_rw_sem_settings));
			if (!ret) {
				rw_sem_settings = settings;
			}
		}
		break;
	case CMD_RW_SEM_SETTINGS:
		settings = rw_sem_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_rw_sem_settings));
		break;
	case CMD_RW_SEM_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));

		if (!rw_sem_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			ret = copy_to_user_variant_buffer(&rw_sem_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("rw-sem");
		}
		break;
	case CMD_RW_SEM_TEST:
		ret = copy_from_user(&ms, (void *)arg, sizeof(int));

		if (!ret) {
			if (ms <= 0 || ms > 20000) {
				ret = -EINVAL;
			} else {
				down_write(&sem);
				for (i = 0; i < ms; i++)
					mdelay(1);
				up_write(&sem);
				down_write(&sem);
				mdelay(1);
				up_write(&sem);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
				ret = down_write_killable(&sem);
				for (i = 0; i < ms; i++)
					mdelay(1);
				up_write(&sem);
#endif
			}
		}
		break;
	default:
		ret = -ENOSYS;
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

int diag_rw_sem_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_mm_tree(&mm_tree);
	init_diag_variant_buffer(&rw_sem_variant_buffer, 1 * 1024 * 1024);
	jump_init();

	if (rw_sem_settings.activated)
		rw_sem_settings.activated = __activate_rw_sem();

	return 0;
}

void diag_rw_sem_exit(void)
{
	if (rw_sem_settings.activated)
		deactivate_rw_sem();
	rw_sem_settings.activated = 0;
	destroy_diag_variant_buffer(&rw_sem_variant_buffer);
}
#endif
