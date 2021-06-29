/*
 * Linux内核诊断工具--内核态mutex-monitor功能
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

#if LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 32)
#include <asm/mutex.h>
#endif

#include "internal.h"
#include "pub/trace_file.h"
#include "pub/trace_point.h"

#include "uapi/mutex_monitor.h"

#if defined(UPSTREAM_4_19_32) || defined(XBY_UBUNTU_1604) || defined(UBUNTU_1604)
int diag_mutex_init(void)
{
	return 0;
}

void diag_mutex_exit(void)
{
}
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0) || defined(CENTOS_8U)
/*
 * Optimistic trylock that only works in the uncontended case. Make sure to
 * follow with a __mutex_trylock() before failing.
 */
static __always_inline bool __mutex_trylock_fast(struct mutex *lock)
{
	unsigned long curr = (unsigned long)current;
	unsigned long zero = 0UL;

	if (atomic_long_try_cmpxchg_acquire(&lock->owner, &zero, curr))
		return true;

	return false;
}

static __always_inline bool __mutex_unlock_fast(struct mutex *lock)
{
	unsigned long curr = (unsigned long)current;

	if (atomic_long_cmpxchg_release(&lock->owner, curr, 0UL) == curr)
		return true;

	return false;
}

#elif LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
/*
 * In the DEBUG case we are using the "NULL fastpath" for mutexes,
 * which forces all calls into the slowpath:
 */
#ifdef CONFIG_DEBUG_MUTEXES
# include "mutex-debug.h"
# include <asm-generic/mutex-null.h>
/*
 * Must be 0 for the debug case so we do not do the unlock outside of the
 * wait_lock region. debug_mutex_unlock() will do the actual unlock in this
 * case.
 */
# undef __mutex_slowpath_needs_to_unlock
# define  __mutex_slowpath_needs_to_unlock()	0
#else
# include "mutex.h"
# include <asm/mutex.h>
#endif
#else
/*
 * Mutexes: blocking mutual exclusion locks
 *
 * started by Ingo Molnar:
 *
 *  Copyright (C) 2004, 2005, 2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *
 * This file contains mutex debugging related internal declarations,
 * prototypes and inline functions, for the CONFIG_DEBUG_MUTEXES case.
 * More details are in kernel/mutex-debug.c.
 */

/*
 * This must be called with lock->wait_lock held.
 */
extern void debug_mutex_lock_common(struct mutex *lock,
				    struct mutex_waiter *waiter);
extern void debug_mutex_wake_waiter(struct mutex *lock,
				    struct mutex_waiter *waiter);
extern void debug_mutex_free_waiter(struct mutex_waiter *waiter);
extern void debug_mutex_add_waiter(struct mutex *lock,
				   struct mutex_waiter *waiter,
				   struct thread_info *ti);
extern void mutex_remove_waiter(struct mutex *lock, struct mutex_waiter *waiter,
				struct thread_info *ti);
extern void debug_mutex_unlock(struct mutex *lock);
extern void debug_mutex_init(struct mutex *lock, const char *name,
			     struct lock_class_key *key);

static inline void mutex_set_owner(struct mutex *lock)
{
	lock->owner = current_thread_info();
}

static inline void mutex_clear_owner(struct mutex *lock)
{
	lock->owner = NULL;
}
#endif

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_mutex_monitor_settings mutex_monitor_settings = {
	.threshold_mutex = 1000,
	.threshold_rw_sem = 200,
};

static int mutex_monitor_alloced;

static struct diag_variant_buffer mutex_monitor_variant_buffer;

DEFINE_ORIG_FUNC(void, mutex_lock, 1, struct mutex *, lock);
DEFINE_ORIG_FUNC(void, mutex_unlock, 1, struct mutex *, lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
static void (*orig___mutex_lock_slowpath)(struct mutex *lock);
static void (*orig___mutex_unlock_slowpath)(struct mutex *lock, unsigned long ip);
#else
static void (*orig___mutex_lock_slowpath)(atomic_t *lock_count);
static void (*orig___mutex_unlock_slowpath)(atomic_t *lock_count);
#endif

static asmlinkage void (*orig_call_rwsem_wake)(struct rw_semaphore *sem);
static asmlinkage void (*orig_call_rwsem_down_read_failed)(struct rw_semaphore *sem);
static asmlinkage struct rw_semaphore *(*orig_call_rwsem_down_write_failed)(struct rw_semaphore *sem);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
static asmlinkage struct rw_semaphore *(*orig_call_rwsem_down_write_failed_killable)(struct rw_semaphore *sem);
#endif

DEFINE_ORIG_FUNC(void, down_read, 1, struct rw_semaphore *, sem);
DEFINE_ORIG_FUNC(void, up_read, 1, struct rw_semaphore *, sem);
DEFINE_ORIG_FUNC(void, down_write, 1, struct rw_semaphore *, sem);
DEFINE_ORIG_FUNC(void, up_write, 1, struct rw_semaphore *, sem);
DEFINE_ORIG_FUNC(int, down_write_trylock, 1, struct rw_semaphore *, sem);
DEFINE_ORIG_FUNC(int, down_read_trylock, 1, struct rw_semaphore *, sem);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
DEFINE_ORIG_FUNC(int, down_write_killable, 1, struct rw_semaphore *, sem);
#endif

struct mutex_desc {
	struct mutex *mutex;
	u64 lock_time;
	struct list_head list;
};

static struct mm_tree mm_tree;

__maybe_unused static struct radix_tree_root mutex_tree;
__maybe_unused static DEFINE_SPINLOCK(tree_lock);
static LIST_HEAD(mutex_list);
static DEFINE_MUTEX(mutex_mutex);

static void clean_data(void)
{
	struct mutex_desc *desc;
	struct mutex_desc *desc_ary[NR_BATCH];
	unsigned long flags;
	int nr_found;
	unsigned long pos = 0;
	int i;

	mutex_lock(&mutex_mutex);
	spin_lock_irqsave(&tree_lock, flags);

	INIT_LIST_HEAD(&mutex_list);
	do {
		nr_found = radix_tree_gang_lookup(&mutex_tree, (void **)desc_ary, pos, NR_BATCH);

		for (i = 0; i < nr_found; i++) {
			desc = desc_ary[i];
			radix_tree_delete(&mutex_tree, (unsigned long)desc->mutex);
			pos = (unsigned long)desc->mutex + 1;
			INIT_LIST_HEAD(&desc->list);
			list_add_tail(&desc->list, &mutex_list);
		}
	} while (nr_found > 0);
	spin_unlock_irqrestore(&tree_lock, flags);

	cleanup_mm_tree(&mm_tree);

	/**
	 * 微妙的并发
	 */
	synchronize_sched();

	while (!list_empty(&mutex_list)) {
        struct mutex_desc *this = list_first_entry(&mutex_list,
										struct mutex_desc, list);

		list_del_init(&this->list);
		kfree(this);
		cond_resched();
	}
	mutex_unlock(&mutex_mutex);
}

static __used noinline struct mutex_desc *__find_desc(struct mutex *mutex)
{
	struct mutex_desc *ret;

	ret = radix_tree_lookup(&mutex_tree, (unsigned long)mutex);

	return ret;
}

static __used noinline struct mutex_desc *find_desc(struct mutex *mutex)
{
	struct mutex_desc *ret = NULL;
	unsigned long flags;

	spin_lock_irqsave(&tree_lock, flags);
	ret = __find_desc(mutex);
	spin_unlock_irqrestore(&tree_lock, flags);

	return ret;
}

static __used noinline struct mutex_desc *find_desc_alloc(struct mutex *mutex)
{
	struct mutex_desc *desc;

	if (mutex == NULL)
		return NULL;

	desc = radix_tree_lookup(&mutex_tree, (unsigned long)mutex);
	if (!desc) {
		desc = kmalloc(sizeof(struct mutex_desc), GFP_ATOMIC | __GFP_ZERO);
		if (desc) {
			unsigned long flags;
			struct mutex_desc *tmp;

			desc->mutex = mutex;
			INIT_LIST_HEAD(&desc->list);

			spin_lock_irqsave(&tree_lock, flags);
			tmp = radix_tree_lookup(&mutex_tree, (unsigned long)mutex);
			if (tmp) {
				kfree(desc);
				desc = tmp;
			} else {
				radix_tree_insert(&mutex_tree, (unsigned long)mutex, desc);
			}
			spin_unlock_irqrestore(&tree_lock, flags);
		}
	}

	return desc;
}

static __used noinline void hook_lock(void *lock)
{
	struct mutex_desc *ret;

	ret = find_desc_alloc(lock);
	if (ret) {
		ret->lock_time = sched_clock();
	}
}

static __used noinline void hook_unlock(void *lock, int threshold)
{
	struct mutex_desc *tmp;
	u64 delay_ns;
	static struct mutex_monitor_detail detail;

	tmp = __find_desc(lock);
	if (!tmp)
		return;
	if (tmp->lock_time == 0)
		return;
	delay_ns = sched_clock() - tmp->lock_time;
	if (delay_ns > threshold * 1000 * 1000) {
		unsigned long flags;

		diag_variant_buffer_spin_lock(&mutex_monitor_variant_buffer, flags);
		detail.et_type = et_mutex_monitor_detail;
		detail.lock = lock;
		detail.delay_ns = delay_ns;
		do_diag_gettimeofday(&detail.tv);
		diag_task_brief(current, &detail.task);
		diag_task_kern_stack(current, &detail.kern_stack);
		diag_task_user_stack(current, &detail.user_stack);
		dump_proc_chains_argv(mutex_monitor_settings.style, &mm_tree, current, &detail.proc_chains);
		diag_variant_buffer_reserve(&mutex_monitor_variant_buffer, sizeof(struct mutex_monitor_detail));
		diag_variant_buffer_write_nolock(&mutex_monitor_variant_buffer, &detail, sizeof(struct mutex_monitor_detail));
		diag_variant_buffer_seal(&mutex_monitor_variant_buffer);
		diag_variant_buffer_spin_unlock(&mutex_monitor_variant_buffer, flags);
	}
	tmp->lock_time = 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
static void diag_mutex_lock(struct mutex *lock)
{
	might_sleep();

	if (!__mutex_trylock_fast(lock))
		orig___mutex_lock_slowpath(lock);
	hook_lock(lock);
}
#else
static void diag_mutex_lock(struct mutex *lock)
{
	might_sleep();
	/*
	 * The locking fastpath is the 1->0 transition from
	 * 'unlocked' into 'locked' state.
	 */
	__mutex_fastpath_lock(&lock->count, *orig___mutex_lock_slowpath);
	mutex_set_owner(lock);
	hook_lock(lock);
}
#endif

void new_mutex_lock(struct mutex *lock)
{
	atomic64_inc_return(&diag_nr_running);
	diag_mutex_lock(lock);
	atomic64_dec_return(&diag_nr_running);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
static void diag_mutex_unlock(struct mutex *lock)
{
	hook_unlock(lock, mutex_monitor_settings.threshold_mutex);
#ifndef CONFIG_DEBUG_LOCK_ALLOC
	if (__mutex_unlock_fast(lock))
		return;
#endif
	orig___mutex_unlock_slowpath(lock, _RET_IP_);
}
#else
static void diag_mutex_unlock(struct mutex *lock)
{
	/*
	 * The unlocking fastpath is the 0->1 transition from 'locked'
	 * into 'unlocked' state:
	 */
#ifndef CONFIG_DEBUG_MUTEXES
	/*
	 * When debugging is enabled we must not clear the owner before time,
	 * the slow path will always be taken, and that clears the owner field
	 * after verifying that it was indeed current.
	 */
	mutex_clear_owner(lock);
#endif
	hook_unlock(lock, mutex_monitor_settings.threshold_mutex);
	__mutex_fastpath_unlock(&lock->count, *orig___mutex_unlock_slowpath);
}
#endif

void new_mutex_unlock(struct mutex *lock)
{
	atomic64_inc_return(&diag_nr_running);
	diag_mutex_unlock(lock);
	atomic64_dec_return(&diag_nr_running);
}

#define RWSEM_READER_OWNED	((struct task_struct *)1UL)

void asmlinkage wrap_call_rwsem_down_read_failed(struct rw_semaphore *sem)
{
	orig_call_rwsem_down_read_failed(sem);
}

void asmlinkage wrap_call_rwsem_wake(struct rw_semaphore *sem)
{
	orig_call_rwsem_wake(sem);
}

struct rw_semaphore * asmlinkage wrap_call_rwsem_down_write_failed(struct rw_semaphore *sem)
{
	return orig_call_rwsem_down_write_failed(sem);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
struct rw_semaphore * asmlinkage wrap_call_rwsem_down_write_failed_killable(struct rw_semaphore *sem)
{
	return orig_call_rwsem_down_write_failed_killable(sem);
}
#endif

static inline void diag___down_read(struct rw_semaphore *sem)
{
	asm volatile("# beginning down_read\n\t"
		     LOCK_PREFIX _ASM_INC "(%1)\n\t"
			 "  jns        1f\n"
		     /* adds 0x00000001 */
			"  pushq %%rdi	\n\t"
        	"  pushq %%rsi	\n\t"
        	"  pushq %%rcx	\n\t"
        	"  pushq %%r8	\n\t"
        	"  pushq %%r9	\n\t"
        	"  pushq %%r10	\n\t"
        	"  pushq %%r11	\n\t"
			"  movq %%rax,%%rdi	\n\t"
		    "  call rwsem_down_read_failed\n"
			"  popq %%r11	\n\t"
        	"  popq %%r10	\n\t"
        	"  popq %%r9	\n\t"
        	"  popq %%r8	\n\t"
        	"  popq %%rcx	\n\t"
        	"  popq %%rsi	\n\t"
        	"  popq %%rdi	\n\t"
		     "1:\n\t"
		     "# ending down_read\n\t"
		     : "+m" (sem->count)
		     : "a" (sem)
		     : "memory", "cc");
}

/*
 * unlock after reading
 */
static inline void diag___up_read(struct rw_semaphore *sem)
{
	long tmp;
	asm volatile("# beginning __up_read\n\t"
		     LOCK_PREFIX "  xadd      %1,(%2)\n\t"
		     /* subtracts 1, returns the old value */
		     "  jns        1f\n\t"
			"  pushq %%rdi	\n\t"
        	"  pushq %%rsi	\n\t"
        	"  pushq %%rcx	\n\t"
        	"  pushq %%r8	\n\t"
        	"  pushq %%r9	\n\t"
        	"  pushq %%r10	\n\t"
        	"  pushq %%r11	\n\t"
			"  movq %%rax,%%rdi	\n\t"
		     "  call rwsem_wake\n" /* expects old value in %edx */
			"  popq %%r11	\n\t"
        	"  popq %%r10	\n\t"
        	"  popq %%r9	\n\t"
        	"  popq %%r8	\n\t"
        	"  popq %%rcx	\n\t"
        	"  popq %%rsi	\n\t"
        	"  popq %%rdi	\n\t"
		     "1:\n"
		     "# ending __up_read\n"
		     : "+m" (sem->count), "=d" (tmp)
		     : "a" (sem), "1" (-RWSEM_ACTIVE_READ_BIAS)
		     : "memory", "cc");
}

/*
 * unlock after writing
 */
static inline void diag___up_write(struct rw_semaphore *sem)
{
	long tmp;
	asm volatile("# beginning __up_write\n\t"
		     LOCK_PREFIX "  xadd      %1,(%2)\n\t"
		     /* subtracts 0xffff0001, returns the old value */
		     "  jns        1f\n\t"
			"  pushq %%rdi	\n\t"
        	"  pushq %%rsi	\n\t"
        	"  pushq %%rcx	\n\t"
        	"  pushq %%r8	\n\t"
        	"  pushq %%r9	\n\t"
        	"  pushq %%r10	\n\t"
        	"  pushq %%r11	\n\t"
			"  movq %%rax,%%rdi	\n\t"
			 "  call rwsem_wake\n" /* expects old value in %edx */
			"  popq %%r11	\n\t"
        	"  popq %%r10	\n\t"
        	"  popq %%r9	\n\t"
        	"  popq %%r8	\n\t"
        	"  popq %%rcx	\n\t"
        	"  popq %%rsi	\n\t"
        	"  popq %%rdi	\n\t"
		     "1:\n\t"
		     "# ending __up_write\n"
		     : "+m" (sem->count), "=d" (tmp)
		     : "a" (sem), "1" (-RWSEM_ACTIVE_WRITE_BIAS)
		     : "memory", "cc");
}

#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
/*
 * All writes to owner are protected by WRITE_ONCE() to make sure that
 * store tearing can't happen as optimistic spinners may read and use
 * the owner value concurrently without lock. Read from owner, however,
 * may not need READ_ONCE() as long as the pointer value is only used
 * for comparison and isn't being dereferenced.
 */
static inline void rwsem_set_owner(struct rw_semaphore *sem)
{
	WRITE_ONCE(sem->owner, current);
}

static inline void rwsem_clear_owner(struct rw_semaphore *sem)
{
	WRITE_ONCE(sem->owner, NULL);
}

static inline void rwsem_set_reader_owned(struct rw_semaphore *sem)
{
	/*
	 * We check the owner value first to make sure that we will only
	 * do a write to the rwsem cacheline when it is really necessary
	 * to minimize cacheline contention.
	 */
	if (sem->owner != RWSEM_READER_OWNED)
		WRITE_ONCE(sem->owner, RWSEM_READER_OWNED);
}

static inline bool rwsem_owner_is_writer(struct task_struct *owner)
{
	return owner && owner != RWSEM_READER_OWNED;
}

static inline bool rwsem_owner_is_reader(struct task_struct *owner)
{
	return owner == RWSEM_READER_OWNED;
}
#else
static inline void rwsem_set_owner(struct rw_semaphore *sem)
{
}

static inline void rwsem_clear_owner(struct rw_semaphore *sem)
{
}

static inline void rwsem_set_reader_owned(struct rw_semaphore *sem)
{
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
static inline void diag___down_write(struct rw_semaphore *sem)
{
	____down_write(sem, "rwsem_down_write_failed");
}
#else

/*
 * lock for writing
 */
static inline void diag___down_write_nested(struct rw_semaphore *sem, int subclass)
{
	long tmp;
	asm volatile("# beginning down_write\n\t"
		     LOCK_PREFIX "  xadd      %1,(%2)\n\t"
		     /* adds 0xffff0001, returns the old value */
		     "  test " __ASM_SEL(%w1,%k1) "," __ASM_SEL(%w1,%k1) "\n\t"
		     /* was the active mask 0 before? */
		     "  jz        1f\n"
			"  pushq %%rdi	\n\t"
        	"  pushq %%rsi	\n\t"
        	"  pushq %%rcx	\n\t"
        	"  pushq %%r8	\n\t"
        	"  pushq %%r9	\n\t"
        	"  pushq %%r10	\n\t"
        	"  pushq %%r11	\n\t"
			"  movq %%rax,%%rdi	\n\t"
		     "  call rwsem_down_write_failed\n"
			"  popq %%r11	\n\t"
        	"  popq %%r10	\n\t"
        	"  popq %%r9	\n\t"
        	"  popq %%r8	\n\t"
        	"  popq %%rcx	\n\t"
        	"  popq %%rsi	\n\t"
        	"  popq %%rdi	\n\t"
		     "1:\n"
		     "# ending down_write"
		     : "+m" (sem->count), "=d" (tmp)
		     : "a" (sem), "1" (RWSEM_ACTIVE_WRITE_BIAS)
		     : "memory", "cc");
}

static inline void diag___down_write(struct rw_semaphore *sem)
{
	diag___down_write_nested(sem, 0);
}
#endif

static void diag_down_read(struct rw_semaphore *sem)
{
	might_sleep();
	rwsem_acquire_read(&sem->dep_map, 0, 0, _RET_IP_);

	LOCK_CONTENDED(sem, __down_read_trylock, diag___down_read);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	rwsem_set_reader_owned(sem);
#endif
	hook_lock(sem);
}

static void diag_up_read(struct rw_semaphore *sem)
{
	hook_unlock(sem, mutex_monitor_settings.threshold_rw_sem);
	rwsem_release(&sem->dep_map, 1, _RET_IP_);

	diag___up_read(sem);
}

static void diag_down_write(struct rw_semaphore *sem)
{
	might_sleep();
	rwsem_acquire(&sem->dep_map, 0, 0, _RET_IP_);

	LOCK_CONTENDED(sem, __down_write_trylock, diag___down_write);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	rwsem_set_owner(sem);
#endif
	hook_lock(sem);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
static inline int diag___down_write_killable(struct rw_semaphore *sem)
{
	if (IS_ERR(____down_write(sem, "rwsem_down_write_failed_killable")))
		return -EINTR;

	return 0;
}

static int diag_down_write_killable(struct rw_semaphore *sem)
{
	might_sleep();
	rwsem_acquire(&sem->dep_map, 0, 0, _RET_IP_);

	if (LOCK_CONTENDED_RETURN(sem, __down_write_trylock, diag___down_write_killable)) {
		rwsem_release(&sem->dep_map, 1, _RET_IP_);
		return -EINTR;
	}

	rwsem_set_owner(sem);
	hook_lock(sem);

	return 0;
}
#endif

/*
 * trylock for writing -- returns 1 if successful, 0 if contention
 */
int diag_down_write_trylock(struct rw_semaphore *sem)
{
	int ret = __down_write_trylock(sem);

	if (ret == 1) {
		rwsem_acquire(&sem->dep_map, 0, 1, _RET_IP_);
		hook_lock(sem);
	}

	return ret;
}

/*
 * trylock for reading -- returns 1 if successful, 0 if contention
 */
int diag_down_read_trylock(struct rw_semaphore *sem)
{
	int ret = __down_read_trylock(sem);

	if (ret == 1) {
		rwsem_acquire_read(&sem->dep_map, 0, 1, _RET_IP_);
		hook_lock(sem);
	}
	return ret;
}

static void diag_up_write(struct rw_semaphore *sem)
{
	hook_unlock(sem, mutex_monitor_settings.threshold_rw_sem);
	rwsem_release(&sem->dep_map, 1, _RET_IP_);

	rwsem_clear_owner(sem);
	diag___up_write(sem);
}

void new_down_read(struct rw_semaphore *sem)
{
	atomic64_inc_return(&diag_nr_running);
	diag_down_read(sem);
	atomic64_dec_return(&diag_nr_running);
}

void new_up_read(struct rw_semaphore *sem)
{
	atomic64_inc_return(&diag_nr_running);
	diag_up_read(sem);
	atomic64_dec_return(&diag_nr_running);
}

void new_down_write(struct rw_semaphore *sem)
{
	atomic64_inc_return(&diag_nr_running);
	diag_down_write(sem);
	atomic64_dec_return(&diag_nr_running);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
int new_down_write_killable(struct rw_semaphore *sem)
{
	int ret = 0;

	atomic64_inc_return(&diag_nr_running);
	ret = diag_down_write_killable(sem);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}
#endif

void new_up_write(struct rw_semaphore *sem)
{
	atomic64_inc_return(&diag_nr_running);
	diag_up_write(sem);
	atomic64_dec_return(&diag_nr_running);
}

int new_down_write_trylock(struct rw_semaphore *sem)
{
	int ret = 0;

	atomic64_inc_return(&diag_nr_running);
	ret = diag_down_write_trylock(sem);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

int new_down_read_trylock(struct rw_semaphore *sem)
{
	int ret = 0;

	atomic64_inc_return(&diag_nr_running);
	ret = diag_down_read_trylock(sem);
	atomic64_dec_return(&diag_nr_running);

	return ret;
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

static int __activate_mutex_monitor(void)
{
	int ret;

	ret = alloc_diag_variant_buffer(&mutex_monitor_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	mutex_monitor_alloced = 1;

	JUMP_CHECK(mutex_lock);
	JUMP_CHECK(mutex_unlock);

	if (mutex_monitor_settings.style == 1) {
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
		hook_tracepoint("sched_process_exec", trace_sched_process_exec_hit, NULL);
#endif
		hook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);
	}
	//get_argv_processes(&mm_tree);

	get_online_cpus();
	new_mutex_lock(orig_text_mutex);
	JUMP_INSTALL(mutex_lock);
	JUMP_INSTALL(mutex_unlock);
	JUMP_INSTALL(down_read);
	JUMP_INSTALL(up_read);
	JUMP_INSTALL(down_write);
	JUMP_INSTALL(up_write);
	JUMP_INSTALL(down_write_trylock);
	JUMP_INSTALL(down_read_trylock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	JUMP_INSTALL(down_write_killable);
#endif
	new_mutex_unlock(orig_text_mutex);
	put_online_cpus();

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_mutex_monitor(void)
{
	if (mutex_monitor_settings.style == 1) {
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
		unhook_tracepoint("sched_process_exec", trace_sched_process_exec_hit, NULL);
#endif
		unhook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);
	}

	get_online_cpus();
	new_mutex_lock(orig_text_mutex);
	JUMP_REMOVE(mutex_lock);
	JUMP_REMOVE(mutex_unlock);
	JUMP_REMOVE(down_read);
	JUMP_REMOVE(up_read);
	JUMP_REMOVE(down_write);
	JUMP_REMOVE(up_write);
	JUMP_REMOVE(down_write_trylock);
	JUMP_REMOVE(down_read_trylock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	JUMP_REMOVE(down_write_killable);
#endif
	new_mutex_unlock(orig_text_mutex);
	put_online_cpus();

	clean_data();

	synchronize_sched();
	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0) {
		msleep(10);
	}
}

int activate_mutex_monitor(void)
{
	if (!mutex_monitor_settings.activated)
		mutex_monitor_settings.activated = __activate_mutex_monitor();

	return mutex_monitor_settings.activated;
}

int deactivate_mutex_monitor(void)
{
	if (mutex_monitor_settings.activated)
		__deactivate_mutex_monitor();
	mutex_monitor_settings.activated = 0;

	return 0;
}

int mutex_monitor_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int i, ms;
	int ret = 0;
	struct diag_mutex_monitor_settings settings;
	static DEFINE_MUTEX(lock);
	static DECLARE_RWSEM(sem);

	switch (id) {
	case DIAG_MUTEX_MONITOR_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_mutex_monitor_settings)) {
			ret = -EINVAL;
		} else if (mutex_monitor_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				mutex_monitor_settings = settings;
			}
		}
		break;
	case DIAG_MUTEX_MONITOR_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_mutex_monitor_settings)) {
			ret = -EINVAL;
		} else {
			settings = mutex_monitor_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_MUTEX_MONITOR_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!mutex_monitor_alloced) {
			ret = -EINVAL;
		} else {
			ret = copy_to_user_variant_buffer(&mutex_monitor_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("mutex-monitor");
		}
		break;
	case DIAG_MUTEX_MONITOR_TEST:
		ms = SYSCALL_PARAM1(regs);

		if (ms <= 0 || ms > 20000) {
			ret = -EINVAL;
		} else {
			mutex_lock(&lock);
			for (i = 0; i < ms; i++)
				mdelay(1);
			mutex_unlock(&lock);
			down_write(&sem);
			for (i = 0; i < ms; i++)
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

long diag_ioctl_mutex_monitor(unsigned int cmd, unsigned long arg)
{
	int i, ms;
	int ret = 0;
	struct diag_mutex_monitor_settings settings;
	struct diag_ioctl_dump_param dump_param;
	static DEFINE_MUTEX(lock);
	static DECLARE_RWSEM(sem);

	switch (cmd) {
	case CMD_MUTEX_MONITOR_SET:
		if (mutex_monitor_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_mutex_monitor_settings));
			if (!ret) {
				mutex_monitor_settings = settings;
			}
		}
		break;
	case CMD_MUTEX_MONITOR_SETTINGS:
		settings = mutex_monitor_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_mutex_monitor_settings));
		break;
	case CMD_MUTEX_MONITOR_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));

		if (!mutex_monitor_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			ret = copy_to_user_variant_buffer(&mutex_monitor_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("mutex-monitor");
		}
		break;
	case CMD_MUTEX_MONITOR_TEST:
		ret = copy_from_user(&ms, (void *)arg, sizeof(int));

		if (!ret) {
			if (ms <= 0 || ms > 20000) {
				ret = -EINVAL;
			} else {
				mutex_lock(&lock);
				for (i = 0; i < ms; i++)
					mdelay(1);
				mutex_unlock(&lock);
				down_write(&sem);
				for (i = 0; i < ms; i++)
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
	LOOKUP_SYMS(__mutex_lock_slowpath);

	LOOKUP_SYMS(call_rwsem_wake);
	LOOKUP_SYMS(call_rwsem_down_read_failed);
	LOOKUP_SYMS(call_rwsem_down_write_failed);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	LOOKUP_SYMS(call_rwsem_down_write_failed_killable);
#endif
	LOOKUP_SYMS(down_read);
	LOOKUP_SYMS(up_read);
	LOOKUP_SYMS(down_write);
	LOOKUP_SYMS(up_write);
	LOOKUP_SYMS(down_write_trylock);
	LOOKUP_SYMS(down_read_trylock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	LOOKUP_SYMS(down_write_killable);
#endif

	orig___mutex_unlock_slowpath = (void *)diag_kallsyms_lookup_name("__mutex_unlock_slowpath.isra.0");
	if (orig___mutex_unlock_slowpath == NULL)
		orig___mutex_unlock_slowpath = (void *)diag_kallsyms_lookup_name("__mutex_unlock_slowpath.isra.12");
	if (orig___mutex_unlock_slowpath == NULL)
		orig___mutex_unlock_slowpath = (void *)diag_kallsyms_lookup_name("__mutex_unlock_slowpath.isra.14");
	if (orig___mutex_unlock_slowpath == NULL)
		orig___mutex_unlock_slowpath = (void *)diag_kallsyms_lookup_name("__mutex_unlock_slowpath.isra.15");
	if (orig___mutex_unlock_slowpath == NULL)
		orig___mutex_unlock_slowpath = (void *)diag_kallsyms_lookup_name("__mutex_unlock_slowpath.isra.16");
	if (orig___mutex_unlock_slowpath == NULL)
		orig___mutex_unlock_slowpath = (void *)diag_kallsyms_lookup_name("__mutex_unlock_slowpath.isra.18");
	if (orig___mutex_unlock_slowpath == NULL)
		orig___mutex_unlock_slowpath = (void *)diag_kallsyms_lookup_name("__mutex_unlock_slowpath.isra.17");
	if (orig___mutex_unlock_slowpath == NULL)
		orig___mutex_unlock_slowpath = (void *)diag_kallsyms_lookup_name("__mutex_unlock_slowpath.isra.19");
	if (orig___mutex_unlock_slowpath == NULL)
		orig___mutex_unlock_slowpath = (void *)diag_kallsyms_lookup_name("__mutex_unlock_slowpath");
	if (orig___mutex_unlock_slowpath == NULL)
		return -EINVAL;

	LOOKUP_SYMS(mutex_lock);
	LOOKUP_SYMS(mutex_unlock);

	return 0;
}

static void jump_init(void)
{
	JUMP_INIT(mutex_lock);
	JUMP_INIT(mutex_unlock);
	JUMP_INIT(down_read);
	JUMP_INIT(up_read);
	JUMP_INIT(down_write);
	JUMP_INIT(up_write);
	JUMP_INIT(down_write_trylock);
	JUMP_INIT(down_read_trylock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	JUMP_INIT(down_write_killable);
#endif
}

int diag_mutex_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_mm_tree(&mm_tree);
	init_diag_variant_buffer(&mutex_monitor_variant_buffer, 1 * 1024 * 1024);
	jump_init();

	if (mutex_monitor_settings.activated)
		mutex_monitor_settings.activated = __activate_mutex_monitor();

	return 0;
}

void diag_mutex_exit(void)
{
	if (mutex_monitor_settings.activated)
		deactivate_mutex_monitor();
	mutex_monitor_settings.activated = 0;
	destroy_diag_variant_buffer(&mutex_monitor_variant_buffer);
}
#endif
