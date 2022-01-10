/*
 * Linux内核诊断工具--内核态throttle-delay功能
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Xiongwei Jiang <xiongwei.jiang@linux.alibaba.com>
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
#include <linux/tracepoint.h>
#include <trace/events/irq.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <trace/events/napi.h>
#include <linux/rtc.h>
#include <linux/time.h>
#include <linux/version.h>
#include <linux/net.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <net/tcp.h>
#include <linux/stop_machine.h>
#include <linux/smp.h>
#include <asm/thread_info.h>

#include "internal.h"
#include "mm_tree.h"
#include "kern_internal.h"
#include "pub/trace_file.h"
#include "pub/trace_point.h"

#include "uapi/throttle_delay.h"

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0) && \
	LINUX_VERSION_CODE <= KERNEL_VERSION(4, 20, 0) \
	&& !defined(UBUNTU_1604)

#if defined(ALIOS_4000_009)
static unsigned long *get_last_dequeued_addr(struct task_struct *p)
{
	/**
	 * task_stack_page, but not end_of_stack !!
	 */
	return task_stack_page(p) + sizeof(struct thread_info) + 32;
}
#else
#if  defined(CENTOS_8U)
#define diag_last_dequeued rh_reserved2
#elif KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
#define diag_last_dequeued ali_reserved3
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
#define diag_last_dequeued rh_reserved3
#else
#define diag_last_dequeued rh_reserved[0]
#endif

static unsigned long *get_last_dequeued_addr(struct task_struct *p)
{
	return &p->diag_last_dequeued;
}

#endif

#define entity_is_task(se)      (!se->my_q)

//static struct kprobe kprobe_dequeue_entity;
//static int (*orig_throttle_cfs_rq)(struct cfs_rq *cfs_rq);


/* task group related information */
struct rt_bandwidth {
	/* nests inside the rq lock: */
	raw_spinlock_t	rt_runtime_lock;
	ktime_t			rt_period;
	u64				rt_runtime;
	struct hrtimer	rt_period_timer;
	unsigned int	rt_period_active;
};
struct cfs_bandwidth {
#ifdef CONFIG_CFS_BANDWIDTH
	raw_spinlock_t lock;
	ktime_t period;
	u64 quota, runtime;
	s64 hierarchical_quota;
	u64 runtime_expires;
	int expires_seq;
        
	u8 idle;
	u8 period_active;
	u8 slack_started;
	struct hrtimer period_timer, slack_timer;
	struct list_head throttled_cfs_rq;
        
	/* statistics */
	int nr_periods, nr_throttled;
	u64 throttled_time;
#endif
};



struct task_group {
        struct cgroup_subsys_state css;

#ifdef CONFIG_FAIR_GROUP_SCHED
        /* schedulable entities of this group on each cpu */
        struct sched_entity **se;
        /* runqueue "owned" by this group on each cpu */
        struct cfs_rq **cfs_rq;
        unsigned long shares;
        int bvt;
#ifdef  CONFIG_SMP
        /*
         * load_avg can be heavily contended at clock tick time, so put
         * it in its own cacheline separated from the fields above which
         * will also be accessed at each tick.
         */
        atomic_long_t load_avg ____cacheline_aligned;
#endif
#endif

#ifdef CONFIG_RT_GROUP_SCHED
        struct sched_rt_entity **rt_se;
        struct rt_rq **rt_rq;

        struct rt_bandwidth rt_bandwidth;
#endif

        struct rcu_head rcu;
        struct list_head list;

        struct task_group *parent;
        struct list_head siblings;
        struct list_head children;

#ifdef CONFIG_SCHED_AUTOGROUP
        struct autogroup *autogroup;
#endif

        struct cfs_bandwidth cfs_bandwidth;

        ALI_HOTFIX_RESERVE(1)
        ALI_HOTFIX_RESERVE(2)
        ALI_HOTFIX_RESERVE(3)
        ALI_HOTFIX_RESERVE(4)
};

/* CFS-related fields in a runqueue */
struct cfs_rq {
        struct load_weight load;
        unsigned int nr_running, h_nr_running;

        u64 exec_clock;
        u64 min_vruntime;
#ifndef CONFIG_64BIT
        u64 min_vruntime_copy;
#endif

        struct rb_root tasks_timeline;
        struct rb_node *rb_leftmost;

        /*
         * 'curr' points to currently running entity on this cfs_rq.
         * It is set to NULL otherwise (i.e when none are currently running).
         */
        struct sched_entity *curr, *next, *last, *skip;

        /* Effective bvt type */
        int ebvt;

#ifdef  CONFIG_SCHED_DEBUG
        unsigned int nr_spread_over;
#endif

#ifdef CONFIG_SMP
        /*
         * CFS load tracking
         */
        struct sched_avg avg;
        u64 runnable_load_sum;
        unsigned long runnable_load_avg;
#ifdef CONFIG_FAIR_GROUP_SCHED
        unsigned long tg_load_avg_contrib;
#endif
        atomic_long_t removed_load_avg, removed_util_avg;
#ifndef CONFIG_64BIT
        u64 load_last_update_time_copy;
#endif

#ifdef CONFIG_FAIR_GROUP_SCHED
        /*
         *   h_load = weight * f(tg)
         *
         * Where f(tg) is the recursive weight fraction assigned to
         * this group.
         */
        unsigned long h_load;
        u64 last_h_load_update;
        struct sched_entity *h_load_next;
#endif /* CONFIG_FAIR_GROUP_SCHED */
#endif /* CONFIG_SMP */

#ifdef CONFIG_FAIR_GROUP_SCHED
        struct rq *rq;  /* cpu runqueue to which this cfs_rq is attached */

        /*
         * leaf cfs_rqs are those that hold tasks (lowest schedulable entity in
         * a hierarchy). Non-leaf lrqs hold other higher schedulable entities
         * (like users, containers etc.)
         *
         * leaf_cfs_rq_list ties together list of leaf cfs_rq's in a cpu. This
         * list is used during load balance.
         */
        int on_list;
        struct list_head leaf_cfs_rq_list;
        struct task_group *tg;  /* group that "owns" this runqueue */
        struct list_head batch_node;
        unsigned int nr_batch_running;  /* only tasks, no group se */

#ifdef CONFIG_CFS_BANDWIDTH
        int runtime_enabled;
        int expires_seq;
        u64 runtime_expires;
        s64 runtime_remaining;

        u64 throttled_clock, throttled_clock_task;
        u64 throttled_clock_task_time;
        int throttled, throttle_count;
        struct list_head throttled_list;
#endif /* CONFIG_CFS_BANDWIDTH */

#ifdef CONFIG_CFS_BVT
        u64 kick_delay_nc;
        u64 throttled_clock_nc;
        u64 throttled_time_nc;          /* total time */
        u64 throttled_time_nc_max;      /* single max time */
        int throttled_nc;
        struct list_head throttled_node_nc;
#endif
#endif /* CONFIG_FAIR_GROUP_SCHED */

        unsigned long   nr_uninterruptible;

        ALI_HOTFIX_RESERVE(1)
        ALI_HOTFIX_RESERVE(2)
        ALI_HOTFIX_RESERVE(3)
        ALI_HOTFIX_RESERVE(4)
};

/*
 * This is the priority-queue data structure of the RT scheduling class:
 */
struct rt_prio_array {
        DECLARE_BITMAP(bitmap, MAX_RT_PRIO+1); /* include 1 bit for delimiter */
        struct list_head queue[MAX_RT_PRIO];
};

/* Real-Time classes' related field in a runqueue: */
struct rt_rq { 
	struct rt_prio_array active;
	unsigned int rt_nr_running;
	unsigned int rr_nr_running;
#if defined CONFIG_SMP || defined CONFIG_RT_GROUP_SCHED
	struct {
		int curr; /* highest queued rt task prio */
#ifdef CONFIG_SMP
		int next; /* next highest */
#endif
	} highest_prio;
#endif 
#ifdef CONFIG_SMP
        unsigned long rt_nr_migratory;
        unsigned long rt_nr_total;
        int overloaded;
        struct plist_head pushable_tasks;
#endif /* CONFIG_SMP */
        int rt_queued;
        
        int rt_throttled;
        u64 rt_time;
        u64 rt_runtime;
        /* Nests inside the rq lock: */
        raw_spinlock_t rt_runtime_lock;

#ifdef CONFIG_RT_GROUP_SCHED
        unsigned long rt_nr_boosted;

        struct rq *rq;
        struct task_group *tg;
#endif

        unsigned long   nr_uninterruptible;
};

/* Deadline class' related fields in a runqueue */
struct dl_rq {
        /* runqueue is an rbtree, ordered by deadline */
        struct rb_root rb_root;
        struct rb_node *rb_leftmost;

        unsigned long dl_nr_running;

#ifdef CONFIG_SMP
        /*
         * Deadline values of the currently executing and the
         * earliest ready task on this rq. Caching these facilitates
         * the decision wether or not a ready but not running task
         * should migrate somewhere else.
         */
        struct {
                u64 curr;
                u64 next;
        } earliest_dl;

        unsigned long dl_nr_migratory;
        int overloaded;

        /*
         * Tasks on this rq that can be pushed away. They are kept in
         * an rb-tree, ordered by tasks' deadlines, with caching
         * of the leftmost (earliest deadline) element.
         */
        struct rb_root pushable_dl_tasks_root;
        struct rb_node *pushable_dl_tasks_leftmost;
#else
        struct dl_bw dl_bw;
#endif
};

#if 0
typedef void (*smp_call_func_t)(void *info);
struct call_single_data {
        struct llist_node llist;
        smp_call_func_t func;
        void *info;
        unsigned int flags;
};
#endif

/*
 * This is the main, per-CPU runqueue data structure.
 *
 * Locking rule: those places that want to lock multiple runqueues
 * (such as the load balancing or the thread migration code), lock
 * acquire operations must be ordered by ascending &runqueue.
 */
struct rq {
        /* runqueue lock: */
        raw_spinlock_t lock;

        /*
         * nr_running and cpu_load should be in the same cacheline because
         * remote CPUs use both these fields when doing load calculation.
         */
        unsigned int nr_running;
#ifdef CONFIG_NUMA_BALANCING
        unsigned int nr_numa_running;
        unsigned int nr_preferred_running;
#endif
        #define CPU_LOAD_IDX_MAX 5
        unsigned long cpu_load[CPU_LOAD_IDX_MAX];
#ifdef CONFIG_NO_HZ_COMMON
#ifdef CONFIG_SMP
        unsigned long last_load_update_tick;
#endif /* CONFIG_SMP */
        unsigned long nohz_flags;
#endif /* CONFIG_NO_HZ_COMMON */
#ifdef CONFIG_NO_HZ_FULL
        unsigned long last_sched_tick;
#endif
        /* capture load from *all* tasks on this cpu: */
        struct load_weight load;
        unsigned long nr_load_updates;
        u64 nr_switches;

        struct cfs_rq cfs;
        struct rt_rq rt;
        struct dl_rq dl;

        u64 kick_start_nc;
#ifdef CONFIG_FAIR_GROUP_SCHED
        /* list of leaf cfs_rq on this cpu: */
        struct list_head leaf_cfs_rq_list;
#ifdef CONFIG_CFS_BVT
        struct list_head throttled_list_nc;
#endif
#endif /* CONFIG_FAIR_GROUP_SCHED */

        /*
         * This is part of a global counter where only the total sum
         * over all CPUs matters. A task can increase this counter on
         * one CPU and if it got migrated afterwards it may decrease
         * it on another CPU. Always updated under the runqueue lock:
         */
        unsigned long nr_uninterruptible;

        struct task_struct *curr, *idle, *stop;
        unsigned long next_balance;
        struct mm_struct *prev_mm;

        unsigned int clock_skip_update;
        u64 clock;
        u64 clock_task;

        atomic_t nr_iowait;

#ifdef CONFIG_SMP
        struct root_domain *rd;
        struct sched_domain *sd;

        unsigned long cpu_capacity;
        unsigned long cpu_capacity_orig;

        struct callback_head *balance_callback;

        unsigned char idle_balance;
        /* For active balancing */
        int active_balance;
        int push_cpu;
        struct cpu_stop_work active_balance_work;
        /* cpu of this runqueue: */
        int cpu;
        int online;

        struct list_head cfs_tasks;
#ifdef CONFIG_CFS_BVT
        unsigned int nr_active_batch;
        unsigned int nr_ls_tasks;
        atomic_t curr_task_type;
        int cpu_sibling;
        unsigned int nr_deactive_batchq;
        struct list_head batchqs;
        u64 throttled_clock_nc;
        s64 exempt_quota_nc;
#endif

        u64 rt_avg;
        u64 age_stamp;
        u64 idle_stamp;
        u64 avg_idle;

        /* This is used to determine avg_idle's max value */
        u64 max_idle_balance_cost;
#endif

#ifdef CONFIG_IRQ_TIME_ACCOUNTING
        u64 prev_irq_time;
#endif
#ifdef CONFIG_PARAVIRT
        u64 prev_steal_time;
#endif
#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
        u64 prev_steal_time_rq;
#endif

        /* calc_load related fields */
        unsigned long calc_load_update;
        long calc_load_active;
        long calc_load_active_r;

#ifdef CONFIG_SCHED_HRTICK
#ifdef CONFIG_SMP
        int hrtick_csd_pending;
        //struct call_single_data hrtick_csd;
#endif
        struct hrtimer hrtick_timer;
#endif

#ifdef CONFIG_SCHEDSTATS
        /* latency stats */
        struct sched_info rq_sched_info;
        unsigned long long rq_cpu_time;
        /* could above be rq->cfs_rq.exec_clock + rq->rt_rq.rt_runtime ? */

        /* sys_sched_yield() stats */
        unsigned int yld_count;

        /* schedule() stats */
        unsigned int sched_count;
        unsigned int sched_goidle;

        /* try_to_wake_up() stats */
        unsigned int ttwu_count;
        unsigned int ttwu_local;
#endif

#ifdef CONFIG_SMP
        struct llist_head wake_list;
#endif

#ifdef CONFIG_CPU_IDLE
        /* Must be inspected within a rcu lock section */
        struct cpuidle_state *idle_state;
#endif

        ALI_HOTFIX_RESERVE(1)
        ALI_HOTFIX_RESERVE(2)
        ALI_HOTFIX_RESERVE(3)
        ALI_HOTFIX_RESERVE(4)
        ALI_HOTFIX_RESERVE(5)
        ALI_HOTFIX_RESERVE(6)
        ALI_HOTFIX_RESERVE(7)
        ALI_HOTFIX_RESERVE(8)
};

typedef int (*tg_visitor)(struct task_group *, void *);

__maybe_unused static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_throttle_delay_settings throttle_delay_settings = {
		.threshold_ms = 50,
};

static int throttle_delay_alloced;
static int diag_throttle_delay_id;
static int throttle_delay_seq;
static struct diag_variant_buffer throttle_delay_variant_buffer;

DEFINE_ORIG_FUNC(void, throttle_cfs_rq, 1,
						 struct cfs_rq *, cfs_rq);

static inline int cpu_of(struct rq *rq)
{       
#ifdef CONFIG_SMP
	return rq->cpu;
#else   
	return 0;
#endif          
}

static inline struct rq *rq_of(struct cfs_rq *cfs_rq)
{
	return cfs_rq->rq;
}

int walk_tg_tree_from(struct task_group *from,
							tg_visitor down, tg_visitor up, void *data)
{
	struct task_group *parent, *child;
	int ret;             

	parent = from;

down:
	ret = (*down)(parent, data);
	if (ret)
		goto out;
	list_for_each_entry_rcu(child, &parent->children, siblings) {
		parent = child;
		goto down;

up:
		continue;
	}
	ret = (*up)(parent, data);
	if (ret || parent == from)
		goto out;

	child = parent;
	parent = parent->parent;
	if (parent)
		goto up;
out:
	return ret;
}

static inline struct task_struct *task_of(struct sched_entity *se)
{
	return container_of(se, struct task_struct, se);
}

int tg_nop(struct task_group *tg, void *data)
{
	return 0;
}

static unsigned long read_last_dequeued(struct task_struct *p) 
{
	unsigned long *ptr = get_last_dequeued_addr(p);

	if (ptr) {
		return *ptr;
	} else {
		return 0;
	}
}


static void update_last_dequeued(struct task_struct *p, unsigned long stamp)
{
	unsigned long *ptr = get_last_dequeued_addr(p);

	if (ptr) {
		*ptr = stamp;
	}
}


static int tg_throttle_down(struct task_group *tg, void *data)
{
	struct rq *rq = data;
	struct cfs_rq *cfs_rq = tg->cfs_rq[cpu_of(rq)];
	struct rb_node *node;
	struct sched_entity *se;

	if (!throttle_delay_settings.activated)
		return 0;

	for (node = rb_first(&cfs_rq->tasks_timeline); node; node = rb_next(node)) {
		se = rb_entry(node, struct sched_entity, run_node);
		if (entity_is_task(se)) {
			struct task_struct *p = task_of(se);
			update_last_dequeued(p, ktime_to_ms(ktime_get()));
		}

	}
	return 0;
}

static void diag_throttle_cfs_rq(struct cfs_rq *cfs_rq)
{
	struct rq *rq = rq_of(cfs_rq);
	
	rcu_read_lock();
	walk_tg_tree_from(cfs_rq->tg, tg_throttle_down, tg_nop, (void *)rq);
	rcu_read_unlock();

	orig_throttle_cfs_rq(cfs_rq);

}


static void new_throttle_cfs_rq(struct cfs_rq *cfs_rq)
{
	atomic64_inc_return(&diag_nr_running);
	diag_throttle_cfs_rq(cfs_rq);
	atomic64_dec_return(&diag_nr_running);
}

static int lookup_syms(void)
{
    LOOKUP_SYMS(throttle_cfs_rq);
    return 0;
}

static void jump_init(void)
{
	JUMP_INIT(throttle_cfs_rq);

} 

#if 0
static int kprobe_dequeue_entity_pre(struct kprobe *p, struct pt_regs *regs)
{
	//struct sched_entity *se = (void *)ORIG_PARAM2(regs);
	//int *flags = (void *)ORIG_PARAM3(regs); 
	//struct task_struct *task;

	if (!throttle_delay_settings.activated)
		return 0;


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
	unsigned long long t_dequeued;
	unsigned long long delta = 0;
	unsigned long long delta_ms;
	unsigned long long now = ktime_to_ms(ktime_get());

	struct task_struct *leader = next->group_leader ? next->group_leader : next;

	if (throttle_delay_settings.bvt == 0 && diag_get_task_type(next) < 0)
		return;

	if (throttle_delay_settings.comm[0] && (strcmp("none", throttle_delay_settings.comm) != 0)) {
		if (strcmp(leader->comm, throttle_delay_settings.comm) != 0)
			return;
	}

	if (throttle_delay_settings.tgid && leader->pid != throttle_delay_settings.tgid) {
		return;
	}

	if (throttle_delay_settings.pid && next->pid != throttle_delay_settings.pid) {
		return;
	}

	t_dequeued = read_last_dequeued(next);
	update_last_dequeued(next, 0);
	if (t_dequeued <= 0)
		return;

	delta = now - t_dequeued;
	delta_ms = delta;

	if (delta_ms >= throttle_delay_settings.threshold_ms) {
		struct throttle_delay_dither *dither;
		unsigned long flags;

		if (strcmp(leader->comm, "qemu-kvm") == 0)
			return;

		dither = &diag_percpu_context[smp_processor_id()]->throttle_delay_dither;
		dither->et_type = et_throttle_delay_dither;
		dither->id = diag_throttle_delay_id;
		do_diag_gettimeofday(&dither->tv);
		dither->seq = throttle_delay_seq;
		throttle_delay_seq++;
		dither->now	= now;
		dither->dequeued = t_dequeued;
		dither->delay_ms = delta_ms;
		diag_task_brief(next, &dither->task);
		diag_task_kern_stack(next, &dither->kern_stack);
		diag_task_user_stack(next, &dither->user_stack);
		dump_proc_chains_simple(next, &dither->proc_chains);

		diag_variant_buffer_spin_lock(&throttle_delay_variant_buffer, flags);
		diag_variant_buffer_reserve(&throttle_delay_variant_buffer, sizeof(struct throttle_delay_dither));
		diag_variant_buffer_write_nolock(&throttle_delay_variant_buffer, dither, sizeof(struct throttle_delay_dither));
		diag_variant_buffer_seal(&throttle_delay_variant_buffer);
		diag_variant_buffer_spin_unlock(&throttle_delay_variant_buffer, flags);
	}
}

static int __activate_throttle_delay(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&throttle_delay_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	throttle_delay_alloced = 1;

//	JUMP_CHECK(throttle_cfs_rq);

#if 1	
    do {                    
        char *inst = (void *)orig_throttle_cfs_rq;
                                            
        if (!diag_ignore_jump_check) {
            if (!inst) {
			pr_info("!inst return 0\n");
                return 0;
			}
            if (inst[0] != 0x0f) {
			pr_info("inst[0] return 0\n");
                return 0;
			}
            if (diag_get_symbol_count("throttle_cfs_rq") > 1) {
			pr_info("diag_get_symbol_count return 0\n");
                return 0;
			}
        }
    } while (0);
#endif


	hook_tracepoint("sched_switch", trace_sched_switch_hit, NULL);
	
	JUMP_INSTALL(throttle_cfs_rq);

	return 1;

out_variant_buffer:
	return 0;
}

int activate_throttle_delay(void)
{
	if (!throttle_delay_settings.activated) {
		throttle_delay_settings.activated = __activate_throttle_delay();
	}

	return throttle_delay_settings.activated;
}

static void __deactivate_throttle_delay(void)
{
	unhook_tracepoint("sched_switch", trace_sched_switch_hit, NULL);

	JUMP_REMOVE(throttle_cfs_rq);

	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0)
	{
		msleep(10);
	}
}

int deactivate_throttle_delay(void)
{
	if (throttle_delay_settings.activated)
		__deactivate_throttle_delay();
	throttle_delay_settings.activated = 0;

	return 0;
}

static void dump_data(void)
{
	struct throttle_delay_rq rq;
	unsigned long flags;
	int cpu;

	rq.et_type = et_throttle_delay_rq;
	rq.id = diag_throttle_delay_id;
	do_diag_gettimeofday(&rq.tv);

	for_each_online_cpu(cpu)
	{
		rq.seq = throttle_delay_seq;
		throttle_delay_seq++;
		rq.cpu = cpu;

		diag_variant_buffer_spin_lock(&throttle_delay_variant_buffer, flags);
		diag_variant_buffer_reserve(&throttle_delay_variant_buffer, sizeof(struct throttle_delay_rq));
		diag_variant_buffer_write_nolock(&throttle_delay_variant_buffer, &rq, sizeof(struct throttle_delay_rq));
		diag_variant_buffer_seal(&throttle_delay_variant_buffer);
		diag_variant_buffer_spin_unlock(&throttle_delay_variant_buffer, flags);
	}


}

int throttle_delay_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	static struct diag_throttle_delay_settings settings;

	switch (id) {
	case DIAG_THROTTLE_DELAY_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_throttle_delay_settings)) {
			ret = -EINVAL;
		} else if (throttle_delay_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				throttle_delay_settings = settings;
			}
		}
		break;
	case DIAG_THROTTLE_DELAY_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_throttle_delay_settings)) {
			ret = -EINVAL;
		} else {
			settings = throttle_delay_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_THROTTLE_DELAY_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!throttle_delay_alloced) {
			ret = -EINVAL;
		} else {
			dump_data();
			ret = copy_to_user_variant_buffer(&throttle_delay_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			diag_throttle_delay_id++;
			record_dump_cmd("throttle-delay");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_throttle_delay(unsigned int cmd, unsigned long arg)
{
	struct diag_ioctl_dump_param dump_param;
	int ret = 0;
	static struct diag_throttle_delay_settings settings;

	switch (cmd) {
	case CMD_THROTTLE_DELAY_SET:
		if (throttle_delay_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_throttle_delay_settings));
			if (!ret) {
				throttle_delay_settings = settings;
			}
		}
		break;
	case CMD_THROTTLE_DELAY_SETTINGS:
		settings = throttle_delay_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_throttle_delay_settings));
		break;
	case CMD_THROTTLE_DELAY_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));
		if (!throttle_delay_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			dump_data();
			ret = copy_to_user_variant_buffer(&throttle_delay_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			diag_throttle_delay_id++;
			record_dump_cmd("throttle-delay");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_throttle_delay_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&throttle_delay_variant_buffer, 4 * 1024 * 1024);
	jump_init();

    if (throttle_delay_settings.activated)
		throttle_delay_settings.activated = __activate_throttle_delay();

    return 0;

}

void diag_throttle_delay_exit(void)
{
    if (throttle_delay_settings.activated)
        __deactivate_throttle_delay();
    throttle_delay_settings.activated = 0;

	destroy_diag_variant_buffer(&throttle_delay_variant_buffer);
}
#else
int diag_throttle_delay_init(void)
{
	return 0;
}

void diag_throttle_delay_exit(void)
{

}
#endif
