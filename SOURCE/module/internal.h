/*
 * Linux内核诊断工具--内核态杂项函数头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef __DIAG_INTERNAL_H
#define __DIAG_INTERNAL_H

#include <linux/interrupt.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/cpu.h>
#include <linux/radix-tree.h>
#include <linux/syscalls.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
#include <linux/unistd.h>
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
#include <linux/hashtable.h>
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
#else
static inline void __percpu_counter_add(struct percpu_counter *fbc,
	s64 amount, s32 batch)
{
	percpu_counter_add_batch(fbc, amount, batch);
}
#endif

#include <linux/sched.h>
#include <linux/binfmts.h>
#include <asm/syscall.h>

#include "symbol.h"
#include "uapi/ali_diagnose.h"
#include "uapi/exit_monitor.h"
#include "uapi/exec_monitor.h"
#include "uapi/irq_delay.h"
#include "uapi/perf.h"
#include "uapi/sys_delay.h"
#include "uapi/sched_delay.h"
#include "uapi/kprobe.h"
#include "uapi/uprobe.h"
#include "uapi/sys_cost.h"
#include "uapi/high_order.h"
#include "uapi/rw_top.h"
#include "uapi/utilization.h"
#include "uapi/sig_info.h"
#include "pub/variant_buffer.h"
#include "pub/stack.h"

/**
 * 手工替换函数相关的宏
 */
#define LOOKUP_SYMS(name) do {					\
		orig_##name = (void *)__kallsyms_lookup_name(#name);		\
		if (!orig_##name) {						\
			pr_err("kallsyms_lookup_name: %s\n", #name);		\
			return -EINVAL;						\
		}								\
	} while (0)

#define LOOKUP_SYMS_NORET(name) do {							\
		orig_##name = (void *)__kallsyms_lookup_name(#name);		\
		if (!orig_##name)						\
			pr_err("kallsyms_lookup_name: %s\n", #name);		\
	} while (0)

#if defined(DIAG_ARM64)

#include <asm/cacheflush.h>

#define __SC_DECL(t, a)	t a
#define __MAP0(m,...)
#define __MAP1(m,t,a,...) m(t,a)
#define __MAP2(m,t,a,...) m(t,a), __MAP1(m,__VA_ARGS__)
#define __MAP3(m,t,a,...) m(t,a), __MAP2(m,__VA_ARGS__)
#define __MAP4(m,t,a,...) m(t,a), __MAP3(m,__VA_ARGS__)
#define __MAP5(m,t,a,...) m(t,a), __MAP4(m,__VA_ARGS__)
#define __MAP6(m,t,a,...) m(t,a), __MAP5(m,__VA_ARGS__)
#define __MAP(n,...) __MAP##n(__VA_ARGS__)

#define RELATIVEJUMP_SIZE   (8)
#define DEFINE_ORIG_FUNC(rt, name, x, ...)					\
	static unsigned int e9_##name[RELATIVEJUMP_SIZE];				\
	static unsigned int inst_##name[RELATIVEJUMP_SIZE];				\
	static rt new_##name(__MAP(x, __SC_DECL, __VA_ARGS__));			\
	static rt (*orig_##name)(__MAP(x, __SC_DECL, __VA_ARGS__))
#define DEFINE_ORIG_FUNC0(rt, name)                                             \
	static unsigned int e9_##name[RELATIVEJUMP_SIZE];                             \
	static unsigned int inst_##name[RELATIVEJUMP_SIZE];                           \
	static rt new_##name(void);                                             \
	static rt (*orig_##name)(void)

#define DEFINE_ORIG_NOINPUT_FUNC(rt, name)                                      \
	static unsigned int e9_##name[RELATIVEJUMP_SIZE];                             \
	static unsigned int inst_##name[RELATIVEJUMP_SIZE];                           \
	static rt new_##name(void);                 \
	static rt (*orig_##name)(void)

extern void (*orig___flush_dcache_area)(void *addr, size_t len);
#define __flush_cache(c, n)			\
	do {							\
		orig___flush_dcache_area(c, n);	\
		__flush_icache_range((unsigned long)c, (unsigned long)c + n);	\
	} while (0)

#define JUMP_INIT(func) do {												\
			unsigned long long addr = (unsigned long long)&new_##func;		\
			/* stp x29, x30, [sp,#-16]! */				\
			e9_##func[0] = 0xa9bf7bfdu;					\
			/* mov x29, #0x0 */							\
			e9_##func[1] = 0xd280001du | ((addr & 0xffff) << 5);		\
			/* movk    x29, #0x0, lsl #16 */				\
			e9_##func[2] = 0xf2a0001du | (((addr & 0xffff0000) >> 16) << 5);        \
			/* movk    x29, #0x0, lsl #32 */				\
			e9_##func[3] = 0xf2c0001du | (((addr & 0xffff00000000) >> 32) << 5);    \
			/* movk    x29, #0x0, lsl #48 */				\
			e9_##func[4] = 0xf2e0001du | (((addr & 0xffff000000000000) >> 48) << 5);   \
			/* blr x29 */									\
			e9_##func[5] = 0xd63f03a0u;						\
			/* ldp x29, x30, [sp],#16 */					\
			e9_##func[6] = 0xa8c17bfdu;						\
			/* ret */										\
			e9_##func[7] = 0xd65f03c0u;						\
		} while (0)

#define JUMP_INSTALL(func) do {						\
				memcpy(inst_##func, orig_##func, RELATIVEJUMP_SIZE);	\
				/* memcpy(orig_##func, e9_##func, RELATIVEJUMP_SIZE); */   \
				/* __flush_cache(orig_##func, RELATIVEJUMP_SIZE);	*/	\
				orig_aarch64_insn_patch_text((void **)orig_##func, (u32 *)e9_##func, RELATIVEJUMP_SIZE);	\
			} while (0)

#define JUMP_REMOVE(func)						\
			/* memcpy(orig_##func, inst_##func, RELATIVEJUMP_SIZE);	*/ \
			/* __flush_cache(orig_##func, RELATIVEJUMP_SIZE); */	\
			orig_aarch64_insn_patch_text((void **)orig_##func, (u32 *)inst_##func, RELATIVEJUMP_SIZE);

#define JUMP_CHECK(func)	\
	do {					\
	} while (0)
#else
#define RELATIVEJUMP_SIZE   5

#define JUMP_INIT(func) do {							\
		e9_##func[0] = 0xe9;						\
		(*(int *)(&e9_##func[1])) = (long)new_##func -			\
		(long) orig_##func - RELATIVEJUMP_SIZE;				\
	} while (0)

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
	#define JUMP_INSTALL(func) do {						\
			memcpy(inst_##func, orig_##func, RELATIVEJUMP_SIZE);	\
			orig_text_poke_smp(orig_##func, e9_##func,		\
					   RELATIVEJUMP_SIZE);			\
		} while (0)

	#define JUMP_REMOVE(func)						\
		orig_text_poke_smp(orig_##func, inst_##func, RELATIVEJUMP_SIZE)
#else
	#define JUMP_INSTALL(func) do {						\
			memcpy(inst_##func, orig_##func, RELATIVEJUMP_SIZE);	\
			orig_text_poke_bp(orig_##func, e9_##func,		\
					   RELATIVEJUMP_SIZE, new_##func);	\
		} while (0)

	#define JUMP_REMOVE(func)						\
		orig_text_poke_bp(orig_##func, inst_##func,			\
					RELATIVEJUMP_SIZE, new_##func)
#endif

extern int diag_get_symbol_count(char *symbol);

#define JUMP_CHECK(func)	\
	do {					\
		char *inst = (void *)orig_##func;	\
											\
		if (!diag_ignore_jump_check) {	\
			if (!inst)						\
				return 0;					\
			if (inst[0] != 0x0f)			\
				return 0;					\
			if (diag_get_symbol_count(#func) > 1)	\
				return 0;					\
		}									\
	} while (0)

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
/*
 * __MAP - apply a macro to syscall arguments
 * __MAP(n, m, t1, a1, t2, a2, ..., tn, an) will expand to
 *    m(t1, a1), m(t2, a2), ..., m(tn, an)
 * The first argument must be equal to the amount of type/name
 * pairs given.  Note that this list of pairs (i.e. the arguments
 * of __MAP starting at the third one) is in the same format as
 * for SYSCALL_DEFINE<n>/COMPAT_SYSCALL_DEFINE<n>
 */
#define __MAP0(m,...)
#define __MAP1(m,t,a) m(t,a)
#define __MAP2(m,t,a,...) m(t,a), __MAP1(m,__VA_ARGS__)
#define __MAP3(m,t,a,...) m(t,a), __MAP2(m,__VA_ARGS__)
#define __MAP4(m,t,a,...) m(t,a), __MAP3(m,__VA_ARGS__)
#define __MAP5(m,t,a,...) m(t,a), __MAP4(m,__VA_ARGS__)
#define __MAP6(m,t,a,...) m(t,a), __MAP5(m,__VA_ARGS__)
#define __MAP(n,...) __MAP##n(__VA_ARGS__)
#define __SC_DECL(t, a)	t a
#define __TYPE_IS_LL(t) (__same_type((t)0, 0LL) || __same_type((t)0, 0ULL))
#define __SC_LONG(t, a) __typeof(__builtin_choose_expr(__TYPE_IS_LL(t), 0LL, 0L)) a
#define __SC_CAST(t, a)	(t) a
#define __SC_ARGS(t, a)	a
#endif

#define DEFINE_ORIG_FUNC(rt, name, x, ...)					\
	static unsigned char e9_##name[RELATIVEJUMP_SIZE];				\
	static unsigned char inst_##name[RELATIVEJUMP_SIZE];				\
	static rt new_##name(__MAP(x, __SC_DECL, __VA_ARGS__));			\
	static rt (*orig_##name)(__MAP(x, __SC_DECL, __VA_ARGS__))

#define DEFINE_ORIG_FUNC0(rt, name)                                             \
	static unsigned char e9_##name[RELATIVEJUMP_SIZE];                             \
	static unsigned char inst_##name[RELATIVEJUMP_SIZE];                           \
	static rt new_##name(void);                                             \
	static rt (*orig_##name)(void)

#define DEFINE_ORIG_NOINPUT_FUNC(rt, name)                                      \
	static unsigned char e9_##name[RELATIVEJUMP_SIZE];                             \
	static unsigned char inst_##name[RELATIVEJUMP_SIZE];                           \
	static rt new_##name(void);                 \
	static rt (*orig_##name)(void)

#endif

#define STACK_IS_END(v) ((v) == 0 || (v) == ULONG_MAX)

extern u64 timer_sampling_period_ms;


#if KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE
struct stack_trace {
	unsigned int nr_entries, max_entries;
	unsigned long *entries;
	int skip;	/* input argument: How many entries to skip */
};
#endif

struct diag_percpu_context;
struct task_struct;

enum diag_printk_type {
	TRACE_PRINTK,
	TRACE_BUFFER_PRINTK,
	TRACE_BUFFER_PRINTK_NOLOCK,
	TRACE_FILE_PRINTK,
	TRACE_FILE_PRINTK_NOLOCK,
};

#define DIAG_TRACE_PRINTK(pre, type, obj, fmt, ...)				\
	do {													\
		switch (type) {							\
		case TRACE_BUFFER_PRINTK:				\
			diag_trace_buffer_printk((struct diag_trace_buffer *)obj, "%*s"fmt, pre, "", ##__VA_ARGS__);	\
			break;												\
		case TRACE_BUFFER_PRINTK_NOLOCK:						\
			diag_trace_buffer_printk_nolock((struct diag_trace_buffer *)obj, "%*s"fmt, pre, "", ##__VA_ARGS__);	\
			break;														\
		case TRACE_FILE_PRINTK:								\
			diag_trace_file_printk((struct diag_trace_file *)obj, "%*s"fmt, pre, "", ##__VA_ARGS__);	\
			break;											\
		case TRACE_FILE_PRINTK_NOLOCK:						\
			diag_trace_file_printk_nolock((struct diag_trace_file *)obj, "%*s"fmt, pre, "", ##__VA_ARGS__);	\
			break;											\
		default:											\
			diag_trace_printk("%*s"fmt, pre, "", ##__VA_ARGS__);	\
			break;										\
		}												\
	} while (0)

extern int diag_net_init(void);
extern void diag_net_exit(void);
extern int diag_pupil_init(void);
extern void diag_pupil_exit(void);

extern int diag_fs_init(void);
extern void diag_fs_exit(void);

int diag_kernel_init(void);
void diag_kernel_exit(void);
extern int diag_io_init(void);
extern void diag_io_exit(void);
extern int diag_mm_init(void);
extern void diag_mm_exit(void);
extern int diag_xby_test_init(void);
extern void diag_xby_test_exit(void);

void diag_printk_all_partitions(void);

extern void kern_task_runs_timer(struct diag_percpu_context *);
extern void syscall_timer(struct diag_percpu_context *);
extern void diag_load_timer(struct diag_percpu_context *);
extern int need_dump(int delay_threshold_ms, u64 *max_delay_ms, u64 base);

#define DIAG_IRQ_TRACE_COUNT 20

#define NR_vm_run (NR_syscalls + 1)
#define NR_page_fault (NR_vm_run + 1)
#define NR_syscalls_virt (NR_page_fault + 1)

extern unsigned long diag_timer_period;

struct irq_func_runtime {
	unsigned int		irq;
	irq_handler_t		handler;
	u64 irq_cnt;
	u64 irq_run_total;
};

struct diag_percpu_context {
	unsigned long trace_buf[BACKTRACE_DEPTH];

	struct {
		u64 syscall_start_time;
		u64 sys_delay_max_ms;
		int sys_delay_in_kvm;
	} sys_delay;

	struct {
		enum {
			_DIAG_TIMER_SILENT,
			_DIAG_TIMER_RUNNING,
		} timer_state;
		int timer_started;
		struct hrtimer timer;
		u64 timer_expected_time;
	} timer_info;

	struct {
		u64 max_irq_delay_ms;
	} irq_delay;

	struct {
		struct irq_runtime {
			int irq;
			s64 time;
			char timestamp[26];
		} irq_runtime;
		
		struct softirq_runtime {
			s64 time[DIAG_NR_SOFTIRQS];
		} softirq_runtime;

		struct timer_runtime {
			s64 start_time;
		} timer_runtime;

		struct irq_result {
				u64 irq_cnt;
				u64 softirq_cnt[DIAG_NR_SOFTIRQS];
				u64 softirq_cnt_d[DIAG_NR_SOFTIRQS];

				u64 irq_run_total;
				u64 sortirq_run_total[DIAG_NR_SOFTIRQS];
				u64 sortirq_run_total_d[DIAG_NR_SOFTIRQS];

				struct irq_runtime max_irq;
				struct softirq_runtime max_softirq;

				struct {
					u64 timer_cnt;
					u64 timer_run_total;
				} timer;
				struct {
					s64 time;
					void *func;
				} max_timer;
		} irq_result;

		struct radix_tree_root irq_tree;
	} irq_stats;

	struct diag_irq_trace {
		struct {
			int irq;
			s64 start_time;
		} irq;
		
		struct {
			int sirq;
			s64 start_time;
		} softirq;

		struct {
			s64 start_time;
		} timer;

		struct {
			unsigned long irq_count;
			unsigned long irq_runs;
			unsigned long sirq_count[DIAG_NR_SOFTIRQS];
			unsigned long sirq_runs[DIAG_NR_SOFTIRQS];
			unsigned long timer_count;
			unsigned long timer_runs;
		} sum;
	} irq_trace;

	struct {
		struct hrtimer timer;
		u64 timer_expected_time;
		int timer_started;
	} run_trace;

	struct exit_monitor_detail exit_monitor_detail;
	struct exit_monitor_map exit_monitor_map;
	struct irq_delay_detail irq_delay_detail;
	struct perf_detail perf_detail;
	struct sys_delay_detail sys_delay_detail;
	struct sched_delay_dither sched_delay_dither;

	struct {
		struct uprobe_detail uprobe_detail;
		struct uprobe_raw_stack_detail uprobe_raw_stack_detail;
		unsigned int sample_step;
	} uprobe;

	struct {
		u64 start_time;
		unsigned long count[NR_syscalls_virt];
		unsigned long cost[NR_syscalls_virt];
		struct sys_cost_detail detail;
	} sys_cost;

	struct high_order_detail high_order_detail;

	struct {
		struct rw_top_perf perf;
	} rw_top;

	struct utilization_detail utilization_detail;
	struct {
		struct kprobe_detail kprobe_detail;
		struct kprobe_raw_stack_detail kprobe_raw_stack_detail;
		unsigned int sample_step;
	} kprobe;

	struct {
		struct exec_monitor_perf perf;
	} exec_monitor;

	struct {
		struct sig_info_perf perf;
	} sig_info;
};

extern struct diag_percpu_context *diag_percpu_context[NR_CPUS];

static inline struct diag_percpu_context * get_percpu_context_cpu(int cpu)
{
	if (cpu >= num_possible_cpus())
		return NULL;
	
	return diag_percpu_context[cpu];
}

static inline struct diag_percpu_context * get_percpu_context(void)
{
	return get_percpu_context_cpu(smp_processor_id());
}

struct alive_task_desc {
	struct task_struct *task;
	ktime_t sched_in;
	ktime_t sched_out;
	unsigned long id;
	struct rb_node rb_node;
};

struct diag_bio_desc {
	dev_t dev;
	sector_t sector;
	unsigned long character_submit;
	unsigned long character_write;
	unsigned long character_read;
	struct rb_node rb_node;
};

struct proc_dir_entry;
extern struct proc_dir_entry *diag_proc_mkdir(const char *name,
		struct proc_dir_entry *parent);

DECLARE_PER_CPU(struct softirq_runtime, softirq_runtime);

#define MAX_TEST_ORDER  4
extern int sysctl_alloc_cost[MAX_TEST_ORDER + 1];

extern void read_lock_alive_tasks(void);
extern void read_unlock_alive_tasks(void);
extern void write_lock_alive_tasks(void);
extern void write_unlock_alive_tasks(void);
extern struct alive_task_desc *find_alive_task(struct task_struct *task);
extern struct alive_task_desc *find_alive_task_alloc(struct task_struct *task);
extern struct alive_task_desc *takeout_alive_task(struct task_struct *task);
extern void inter_alive_tasks(int (*cb)(struct alive_task_desc *desc));
extern void cleanup_alive_tasks(void);

extern void diag_print_process_chain(int pre, struct task_struct *tsk);
extern void diag_print_process_chain_cmdline(int pre, struct task_struct *tsk);
extern unsigned int sysctl_debug_trace_printk;
#if defined(XBY_DEBUG)
#define debug_trace_printk(fmt, ...)		\
	do {							\
		diag_trace_printk(fmt, ##__VA_ARGS__);	\
	} while (0)
#else
#define debug_trace_printk(fmt, ...)		\
	do {							\
		if (sysctl_debug_trace_printk)			\
			diag_trace_printk(fmt, ##__VA_ARGS__);	\
	} while (0)
#endif											\

extern int sysctl_force_printk;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
#define diag_trace_printk(fmt, ...)      \
({                                              \
	printk(KERN_DEBUG fmt, ##__VA_ARGS__);  \
})
#else
#define diag_trace_printk(fmt, ...)      \
({                                              \
	if (sysctl_force_printk) {		\
		printk(KERN_DEBUG fmt, ##__VA_ARGS__);	\
	} else {									\
		trace_printk(fmt, ##__VA_ARGS__);  		\
	}											\
})
#endif
#define hash_shift 8
#define hash_size (1 << hash_shift)
#define hash_mask (hash_size - 1)

#ifndef DECLARE_HASHTABLE
#define DECLARE_HASHTABLE(name, bits)                                   	\
	struct hlist_head name[1 << (bits)]
#endif

struct diag_stack_desc {
        atomic64_t hit_count;
		int alloc_count_orders[MAX_ORDER];
		unsigned long trace_buf[BACKTRACE_DEPTH];
        struct rb_node rb_node;
		struct list_head list;
};

struct diag_stack_trace {
        struct rb_root stack_tree;
        spinlock_t tree_lock;
		struct list_head list;
};

void dump_cgroups(int pre);
void dump_cgroups_tsk(int pre, struct task_struct *tsk);
void diag_cgroup_name(struct task_struct *tsk, char *buf, unsigned int count, int cgroup);
void diag_comm_name(struct task_struct *tsk, char *buf, unsigned int count);
int diag_get_task_type(struct task_struct *tsk);

struct diag_stack_desc *diag_stack_desc_find_alloc(struct diag_stack_trace *trace);
int diag_dump_trace_stack(struct diag_stack_trace *trace);
int diag_printk_trace_stack(struct diag_stack_trace *trace);
void diag_init_trace_stack(struct diag_stack_trace *trace);
void diag_cleanup_trace_stack(struct diag_stack_trace *trace);

int diag_stack_trace_init(void);
void diag_stack_trace_exit(void);
void sys_loop_timer(struct diag_percpu_context *context);
void irq_delay_timer(struct diag_percpu_context *context);
void perf_timer(struct diag_percpu_context *context);
void utilization_timer(struct diag_percpu_context *context);

void diag_hook_sys_enter(void);
void diag_unhook_sys_enter(void);

ssize_t dump_pid_cmdline(int pre, enum diag_printk_type type, void *obj,
	struct task_struct *tsk, char *buf, size_t _count);


#define NR_BATCH 5
static inline ktime_t __ktime_add_ms(const ktime_t kt, const u64 msec)
{
	return ktime_add_ns(kt, msec * NSEC_PER_MSEC);
}

static inline ktime_t __ktime_add_us(const ktime_t kt, const u64 msec)
{
	return ktime_add_ns(kt, msec * NSEC_PER_USEC);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
static inline ktime_t __ms_to_ktime(u64 ms)
{
	static const ktime_t ktime_zero = {.tv64 = 0};

	return __ktime_add_ms(ktime_zero, ms);
}

static inline ktime_t __us_to_ktime(u64 ms)
{
	static const ktime_t ktime_zero = {.tv64 = 0};

	return __ktime_add_us(ktime_zero, ms);
}
#else
static inline ktime_t __ms_to_ktime(u64 ms)
{
	return ms * NSEC_PER_MSEC;
}

static inline ktime_t __us_to_ktime(u64 ms)
{
	return ms * NSEC_PER_USEC;
}
#endif

struct diag_percpu_context *get_percpu_context_cpu(int cpu);
struct diag_percpu_context *get_percpu_context(void);

extern void diag_hook_vm_run_pre(void);
extern void diag_hook_vm_run_post(void);

extern int hook_vcpu_run_init(void);
extern void hook_vcpu_run_exit(void);
extern atomic64_t xby_debug_counter1;
extern atomic64_t xby_debug_counter2;
extern atomic64_t xby_debug_counter3;
extern atomic64_t xby_debug_counter4;
extern atomic64_t xby_debug_counter5;

unsigned int ipstr2int(const char *ipstr);
char *int2ipstr(const unsigned int ip, char *ipstr, const unsigned int ip_str_len);
char *mac2str(const unsigned char *mac, char *mac_str, const unsigned int mac_str_len);

#if defined(DIAG_ARM64)
#define ORIG_PARAM1(__regs) ((__regs)->regs[0])
#define ORIG_PARAM2(__regs) ((__regs)->regs[1])
#define ORIG_PARAM3(__regs) ((__regs)->regs[2])
#define ORIG_PARAM4(__regs) ((__regs)->regs[3])
#define ORIG_PARAM5(__regs) ((__regs)->regs[4])
#define ORIG_PARAM6(__regs) ((__regs)->regs[5])
//#define RETURN_REG(__regs) ((__regs)->regs[0])
#else
#define ORIG_PARAM1(regs) ((regs)->di)
#define ORIG_PARAM2(regs) ((regs)->si)
#define ORIG_PARAM3(regs) ((regs)->dx)
#define ORIG_PARAM4(regs) ((regs)->cx)
#define ORIG_PARAM5(regs) ((regs)->r8)
#define ORIG_PARAM6(regs) ((regs)->r9)
//#define RETURN_REG(__regs) ((__regs)->ax)
#endif

#define SYSCALL_PARAM1 ORIG_PARAM2
#define SYSCALL_PARAM2 ORIG_PARAM3
#if defined(DIAG_ARM64)
#define SYSCALL_PARAM3 ORIG_PARAM4
#else
#define SYSCALL_PARAM3(regs) ((regs)->r10)
#endif
#define SYSCALL_PARAM4 ORIG_PARAM5
#define SYSCALL_PARAM5 ORIG_PARAM6

#if defined(DIAG_ARM64)
#define SYSCALL_NO(regs) ((regs)->syscallno)
#else
#define SYSCALL_NO(regs) ((regs)->orig_ax)
#endif

#if defined(DIAG_ARM64)
#include <linux/atomic.h>
static inline long xadd(long *ptr, long i)
{
	unsigned long tmp;
	long result;

	asm volatile("// arch_accurate_add\n"
		"1:	ldxr	%0, %2\n"
		"	add	%0, %0, %3\n"
		"	stlxr	%w1, %0, %2\n"
		"	cbnz	%w1, 1b"
			: "=&r" (result), "=&r" (tmp), "+Q" (*ptr)
			: "Ir" (i)
			: "memory");

	smp_mb();
	return result;
}
#endif

int diag_copy_stack_frame(struct task_struct *tsk,
	const void __user *fp,
	void *frame,
	unsigned int size);

#if KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE
#define synchronize_sched synchronize_rcu

static inline void do_gettimeofday(struct timeval *tv)
{
	struct timespec64 ts;

	ktime_get_real_ts64(&ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = ts.tv_nsec/1000;
}
#endif

extern unsigned long diag_ignore_jump_check;

int activate_run_trace(void);
int deactivate_run_trace(void);
int activate_load_monitor(void);
int deactivate_load_monitor(void);
int activate_perf(void);
int deactivate_exit_monitor(void);
int activate_exit_monitor(void);
int deactivate_perf(void);
int activate_tcp_retrans(void);
int deactivate_tcp_retrans(void);
int activate_sys_delay(void);
int deactivate_sys_delay(void);
int activate_irq_delay(void);
int deactivate_irq_delay(void);
int activate_mutex_monitor(void);
int deactivate_mutex_monitor(void);
int activate_utilization(void);
int deactivate_utilization(void);
int activate_irq_stats(void);
int deactivate_irq_stats(void);
int activate_irq_trace(void);
int deactivate_irq_trace(void);
int activate_exec_monitor(void);
int deactivate_exec_monitor(void);
int activate_kprobe(void);
int deactivate_kprobe(void);
int activate_mm_leak(void);
int deactivate_mm_leak(void);
int activate_alloc_top(void);
int deactivate_alloc_top(void);
int activate_rw_top(void);
int deactivate_rw_top(void);
int activate_fs_shm(void);
int deactivate_fs_shm(void);
int activate_drop_packet(void);
int deactivate_drop_packet(void);
int activate_sched_delay(void);
int deactivate_sched_delay(void);
int activate_reboot(void);
int deactivate_reboot(void);
int activate_fs_orphan(void);
int deactivate_fs_orphan(void);
int activate_net_bandwidth(void);
int deactivate_net_bandwidth(void);

int perf_syscall(struct pt_regs *regs, long id);

void diag_task_brief(struct task_struct *tsk, struct diag_task_detail *detail);
void printk_task_brief(struct diag_task_detail *detail);
void diag_task_kern_stack(struct task_struct *tsk, struct diag_kern_stack_detail *detail);
void diag_task_user_stack(struct task_struct *tsk, struct diag_user_stack_detail *detail);
void printk_task_user_stack(struct diag_user_stack_detail *detail);
void diag_task_raw_stack(struct task_struct *tsk, struct diag_raw_stack_detail *detail);

void cb_sys_enter_run_trace(void *__data, struct pt_regs *regs, long id);
void cb_sys_enter_sys_delay(void *__data, struct pt_regs *regs, long id);
void cb_sys_enter_sys_cost(void *__data, struct pt_regs *regs, long id);

int str_to_cpumask(char *cpus, struct cpumask *cpumask);
void cpumask_to_str(struct cpumask *cpumask, char *buf, int len);

int activate_ping_delay(void);
int deactivate_ping_delay(void);
int ping_delay_syscall(struct pt_regs *regs, long id);
int diag_ping_delay_init(void);
void diag_ping_delay_exit(void);

int activate_uprobe(void);
int deactivate_uprobe(void);
int diag_uprobe_init(void);
void diag_uprobe_exit(void);

int activate_sys_cost(void);
int deactivate_sys_cost(void);
int diag_sys_cost_init(void);
void diag_sys_cost_exit(void);

int activate_fs_cache(void);
int deactivate_fs_cache(void);
int fs_cache_syscall(struct pt_regs *regs, long id);
int diag_fs_cache_init(void);
void diag_fs_cache_exit(void);

int activate_high_order(void);
int deactivate_high_order(void);
int high_order_syscall(struct pt_regs *regs, long id);
int diag_high_order_init(void);
void diag_high_order_exit(void);
void record_dump_cmd(char *module);

int activate_sig_info(void);
int deactivate_sig_info(void);
int diag_sig_info_init(void);
void diag_sig_info_exit(void);

int diag_dev_init(void);
void diag_dev_cleanup(void);

#endif /* __DIAG_INTERNAL_H */

