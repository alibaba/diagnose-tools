/*
 * Linux内核诊断工具--内核态堆栈公共函数实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
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
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/file.h>
#include <linux/pid_namespace.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
#include <linux/blk-mq.h>
#endif
#include <linux/bitmap.h>
#include <linux/cpumask.h>
#include <linux/mm.h>

#include "mm_tree.h"
#include "internal.h"
#include "pub/trace_file.h"
#include "pub/stack.h"

extern struct mm_struct *get_task_mm(struct task_struct *task);
extern void mmput(struct mm_struct *);

void perfect_save_stack_trace_user(struct stack_trace *trace);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
struct page *diag_follow_page(struct vm_area_struct *vma, unsigned long address,
			unsigned int flags)
{
	return orig_follow_page(vma, address, flags);
}
#else
static inline struct page *diag_follow_page(struct vm_area_struct *vma,
		unsigned long address, unsigned int foll_flags)
{
	unsigned int unused_page_mask;

	return orig_follow_page_mask(vma, address, foll_flags, &unused_page_mask);
}
#endif

#if defined(DIAG_ARM64)
struct stackframe {
	unsigned long fp;
	unsigned long sp;
	unsigned long pc;
};

struct stack_trace_data {
	struct stack_trace *trace;
	unsigned int skip;
};

static int
copy_stack_frame(const void __user *fp, struct stackframe *frame)
{
	int ret = 0;
	unsigned long data[2];

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
	if (!access_ok(VERIFY_READ, fp, sizeof(*frame)))
#else
	if (!access_ok(fp, sizeof(*frame)))
#endif
		goto out;

	ret = __copy_from_user_inatomic(data, fp, 16);
	if (ret)
		ret = -EFAULT;
	else
		ret = 16;

	if (ret <= 0) {
		ret = 0;
		goto out;
	}

	frame->fp = data[0];
	frame->pc = data[1];

out:
	return ret;
}

/*
 * AArch64 PCS assigns the frame pointer to x29.
 *
 * A simple function prologue looks like this:
 * 	sub	sp, sp, #0x10
 *   	stp	x29, x30, [sp]
 *	mov	x29, sp
 *
 * A simple function epilogue looks like this:
 *	mov	sp, x29
 *	ldp	x29, x30, [sp]
 *	add	sp, sp, #0x10
 */
int unwind_frame(struct stackframe *frame)
{
	unsigned long high, low;
	unsigned long fp = frame->fp;

	low  = frame->sp;
	high = ALIGN(low, 1024 * 1024);

	if (fp < low || fp > high || fp & 0xf)
		return -EINVAL;

	frame->sp = fp + 0x10;
	if (!copy_stack_frame((void *)fp, frame))
		return -EINVAL;

	return 0;
}

static int save_trace(struct stackframe *frame, void *d)
{
	struct stack_trace_data *data = d;
	struct stack_trace *trace = data->trace;
	unsigned long addr = frame->pc;

	if (data->skip) {
		data->skip--;
		return 0;
	}

	trace->entries[trace->nr_entries++] = addr;

	return trace->nr_entries >= trace->max_entries;
}

void walk_stackframe(struct stackframe *frame,
		     int (*fn)(struct stackframe *, void *), void *data)
{
	while (1) {
		int ret;

		if (fn(frame, data))
			break;
		ret = unwind_frame(frame);
		if (ret < 0)
			break;
	}
}

static inline void diag__save_stack_trace_user(int orig, struct task_struct *tsk, struct stack_trace *trace)
{
	const struct pt_regs *regs = task_pt_regs(tsk);
	struct stack_trace_data data;
	struct stackframe frame;

	if (regs == NULL) {
		if (trace->nr_entries < trace->max_entries)
			trace->entries[trace->nr_entries++] = ULONG_MAX;
		return;
	}

	data.trace = trace;
	data.skip = trace->skip;

	frame.fp = regs->user_regs.regs[29];
	frame.sp = regs->user_regs.sp;
	frame.pc = regs->user_regs.pc;

	walk_stackframe(&frame, save_trace, &data);
	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}

void perfect_save_stack_trace_user(struct stack_trace *trace)
{
	diag__save_stack_trace_user(1, current, trace);
}

void diag_save_stack_trace_user(struct stack_trace *trace)
{
	perfect_save_stack_trace_user(trace);
}
#else

void diag_save_stack_trace_user(struct stack_trace *trace)
{
	perfect_save_stack_trace_user(trace);
}
#endif

int diagnose_stack_trace_equal(unsigned long *backtrace1, unsigned long *backtrace2)
{
	int i;

	for (i = 0; i < BACKTRACE_DEPTH; i++) {
		if ((backtrace1[i] == 0) && (backtrace2[i] == 0))
			break;

		if (backtrace1[i] != backtrace2[i])
			return 0;
	}

	return 1;
}

int diagnose_stack_trace_cmp(unsigned long *backtrace1, unsigned long *backtrace2)
{
	int i;

	for (i = 0; i < BACKTRACE_DEPTH; i++) {
		if (backtrace1[i] < backtrace2[i])
			return -1;
		else if (backtrace1[i] > backtrace2[i])
			return 1;
		else if ((backtrace1[i] == 0) && (backtrace2[i] == 0))
			return 0;
	}

	return 0;
}

static void __diagnose_print_stack_trace(int pre, enum diag_printk_type type, void *obj,
	struct task_struct *p, unsigned long *backtrace)
{
#if KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE
	int i;
	
	orig_stack_trace_save_tsk(p, backtrace, BACKTRACE_DEPTH, 0);
#else
	struct stack_trace trace;
	int i;

	memset(&trace, 0, sizeof(trace));
	memset(backtrace, 0, BACKTRACE_DEPTH * sizeof(unsigned long));
	trace.max_entries = BACKTRACE_DEPTH;
	trace.entries = backtrace;
	save_stack_trace_tsk(p, &trace);
#endif

	for (i = 0; i < BACKTRACE_DEPTH; i++) {
		if (STACK_IS_END(backtrace[i]))
			break;

		DIAG_TRACE_PRINTK(pre, type, obj, " %pS\n", (void *)backtrace[i]);
	}
}

void diagnose_print_stack_trace(int pre, struct task_struct *p, unsigned long *backtrace)
{
	__diagnose_print_stack_trace(pre, TRACE_PRINTK, NULL, p, backtrace);
}

void diagnose_trace_buffer_stack_trace(int pre, struct diag_trace_buffer *buffer,
	struct task_struct *p, unsigned long *backtrace)
{
	__diagnose_print_stack_trace(pre, TRACE_BUFFER_PRINTK, buffer, p, backtrace);
}

void diagnose_trace_buffer_nolock_stack_trace(int pre, struct diag_trace_buffer *buffer,
	struct task_struct *p, unsigned long *backtrace)
{
	__diagnose_print_stack_trace(pre, TRACE_BUFFER_PRINTK_NOLOCK, buffer, p, backtrace);
}

void diagnose_trace_file_stack_trace(int pre, struct diag_trace_file *file,
	struct task_struct *p, unsigned long *backtrace)
{
	__diagnose_print_stack_trace(pre, TRACE_FILE_PRINTK, file, p, backtrace);
}

void diagnose_trace_file_nolock_stack_trace(int pre, struct diag_trace_file *file,
	struct task_struct *p, unsigned long *backtrace)
{
	__diagnose_print_stack_trace(pre, TRACE_FILE_PRINTK_NOLOCK, file, p, backtrace);
}

static void __diagnose_print_stack_trace_user(int pre, enum diag_printk_type type, void *obj,
	unsigned long *backtrace)
{
#if KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE
	int i;
	
	orig_stack_trace_save_user(backtrace, BACKTRACE_DEPTH);
#else
	struct stack_trace trace;
	int i;

	memset(&trace, 0, sizeof(trace));
	memset(backtrace, 0, BACKTRACE_DEPTH * sizeof(unsigned long));
	trace.max_entries = BACKTRACE_DEPTH;
	trace.entries = backtrace;
	diag_save_stack_trace_user(&trace);
#endif

	for (i = 0; i < BACKTRACE_DEPTH; i++) {
		if (STACK_IS_END(backtrace[i]))
				break;

		DIAG_TRACE_PRINTK(pre, type, obj, "_USER_STACK_ %d %lx\n", current->tgid, backtrace[i]);
	}
}

void diagnose_print_stack_trace_user(int pre, unsigned long *backtrace)
{
	__diagnose_print_stack_trace_user(pre, TRACE_PRINTK, NULL, backtrace);
}

void diagnose_trace_buffer_nolock_stack_trace_user(int pre, struct diag_trace_buffer *buffer,
	unsigned long *backtrace)
{
	__diagnose_print_stack_trace_user(pre, TRACE_BUFFER_PRINTK_NOLOCK, buffer, backtrace);
}

void diagnose_trace_buffer_stack_trace_user(int pre, struct diag_trace_buffer *buffer,
	unsigned long *backtrace)
{
	__diagnose_print_stack_trace_user(pre, TRACE_BUFFER_PRINTK, buffer, backtrace);
}

void diagnose_trace_file_nolock_stack_trace_user(int pre, struct diag_trace_file *file,
	unsigned long *backtrace)
{
	__diagnose_print_stack_trace_user(pre, TRACE_FILE_PRINTK_NOLOCK, file, backtrace);
}

void diagnose_trace_file_stack_trace_user(int pre, struct diag_trace_file *file,
	unsigned long *backtrace)
{
	__diagnose_print_stack_trace_user(pre, TRACE_FILE_PRINTK, file, backtrace);
}

static void __diagnose_print_stack_trace_unfold(int pre, enum diag_printk_type type, void *obj,
	struct task_struct *p, unsigned long *backtrace)
{
#if KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE
	int i;
	
	orig_stack_trace_save_tsk(p, backtrace, BACKTRACE_DEPTH, 0);
#else
	struct stack_trace trace;
	int i;

	memset(&trace, 0, sizeof(trace));
	memset(backtrace, 0, BACKTRACE_DEPTH * sizeof(unsigned long));
	trace.max_entries = BACKTRACE_DEPTH;
	trace.entries = backtrace;
	save_stack_trace_tsk(p, &trace);
#endif

	for (i = 0; i < BACKTRACE_DEPTH; i++) {
                if (STACK_IS_END(backtrace[i]))
			break;
		DIAG_TRACE_PRINTK(pre, type, obj,
			"%lx %pS ([kernel.kallsyms])\n",
			backtrace[i],
			(void *)backtrace[i]);
	}
}

void diagnose_print_stack_trace_unfold(int pre, struct task_struct *p, unsigned long *backtrace)
{
	__diagnose_print_stack_trace_unfold(pre, TRACE_PRINTK, NULL, p, backtrace);
}

void diagnose_trace_buffer_stack_trace_unfold(int pre, struct diag_trace_buffer *buffer,
	struct task_struct *p, unsigned long *backtrace)
{
	__diagnose_print_stack_trace_unfold(pre, TRACE_BUFFER_PRINTK, buffer, p, backtrace);
}

void diagnose_trace_buffer_nolock_stack_trace_unfold(int pre, struct diag_trace_buffer *buffer,
	struct task_struct *p, unsigned long *backtrace)
{
	__diagnose_print_stack_trace_unfold(pre, TRACE_BUFFER_PRINTK_NOLOCK, buffer, p, backtrace);
}

void diagnose_trace_file_stack_trace_unfold(int pre, struct diag_trace_file *file,
	struct task_struct *p, unsigned long *backtrace)
{
	__diagnose_print_stack_trace_unfold(pre, TRACE_FILE_PRINTK, file, p, backtrace);
}

void diagnose_trace_file_nolock_stack_trace_unfold(int pre, struct diag_trace_file *file,
	struct task_struct *p, unsigned long *backtrace)
{
	__diagnose_print_stack_trace_unfold(pre, TRACE_FILE_PRINTK_NOLOCK, file, p, backtrace);
}

static void __diagnose_print_stack_trace_unfold_user(int pre, enum diag_printk_type type, void *obj,
	unsigned long *backtrace)
{
#if KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE
	int i;
	
	orig_stack_trace_save_user(backtrace, BACKTRACE_DEPTH);
#else
	struct stack_trace trace;
	int i;

	memset(&trace, 0, sizeof(trace));
	memset(backtrace, 0, BACKTRACE_DEPTH * sizeof(unsigned long));
	trace.max_entries = BACKTRACE_DEPTH;
	trace.entries = backtrace;
	diag_save_stack_trace_user(&trace);
#endif

	for (i = 0; i < BACKTRACE_DEPTH; i++) {
		if (STACK_IS_END(backtrace[i]))
			break;

		DIAG_TRACE_PRINTK(pre, type, obj, "_USER_STACK_ %d %lx (%s)\n",
			current->tgid, backtrace[i], current->comm);
	}
}

void diagnose_print_stack_trace_unfold_user(int pre, unsigned long *backtrace)
{
	__diagnose_print_stack_trace_unfold_user(pre, TRACE_PRINTK, NULL, backtrace);
}

void diagnose_trace_buffer_nolock_stack_trace_unfold_user(int pre, struct diag_trace_buffer *buffer,
	unsigned long *backtrace)
{
	__diagnose_print_stack_trace_unfold_user(pre, TRACE_BUFFER_PRINTK_NOLOCK, buffer, backtrace);
}

void diagnose_trace_buffer_stack_trace_unfold_user(int pre, struct diag_trace_buffer *buffer,
	unsigned long *backtrace)
{
	__diagnose_print_stack_trace_unfold_user(pre, TRACE_BUFFER_PRINTK, buffer, backtrace);
}

void diagnose_trace_file_nolock_stack_trace_unfold_user(int pre, struct diag_trace_file *file,
	unsigned long *backtrace)
{
	__diagnose_print_stack_trace_unfold_user(pre, TRACE_FILE_PRINTK_NOLOCK, file, backtrace);
}

void diagnose_trace_file_stack_trace_unfold_user(int pre, struct diag_trace_file *file,
	unsigned long *backtrace)
{
	__diagnose_print_stack_trace_unfold_user(pre, TRACE_FILE_PRINTK, file, backtrace);
}

void diagnose_save_stack_trace(struct task_struct *tsk, unsigned long *backtrace)
{
#if KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE
	orig_stack_trace_save_tsk(tsk, backtrace, BACKTRACE_DEPTH, 0);
#else
	struct stack_trace trace;

	memset(&trace, 0, sizeof(trace));
	memset(backtrace, 0, BACKTRACE_DEPTH * sizeof(unsigned long));
	trace.max_entries = BACKTRACE_DEPTH;
	trace.entries = backtrace;
	save_stack_trace_tsk(tsk, &trace);
#endif
}

#if !defined(DIAG_ARM64)
struct stack_frame_user {
	const void __user	*next_fp;
	unsigned long		ret_addr;
};

static int
copy_stack_frame(const void __user *fp, struct stack_frame_user *frame)
{
	int ret;

#if KERNEL_VERSION(5, 0, 0) >= LINUX_VERSION_CODE
	if (!access_ok(VERIFY_READ, fp, sizeof(*frame)))
		return 0;
#endif

	ret = 1;
	pagefault_disable();
	if (__copy_from_user_inatomic(frame, fp, sizeof(*frame)))
		ret = 0;
	pagefault_enable();

	return ret;
}

static inline void __save_stack_trace_user(struct stack_trace *trace)
{
	const struct pt_regs *regs = task_pt_regs(current);
	const void __user *fp = (const void __user *)regs->bp;
	int count = 0;

	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = regs->ip;

	while (trace->nr_entries < trace->max_entries) {
		struct stack_frame_user frame;

		frame.next_fp = NULL;
		frame.ret_addr = 0;
		if (!copy_stack_frame(fp, &frame))
			break;
		if ((unsigned long)fp < regs->sp)
			break;
		if (frame.ret_addr) {
			trace->entries[trace->nr_entries++] =
				frame.ret_addr;
		}
		if (fp == frame.next_fp)
			break;
		fp = frame.next_fp;
		count++;
		/**
		 * 线上环境发现这里有hardlockup，这里强制退出
		 */
		if (count >= trace->max_entries || count >= 100)
			break;
	}
}

void perfect_save_stack_trace_user(struct stack_trace *trace)
{
	/*
	 * Trace user stack if we are not a kernel thread
	 */
	if (current->mm) {
		__save_stack_trace_user(trace);
	}
	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}
#endif

void diagnose_save_stack_trace_user(unsigned long *backtrace)
{
	struct stack_trace trace;

	memset(&trace, 0, sizeof(trace));
	memset(backtrace, 0, BACKTRACE_DEPTH * sizeof(unsigned long));
	trace.max_entries = BACKTRACE_DEPTH;
	trace.entries = backtrace;
	perfect_save_stack_trace_user(&trace);
}

void diag_task_kern_stack(struct task_struct *tsk, struct diag_kern_stack_detail *detail)
{
	diagnose_save_stack_trace(tsk, detail->stack);
}
#if !defined(DIAG_ARM64)
static int
copy_stack_frame_remote(struct task_struct *tsk, const void __user *fp, struct stack_frame_user *frame)
{
	int ret;
	struct mm_struct *mm;

	mm = get_task_mm(tsk);
	if (!mm)
		return 0;

	ret = orig_access_remote_vm(mm, (unsigned long)fp, frame, sizeof(*frame), 0);
	mmput(mm);

	return ret;
}

static inline void save_stack_trace_user_remote(struct task_struct *tsk,
	struct stack_trace *trace)
{
	const struct pt_regs *regs = task_pt_regs(tsk);
	const void __user *fp = (const void __user *)regs->bp;
	int count = 0;

	if (in_atomic() || irqs_disabled()) {
		return;
	}

	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = regs->ip;

	while (trace->nr_entries < trace->max_entries) {
		struct stack_frame_user frame;

		frame.next_fp = NULL;
		frame.ret_addr = 0;
	
		if (!copy_stack_frame_remote(tsk, fp, &frame)) {
			break;
		}

		if ((unsigned long)fp < regs->sp)
			break;

		if (frame.ret_addr) {
			trace->entries[trace->nr_entries++] =
				frame.ret_addr;
		} else
			break;

		if (fp == frame.next_fp)
			break;
		fp = frame.next_fp;

		count++;
		/**
		 * 线上环境发现这里有hardlockup，这里强制退出
		 */
		if (count >= trace->max_entries || count >= 100)
			break;
	}
}

void diagnose_save_stack_trace_user_remote(struct task_struct *tsk, unsigned long *backtrace)
{
	struct stack_trace trace;

	memset(&trace, 0, sizeof(trace));
	memset(backtrace, 0, BACKTRACE_DEPTH * sizeof(unsigned long));
	trace.max_entries = BACKTRACE_DEPTH;
	trace.entries = backtrace;

	/*
	 * Trace user stack if we are not a kernel thread
	 */
	if (tsk->mm) {
		save_stack_trace_user_remote(tsk, &trace);
	}
	if (trace.nr_entries < trace.max_entries)
		trace.entries[trace.nr_entries++] = ULONG_MAX;
}

static int diagnose_task_raw_stack_remote(struct task_struct *tsk,
	void *to, void __user *from, unsigned long n)
{
	int ret;
	struct mm_struct *mm;

	if (in_atomic() || irqs_disabled()) {
		return 0;
	}

	mm = get_task_mm(tsk);
	if (!mm)
		return 0;

	ret = orig_access_remote_vm(mm, (unsigned long)from, to, n, 0);
	mmput(mm);

	return ret < 0 ? ret : 0;
}

#else
static void diagnose_save_stack_trace_user_remote(struct task_struct *tsk, unsigned long *backtrace)
{
	//
}

static int diagnose_task_raw_stack_remote(struct task_struct *tsk,
	void *to, const void __user *from, unsigned long n)
{
	return 0;
}
#endif

void diag_task_user_stack(struct task_struct *tsk, struct diag_user_stack_detail *detail)
{
	struct pt_regs *regs;
	unsigned long sp, ip, bp;
	
	sp = 0;
	ip = 0;
	bp = 0;
	regs = task_pt_regs(tsk);
	if (regs) {
		sp = regs->sp;
#if defined(DIAG_ARM64)
		ip = regs->pc;
		bp = regs->sp;
#else
		ip = regs->ip;
		bp = regs->bp;
#endif
	}
#if defined(DIAG_ARM64)
	detail->regs = regs->user_regs;
#else
	detail->regs = *regs;
#endif
	detail->sp = sp;
	detail->ip = ip;
	detail->bp = bp;

	if (tsk == current) {
		diagnose_save_stack_trace_user(detail->stack);
	} else {
		diagnose_save_stack_trace_user_remote(tsk, detail->stack);
	}
}

void printk_task_user_stack(struct diag_user_stack_detail *user_stack)
{
	int i;

	printk("    用户态堆栈：\n");
	for (i = 0; i < BACKTRACE_DEPTH; i++) {
		if (user_stack->stack[i] == (size_t)-1 || user_stack->stack[i] == 0) {
			break;
		}
		printk("#~        0x%lx\n", user_stack->stack[i]);
	}
}

void diag_task_raw_stack(struct task_struct *tsk, struct diag_raw_stack_detail *detail)
{
	struct pt_regs *regs;
	int i;
	int ret;
	unsigned long sp, ip, bp;
	char *stack;

	memset(detail->stack, 0, DIAG_USER_STACK_SIZE);
	detail->stack_size = 0;

	if (!tsk || !tsk->mm)
		return;

	regs = task_pt_regs(tsk);
	if (!regs)
		return;

#if defined(DIAG_ARM64)
	sp = regs->sp;
	ip = regs->pc;
	bp = regs->sp;
#else
	sp = regs->sp;
	ip = regs->ip;
	bp = regs->bp;
#endif
#if defined(DIAG_ARM64)
	detail->regs = regs->user_regs;
#else
	detail->regs = *regs;
#endif
	detail->sp = sp;
	detail->ip = ip;
	detail->bp = bp;
	stack = (char *)&detail->stack[0];
	for (i = 0; i < (DIAG_USER_STACK_SIZE / 1024); i++) {
		if (tsk == current) {
			ret = __copy_from_user_inatomic(stack,
				(void __user *)sp + detail->stack_size, 1024);
		} else {
			ret = diagnose_task_raw_stack_remote(tsk, stack,
				(void __user *)sp + detail->stack_size, 1024);
		}
		if (ret)
			break;
		else
			detail->stack_size += 1024;

		stack += 1024;
	}
}
