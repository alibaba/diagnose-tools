/*
 * Alibaba 内核诊断模块
 * 
 * 访问非当前进程堆栈，特别是其用户态堆栈。
 * 由于本功能存在潜在风险，因此仅仅用于实验版本。
 *
 * Copyright (C) 2019 Alibaba Ltd.
 *
 * Author: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
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
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0)
#include <linux/sched/mm.h>
#endif
#include "mm_tree.h"
#include "internal.h"
#include "pub/trace_file.h"
#include "pub/remote_stack.h"

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

#if defined(DIAG_ARM64)
void diag_save_remote_stack_trace_user(int might_sleep, struct task_struct *tsk, struct stack_trace *trace)
{
}
#else
struct stack_frame_user {
	const void __user   *next_fp;
	unsigned long       ret_addr;
};

static int
copy_stack_frame_might_sleep(struct task_struct *tsk, const void __user *fp, struct stack_frame_user *frame)
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

int copy_stack_frame_atomic(struct task_struct *tsk,
	const void __user *fp,
	void *frame,
	unsigned int size)
{
	struct vm_area_struct *vma;
	void *addr;
	struct page *page;
	unsigned long fp_addr = (unsigned long)fp;
	unsigned long pfn;
	int ret;

	if (!tsk->mm)
		return 0;

	if (((fp_addr + size) / PAGE_SIZE) != (fp_addr / PAGE_SIZE))
		return 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
	if (tsk == current && !access_ok(VERIFY_READ, fp, size))
#else
	if (tsk == current && !access_ok(fp, size))
#endif
		return 0;

	vma = kmalloc(sizeof(struct vm_area_struct), GFP_ATOMIC | __GFP_ZERO);
	if (!vma)
		return 0;

	vma->vm_mm = tsk->mm;
	vma->vm_flags = VM_PFNMAP;
	ret = follow_pfn(vma, fp_addr, &pfn);
	kfree(vma);
	if (ret)
		return 0;
	if (!pfn_valid(pfn))
		return 0;

	page = pfn_to_page(pfn);
	if (IS_ERR_OR_NULL(page))
		return 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	addr = kmap_atomic(page, KM_USER0);
#else
	addr = kmap_atomic(page);
#endif
	memcpy(frame, addr + (fp_addr % PAGE_SIZE), size);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	kunmap_atomic(addr, KM_USER0);
#else
	kunmap_atomic(addr);
#endif
	return 1;
}

static inline void
diag__save_stack_trace_user(int might_sleep, struct task_struct *tsk,
	struct stack_trace *trace)
{
	const struct pt_regs *regs = task_pt_regs(tsk);
	const void __user *fp = (const void __user *)regs->bp;

	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = regs->ip;

	while (trace->nr_entries < trace->max_entries) {
		struct stack_frame_user frame;

		frame.next_fp = NULL;
		frame.ret_addr = 0;
	
		if (might_sleep) {
			if (!copy_stack_frame_might_sleep(tsk, fp, &frame))
				break;
		} else {
			if (!copy_stack_frame_atomic(tsk, fp, &frame, sizeof(frame)))
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
	}
}

void diag_save_remote_stack_trace_user(int might_sleep, struct task_struct *tsk, struct stack_trace *trace)
{
	/*
	 * Trace user stack if we are not a kernel thread
	 */
	if (tsk->mm) {
		diag__save_stack_trace_user(might_sleep, tsk, trace);
	}
	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}
#endif

static void __diagnose_print_stack_trace_user_tsk(int pre, int might_sleep, enum diag_printk_type type, void *obj,
	struct task_struct *tsk, unsigned long *backtrace)
{
	struct stack_trace trace;
	int i;

	memset(&trace, 0, sizeof(trace));
	memset(backtrace, 0, BACKTRACE_DEPTH * sizeof(unsigned long));
	trace.max_entries = BACKTRACE_DEPTH;
	trace.entries = backtrace;
	diag_save_remote_stack_trace_user(might_sleep, tsk, &trace);

	for (i = 0; i < BACKTRACE_DEPTH; i++) {
		if (STACK_IS_END(backtrace[i]))
				break;

		DIAG_TRACE_PRINTK(pre, type, obj, "_USER_STACK_ %d %lx\n", tsk->tgid, backtrace[i]);
	}
}

void diagnose_print_stack_trace_user_tsk(int pre, int might_sleep, struct task_struct *tsk, unsigned long *backtrace)
{
	__diagnose_print_stack_trace_user_tsk(pre, might_sleep, TRACE_PRINTK, NULL, tsk, backtrace);
}

static void __diagnose_print_stack_trace_unfold_user_tsk(int pre, int orig, enum diag_printk_type type, void *obj,
	struct task_struct *tsk, unsigned long *backtrace)
{
	struct stack_trace trace;
	int i;

	memset(&trace, 0, sizeof(trace));
	memset(backtrace, 0, BACKTRACE_DEPTH * sizeof(unsigned long));
	trace.max_entries = BACKTRACE_DEPTH;
	trace.entries = backtrace;
	diag_save_remote_stack_trace_user(orig, tsk, &trace);

	for (i = 0; i < BACKTRACE_DEPTH; i++) {
		if (STACK_IS_END(backtrace[i]))
				break;

		DIAG_TRACE_PRINTK(pre, type, obj, "_USER_STACK_ %d %lx (%s)\n",
			tsk->tgid, backtrace[i], tsk->comm);
	}
}

void diagnose_print_stack_trace_unfold_user_tsk(int pre, int orig, struct task_struct *tsk, unsigned long *backtrace)
{
	__diagnose_print_stack_trace_unfold_user_tsk(pre, orig, TRACE_PRINTK, NULL, tsk, backtrace);
}

void diagnose_trace_buffer_nolock_stack_trace_unfold_user_tsk(int pre, int orig, struct diag_trace_buffer *buffer,
	struct task_struct *tsk, unsigned long *backtrace)
{
	__diagnose_print_stack_trace_unfold_user_tsk(pre, orig, TRACE_BUFFER_PRINTK_NOLOCK, buffer, tsk, backtrace);
}

void diagnose_trace_buffer_stack_trace_unfold_user_tsk(int pre, int orig, struct diag_trace_buffer *buffer,
	struct task_struct *tsk, unsigned long *backtrace)
{
	__diagnose_print_stack_trace_unfold_user_tsk(pre, orig, TRACE_BUFFER_PRINTK, buffer, tsk, backtrace);
}

void diagnose_trace_file_nolock_stack_trace_unfold_user_tsk(int pre, int orig, struct diag_trace_file *file,
	struct task_struct *tsk, unsigned long *backtrace)
{
	__diagnose_print_stack_trace_unfold_user_tsk(pre, orig, TRACE_FILE_PRINTK_NOLOCK, file, tsk, backtrace);
}

void diagnose_trace_file_stack_trace_unfold_user_tsk(int pre, int orig, struct diag_trace_file *file,
	struct task_struct *tsk, unsigned long *backtrace)
{
	__diagnose_print_stack_trace_unfold_user_tsk(pre, orig, TRACE_FILE_PRINTK, file, tsk, backtrace);
}

