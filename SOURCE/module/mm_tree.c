/*
 * Linux内核诊断工具--内核态进程地址空间管理
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
#include <linux/nmi.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/version.h>
#if KERNEL_VERSION(4, 15, 0) <= LINUX_VERSION_CODE
#include <linux/sched/mm.h>
#endif
#include <asm/irq_regs.h>

#include "internal.h"
#include "mm_tree.h"
#include "pub/trace_file.h"


void free_mm_info(struct rcu_head *rcu)
{
	struct mm_info *this = container_of(rcu, struct mm_info, rcu_head);

	kfree(this);
}

void init_mm_tree(struct mm_tree *mm_tree)
{
	INIT_RADIX_TREE(&mm_tree->mm_tree, GFP_ATOMIC);
	spin_lock_init(&mm_tree->mm_tree_lock);
}

void cleanup_mm_tree(struct mm_tree *mm_tree)
{
	struct mm_info *mms[NR_BATCH];
	struct mm_info *mm_info;
	int nr_found;
	unsigned long pos;
	int i;
	unsigned long flags;

	pos = 0;
	spin_lock_irqsave(&mm_tree->mm_tree_lock, flags);
	do {
		nr_found = radix_tree_gang_lookup(&mm_tree->mm_tree, (void **)mms, pos, NR_BATCH);
		for (i = 0; i < nr_found; i++) {
			mm_info = mms[i];
			radix_tree_delete(&mm_tree->mm_tree, (unsigned long)mm_info->mm);
			pos = (unsigned long)mm_info->mm + 1;
			call_rcu(&mm_info->rcu_head, free_mm_info);
		}
	} while (nr_found > 0);
	spin_unlock_irqrestore(&mm_tree->mm_tree_lock, flags);
}

struct mm_info *find_mm_info(struct mm_tree *mm_tree, struct mm_struct *mm)
{
	struct mm_info *info;

	if (mm == NULL)
		return NULL;

	info = radix_tree_lookup(&mm_tree->mm_tree, (unsigned long)mm);

	return info;
}

void putin_mm_info(struct mm_tree *mm_tree, struct mm_info *mm_info)
{
	unsigned long flags;
	struct mm_info *tmp;
	struct mm_struct *mm;

	if (!mm_info)
		return;

	mm = mm_info->mm;

	spin_lock_irqsave(&mm_tree->mm_tree_lock, flags);
	tmp = radix_tree_lookup(&mm_tree->mm_tree, (unsigned long)mm);
	if (tmp) {
		radix_tree_delete(&mm_tree->mm_tree, (unsigned long)mm);
		call_rcu(&tmp->rcu_head, free_mm_info);
	}
	radix_tree_insert(&mm_tree->mm_tree, (unsigned long)mm, mm_info);
	spin_unlock_irqrestore(&mm_tree->mm_tree_lock, flags);
}

struct mm_info *takeout_mm_info(struct mm_tree *mm_tree, struct mm_struct *mm)
{
	unsigned long flags;
	struct mm_info *info = NULL;

	spin_lock_irqsave(&mm_tree->mm_tree_lock, flags);
	info = radix_tree_delete(&mm_tree->mm_tree, (unsigned long)mm);
	spin_unlock_irqrestore(&mm_tree->mm_tree_lock, flags);

	return info;
}

void __get_argv_processes(struct mm_tree *mm_tree)
{
	struct task_struct *p;
	unsigned long flags;
	struct mm_info *mms[NR_BATCH];
	struct mm_info *mm_info;
	int nr_found;
	unsigned long pos;
	int i;

	rcu_read_lock();
	for_each_process(p) {
		if (p->mm) {
			struct mm_info *mm_info;

			mm_info = kmalloc(sizeof(struct mm_info), GFP_ATOMIC | __GFP_ZERO);
			if (!mm_info)
				continue;
			mm_info->pid = p->pid;
			mm_info->mm = p->mm;
			spin_lock_irqsave(&mm_tree->mm_tree_lock, flags);
			radix_tree_insert(&mm_tree->mm_tree, (unsigned long)p->mm, mm_info);
			spin_unlock_irqrestore(&mm_tree->mm_tree_lock, flags);
			touch_softlockup_watchdog();
		}
	}
	rcu_read_unlock();

	pos = 0;
	do {
		nr_found = radix_tree_gang_lookup(&mm_tree->mm_tree, (void **)mms, pos, NR_BATCH);
		for (i = 0; i < nr_found; i++) {
			mm_info = mms[i];
			get_argv_from_mm(mm_info->mm, mm_info->argv, 255);
			pos = (unsigned long)mm_info->mm + 1;
			touch_softlockup_watchdog();
		}
	} while (nr_found > 0);
}

void dump_proc_chains_argv(int style, struct mm_tree *mm_tree,
	struct task_struct *tsk,
	struct diag_proc_chains_detail *detail)
{
	struct task_struct *walker;
	struct mm_info *mm_info;
	int cnt = 0;
	int i = 0;

	for (i = 0; i < PROCESS_CHAINS_COUNT; i++) {
		detail->chains[i][0] = 0;
		detail->tgid[i] = 0;
	}
	if (style == 0)
		return;

	rcu_read_lock();
	walker = tsk;

	while (walker->pid > 0) {
		if (!thread_group_leader(walker))
			walker = rcu_dereference(walker->group_leader);
		mm_info = find_mm_info(mm_tree, walker->mm);
		if (mm_info) {
			if (mm_info->cgroup_buf[0] == 0)
				diag_cgroup_name(walker, mm_info->cgroup_buf, 255, 0);
			strncpy(detail->chains[cnt], mm_info->argv, PROCESS_ARGV_LEN);
			detail->full_argv[cnt] = 1;
		} else {
			strncpy(detail->chains[cnt], walker->comm, TASK_COMM_LEN);
			detail->full_argv[cnt] = 0;
		}
		detail->tgid[cnt] = walker->pid;
		walker = rcu_dereference(walker->real_parent);
		cnt++;
		if (cnt >= PROCESS_CHAINS_COUNT)
			break;
	}
	rcu_read_unlock();
}

int get_argv_from_mm(struct mm_struct *mm, char *buf, size_t size)
{
	int ret = 0;
	unsigned long offset, pos;
	char *kaddr;
	struct page *page;
	int i = 0;
	unsigned long len = 0;

	memset(buf, 0, size);
	if (!mm)
		return 0;

	pos = mm->arg_start;
	offset = pos % PAGE_SIZE;
	len = mm->arg_end - mm->arg_start;
	if (len >= size)
		len = size;
	if (offset + len >= PAGE_SIZE)
		len = PAGE_SIZE - offset;

#if KERNEL_VERSION(4, 15, 0) <= LINUX_VERSION_CODE
	ret = get_user_pages_remote(current, mm, pos, 1, FOLL_FORCE,
			&page, NULL, NULL);
#elif KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
	ret = get_user_pages_remote(current, mm, pos, 1, FOLL_FORCE,
			&page, NULL);
#else
	ret = get_user_pages(current, mm, pos, 1, 0, 1, &page, NULL);
#endif
	if (ret <= 0)
		return 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	kaddr = kmap_atomic(page, KM_USER0);
#else
	kaddr = kmap_atomic(page);
#endif
	memcpy(buf, kaddr + offset, len);
	for (i = 0; i < len; i++)
		if (buf[i] == 0)
			buf[i] = ' ';
	buf[len] = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	kunmap_atomic(kaddr, KM_USER0);
#else
	kunmap_atomic(kaddr);
#endif
	put_page(page);

	ret = 1;
	return ret;
}

void diag_hook_exec(struct linux_binprm *bprm, struct mm_tree *mm_tree)
{
	struct mm_struct *mm = NULL;
	struct mm_info *mm_info;

	if (bprm->mm)
	{
		mm = bprm->mm;
	}
	else
	{
		mm = bprm->vma ? bprm->vma->vm_mm : NULL;
	}

	if (!mm)
		return;

	mm_info = kmalloc(sizeof(struct mm_info), GFP_ATOMIC | __GFP_ZERO);
	if (!mm_info)
		return;

	mm_info->mm = mm;
	get_argv_from_mm(mm, mm_info->argv, 255);
	putin_mm_info(mm_tree, mm_info);
}

void diag_hook_process_exit_exec(struct task_struct *tsk, struct mm_tree *mm_tree)
{
	struct mm_info *mm_info;

	if (!tsk)
		return;
	if (!thread_group_leader(tsk))
		tsk = rcu_dereference(tsk->group_leader);
	if (!tsk || !tsk->mm)
		return;

	mm_info = takeout_mm_info(mm_tree, tsk->mm);
	if (mm_info) {
		kfree(mm_info);
	}
}

void dump_proc_chains_simple(struct task_struct *tsk,
	struct diag_proc_chains_detail *detail)
{
	struct task_struct *walker;
	int cnt = 0;
	int i = 0;

	rcu_read_lock();
	walker = tsk;
	for (i = 0; i < PROCESS_CHAINS_COUNT; i++) {
		detail->chains[i][0] = 0;
	}
	while (walker->pid > 0) {
		if (!thread_group_leader(walker))
			walker = rcu_dereference(walker->group_leader);
		strncpy(detail->chains[cnt], walker->comm, PROCESS_ARGV_LEN);
		detail->full_argv[cnt] = 0;
		detail->tgid[cnt] = walker->pid;

		walker = rcu_dereference(walker->real_parent);
		cnt++;
		if (cnt >= PROCESS_CHAINS_COUNT)
			break;
	}
	rcu_read_unlock();
}

void printk_process_chains(struct diag_proc_chains_detail *proc_chains)
{
	int i;

	if (proc_chains == NULL)
		return;

	printk("    进程链信息：\n");
	for (i = 0; i < PROCESS_CHAINS_COUNT; i++) {
		if (proc_chains->chains[i][0] == 0)
			break;

		printk("          %s\n", proc_chains->chains[i]);
	}
}

static void __diag_print_process_chain(int pre, enum diag_printk_type type, void *obj, struct task_struct *tsk)
{
	struct task_struct *walker = tsk;

	rcu_read_lock();
	while (walker->pid > 0) {
		if (!thread_group_leader(walker))
			walker = rcu_dereference(walker->group_leader);
		DIAG_TRACE_PRINTK(pre, type, obj, "pid: %d, comm: %s\n", walker->pid, walker->comm);
		walker = rcu_dereference(walker->real_parent);
	}
	rcu_read_unlock();
}

void diag_print_process_chain(int pre, struct task_struct *tsk)
{
	__diag_print_process_chain(pre, TRACE_PRINTK, NULL, tsk);
}

void diag_trace_buffer_process_chain(int pre, struct diag_trace_buffer *buffer, struct task_struct *tsk)
{
	__diag_print_process_chain(pre, TRACE_BUFFER_PRINTK, buffer, tsk);
}

void diag_trace_buffer_nolock_process_chain(int pre, struct diag_trace_buffer *buffer, struct task_struct *tsk)
{
	__diag_print_process_chain(pre, TRACE_BUFFER_PRINTK_NOLOCK, buffer, tsk);
}

void diag_trace_file_process_chain(int pre, struct diag_trace_file *file, struct task_struct *tsk)
{
	__diag_print_process_chain(pre, TRACE_FILE_PRINTK, file, tsk);
}

void diag_trace_file_nolock_process_chain(int pre, struct diag_trace_file *file, struct task_struct *tsk)
{
	__diag_print_process_chain(pre, TRACE_FILE_PRINTK_NOLOCK, file, tsk);
}

static void print_all(int pre, enum diag_printk_type type, void *obj, char *buf, size_t size)
{
	char *p = buf;
	int len = 0;

	while (p < buf + size) {
		if (*p == 0)
			*p = ' ';
		p++;
	}
	buf[size - 1] = 0;
	len = strlen(buf);
	if (len > 0)
		DIAG_TRACE_PRINTK(pre, type, obj, "    命令行： %s\n", buf);
}

ssize_t dump_pid_cmdline(int pre, enum diag_printk_type type, void *obj,
	struct task_struct *tsk, char *buf, size_t _count)
{
	struct mm_struct *mm;
	unsigned long count = _count;
	unsigned long arg_start, arg_end;
	unsigned long len;
	char c;
	ssize_t rv;
	int nr_read;

	if (!tsk)
		return -ESRCH;
	mm = get_task_mm(tsk);
	if (!mm)
		return 0;
	/* Check if process spawned far enough to have cmdline. */
	if (!mm->env_end) {
		rv = 0;
		goto out_mmput;
	}

	down_read(&mm->mmap_sem);
	arg_start = mm->arg_start;
	arg_end = mm->arg_end;
	up_read(&mm->mmap_sem);

	if (arg_start > arg_end) {
		return -EFAULT;
	}

	len = arg_end - arg_start;

	/* Empty ARGV. */
	if (len == 0) {
		rv = 0;
		goto out_mmput;
	}
	/*
	 * Inherently racy -- command line shares address space
	 * with code and data.
	 */
	rv = orig_access_remote_vm(mm, arg_end - 1, &c, 1, 0);
	if (rv <= 0)
		goto out_mmput;

	rv = 0;

	count = min(len, _count - 1);
	memset(buf, 0, _count);
	nr_read = orig_access_remote_vm(mm, arg_start, buf, _count, 0);
	if (nr_read < 0)
		rv = nr_read;
	if (nr_read <= 0)
		goto out_mmput;
	
	print_all(pre, type, obj, buf, count);

out_mmput:
	mmput(mm);
	return rv;
}

static void __diag_print_process_chain_cmdline(int pre, enum diag_printk_type type, void *obj,
	struct task_struct *tsk)
{
	struct task_struct *walker = tsk;
	struct task_struct *parents[20];
	int idx = 0;
	int i;
	char buf[255];

	rcu_read_lock();
	while (walker->pid > 0) {
		if (!thread_group_leader(walker))
			walker = rcu_dereference(walker->group_leader);
		parents[idx++] = walker;
		get_task_struct(walker);
		if (idx >= 20)
			break;
		walker = rcu_dereference(walker->real_parent);
	}
	rcu_read_unlock();

	for (i = 0; i < idx; i++) {
		DIAG_TRACE_PRINTK(pre, type, obj, "父进程PID： %d, 名称： %s\n", parents[i]->pid, parents[i]->comm);
		dump_pid_cmdline(pre, type, obj, parents[i], buf, 255);
		put_task_struct(parents[i]);
	}
}

void diag_print_process_chain_cmdline(int pre, struct task_struct *tsk)
{
	__diag_print_process_chain_cmdline(pre, TRACE_PRINTK, NULL, tsk);
}

void diag_trace_buffer_process_chain_cmdline(int pre,
	struct diag_trace_buffer *buffer, struct task_struct *tsk)
{
	__diag_print_process_chain_cmdline(pre, TRACE_BUFFER_PRINTK, buffer, tsk);
}

void diag_trace_buffer_nolock_process_chain_cmdline(int pre,
	struct diag_trace_buffer *buffer, struct task_struct *tsk)
{
	__diag_print_process_chain_cmdline(pre, TRACE_BUFFER_PRINTK_NOLOCK, buffer, tsk);
}

void diag_trace_file_process_chain_cmdline(int pre,
	struct diag_trace_file *file, struct task_struct *tsk)
{
	__diag_print_process_chain_cmdline(pre, TRACE_FILE_PRINTK, file, tsk);
}

void diag_trace_file_nolock_process_chain_cmdline(int pre,
	struct diag_trace_file *file, struct task_struct *tsk)
{
	__diag_print_process_chain_cmdline(pre, TRACE_FILE_PRINTK_NOLOCK, file, tsk);
}
