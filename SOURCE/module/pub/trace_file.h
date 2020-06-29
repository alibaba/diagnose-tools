/*
 * Linux内核诊断工具--内核态缓冲区文件公共函数实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/proc_fs.h>

#include "pub/trace_buffer.h"

struct diag_trace_file;

typedef ssize_t (*diag_trace_file_prepare_read)(struct diag_trace_file *trace_file,
		struct file *file, char __user *buf, size_t size, loff_t *ppos);
typedef ssize_t (*diag_trace_file_write_cb)(struct diag_trace_file *trace_file,
		struct file *file, const char __user *buf, size_t count,
		loff_t *offs);
struct diag_trace_file {
	struct diag_trace_buffer trace_buffer;
	struct file_operations fops;
	struct proc_dir_entry *pe;
	diag_trace_file_prepare_read prepare_read;
	diag_trace_file_write_cb write;
	unsigned int buf_size;
	char file_name[255];
};

int init_diag_trace_file(struct diag_trace_file *file,
	char *filename, unsigned int buf_size, diag_trace_file_prepare_read prepare_read,
	diag_trace_file_write_cb write);
void destroy_diag_trace_file(struct diag_trace_file *file);
void discard_diag_trace_file(struct diag_trace_file *file);
#define diag_trace_file_printk_nolock(file, fmt, ...)				\
	do {							\
		diag_trace_buffer_printk_nolock(&(file)->trace_buffer, fmt, ##__VA_ARGS__);	\
	} while (0)

#define diag_trace_file_printk(file, fmt, ...)				\
	do {							\
		diag_trace_buffer_printk(&(file)->trace_buffer, fmt, ##__VA_ARGS__);	\
	} while (0)

static inline asmlinkage int
diag_trace_file_write_nolock(struct diag_trace_file *file,
	const void *data, size_t len)
{
	return diag_trace_buffer_write_nolock(&file->trace_buffer, data, len);
}
static inline asmlinkage int
diag_trace_file_write(struct diag_trace_file *file,
	const void *data, size_t len)
{
	return diag_trace_buffer_write(&file->trace_buffer, data, len);
}

#define diag_trace_file_spin_lock(file, flags)	\
	diag_trace_buffer_spin_lock(&((file)->trace_buffer), flags)
#define diag_trace_file_spin_unlock(file, flags)	\
	diag_trace_buffer_spin_unlock(&((file)->trace_buffer), flags)
static inline void diag_trace_file_mutex_lock(struct diag_trace_file *file)
{
	diag_trace_buffer_mutex_lock(&file->trace_buffer);
}

static inline void diag_trace_file_mutex_unlock(struct diag_trace_file *file)
{
	diag_trace_buffer_mutex_unlock(&file->trace_buffer);
}

void diagnose_trace_file_stack_trace(int pre, struct diag_trace_file *file,
	struct task_struct *p, unsigned long *backtrace);
void diagnose_trace_file_nolock_stack_trace(int pre, struct diag_trace_file *file,
	struct task_struct *p, unsigned long *backtrace);
void diagnose_trace_file_stack_trace_unfold(int pre, struct diag_trace_file *file,
	struct task_struct *p, unsigned long *backtrace);
void diagnose_trace_file_nolock_stack_trace_unfold(int pre, struct diag_trace_file *file,
	struct task_struct *p, unsigned long *backtrace);
void diagnose_trace_file_nolock_stack_trace_user(int pre, struct diag_trace_file *file,
	unsigned long *backtrace);
void diagnose_trace_file_stack_trace_user(int pre, struct diag_trace_file *file,
	unsigned long *backtrace);
void diagnose_trace_file_nolock_stack_trace_unfold_user(int pre, struct diag_trace_file *file,
	unsigned long *backtrace);
void diagnose_trace_file_stack_trace_unfold_user(int pre, struct diag_trace_file *file,
	unsigned long *backtrace);
void diagnose_trace_file_nolock_stack_trace_user_tsk(int pre, int might_sleep, struct diag_trace_file *file,
	struct task_struct *tsk, unsigned long *backtrace);
void diagnose_trace_file_stack_trace_user_tsk(int pre, struct diag_trace_file *file,
	struct task_struct *tsk, unsigned long *backtrace);
void diagnose_trace_file_nolock_stack_trace_unfold_user_tsk(int pre, int might_sleep, struct diag_trace_file *file,
	struct task_struct *tsk, unsigned long *backtrace);
void diagnose_trace_file_stack_trace_unfold_user_tsk(int pre, int might_sleep, struct diag_trace_file *file,
	struct task_struct *tsk, unsigned long *backtrace);
void diag_trace_file_process_chain(int pre, struct diag_trace_file *file, struct task_struct *tsk);
void diag_trace_file_nolock_process_chain(int pre, struct diag_trace_file *file, struct task_struct *tsk);
void diag_trace_file_process_chain_cmdline(int pre, struct diag_trace_file *file, struct task_struct *tsk);
void diag_trace_file_nolock_process_chain_cmdline(int pre, struct diag_trace_file *file, struct task_struct *tsk);
void trace_file_cgroups_tsk(int pre, struct diag_trace_file *file, struct task_struct *tsk);
void trace_file_nolock_cgroups_tsk(int pre, struct diag_trace_file *file, struct task_struct *tsk);
void trace_file_cgroups(int pre, struct diag_trace_file *file);
void trace_file_nolock_cgroups(int pre, struct diag_trace_file *file);
void diag_trace_file_all_task_stack(int pre, struct diag_trace_file *file);
void diag_trace_file_nolock_all_task_stack(int pre, struct diag_trace_file *file);
