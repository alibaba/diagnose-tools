/*
 * diagnose-tools 工具通用调试缓冲区模块
 * 这是为了解决procfs/trace的问题而编写 
 *
 * Copyright (C) 20２０ Alibaba Ltd.
 *
 * 作者： Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/stddef.h>

/**
 * 调试缓冲区描述符
 *    buffer: 当前正在接受调用者输出的缓冲区
 *        data: 数据起始指针
 *        pos:  当前写入位置
 *        circle: 是否已经产生了回绕
 *        tail: 有效位置的尾部
 *    product: 将buffer中数据临时保存到此，避免影响记录速度
 *        data: 数据起始指针
 *        len:  数据有效长度
 *    buf_size: buffer/product的大小
 */
#define DIAG_TRACE_BUF_SIZE 1024

struct diag_trace_buffer {
	struct {
		char *data;
		unsigned int pos;
		int circle;
		unsigned int tail;
		spinlock_t lock;
		struct mutex mutex;
	} buffer;

	struct {
		char *data;
		unsigned int len;
	} product;

	char fmt_buffer[DIAG_TRACE_BUF_SIZE];
	unsigned int buf_size;
};

int init_diag_trace_buffer(struct diag_trace_buffer *buffer,
	unsigned int buf_size);
void destroy_diag_trace_buffer(struct diag_trace_buffer *buffer);
void discard_diag_trace_buffer(struct diag_trace_buffer *buffer);
void backup_diag_trace_buffer(struct diag_trace_buffer *buffer);
asmlinkage int
diag_trace_buffer_printk_nolock(struct diag_trace_buffer *buffer,
	const char *fmt, ...);
asmlinkage int
diag_trace_buffer_printk(struct diag_trace_buffer *buffer,
	const char *fmt, ...);
asmlinkage int
diag_trace_buffer_write_nolock(struct diag_trace_buffer *buffer,
	const void *data, size_t len);
asmlinkage int
diag_trace_buffer_write(struct diag_trace_buffer *buffer,
	const void *data, size_t len);
#define diag_trace_buffer_spin_lock(__buffer, flags)	\
	spin_lock_irqsave(&((__buffer)->buffer.lock), flags)
#define diag_trace_buffer_spin_unlock(__buffer, flags)	\
	spin_unlock_irqrestore(&((__buffer)->buffer.lock), flags)
void diag_trace_buffer_mutex_lock(struct diag_trace_buffer *buffer);
void diag_trace_buffer_mutex_unlock(struct diag_trace_buffer *buffer);

void diagnose_trace_buffer_stack_trace(int pre, struct diag_trace_buffer *buffer,
	struct task_struct *p, unsigned long *backtrace);
void diagnose_trace_buffer_nolock_stack_trace(int pre, struct diag_trace_buffer *buffer,
	struct task_struct *p, unsigned long *backtrace);
void diagnose_trace_buffer_nolock_stack_trace_user(int pre, struct diag_trace_buffer *buffer,
	unsigned long *backtrace);
void diagnose_trace_buffer_stack_trace_user(int pre, struct diag_trace_buffer *buffer,
	unsigned long *backtrace);
void diagnose_trace_buffer_nolock_stack_trace_user_tsk(int pre, struct diag_trace_buffer *buffer,
	struct task_struct *tsk, unsigned long *backtrace);
void diagnose_trace_buffer_stack_trace_user_tsk(int pre, struct diag_trace_buffer *buffer,
	struct task_struct *tsk, unsigned long *backtrace);
void diag_trace_buffer_process_chain(int pre, struct diag_trace_buffer *buffer, struct task_struct *tsk);
void diag_trace_buffer_nolock_process_chain(int pre, struct diag_trace_buffer *buffer, struct task_struct *tsk);
void diag_trace_buffer_process_chain_cmdline(int pre, struct diag_trace_buffer *buffer, struct task_struct *tsk);
void diag_trace_buffer_nolock_process_chain_cmdline(int pre, struct diag_trace_buffer *buffer, struct task_struct *tsk);
void trace_buffer_cgroups_tsk(int pre, struct diag_trace_buffer *buffer, struct task_struct *tsk);
void trace_buffer_nolock_cgroups_tsk(int pre, struct diag_trace_buffer *buffer, struct task_struct *tsk);
void trace_buffer_cgroups(int pre, struct diag_trace_buffer *buffer);
void trace_buffer_nolock_cgroups(int pre, struct diag_trace_buffer *buffer);
void diag_trace_buffer_all_task_stack(int pre, struct diag_trace_buffer *buffer);
void diag_trace_buffer_nolock_all_task_stack(int pre,
	struct diag_trace_buffer *buffer);
void diagnose_trace_buffer_nolock_stack_trace_unfold(int pre, struct diag_trace_buffer *buffer,
	struct task_struct *p, unsigned long *backtrace);
void diagnose_trace_buffer_nolock_stack_trace_unfold_user(int pre, struct diag_trace_buffer *buffer,
	unsigned long *backtrace);
void diagnose_print_stack_trace_unfold_user_tsk(int pre, int might_sleep, struct task_struct *tsk, unsigned long *backtrace);
void diagnose_trace_buffer_nolock_stack_trace_unfold_user_tsk(int pre, int might_sleep, struct diag_trace_buffer *buffer,
	struct task_struct *tsk, unsigned long *backtrace);
void diagnose_trace_buffer_stack_trace_unfold_user_tsk(int pre, int might_sleep, struct diag_trace_buffer *buffer,
	struct task_struct *tsk, unsigned long *backtrace);

