/*
 *  Linux内核诊断工具--工具通用调试缓冲区模块
 *  这是为了解决procfs/trace的问题而编写 
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者： Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 */

#ifndef __DIAG_VARIANT_BUFFER
#define __DIAG_VARIANT_BUFFER

#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/stddef.h>

#include "uapi/variant_buffer.h"

struct diag_variant_buffer {
	struct {
		char *data;
		unsigned int pos;
		struct diag_variant_buffer_head *head;
	} buffers[2];
	/* 0 or 1 */
	int buffer_toggle;

	struct {
		char *data;
		unsigned int len;
	} product;

	unsigned int buf_size;
	unsigned int alloced;
	spinlock_t lock;
	struct mutex mutex;
};

#define diag_variant_buffer_spin_lock(__buffer, flags)	\
	spin_lock_irqsave(&((__buffer)->lock), flags)
#define diag_variant_buffer_spin_unlock(__buffer, flags)	\
	spin_unlock_irqrestore(&((__buffer)->lock), flags)
int init_diag_variant_buffer(struct diag_variant_buffer *buffer,
	unsigned int buf_size);
int alloc_diag_variant_buffer(struct diag_variant_buffer *buffer);
void destroy_diag_variant_buffer(struct diag_variant_buffer *buffer);
void discard_diag_variant_buffer(struct diag_variant_buffer *buffer);
void backup_diag_variant_buffer(struct diag_variant_buffer *buffer);
asmlinkage int
diag_variant_buffer_reserve(struct diag_variant_buffer *buffer, size_t len);
asmlinkage int
diag_variant_buffer_seal(struct diag_variant_buffer *buffer);
asmlinkage int
diag_variant_buffer_write_nolock(struct diag_variant_buffer *buffer,
	const void *data, size_t len);
void diag_variant_buffer_mutex_lock(struct diag_variant_buffer *buffer);
void diag_variant_buffer_mutex_unlock(struct diag_variant_buffer *buffer);
int copy_to_user_variant_buffer(struct diag_variant_buffer *variant_buffer,
	void __user *ptr_len, void __user *buf, size_t size);
#endif /* __DIAG_VARIANT_BUFFER */
