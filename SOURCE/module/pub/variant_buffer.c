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

#include <linux/vmalloc.h>
#include <linux/uaccess.h>

#include "internal.h"
#include "pub/variant_buffer.h"
#include "pub/trace_buffer.h"

int init_diag_variant_buffer(struct diag_variant_buffer *buffer,
	unsigned int buf_size)
{
	int ret = 0;

	ret = -EINVAL;
	if (buf_size < 10 * DIAG_TRACE_BUF_SIZE)
		return ret;

	memset(buffer, 0, sizeof(struct diag_variant_buffer));
	buffer->buf_size = buf_size;
	spin_lock_init(&buffer->lock);
	mutex_init(&buffer->mutex);

 	ret = 0;
	return ret;
}

int alloc_diag_variant_buffer(struct diag_variant_buffer *buffer)
{
	int ret = -ENOMEM;
	char *buf1 = NULL, *buf2 = NULL, *buf3 = NULL;
	unsigned int buf_size;

	buf_size = buffer->buf_size;
	if (buffer->alloced)
		return 0;

	ret = -EINVAL;
	if (buf_size < 10 * DIAG_TRACE_BUF_SIZE)
		return ret;

	ret = -ENOMEM;
	buf1 = vmalloc(buf_size);
	if (!buf1)
		goto out_nomem;

	buf2 = vmalloc(buf_size);
	if (!buf2)
		goto out_nomem;

	buf3 = vmalloc(buf_size * 2);
	if (!buf3)
		goto out_nomem;

	memset(buf1, 0, buf_size);
	memset(buf2, 0, buf_size);
	memset(buf3, 0, buf_size * 2);
	buffer->buffers[0].data = buf1;
	buffer->buffers[1].data = buf2;
	buffer->product.data = buf3;

	buffer->alloced = 1;

 	ret = 0;
	return ret;
out_nomem:
	if (buf1)
		vfree(buf1);
	if (buf2)
		vfree(buf2);
	if (buf3)
		vfree(buf3);
	
	return ret;
}

void destroy_diag_variant_buffer(struct diag_variant_buffer *buffer)
{
	if (buffer->buffers[0].data)
		vfree(buffer->buffers[0].data);
	if (buffer->buffers[1].data)
		vfree(buffer->buffers[1].data);
	if (buffer->product.data)
		vfree(buffer->product.data);

	memset(buffer, 0, sizeof(struct diag_variant_buffer));
}

void discard_diag_variant_buffer(struct diag_variant_buffer *buffer)
{
	unsigned long flags;

	if (!buffer->alloced)
		return;

	diag_variant_buffer_mutex_lock(buffer);
	diag_variant_buffer_spin_lock(buffer, flags);
	buffer->buffers[0].pos = buffer->buffers[1].pos = 0;
	buffer->buffer_toggle = 0;
	diag_variant_buffer_spin_unlock(buffer, flags);
	diag_variant_buffer_mutex_unlock(buffer);
}

void backup_diag_variant_buffer(struct diag_variant_buffer *buffer)
{
	unsigned long flags;

	if (!buffer->alloced)
		return;

	diag_variant_buffer_mutex_lock(buffer);
	diag_variant_buffer_spin_lock(buffer, flags);

	buffer->product.len = 0;
	if (buffer->buffer_toggle == 0) {
		if (buffer->buffers[1].pos) {
			memcpy(buffer->product.data,
				buffer->buffers[1].data, buffer->buffers[1].pos);
			buffer->product.len = buffer->product.len + buffer->buffers[1].pos;
		}
		if (buffer->buffers[0].pos) {
			memcpy(buffer->product.data + buffer->product.len,
				buffer->buffers[0].data, buffer->buffers[0].pos);
			buffer->product.len = buffer->product.len + buffer->buffers[0].pos;
		}
	} else {
		if (buffer->buffers[0].pos) {
			memcpy(buffer->product.data,
				buffer->buffers[0].data, buffer->buffers[0].pos);
			buffer->product.len = buffer->product.len + buffer->buffers[0].pos;
		}
		if (buffer->buffers[1].pos) {
			memcpy(buffer->product.data + buffer->product.len,
				buffer->buffers[1].data, buffer->buffers[1].pos);
			buffer->product.len = buffer->product.len + buffer->buffers[1].pos;
		}
	}

	buffer->buffers[0].pos = buffer->buffers[1].pos = 0;
	buffer->buffers[0].head = buffer->buffers[1].head = NULL;
	buffer->buffer_toggle = 0;

	diag_variant_buffer_spin_unlock(buffer, flags);
	diag_variant_buffer_mutex_unlock(buffer);
}

asmlinkage int
diag_variant_buffer_reserve(struct diag_variant_buffer *buffer, size_t len)
{
	int real_len = (len + sizeof(unsigned long)) & (sizeof(unsigned long) - 1);
	real_len += sizeof(struct diag_variant_buffer_head);
	/**
	 * 这样可以简单的略过整型溢出检查。
	 */
	if (len > 1024 * 1024 * 1024)
		return len;
	if (!buffer->alloced)
		return len;

	if (buffer->buffer_toggle == 0) {
		if (buffer->buffers[0].pos + real_len >= buffer->buf_size) {
			buffer->buffer_toggle = 1;
			buffer->buffers[1].pos = sizeof(struct diag_variant_buffer_head);
			buffer->buffers[1].head = (void *)buffer->buffers[1].data;
			memset(buffer->buffers[1].head, 0, sizeof(struct diag_variant_buffer_head));
		} else {
			buffer->buffers[0].head = (void *)buffer->buffers[0].data + buffer->buffers[0].pos;
			memset(buffer->buffers[0].head, 0, sizeof(struct diag_variant_buffer_head));
			buffer->buffers[0].pos += sizeof(struct diag_variant_buffer_head);
		}
	} else {
		if (buffer->buffers[1].pos + real_len >= buffer->buf_size) {
			buffer->buffer_toggle = 0;
			buffer->buffers[0].pos = sizeof(struct diag_variant_buffer_head);
			buffer->buffers[0].head = (void *)buffer->buffers[0].data;
			memset(buffer->buffers[0].head, 0, sizeof(struct diag_variant_buffer_head));
		} else {
			buffer->buffers[1].head = (void *)buffer->buffers[1].data + buffer->buffers[1].pos;
			memset(buffer->buffers[1].head, 0, sizeof(struct diag_variant_buffer_head));
			buffer->buffers[1].pos += sizeof(struct diag_variant_buffer_head);
		}
	}

	return len;
}

asmlinkage int
diag_variant_buffer_seal(struct diag_variant_buffer *buffer)
{
	int idx = !!buffer->buffer_toggle;
	void *rbound = buffer->buffers[idx].data + buffer->buf_size;

	if (!buffer->alloced)
		return -EINVAL;
	if ((void *)buffer->buffers[idx].head < (void *)buffer->buffers[idx].data)
		return -EINVAL;
	if ((void *)buffer->buffers[idx].head > (rbound - sizeof(struct diag_variant_buffer_head)))
		return -EINVAL;

	buffer->buffers[idx].head->magic = DIAG_VARIANT_BUFFER_HEAD_MAGIC_SEALED;
	buffer->buffers[idx].head->len = (void *)buffer->buffers[idx].data + buffer->buffers[idx].pos
			- (void *)buffer->buffers[idx].head;

	return 0;
}

asmlinkage int
diag_variant_buffer_write_nolock(struct diag_variant_buffer *buffer,
	const void *data, size_t len)
{
	unsigned int left;
	int idx = !!buffer->buffer_toggle;

	if (!buffer->alloced)
		return -EINVAL;

	left = buffer->buf_size - buffer->buffers[idx].pos;
	if (len < left) {
		memcpy(buffer->buffers[idx].data + buffer->buffers[idx].pos,
			data, len);
		buffer->buffers[idx].pos += len;
	}

	return len;
}

void diag_variant_buffer_mutex_lock(struct diag_variant_buffer *buffer)
{
	mutex_lock(&buffer->mutex);
}

void diag_variant_buffer_mutex_unlock(struct diag_variant_buffer *buffer)
{
	mutex_unlock(&buffer->mutex);
}

int copy_to_user_variant_buffer(struct diag_variant_buffer *variant_buffer,
	void __user *ptr_len, void __user *buf, size_t size)
{
	size_t len;
	int ret;

	backup_diag_variant_buffer(variant_buffer);
	len = variant_buffer->product.len;
	if (size < len)
		len = size;
	ret = copy_to_user(buf, variant_buffer->product.data, len);
	if (!ret)
		ret = len;
	if (ret >= 0) {
		ret = copy_to_user(ptr_len, &ret, sizeof(int));
	}

	return ret;
}
