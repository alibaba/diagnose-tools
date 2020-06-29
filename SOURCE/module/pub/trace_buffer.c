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

#include <linux/vmalloc.h>

#include "internal.h"
#include "pub/trace_buffer.h"

int init_diag_trace_buffer(struct diag_trace_buffer *buffer,
	unsigned int buf_size)
{
	int ret = -ENOMEM;
	char *buf1 = NULL, *buf2 = NULL;

	ret = -EINVAL;
	if (buf_size < 10 * DIAG_TRACE_BUF_SIZE)
		return ret;

	buf1 = vmalloc(buf_size);
	if (!buf1)
		goto out_nomem;

	buf2 = vmalloc(buf_size);
	if (!buf2)
		goto out_nomem;

	memset(buf1, 0, buf_size);
	memset(buf2, 0, buf_size);
	memset(buffer, 0, sizeof(struct diag_trace_buffer));
	buffer->buf_size = buf_size;
	buffer->buffer.data = buf1;
	spin_lock_init(&buffer->buffer.lock);
	mutex_init(&buffer->buffer.mutex);
	buffer->product.data = buf2;

 	ret = 0;
	return ret;
out_nomem:
	if (buf1)
		vfree(buf1);
	if (buf2)
		vfree(buf2);
	
	return ret;
}

void destroy_diag_trace_buffer(struct diag_trace_buffer *buffer)
{
	if (buffer->buffer.data)
		vfree(buffer->buffer.data);
	if (buffer->product.data)
		vfree(buffer->product.data);

	memset(buffer, 0, sizeof(struct diag_trace_buffer));
}

void discard_diag_trace_buffer(struct diag_trace_buffer *buffer)
{
	unsigned long flags;

	diag_trace_buffer_mutex_lock(buffer);
	diag_trace_buffer_spin_lock(buffer, flags);
	buffer->buffer.circle = buffer->buffer.pos = buffer->buffer.tail = 0;
	diag_trace_buffer_spin_unlock(buffer, flags);
	diag_trace_buffer_mutex_unlock(buffer);
}

void backup_diag_trace_buffer(struct diag_trace_buffer *buffer)
{
	unsigned long flags;

	if (!buffer->buffer.data || !buffer->product.data)
		return;

	diag_trace_buffer_mutex_lock(buffer);
	diag_trace_buffer_spin_lock(buffer, flags);

	buffer->product.len = 0;
	if (buffer->buffer.pos < buffer->buf_size) {
		if (buffer->buffer.circle) {
			int tail_len = 0;
			if (buffer->buffer.tail > buffer->buffer.pos) {
				tail_len = buffer->buffer.tail - buffer->buffer.pos;

				memcpy(buffer->product.data,
					buffer->buffer.data + buffer->buffer.pos,
					tail_len);
			}
			memcpy(buffer->product.data + tail_len,
				buffer->buffer.data,
				buffer->buffer.pos);
			buffer->product.len = buffer->buffer.pos + tail_len;
		} else {
			memcpy(buffer->product.data, buffer->buffer.data, buffer->buffer.pos);
			buffer->product.len = buffer->buffer.pos;
		}
	}

	buffer->buffer.circle = buffer->buffer.pos = buffer->buffer.tail = 0;

	diag_trace_buffer_spin_unlock(buffer, flags);
	diag_trace_buffer_mutex_unlock(buffer);
}

asmlinkage int
diag_trace_buffer_write_nolock(struct diag_trace_buffer *buffer,
	const void *data, size_t len)
{
	unsigned int left;

	left = buffer->buf_size - buffer->buffer.pos;
	if (len < left) {
		memcpy(buffer->buffer.data + buffer->buffer.pos,
			data, len);
		buffer->buffer.pos += len;
	} else {
		buffer->buffer.tail = buffer->buffer.pos;
		memcpy(buffer->buffer.data, data, len);
		buffer->buffer.pos = len;
		buffer->buffer.circle = 1;
	}

	return len;
}

asmlinkage int
diag_trace_buffer_write(struct diag_trace_buffer *buffer,
	const void *data, size_t len)
{
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&buffer->buffer.lock, flags);
	ret = diag_trace_buffer_write_nolock(buffer, data, len);
	spin_unlock_irqrestore(&buffer->buffer.lock, flags);

	return ret;
}

static asmlinkage int
__diag_trace_buffer_printk_nolock(struct diag_trace_buffer *buffer,
	const char *fmt, va_list ap)
{
	unsigned int len = 0;
	unsigned int left;

	len = vsnprintf(buffer->fmt_buffer, DIAG_TRACE_BUF_SIZE, fmt, ap);
	if (len > DIAG_TRACE_BUF_SIZE)
		return len;

	left = buffer->buf_size - buffer->buffer.pos;
	if (len < left) {
		memcpy(buffer->buffer.data + buffer->buffer.pos,
			buffer->fmt_buffer, len);
		buffer->buffer.pos += len;
	} else {
		buffer->buffer.tail = buffer->buffer.pos;
		memcpy(buffer->buffer.data, buffer->fmt_buffer, len);
		buffer->buffer.pos = len;
		buffer->buffer.circle = 1;
	}

	return len;
}

asmlinkage int
diag_trace_buffer_printk_nolock(struct diag_trace_buffer *buffer,
	const char *fmt, ...)
{
	va_list ap;
	int ret;
	
	va_start(ap, fmt);
	ret = __diag_trace_buffer_printk_nolock(buffer, fmt, ap);
	va_end(ap);
	
	return ret;
}

asmlinkage int
diag_trace_buffer_printk(struct diag_trace_buffer *buffer,
	const char *fmt, ...)
{
	int ret;
	unsigned long flags;
	va_list ap;
	
	spin_lock_irqsave(&buffer->buffer.lock, flags);
	va_start(ap, fmt);
	ret = __diag_trace_buffer_printk_nolock(buffer, fmt, ap);
	va_end(ap);
	spin_unlock_irqrestore(&buffer->buffer.lock, flags);

	return ret;
}

void diag_trace_buffer_mutex_lock(struct diag_trace_buffer *buffer)
{
	mutex_lock(&buffer->buffer.mutex);
}

void diag_trace_buffer_mutex_unlock(struct diag_trace_buffer *buffer)
{
	mutex_unlock(&buffer->buffer.mutex);
}

