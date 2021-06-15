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

#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/uio.h>

#include "pub/trace_file.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0) && !defined(XBY_CENTOS_6_5)
static inline void *__PDE_DATA(const struct inode *inode)
{
	return PDE(inode)->data;
}

void *PDE_DATA(const struct inode *inode)
{
	return __PDE_DATA(inode);
}

void kvfree(const void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		kfree(addr);
}
#elif defined(XBY_CENTOS_6_5) || defined(CENTOS_3_10_123_9_3)
void kvfree(const void *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		kfree(addr);
}
#endif

static inline bool __seq_has_overflowed(struct seq_file *m)
{
	return m->count == m->size;
}

static struct diag_trace_file *to_trace_file(struct file *file)
{
	if (!file)
		return NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
	if (!file->f_dentry || !file->f_dentry->d_inode)
		return NULL;

	return PDE_DATA(file->f_dentry->d_inode);
#else
	if (!file->f_inode)
		return NULL;

	return PDE_DATA(file->f_inode);
#endif
}

static int trace_file_show(struct seq_file *m, void *v)
{
	struct diag_trace_file *trace_file = m->private;

	if (!trace_file)
		return -EINVAL;

	seq_write(m, trace_file->trace_buffer.product.data,
		trace_file->trace_buffer.product.len);
	
	return 0;
}

static void *__seq_buf_alloc(unsigned long size)
{
	void *buf;

	buf = vmalloc(size);

	return buf;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
static int trace_file_open(struct inode *inode, struct file *filp)
{
	struct diag_trace_file *trace_file = to_trace_file(filp);

	if (!trace_file)
		return -EINVAL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	return single_open(filp, trace_file_show, trace_file);
#else
	return single_open_size(filp, trace_file_show, trace_file, trace_file->buf_size);
#endif
}

static int traverse(struct diag_trace_file *trace_file, struct seq_file *m, loff_t offset)
{
	loff_t pos = 0, index;
	int error = 0;
	void *p;

	m->version = 0;
	index = 0;
	m->count = m->from = 0;
	if (!offset) {
		m->index = index;
		return 0;
	}
	if (!m->buf) {
		m->buf = __seq_buf_alloc(m->size = trace_file->buf_size);
		if (!m->buf)
			return -ENOMEM;
	}
	p = m->op->start(m, &index);
	while (p) {
		error = PTR_ERR(p);
		if (IS_ERR(p))
			break;
		error = m->op->show(m, p);
		if (error < 0)
			break;
		if (unlikely(error)) {
			error = 0;
			m->count = 0;
		}
		if (__seq_has_overflowed(m))
			goto Eoverflow;
		if (pos + m->count > offset) {
			m->from = offset - pos;
			m->count -= m->from;
			m->index = index;
			break;
		}
		pos += m->count;
		m->count = 0;
		if (pos == offset) {
			index++;
			m->index = index;
			break;
		}
		p = m->op->next(m, p, &index);
	}
	m->op->stop(m, p);
	m->index = index;
	return error;

Eoverflow:
	m->op->stop(m, p);
	kvfree(m->buf);
	m->count = 0;
	m->buf = __seq_buf_alloc(m->size <<= 1);
	return !m->buf ? -ENOMEM : -EAGAIN;
}

ssize_t __seq_read(struct diag_trace_file *trace_file,
	struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	struct seq_file *m = file->private_data;
	size_t copied = 0;
	loff_t pos;
	size_t n;
	void *p;
	int err = 0;

	mutex_lock(&m->lock);

	/*
	 * seq_file->op->..m_start/m_stop/m_next may do special actions
	 * or optimisations based on the file->f_version, so we want to
	 * pass the file->f_version to those methods.
	 *
	 * seq_file->version is just copy of f_version, and seq_file
	 * methods can treat it simply as file version.
	 * It is copied in first and copied out after all operations.
	 * It is convenient to have it as  part of structure to avoid the
	 * need of passing another argument to all the seq_file methods.
	 */
	m->version = file->f_version;

	/* Don't assume *ppos is where we left it */
	if (unlikely(*ppos != m->read_pos)) {
		while ((err = traverse(trace_file, m, *ppos)) == -EAGAIN)
			;
		if (err) {
			/* With prejudice... */
			m->read_pos = 0;
			m->version = 0;
			m->index = 0;
			m->count = 0;
			goto Done;
		} else {
			m->read_pos = *ppos;
		}
	}

	/* grab buffer if we didn't have one */
	if (!m->buf) {
		/**
		 * 这里直接分配最大的内存，避免多次重试
		 */
		m->buf = __seq_buf_alloc(m->size = trace_file->buf_size);
		if (!m->buf)
			goto Enomem;
	}
	/* if not empty - flush it first */
	if (m->count) {
		n = min(m->count, size);
		err = copy_to_user(buf, m->buf + m->from, n);
		if (err)
			goto Efault;
		m->count -= n;
		m->from += n;
		size -= n;
		buf += n;
		copied += n;
		if (!m->count) {
			m->from = 0;
			m->index++;
		}
		if (!size)
			goto Done;
	}
	/* we need at least one record in buffer */
	pos = m->index;
	p = m->op->start(m, &pos);
	while (1) {
		err = PTR_ERR(p);
		if (!p || IS_ERR(p))
			break;
		err = m->op->show(m, p);
		if (err < 0)
			break;
		if (unlikely(err))
			m->count = 0;
		if (unlikely(!m->count)) {
			p = m->op->next(m, p, &pos);
			m->index = pos;
			continue;
		}
		if (m->count < m->size)
			goto Fill;
		m->op->stop(m, p);
		kvfree(m->buf);
		m->count = 0;
		m->buf = __seq_buf_alloc(m->size <<= 1);
		if (!m->buf)
			goto Enomem;
		m->version = 0;
		pos = m->index;
		p = m->op->start(m, &pos);
	}
	m->op->stop(m, p);
	m->count = 0;
	goto Done;
Fill:
	/* they want more? let's try to get some more */
	while (m->count < size) {
		size_t offs = m->count;
		loff_t next = pos;
		p = m->op->next(m, p, &next);
		if (!p || IS_ERR(p)) {
			err = PTR_ERR(p);
			break;
		}
		err = m->op->show(m, p);
		if (__seq_has_overflowed(m) || err) {
			m->count = offs;
			if (likely(err <= 0))
				break;
		}
		pos = next;
	}
	m->op->stop(m, p);
	n = min(m->count, size);
	err = copy_to_user(buf, m->buf, n);
	if (err)
		goto Efault;
	copied += n;
	m->count -= n;
	if (m->count)
		m->from = n;
	else
		pos++;
	m->index = pos;
Done:
	if (!copied)
		copied = err;
	else {
		*ppos += copied;
		m->read_pos += copied;
	}
	file->f_version = m->version;
	mutex_unlock(&m->lock);
	return copied;
Enomem:
	err = -ENOMEM;
	goto Done;
Efault:
	err = -EFAULT;
	goto Done;
}
#else
static int trace_file_open(struct inode *inode, struct file *filp)
{
	struct diag_trace_file *trace_file = to_trace_file(filp);

	if (!trace_file)
		return -EINVAL;

	return single_open(filp, trace_file_show, trace_file);
}

static int traverse(struct diag_trace_file *trace_file,
	struct seq_file *m, loff_t offset)
{
	loff_t pos = 0;
	int error = 0;
	void *p;

	m->index = 0;
	m->count = m->from = 0;
	if (!offset)
		return 0;

	if (!m->buf) {
		m->buf = __seq_buf_alloc(m->size = trace_file->buf_size);
		if (!m->buf)
			return -ENOMEM;
	}
	p = m->op->start(m, &m->index);
	while (p) {
		error = PTR_ERR(p);
		if (IS_ERR(p))
			break;
		error = m->op->show(m, p);
		if (error < 0)
			break;
		if (unlikely(error)) {
			error = 0;
			m->count = 0;
		}
		if (seq_has_overflowed(m))
			goto Eoverflow;
		p = m->op->next(m, p, &m->index);
		if (pos + m->count > offset) {
			m->from = offset - pos;
			m->count -= m->from;
			break;
		}
		pos += m->count;
		m->count = 0;
		if (pos == offset)
			break;
	}
	m->op->stop(m, p);
	return error;

Eoverflow:
	m->op->stop(m, p);
	kvfree(m->buf);
	m->count = 0;
	m->buf = __seq_buf_alloc(m->size <<= 1);
	return !m->buf ? -ENOMEM : -EAGAIN;
}

/*
 * Ready-made ->f_op->read_iter()
 */
ssize_t __seq_read_iter(struct diag_trace_file *trace_file,
	struct kiocb *iocb, struct iov_iter *iter)
{
	struct seq_file *m = iocb->ki_filp->private_data;
	size_t copied = 0;
	size_t n;
	void *p;
	int err = 0;

	if (!iov_iter_count(iter))
		return 0;

	mutex_lock(&m->lock);

	/*
	 * if request is to read from zero offset, reset iterator to first
	 * record as it might have been already advanced by previous requests
	 */
	if (iocb->ki_pos == 0) {
		m->index = 0;
		m->count = 0;
	}

	/* Don't assume ki_pos is where we left it */
	if (unlikely(iocb->ki_pos != m->read_pos)) {
		while ((err = traverse(trace_file, m, iocb->ki_pos)) == -EAGAIN)
			;
		if (err) {
			/* With prejudice... */
			m->read_pos = 0;
			m->index = 0;
			m->count = 0;
			goto Done;
		} else {
			m->read_pos = iocb->ki_pos;
		}
	}

	/* grab buffer if we didn't have one */
	if (!m->buf) {
		m->buf = __seq_buf_alloc(m->size = trace_file->buf_size);
		if (!m->buf)
			goto Enomem;
	}
	// something left in the buffer - copy it out first
	if (m->count) {
		n = copy_to_iter(m->buf + m->from, m->count, iter);
		m->count -= n;
		m->from += n;
		copied += n;
		if (m->count)	// hadn't managed to copy everything
			goto Done;
	}
	// get a non-empty record in the buffer
	m->from = 0;
	p = m->op->start(m, &m->index);
	while (1) {
		err = PTR_ERR(p);
		if (!p || IS_ERR(p))	// EOF or an error
			break;
		err = m->op->show(m, p);
		if (err < 0)		// hard error
			break;
		if (unlikely(err))	// ->show() says "skip it"
			m->count = 0;
		if (unlikely(!m->count)) { // empty record
			p = m->op->next(m, p, &m->index);
			continue;
		}
		if (!seq_has_overflowed(m)) // got it
			goto Fill;
		// need a bigger buffer
		m->op->stop(m, p);
		kvfree(m->buf);
		m->count = 0;
		m->buf = __seq_buf_alloc(m->size <<= 1);
		if (!m->buf)
			goto Enomem;
		p = m->op->start(m, &m->index);
	}
	// EOF or an error
	m->op->stop(m, p);
	m->count = 0;
	goto Done;
Fill:
	// one non-empty record is in the buffer; if they want more,
	// try to fit more in, but in any case we need to advance
	// the iterator once for every record shown.
	while (1) {
		size_t offs = m->count;
		loff_t pos = m->index;

		p = m->op->next(m, p, &m->index);
		if (pos == m->index) {
			pr_info_ratelimited("buggy .next function %ps did not update position index\n",
					    m->op->next);
			m->index++;
		}
		if (!p || IS_ERR(p))	// no next record for us
			break;
		if (m->count >= iov_iter_count(iter))
			break;
		err = m->op->show(m, p);
		if (err > 0) {		// ->show() says "skip it"
			m->count = offs;
		} else if (err || seq_has_overflowed(m)) {
			m->count = offs;
			break;
		}
	}
	m->op->stop(m, p);
	n = copy_to_iter(m->buf, m->count, iter);
	copied += n;
	m->count -= n;
	m->from = n;
Done:
	if (unlikely(!copied)) {
		copied = m->count ? -EFAULT : err;
	} else {
		iocb->ki_pos += copied;
		m->read_pos += copied;
	}
	mutex_unlock(&m->lock);
	return copied;
Enomem:
	err = -ENOMEM;
	goto Done;
}

/**
 *	seq_read -	->read() method for sequential files.
 *	@file: the file to read from
 *	@buf: the buffer to read to
 *	@size: the maximum number of bytes to read
 *	@ppos: the current position in the file
 *
 *	Ready-made ->f_op->read()
 */
ssize_t __seq_read(struct diag_trace_file *trace_file,
	struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	struct iovec iov = { .iov_base = buf, .iov_len = size};
	struct kiocb kiocb;
	struct iov_iter iter;
	ssize_t ret;

	init_sync_kiocb(&kiocb, file);
	iov_iter_init(&iter, READ, &iov, 1, size);

	kiocb.ki_pos = *ppos;
	ret = __seq_read_iter(trace_file, &kiocb, &iter);
	*ppos = kiocb.ki_pos;
	return ret;
}
#endif

static ssize_t trace_file_read(
	struct file *file,
	char __user *buf,
	size_t size,
	loff_t *ppos)
{
	struct diag_trace_file *trace_file = to_trace_file(file);
	ssize_t ret;

	if (!trace_file)
		return -EINVAL;

	if (trace_file->prepare_read)
		trace_file->prepare_read(trace_file, file, buf, size, ppos);
	backup_diag_trace_buffer(&trace_file->trace_buffer);
	ret = __seq_read(trace_file, file, buf, size, ppos);
	return ret;
}

int __seq_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;
	kvfree(m->buf);
	kfree(m);
	return 0;
}

int __single_release(struct inode *inode, struct file *file)
{
	const struct seq_operations *op = ((struct seq_file *)file->private_data)->op;
	int res = __seq_release(inode, file);
	kfree(op);
	return res;
}

static ssize_t trace_file_write(struct file *file,
		const char __user *buf, size_t count, loff_t *offs)
{
	ssize_t ret;
	struct diag_trace_file *trace_file = to_trace_file(file);

	if (!trace_file)
		return count;

	ret = count;
	if (trace_file->write)
		ret = trace_file->write(trace_file, file, buf, count, offs);

	if (ret)
		return ret;

	return count;
}

int init_diag_trace_file(struct diag_trace_file *file,
	char *filename, unsigned int buf_size,
	diag_trace_file_prepare_read prepare_read,
	diag_trace_file_write_cb write)
{
	int ret = 0;
	struct proc_dir_entry *pe;

	if (!filename || strlen(filename) >= 255)
		return -EINVAL;

	memset(file, 0, sizeof(struct diag_trace_file));
	ret = init_diag_trace_buffer(&file->trace_buffer, buf_size);
	if (ret)
		goto out_buffer;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
	file->fops.open = trace_file_open;
	file->fops.read = trace_file_read;
	file->fops.write = trace_file_write;
	file->fops.llseek = seq_lseek;
	file->fops.release = __single_release;
	file->prepare_read = prepare_read;
	file->write = write;
	file->buf_size = buf_size;
	strncpy(file->file_name, filename, 255);
	pe = proc_create_data(filename,
			S_IFREG | 0666,
			NULL,
			&file->fops, file);
#else
	file->proc_ops.proc_open = trace_file_open;
	file->proc_ops.proc_read = trace_file_read;
	file->proc_ops.proc_write = trace_file_write;
	file->proc_ops.proc_lseek = seq_lseek;
	file->proc_ops.proc_release = single_release;
	file->prepare_read = prepare_read;
	file->write = write;
	file->buf_size = buf_size;
	strncpy(file->file_name, filename, 255);
	pe = proc_create_data(filename,
			S_IFREG | 0666,
			NULL,
			&file->proc_ops, file);
#endif

	ret = -ENOMEM;
	if (!pe)
		goto err_proc;

	ret = 0;
	return ret;

err_proc:
	destroy_diag_trace_buffer(&file->trace_buffer);
out_buffer:
	return ret;
}

void destroy_diag_trace_file(struct diag_trace_file *file)
{
	destroy_diag_trace_buffer(&file->trace_buffer);
	remove_proc_entry(file->file_name, NULL);
	memset(file, 0, sizeof(struct diag_trace_file));
}

void discard_diag_trace_file(struct diag_trace_file *file)
{
	discard_diag_trace_buffer(&file->trace_buffer);
}
