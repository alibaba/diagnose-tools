/*
 * Linux内核诊断工具--内核态rw-top功能
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
#include <linux/percpu_counter.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#include <linux/context_tracking.h>
#endif
#include <linux/pagemap.h>
#include <linux/sort.h>
#include <linux/fsnotify.h>
#include <linux/backing-dev.h>
#include <linux/aio.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0) && LINUX_VERSION_CODE <= KERNEL_VERSION(4, 20, 0)
#include <linux/iomap.h>
#include <linux/swap.h>
#endif

#include <asm/irq_regs.h>
#include <asm/unistd.h>

#if !defined(DIAG_ARM64)
#include <asm/asm-offsets.h>
#endif

#include "internal.h"
#include "mm_tree.h"
#include "pub/trace_file.h"
#include "pub/kprobe.h"
#include "uapi/rw_top.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32) && LINUX_VERSION_CODE <= KERNEL_VERSION(4, 20, 0)
static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_rw_top_settings rw_top_settings = {
	.top = 20,
};

static unsigned long rw_top_alloced = 0;

static struct diag_variant_buffer rw_top_variant_buffer;

static struct kprobe diag_kprobe_page_cache_read;

enum rw_type {
	RW_READ,
	RW_WRITE,
	RW_FILEMAP_FAULT,
	RW_ALL,
	NR_RW_TYPE,
};

struct file_info {
	struct list_head list;
	struct inode *f_inode;
	char path_name[DIAG_PATH_LEN];
	atomic64_t rw_size[NR_RW_TYPE];
};

#define MAX_FILE_COUNT 300000
struct file_info *file_buf[MAX_FILE_COUNT];

static atomic64_t file_count_in_tree = ATOMIC64_INIT(0);
__maybe_unused static struct radix_tree_root file_tree;
__maybe_unused static DEFINE_SPINLOCK(tree_lock);
static LIST_HEAD(file_list);
static DEFINE_MUTEX(file_mutex);

__maybe_unused static u64 last_jiffies;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 12, 0)
static int (*orig_file_read_actor)(read_descriptor_t *desc, struct page *page,
			unsigned long offset, unsigned long size);
DEFINE_ORIG_FUNC(ssize_t, do_sync_write, 4,
	struct file *, filp,
	const char __user *, buf,
	size_t, len,
	loff_t *, ppos);
DEFINE_ORIG_FUNC(ssize_t, generic_file_aio_read, 4,
	struct kiocb *, iocb,
	const struct iovec *, iov,
	unsigned long, nr_segs,
	loff_t, pos);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(4, 10, 0)
DEFINE_ORIG_FUNC(ssize_t, __generic_file_write_iter, 2,
	struct kiocb *, iocb,
	struct iov_iter *, from);
DEFINE_ORIG_FUNC(ssize_t, ext4_file_read_iter, 2,
	struct kiocb *, iocb,
	struct iov_iter *, to);
ssize_t
(*orig_dax_iomap_rw)(struct kiocb *iocb, struct iov_iter *iter,
		struct iomap_ops *ops);
struct iomap_ops *orig_ext4_iomap_ops;
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(4, 20, 0)
DEFINE_ORIG_FUNC(ssize_t, __generic_file_write_iter, 2,
	struct kiocb *, iocb,
	struct iov_iter *, from);
DEFINE_ORIG_FUNC(ssize_t, ext4_file_read_iter, 2,
	struct kiocb *, iocb,
	struct iov_iter *, to);
static ssize_t
(*orig_dax_iomap_rw)(struct kiocb *iocb, struct iov_iter *iter,
		const struct iomap_ops *ops);
static struct iomap_ops *orig_ext4_iomap_ops;
#endif

static struct inode_operations *orig_shmem_inode_operations;

static int need_trace(struct file *file)
{
	struct path *path;

	if (!rw_top_settings.activated)
		return 0;

	if (!file)
		return 0;

	path = &file->f_path;
	if (path->dentry && path->dentry->d_op && path->dentry->d_op->d_dname)
		return 0;

	if (rw_top_settings.shm) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
		if (file->f_inode && file->f_inode->i_op != orig_shmem_inode_operations)
#else 
		if (file->f_mapping && file->f_mapping->host && file->f_mapping->host->i_op != orig_shmem_inode_operations)
#endif
			return 0;
	}

	return 1;
}

static struct file_info *find_alloc_file_info(struct file *file)
{
	struct file_info *info;
	char path_name[DIAG_PATH_LEN];
	char *ret_path;
	struct inode *f_inode;

	if (!file)
		return NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	f_inode = file->f_inode;
#else
	if (!file->f_mapping)
		return NULL;
	f_inode = file->f_mapping->host;
#endif

	if (f_inode == NULL)
		return NULL;

	info = radix_tree_lookup(&file_tree, (unsigned long)f_inode);
	if (!info && MAX_FILE_COUNT > atomic64_read(&file_count_in_tree)) {
		info = kmalloc(sizeof(struct file_info), GFP_ATOMIC | __GFP_ZERO);
		if (info) {
			unsigned long flags;
			struct file_info *tmp;

			memset(path_name, 0, DIAG_PATH_LEN);
			ret_path = d_path(&file->f_path, path_name, sizeof(path_name) / sizeof(path_name[0]));
			if (IS_ERR(ret_path)) {
				//atomic64_inc(&xby_debug5);
				return NULL;
			}

			info->f_inode = f_inode;
			strncpy(info->path_name, ret_path, DIAG_PATH_LEN);
			info->path_name[DIAG_PATH_LEN - 1] = 0;
			
			spin_lock_irqsave(&tree_lock, flags);
			tmp = radix_tree_lookup(&file_tree, (unsigned long)f_inode);
			if (tmp) {
				kfree(info);
				info = tmp;
			} else {
				radix_tree_insert(&file_tree, (unsigned long)f_inode, info);
				atomic64_inc(&file_count_in_tree);
			}
			spin_unlock_irqrestore(&tree_lock, flags);
		}
	}

	return info;
}

__maybe_unused static struct file_info *takeout_file_info(struct file *file)
{
	unsigned long flags;
	struct file_info *info = NULL;
	struct inode *f_inode;

	if (!file)
		return NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	f_inode = file->f_inode;
#else
	if (!file->f_mapping)
		return NULL;
	f_inode = file->f_mapping->host;
#endif

	if (f_inode == NULL)
		return NULL;

	spin_lock_irqsave(&tree_lock, flags);
	info = radix_tree_delete(&file_tree, (unsigned long)f_inode);
	if (info)
		atomic64_dec(&file_count_in_tree);
	spin_unlock_irqrestore(&tree_lock, flags);

	return info;
}

static void hook_rw(enum rw_type rw_type, struct file *file, size_t count)
{
	struct file_info *info;
	unsigned long flags;

	if (!need_trace(file))
		return;

	switch (rw_type) {
	case RW_READ:
		break;
	case RW_WRITE:
		break;
	case RW_FILEMAP_FAULT:
		break;
	default:
		return;
	}

	info = find_alloc_file_info(file);
	if (info) {
		atomic64_add(count, &info->rw_size[rw_type]);
		atomic64_add(count, &info->rw_size[RW_ALL]);
		if (rw_top_settings.perf) {
			struct rw_top_perf *perf;

			perf = &diag_percpu_context[smp_processor_id()]->rw_top.perf;
			perf->et_type = et_rw_top_perf;
			perf->id = 0;
			perf->seq = 0;
			do_gettimeofday(&perf->tv);
			diag_task_brief(current, &perf->task);
			diag_task_kern_stack(current, &perf->kern_stack);
			diag_task_user_stack(current, &perf->user_stack);
			perf->proc_chains.chains[0][0] = 0;
			memcpy(perf->path_name, info->path_name, DIAG_PATH_LEN);
			dump_proc_chains_simple(current, &perf->proc_chains);
			diag_variant_buffer_spin_lock(&rw_top_variant_buffer, flags);
			diag_variant_buffer_reserve(&rw_top_variant_buffer, sizeof(struct rw_top_perf));
			diag_variant_buffer_write_nolock(&rw_top_variant_buffer, perf, sizeof(struct rw_top_perf));
			diag_variant_buffer_seal(&rw_top_variant_buffer);
			diag_variant_buffer_spin_unlock(&rw_top_variant_buffer, flags);
		}
	}
}

static int kprobe_page_cache_read_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (void *)ORIG_PARAM1(regs);

	hook_rw(2, file, PAGE_SIZE);

	return 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 12, 0)
static int (*orig_generic_segment_checks)(const struct iovec *iov,
			unsigned long *nr_segs, size_t *count, int access_flags);
static void (*orig_mark_page_accessed)(struct page *page);

static void shrink_readahead_size_eio(struct file *filp,
					struct file_ra_state *ra)
{
	ra->ra_pages /= 4;
}

/**
 * do_generic_file_read - generic file read routine
 * @filp:	the file to read
 * @ppos:	current file position
 * @desc:	read_descriptor
 * @actor:	read method
 *
 * This is a generic file read routine, and uses the
 * mapping->a_ops->readpage() function for the actual low-level stuff.
 *
 * This is really ugly. But the goto's actually try to clarify some
 * of the logic when it comes to error handling etc.
 */
static void diag_do_generic_file_read(struct file *filp, loff_t *ppos,
		read_descriptor_t *desc, read_actor_t actor)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct file_ra_state *ra = &filp->f_ra;
	pgoff_t index;
	pgoff_t last_index;
	pgoff_t prev_index;
	unsigned long offset;      /* offset into pagecache page */
	unsigned int prev_offset;
	int error;

	index = *ppos >> PAGE_CACHE_SHIFT;
	prev_index = ra->prev_pos >> PAGE_CACHE_SHIFT;
	prev_offset = ra->prev_pos & (PAGE_CACHE_SIZE-1);
	last_index = (*ppos + desc->count + PAGE_CACHE_SIZE-1) >> PAGE_CACHE_SHIFT;
	offset = *ppos & ~PAGE_CACHE_MASK;

	for (;;) {
		struct page *page;
		pgoff_t end_index;
		loff_t isize;
		unsigned long nr, ret;

		cond_resched();
find_page:
		page = find_get_page(mapping, index);
		if (!page) {
			page_cache_sync_readahead(mapping,
					ra, filp,
					index, last_index - index);
			page = find_get_page(mapping, index);
			hook_rw(0, filp, PAGE_SIZE);
			if (unlikely(page == NULL))
				goto no_cached_page;
		}
		if (PageReadahead(page)) {
			page_cache_async_readahead(mapping,
					ra, filp, page,
					index, last_index - index);
		}
		if (!PageUptodate(page)) {
			if (inode->i_blkbits == PAGE_CACHE_SHIFT ||
					!mapping->a_ops->is_partially_uptodate)
				goto page_not_up_to_date;
			if (!trylock_page(page))
				goto page_not_up_to_date;
			/* Did it get truncated before we got the lock? */
			if (!page->mapping)
				goto page_not_up_to_date_locked;
			if (!mapping->a_ops->is_partially_uptodate(page,
								desc, offset))
				goto page_not_up_to_date_locked;
			unlock_page(page);
		}
page_ok:
		/*
		 * i_size must be checked after we know the page is Uptodate.
		 *
		 * Checking i_size after the check allows us to calculate
		 * the correct value for "nr", which means the zero-filled
		 * part of the page is not copied back to userspace (unless
		 * another truncate extends the file - this is desired though).
		 */

		isize = i_size_read(inode);
		end_index = (isize - 1) >> PAGE_CACHE_SHIFT;
		if (unlikely(!isize || index > end_index)) {
			page_cache_release(page);
			goto out;
		}

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_CACHE_SIZE;
		if (index == end_index) {
			nr = ((isize - 1) & ~PAGE_CACHE_MASK) + 1;
			if (nr <= offset) {
				page_cache_release(page);
				goto out;
			}
		}
		nr = nr - offset;

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.
		 */
		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		/*
		 * When a sequential read accesses a page several times,
		 * only mark it as accessed the first time.
		 */
		if (prev_index != index || offset != prev_offset)
			orig_mark_page_accessed(page);
		prev_index = index;

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 *
		 * The actor routine returns how many bytes were actually used..
		 * NOTE! This may not be the same as how much of a user buffer
		 * we filled up (we may be padding etc), so we can only update
		 * "pos" here (the actor routine has to update the user buffer
		 * pointers and the remaining count).
		 */
		ret = actor(desc, page, offset, nr);
		offset += ret;
		index += offset >> PAGE_CACHE_SHIFT;
		offset &= ~PAGE_CACHE_MASK;
		prev_offset = offset;

		page_cache_release(page);
		if (ret == nr && desc->count)
			continue;
		goto out;

page_not_up_to_date:
		/* Get exclusive access to the page ... */
		error = lock_page_killable(page);
		if (unlikely(error))
			goto readpage_error;

page_not_up_to_date_locked:
		/* Did it get truncated before we got the lock? */
		if (!page->mapping) {
			unlock_page(page);
			page_cache_release(page);
			continue;
		}

		/* Did somebody else fill it already? */
		if (PageUptodate(page)) {
			unlock_page(page);
			goto page_ok;
		}

readpage:
		/*
		 * A previous I/O error may have been due to temporary
		 * failures, eg. multipath errors.
		 * PG_error will be set again if readpage fails.
		 */
		ClearPageError(page);
		/* Start the actual read. The read will unlock the page. */
		error = mapping->a_ops->readpage(filp, page);

		if (unlikely(error)) {
			if (error == AOP_TRUNCATED_PAGE) {
				page_cache_release(page);
				goto find_page;
			}
			goto readpage_error;
		}

		if (!PageUptodate(page)) {
			error = lock_page_killable(page);
			if (unlikely(error))
				goto readpage_error;
			if (!PageUptodate(page)) {
				if (page->mapping == NULL) {
					/*
					 * invalidate_mapping_pages got it
					 */
					unlock_page(page);
					page_cache_release(page);
					goto find_page;
				}
				unlock_page(page);
				shrink_readahead_size_eio(filp, ra);
				error = -EIO;
				goto readpage_error;
			}
			unlock_page(page);
		}

		goto page_ok;

readpage_error:
		/* UHHUH! A synchronous read error occurred. Report it */
		desc->error = error;
		page_cache_release(page);
		goto out;

no_cached_page:
		/*
		 * Ok, it wasn't cached, so we need to create a new
		 * page..
		 */
		page = page_cache_alloc_cold(mapping);
		if (!page) {
			desc->error = -ENOMEM;
			goto out;
		}
		error = add_to_page_cache_lru(page, mapping,
						index, GFP_KERNEL);
		if (error) {
			page_cache_release(page);
			if (error == -EEXIST)
				goto find_page;
			desc->error = error;
			goto out;
		}
		goto readpage;
	}
out:
	ra->prev_pos = prev_index;
	ra->prev_pos <<= PAGE_CACHE_SHIFT;
	ra->prev_pos |= prev_offset;

	*ppos = ((loff_t)index << PAGE_CACHE_SHIFT) + offset;
	file_accessed(filp);
}

/**
 * generic_file_aio_read - generic filesystem read routine
 * @iocb:	kernel I/O control block
 * @iov:	io vector request
 * @nr_segs:	number of segments in the iovec
 * @pos:	current file position
 *
 * This is the "read()" routine for all filesystems
 * that can use the page cache directly.
 */
static ssize_t
diag_generic_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	struct file *filp = iocb->ki_filp;
	ssize_t retval;
	unsigned long seg = 0;
	size_t count;
	loff_t *ppos = &iocb->ki_pos;

	count = 0;
	retval = orig_generic_segment_checks(iov, &nr_segs, &count, VERIFY_WRITE);
	if (retval)
		return retval;

	/* coalesce the iovecs and go direct-to-BIO for O_DIRECT */
	if (filp->f_flags & O_DIRECT) {
		loff_t size;
		struct address_space *mapping;
		struct inode *inode;

		mapping = filp->f_mapping;
		inode = mapping->host;
		if (!count)
			goto out; /* skip atime */
		size = i_size_read(inode);
		if (pos < size) {
			retval = filemap_write_and_wait_range(mapping, pos,
					pos + iov_length(iov, nr_segs) - 1);
			if (!retval) {
				retval = mapping->a_ops->direct_IO(READ, iocb,
							iov, pos, nr_segs);
				hook_rw(0, filp, count);
			}
			if (retval > 0) {
				*ppos = pos + retval;
				count -= retval;
			}

			/*
			 * Btrfs can have a short DIO read if we encounter
			 * compressed extents, so if there was an error, or if
			 * we've already read everything we wanted to, or if
			 * there was a short read because we hit EOF, go ahead
			 * and return.  Otherwise fallthrough to buffered io for
			 * the rest of the read.
			 */
			if (retval < 0 || !count || *ppos >= size) {
				file_accessed(filp);
				goto out;
			}
		}
	}

	count = retval;
	for (seg = 0; seg < nr_segs; seg++) {
		read_descriptor_t desc;
		loff_t offset = 0;

		/*
		 * If we did a short DIO read we need to skip the section of the
		 * iov that we've already read data into.
		 */
		if (count) {
			if (count > iov[seg].iov_len) {
				count -= iov[seg].iov_len;
				continue;
			}
			offset = count;
			count = 0;
		}

		desc.written = 0;
		desc.arg.buf = iov[seg].iov_base + offset;
		desc.count = iov[seg].iov_len - offset;
		if (desc.count == 0)
			continue;
		desc.error = 0;
		diag_do_generic_file_read(filp, ppos, &desc, *orig_file_read_actor);
		retval += desc.written;
		if (desc.error) {
			retval = retval ?: desc.error;
			break;
		}
		if (desc.count > 0)
			break;
	}
out:
	return retval;
}

static ssize_t
new_generic_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	ssize_t ret = 0;

	atomic64_inc_return(&diag_nr_running);
	ret = diag_generic_file_aio_read(iocb, iov, nr_segs, pos);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}
static ssize_t diag_do_sync_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
	struct iovec iov = { .iov_base = (void __user *)buf, .iov_len = len };
	struct kiocb kiocb;
	ssize_t ret;

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = *ppos;
	kiocb.ki_left = len;
	kiocb.ki_nbytes = len;

	ret = filp->f_op->aio_write(&kiocb, &iov, 1, kiocb.ki_pos);
	if (-EIOCBQUEUED == ret)
		ret = wait_on_sync_kiocb(&kiocb);
	*ppos = kiocb.ki_pos;

	hook_rw(1, filp, len);

	return ret;
}

static ssize_t new_do_sync_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
	ssize_t ret = 0;

	atomic64_inc_return(&diag_nr_running);
	ret = diag_do_sync_write(filp, buf, len, ppos);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

#elif LINUX_VERSION_CODE <= KERNEL_VERSION(4, 10, 0)
static int (*orig_wait_on_page_bit_killable)(struct page *page, int bit_nr);

static inline int diag_wait_on_page_locked_killable(struct page *page)
{
	if (!PageLocked(page))
		return 0;
	return orig_wait_on_page_bit_killable(compound_head(page), PG_locked);
}

/**
 * __generic_file_write_iter - write data to a file
 * @iocb:	IO state structure (file, offset, etc.)
 * @from:	iov_iter with data to write
 *
 * This function does all the work needed for actually writing data to a
 * file. It does all basic checks, removes SUID from the file, updates
 * modification times and calls proper subroutines depending on whether we
 * do direct IO or a standard buffered write.
 *
 * It expects i_mutex to be grabbed unless we work on a block device or similar
 * object which does not need locking at all.
 *
 * This function does *not* take care of syncing data in case of O_SYNC write.
 * A caller has to handle it. This is mainly due to the fact that we want to
 * avoid syncing under i_mutex.
 */
ssize_t diag__generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct address_space * mapping = file->f_mapping;
	struct inode 	*inode = mapping->host;
	ssize_t		written = 0;
	ssize_t		err;
	ssize_t		status;

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(inode);
	err = file_remove_privs(file);
	if (err)
		goto out;

	err = file_update_time(file);
	if (err)
		goto out;

	if (iocb->ki_flags & IOCB_DIRECT) {
		loff_t pos, endbyte;

		written = generic_file_direct_write(iocb, from);
		/*
		 * If the write stopped short of completing, fall back to
		 * buffered writes.  Some filesystems do this for writes to
		 * holes, for example.  For DAX files, a buffered write will
		 * not succeed (even if it did, DAX does not handle dirty
		 * page-cache pages correctly).
		 */
		if (written < 0 || !iov_iter_count(from) || IS_DAX(inode))
			goto out;

		status = generic_perform_write(file, from, pos = iocb->ki_pos);
		/*
		 * If generic_perform_write() returned a synchronous error
		 * then we want to return the number of bytes which were
		 * direct-written, or the error code if that was zero.  Note
		 * that this differs from normal direct-io semantics, which
		 * will return -EFOO even if some bytes were written.
		 */
		if (unlikely(status < 0)) {
			err = status;
			goto out;
		}
		/*
		 * We need to ensure that the page cache pages are written to
		 * disk and invalidated to preserve the expected O_DIRECT
		 * semantics.
		 */
		endbyte = pos + status - 1;
		err = filemap_write_and_wait_range(mapping, pos, endbyte);
		if (err == 0) {
			iocb->ki_pos = endbyte + 1;
			written += status;
			invalidate_mapping_pages(mapping,
						 pos >> PAGE_SHIFT,
						 endbyte >> PAGE_SHIFT);			
		} else {
			/*
			 * We don't know how much we wrote, so just return
			 * the number of bytes which were direct-written
			 */
		}
	} else {
		written = generic_perform_write(file, from, iocb->ki_pos);
		if (likely(written > 0))
			iocb->ki_pos += written;
	}
out:
	current->backing_dev_info = NULL;
	if (written)
		hook_rw(1, file, written);
	return written ? written : err;
}

static ssize_t new___generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret = 0;

	atomic64_inc_return(&diag_nr_running);
	ret = diag__generic_file_write_iter(iocb, from);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

static void shrink_readahead_size_eio(struct file *filp,
					struct file_ra_state *ra)
{
	ra->ra_pages /= 4;
}

/**
 * do_generic_file_read - generic file read routine
 * @filp:	the file to read
 * @ppos:	current file position
 * @iter:	data destination
 * @written:	already copied
 *
 * This is a generic file read routine, and uses the
 * mapping->a_ops->readpage() function for the actual low-level stuff.
 *
 * This is really ugly. But the goto's actually try to clarify some
 * of the logic when it comes to error handling etc.
 */
static ssize_t diag_do_generic_file_read(struct file *filp, loff_t *ppos,
		struct iov_iter *iter, ssize_t written)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct file_ra_state *ra = &filp->f_ra;
	pgoff_t index;
	pgoff_t last_index;
	pgoff_t prev_index;
	unsigned long offset;      /* offset into pagecache page */
	unsigned int prev_offset;
	int error = 0;

	if (unlikely(*ppos >= inode->i_sb->s_maxbytes))
		return 0;
	iov_iter_truncate(iter, inode->i_sb->s_maxbytes);

	index = *ppos >> PAGE_SHIFT;
	prev_index = ra->prev_pos >> PAGE_SHIFT;
	prev_offset = ra->prev_pos & (PAGE_SIZE-1);
	last_index = (*ppos + iter->count + PAGE_SIZE-1) >> PAGE_SHIFT;
	offset = *ppos & ~PAGE_MASK;

	for (;;) {
		struct page *page;
		pgoff_t end_index;
		loff_t isize;
		unsigned long nr, ret;

		cond_resched();
find_page:
		if (fatal_signal_pending(current)) {
			error = -EINTR;
			goto out;
		}

		page = find_get_page(mapping, index);
		if (!page) {
			page_cache_sync_readahead(mapping,
					ra, filp,
					index, last_index - index);
			page = find_get_page(mapping, index);
			hook_rw(0, filp, PAGE_SIZE);
			if (unlikely(page == NULL))
				goto no_cached_page;
		}
		if (PageReadahead(page)) {
			page_cache_async_readahead(mapping,
					ra, filp, page,
					index, last_index - index);
		}
		if (!PageUptodate(page)) {
			/*
			 * See comment in do_read_cache_page on why
			 * wait_on_page_locked is used to avoid unnecessarily
			 * serialisations and why it's safe.
			 */
			error = diag_wait_on_page_locked_killable(page);
			if (unlikely(error))
				goto readpage_error;
			if (PageUptodate(page))
				goto page_ok;

			if (inode->i_blkbits == PAGE_SHIFT ||
					!mapping->a_ops->is_partially_uptodate)
				goto page_not_up_to_date;
			/* pipes can't handle partially uptodate pages */
			if (unlikely(iter->type & ITER_PIPE))
				goto page_not_up_to_date;
			if (!trylock_page(page))
				goto page_not_up_to_date;
			/* Did it get truncated before we got the lock? */
			if (!page->mapping)
				goto page_not_up_to_date_locked;
			if (!mapping->a_ops->is_partially_uptodate(page,
							offset, iter->count))
				goto page_not_up_to_date_locked;
			unlock_page(page);
		}
page_ok:
		/*
		 * i_size must be checked after we know the page is Uptodate.
		 *
		 * Checking i_size after the check allows us to calculate
		 * the correct value for "nr", which means the zero-filled
		 * part of the page is not copied back to userspace (unless
		 * another truncate extends the file - this is desired though).
		 */

		isize = i_size_read(inode);
		end_index = (isize - 1) >> PAGE_SHIFT;
		if (unlikely(!isize || index > end_index)) {
			put_page(page);
			goto out;
		}

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_SIZE;
		if (index == end_index) {
			nr = ((isize - 1) & ~PAGE_MASK) + 1;
			if (nr <= offset) {
				put_page(page);
				goto out;
			}
		}
		nr = nr - offset;

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.
		 */
		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		/*
		 * When a sequential read accesses a page several times,
		 * only mark it as accessed the first time.
		 */
		if (prev_index != index || offset != prev_offset)
			mark_page_accessed(page);
		prev_index = index;

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 */

		ret = copy_page_to_iter(page, offset, nr, iter);
		offset += ret;
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;
		prev_offset = offset;

		put_page(page);
		written += ret;
		if (!iov_iter_count(iter))
			goto out;
		if (ret < nr) {
			error = -EFAULT;
			goto out;
		}
		continue;

page_not_up_to_date:
		/* Get exclusive access to the page ... */
		error = lock_page_killable(page);
		if (unlikely(error))
			goto readpage_error;

page_not_up_to_date_locked:
		/* Did it get truncated before we got the lock? */
		if (!page->mapping) {
			unlock_page(page);
			put_page(page);
			continue;
		}

		/* Did somebody else fill it already? */
		if (PageUptodate(page)) {
			unlock_page(page);
			goto page_ok;
		}

readpage:
		/*
		 * A previous I/O error may have been due to temporary
		 * failures, eg. multipath errors.
		 * PG_error will be set again if readpage fails.
		 */
		ClearPageError(page);
		/* Start the actual read. The read will unlock the page. */
		error = mapping->a_ops->readpage(filp, page);

		if (unlikely(error)) {
			if (error == AOP_TRUNCATED_PAGE) {
				put_page(page);
				error = 0;
				goto find_page;
			}
			goto readpage_error;
		}

		if (!PageUptodate(page)) {
			error = lock_page_killable(page);
			if (unlikely(error))
				goto readpage_error;
			if (!PageUptodate(page)) {
				if (page->mapping == NULL) {
					/*
					 * invalidate_mapping_pages got it
					 */
					unlock_page(page);
					put_page(page);
					goto find_page;
				}
				unlock_page(page);
				shrink_readahead_size_eio(filp, ra);
				error = -EIO;
				goto readpage_error;
			}
			unlock_page(page);
		}

		goto page_ok;

readpage_error:
		/* UHHUH! A synchronous read error occurred. Report it */
		put_page(page);
		goto out;

no_cached_page:
		/*
		 * Ok, it wasn't cached, so we need to create a new
		 * page..
		 */
		page = page_cache_alloc_cold(mapping);
		if (!page) {
			error = -ENOMEM;
			goto out;
		}
		error = add_to_page_cache_lru(page, mapping, index,
				mapping_gfp_constraint(mapping, GFP_KERNEL));
		if (error) {
			put_page(page);
			if (error == -EEXIST) {
				error = 0;
				goto find_page;
			}
			goto out;
		}
		goto readpage;
	}

out:
	ra->prev_pos = prev_index;
	ra->prev_pos <<= PAGE_SHIFT;
	ra->prev_pos |= prev_offset;

	*ppos = ((loff_t)index << PAGE_SHIFT) + offset;
	file_accessed(filp);
	return written ? written : error;
}

/**
 * generic_file_read_iter - generic filesystem read routine
 * @iocb:	kernel I/O control block
 * @iter:	destination for the data read
 *
 * This is the "read_iter()" routine for all filesystems
 * that can use the page cache directly.
 */
ssize_t
diag_generic_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	ssize_t retval = 0;
	size_t count = iov_iter_count(iter);

	if (!count)
		goto out; /* skip atime */

	if (iocb->ki_flags & IOCB_DIRECT) {
		struct address_space *mapping = file->f_mapping;
		struct inode *inode = mapping->host;
		struct iov_iter data = *iter;
		loff_t size;

		size = i_size_read(inode);
		retval = filemap_write_and_wait_range(mapping, iocb->ki_pos,
					iocb->ki_pos + count - 1);
		if (retval < 0)
			goto out;

		file_accessed(file);

		retval = mapping->a_ops->direct_IO(iocb, &data);
		if (retval >= 0) {
			iocb->ki_pos += retval;
			hook_rw(0, file, retval);
			iov_iter_advance(iter, retval);
		}

		/*
		 * Btrfs can have a short DIO read if we encounter
		 * compressed extents, so if there was an error, or if
		 * we've already read everything we wanted to, or if
		 * there was a short read because we hit EOF, go ahead
		 * and return.  Otherwise fallthrough to buffered io for
		 * the rest of the read.  Buffered reads will not work for
		 * DAX files, so don't bother trying.
		 */
		if (retval < 0 || !iov_iter_count(iter) || iocb->ki_pos >= size ||
		    IS_DAX(inode))
			goto out;
	}

	retval = diag_do_generic_file_read(file, &iocb->ki_pos, iter, retval);
out:
	return retval;
}

#ifdef CONFIG_FS_DAX
static ssize_t ext4_dax_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	inode_lock_shared(inode);
	/*
	 * Recheck under inode lock - at this point we are sure it cannot
	 * change anymore
	 */
	if (!IS_DAX(inode)) {
		inode_unlock_shared(inode);
		/* Fallback to buffered IO in case we cannot support DAX */
		return diag_generic_file_read_iter(iocb, to);
	}
	ret = orig_dax_iomap_rw(iocb, to, orig_ext4_iomap_ops);
	inode_unlock_shared(inode);

	file_accessed(iocb->ki_filp);
	return ret;
}
#endif
static ssize_t diag_ext4_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	ssize_t ret = 0;

	if (!iov_iter_count(to))
		return 0; /* skip atime */

	
#ifdef CONFIG_FS_DAX
	if (IS_DAX(file_inode(iocb->ki_filp))) {
		ret = ext4_dax_read_iter(iocb, to);
		if (ret > 0)
			hook_rw(0, iocb->ki_filp, ret);
		return ret;
	}
#endif
	ret = diag_generic_file_read_iter(iocb, to);
	return ret;
}

static ssize_t new_ext4_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	ssize_t ret = 0;

	atomic64_inc_return(&diag_nr_running);
	ret = diag_ext4_file_read_iter(iocb, to);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}
#else
static ssize_t diag__generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct address_space * mapping = file->f_mapping;
	struct inode 	*inode = mapping->host;
	ssize_t		written = 0;
	ssize_t		err;
	ssize_t		status;

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(inode);
	err = file_remove_privs(file);
	if (err)
		goto out;

	err = file_update_time(file);
	if (err)
		goto out;

	if (iocb->ki_flags & IOCB_DIRECT) {
		loff_t pos, endbyte;

		written = generic_file_direct_write(iocb, from);
		/*
		 * If the write stopped short of completing, fall back to
		 * buffered writes.  Some filesystems do this for writes to
		 * holes, for example.  For DAX files, a buffered write will
		 * not succeed (even if it did, DAX does not handle dirty
		 * page-cache pages correctly).
		 */
		if (written < 0 || !iov_iter_count(from) || IS_DAX(inode))
			goto out;

		status = generic_perform_write(file, from, pos = iocb->ki_pos);
		/*
		 * If generic_perform_write() returned a synchronous error
		 * then we want to return the number of bytes which were
		 * direct-written, or the error code if that was zero.  Note
		 * that this differs from normal direct-io semantics, which
		 * will return -EFOO even if some bytes were written.
		 */
		if (unlikely(status < 0)) {
			err = status;
			goto out;
		}
		/*
		 * We need to ensure that the page cache pages are written to
		 * disk and invalidated to preserve the expected O_DIRECT
		 * semantics.
		 */
		endbyte = pos + status - 1;
		err = filemap_write_and_wait_range(mapping, pos, endbyte);
		if (err == 0) {
			iocb->ki_pos = endbyte + 1;
			written += status;
			invalidate_mapping_pages(mapping,
						 pos >> PAGE_SHIFT,
						 endbyte >> PAGE_SHIFT);
		} else {
			/*
			 * We don't know how much we wrote, so just return
			 * the number of bytes which were direct-written
			 */
		}
	} else {
		written = generic_perform_write(file, from, iocb->ki_pos);
		if (likely(written > 0))
			iocb->ki_pos += written;
	}
out:
	current->backing_dev_info = NULL;
	if (written)
		hook_rw(1, file, written);
	return written ? written : err;
}

static ssize_t new___generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t ret = 0;

	atomic64_inc_return(&diag_nr_running);
	ret = diag__generic_file_write_iter(iocb, from);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

/* Number of quota types we support */
#define EXT4_MAXQUOTAS 3

static inline struct ext4_sb_info *EXT4_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

struct ext4_es_stats {
	unsigned long es_stats_shrunk;
	unsigned long es_stats_cache_hits;
	unsigned long es_stats_cache_misses;
	u64 es_stats_scan_time;
	u64 es_stats_max_scan_time;
	struct percpu_counter es_stats_all_cnt;
	struct percpu_counter es_stats_shk_cnt;
};

/* data type for filesystem-wide blocks number */
typedef unsigned long long ext4_fsblk_t;

/* data type for block group number */
typedef unsigned int ext4_group_t;

/*
 * fourth extended-fs super-block data in memory
 */
struct ext4_sb_info {
	unsigned long s_desc_size;	/* Size of a group descriptor in bytes */
	unsigned long s_inodes_per_block;/* Number of inodes per block */
	unsigned long s_blocks_per_group;/* Number of blocks in a group */
	unsigned long s_clusters_per_group; /* Number of clusters in a group */
	unsigned long s_inodes_per_group;/* Number of inodes in a group */
	unsigned long s_itb_per_group;	/* Number of inode table blocks per group */
	unsigned long s_gdb_count;	/* Number of group descriptor blocks */
	unsigned long s_desc_per_block;	/* Number of group descriptors per block */
	ext4_group_t s_groups_count;	/* Number of groups in the fs */
	ext4_group_t s_blockfile_groups;/* Groups acceptable for non-extent files */
	unsigned long s_overhead;  /* # of fs overhead clusters */
	unsigned int s_cluster_ratio;	/* Number of blocks per cluster */
	unsigned int s_cluster_bits;	/* log2 of s_cluster_ratio */
	loff_t s_bitmap_maxbytes;	/* max bytes for bitmap files */
	struct buffer_head * s_sbh;	/* Buffer containing the super block */
	struct ext4_super_block *s_es;	/* Pointer to the super block in the buffer */
	struct buffer_head **s_group_desc;
	unsigned int s_mount_opt;
	unsigned int s_mount_opt2;
	unsigned int s_mount_flags;
	unsigned int s_def_mount_opt;
	ext4_fsblk_t s_sb_block;
	atomic64_t s_resv_clusters;
	kuid_t s_resuid;
	kgid_t s_resgid;
	unsigned short s_mount_state;
	unsigned short s_pad;
	int s_addr_per_block_bits;
	int s_desc_per_block_bits;
	int s_inode_size;
	int s_first_ino;
	unsigned int s_inode_readahead_blks;
	unsigned int s_inode_goal;
	u32 s_hash_seed[4];
	int s_def_hash_version;
	int s_hash_unsigned;	/* 3 if hash should be signed, 0 if not */
	struct percpu_counter s_freeclusters_counter;
	struct percpu_counter s_freeinodes_counter;
	struct percpu_counter s_dirs_counter;
	struct percpu_counter s_dirtyclusters_counter;
	struct blockgroup_lock *s_blockgroup_lock;
	struct proc_dir_entry *s_proc;
	struct kobject s_kobj;
	struct completion s_kobj_unregister;
	struct super_block *s_sb;

	/* Journaling */
	struct journal_s *s_journal;
	struct list_head s_orphan;
	struct mutex s_orphan_lock;
	unsigned long s_ext4_flags;		/* Ext4 superblock flags */
	unsigned long s_commit_interval;
	u32 s_max_batch_time;
	u32 s_min_batch_time;
	struct block_device *journal_bdev;
#ifdef CONFIG_QUOTA
	/* Names of quota files with journalled quota */
	char __rcu *s_qf_names[EXT4_MAXQUOTAS];
	int s_jquota_fmt;			/* Format of quota to use */
#endif
	unsigned int s_want_extra_isize; /* New inodes should reserve # bytes */
	struct rb_root system_blks;

#ifdef EXTENTS_STATS
	/* ext4 extents stats */
	unsigned long s_ext_min;
	unsigned long s_ext_max;
	unsigned long s_depth_max;
	spinlock_t s_ext_stats_lock;
	unsigned long s_ext_blocks;
	unsigned long s_ext_extents;
#endif

	/* for buddy allocator */
	struct ext4_group_info ***s_group_info;
	struct inode *s_buddy_cache;
	spinlock_t s_md_lock;
	unsigned short *s_mb_offsets;
	unsigned int *s_mb_maxs;
	unsigned int s_group_info_size;
	unsigned int s_mb_free_pending;
	struct list_head s_freed_data_list;	/* List of blocks to be freed
						   after commit completed */

	/* tunables */
	unsigned long s_stripe;
	unsigned int s_mb_stream_request;
	unsigned int s_mb_max_to_scan;
	unsigned int s_mb_min_to_scan;
	unsigned int s_mb_stats;
	unsigned int s_mb_order2_reqs;
	unsigned int s_mb_group_prealloc;
	unsigned int s_max_dir_size_kb;
	/* where last allocation was done - for stream allocation */
	unsigned long s_mb_last_group;
	unsigned long s_mb_last_start;

	/* stats for buddy allocator */
	atomic_t s_bal_reqs;	/* number of reqs with len > 1 */
	atomic_t s_bal_success;	/* we found long enough chunks */
	atomic_t s_bal_allocated;	/* in blocks */
	atomic_t s_bal_ex_scanned;	/* total extents scanned */
	atomic_t s_bal_goals;	/* goal hits */
	atomic_t s_bal_breaks;	/* too long searches */
	atomic_t s_bal_2orders;	/* 2^order hits */
	spinlock_t s_bal_lock;
	unsigned long s_mb_buddies_generated;
	unsigned long long s_mb_generation_time;
	atomic_t s_mb_lost_chunks;
	atomic_t s_mb_preallocated;
	atomic_t s_mb_discarded;
	atomic_t s_lock_busy;

	/* locality groups */
	struct ext4_locality_group __percpu *s_locality_groups;

	/* for write statistics */
	unsigned long s_sectors_written_start;
	u64 s_kbytes_written;

	/* the size of zero-out chunk */
	unsigned int s_extent_max_zeroout_kb;

	unsigned int s_log_groups_per_flex;
	struct flex_groups *s_flex_groups;
	ext4_group_t s_flex_groups_allocated;

	/* workqueue for reserved extent conversions (buffered io) */
	struct workqueue_struct *rsv_conversion_wq;

	/* timer for periodic error stats printing */
	struct timer_list s_err_report;

	/* Lazy inode table initialization info */
	struct ext4_li_request *s_li_request;
	/* Wait multiplier for lazy initialization thread */
	unsigned int s_li_wait_mult;

	/* Kernel thread for multiple mount protection */
	struct task_struct *s_mmp_tsk;

	/* record the last minlen when FITRIM is called. */
	atomic_t s_last_trim_minblks;

	/* Reference to checksum algorithm driver via cryptoapi */
	struct crypto_shash *s_chksum_driver;

	/* Precomputed FS UUID checksum for seeding other checksums */
	__u32 s_csum_seed;

	/* Reclaim extents from extent status tree */
	struct shrinker s_es_shrinker;
	struct list_head s_es_list;	/* List of inodes with reclaimable extents */
	long s_es_nr_inode;
	struct ext4_es_stats s_es_stats;
	struct mb_cache *s_ea_block_cache;
	struct mb_cache *s_ea_inode_cache;
	spinlock_t s_es_lock ____cacheline_aligned_in_smp;

	/* Ratelimit ext4 messages. */
	struct ratelimit_state s_err_ratelimit_state;
	struct ratelimit_state s_warning_ratelimit_state;
	struct ratelimit_state s_msg_ratelimit_state;

	/* Barrier between changing inodes' journal flags and writepages ops. */
	struct percpu_rw_semaphore s_journal_flag_rwsem;
	struct dax_device *s_daxdev;
};

/*
 * Superblock flags
 */
#define EXT4_FLAGS_RESIZING	0
#define EXT4_FLAGS_SHUTDOWN	1

static inline int ext4_forced_shutdown(struct ext4_sb_info *sbi)
{
	return test_bit(EXT4_FLAGS_SHUTDOWN, &sbi->s_ext4_flags);
}

static void shrink_readahead_size_eio(struct file *filp,
					struct file_ra_state *ra)
{
	ra->ra_pages /= 4;
}

/**
 * generic_file_buffered_read - generic file read routine
 * @iocb:	the iocb to read
 * @iter:	data destination
 * @written:	already copied
 *
 * This is a generic file read routine, and uses the
 * mapping->a_ops->readpage() function for the actual low-level stuff.
 *
 * This is really ugly. But the goto's actually try to clarify some
 * of the logic when it comes to error handling etc.
 */
static ssize_t diag_generic_file_buffered_read(struct kiocb *iocb,
		struct iov_iter *iter, ssize_t written)
{
	struct file *filp = iocb->ki_filp;
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct file_ra_state *ra = &filp->f_ra;
	loff_t *ppos = &iocb->ki_pos;
	pgoff_t index;
	pgoff_t last_index;
	pgoff_t prev_index;
	unsigned long offset;      /* offset into pagecache page */
	unsigned int prev_offset;
	int error = 0;

	if (unlikely(*ppos >= inode->i_sb->s_maxbytes))
		return 0;
	iov_iter_truncate(iter, inode->i_sb->s_maxbytes);

	index = *ppos >> PAGE_SHIFT;
	prev_index = ra->prev_pos >> PAGE_SHIFT;
	prev_offset = ra->prev_pos & (PAGE_SIZE-1);
	last_index = (*ppos + iter->count + PAGE_SIZE-1) >> PAGE_SHIFT;
	offset = *ppos & ~PAGE_MASK;

	for (;;) {
		struct page *page;
		pgoff_t end_index;
		loff_t isize;
		unsigned long nr, ret;

		cond_resched();
find_page:
		if (fatal_signal_pending(current)) {
			error = -EINTR;
			goto out;
		}

		page = find_get_page(mapping, index);
		if (!page) {
			if (iocb->ki_flags & IOCB_NOWAIT)
				goto would_block;
			page_cache_sync_readahead(mapping,
					ra, filp,
					index, last_index - index);
			page = find_get_page(mapping, index);
			hook_rw(0, filp, PAGE_SIZE);
			if (unlikely(page == NULL))
				goto no_cached_page;
		}
		if (PageReadahead(page)) {
			page_cache_async_readahead(mapping,
					ra, filp, page,
					index, last_index - index);
		}
		if (!PageUptodate(page)) {
			if (iocb->ki_flags & IOCB_NOWAIT) {
				put_page(page);
				goto would_block;
			}

			/*
			 * See comment in do_read_cache_page on why
			 * wait_on_page_locked is used to avoid unnecessarily
			 * serialisations and why it's safe.
			 */
			error = wait_on_page_locked_killable(page);
			if (unlikely(error))
				goto readpage_error;
			if (PageUptodate(page))
				goto page_ok;

			if (inode->i_blkbits == PAGE_SHIFT ||
					!mapping->a_ops->is_partially_uptodate)
				goto page_not_up_to_date;
			/* pipes can't handle partially uptodate pages */
			if (unlikely(iter->type & ITER_PIPE))
				goto page_not_up_to_date;
			if (!trylock_page(page))
				goto page_not_up_to_date;
			/* Did it get truncated before we got the lock? */
			if (!page->mapping)
				goto page_not_up_to_date_locked;
			if (!mapping->a_ops->is_partially_uptodate(page,
							offset, iter->count))
				goto page_not_up_to_date_locked;
			unlock_page(page);
		}
page_ok:
		/*
		 * i_size must be checked after we know the page is Uptodate.
		 *
		 * Checking i_size after the check allows us to calculate
		 * the correct value for "nr", which means the zero-filled
		 * part of the page is not copied back to userspace (unless
		 * another truncate extends the file - this is desired though).
		 */

		isize = i_size_read(inode);
		end_index = (isize - 1) >> PAGE_SHIFT;
		if (unlikely(!isize || index > end_index)) {
			put_page(page);
			goto out;
		}

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_SIZE;
		if (index == end_index) {
			nr = ((isize - 1) & ~PAGE_MASK) + 1;
			if (nr <= offset) {
				put_page(page);
				goto out;
			}
		}
		nr = nr - offset;

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.
		 */
		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		/*
		 * When a sequential read accesses a page several times,
		 * only mark it as accessed the first time.
		 */
		if (prev_index != index || offset != prev_offset)
			mark_page_accessed(page);
		prev_index = index;

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 */

		ret = copy_page_to_iter(page, offset, nr, iter);
		offset += ret;
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;
		prev_offset = offset;

		put_page(page);
		written += ret;
		if (!iov_iter_count(iter))
			goto out;
		if (ret < nr) {
			error = -EFAULT;
			goto out;
		}
		continue;

page_not_up_to_date:
		/* Get exclusive access to the page ... */
		error = lock_page_killable(page);
		if (unlikely(error))
			goto readpage_error;

page_not_up_to_date_locked:
		/* Did it get truncated before we got the lock? */
		if (!page->mapping) {
			unlock_page(page);
			put_page(page);
			continue;
		}

		/* Did somebody else fill it already? */
		if (PageUptodate(page)) {
			unlock_page(page);
			goto page_ok;
		}

readpage:
		/*
		 * A previous I/O error may have been due to temporary
		 * failures, eg. multipath errors.
		 * PG_error will be set again if readpage fails.
		 */
		ClearPageError(page);
		/* Start the actual read. The read will unlock the page. */
		error = mapping->a_ops->readpage(filp, page);

		if (unlikely(error)) {
			if (error == AOP_TRUNCATED_PAGE) {
				put_page(page);
				error = 0;
				goto find_page;
			}
			goto readpage_error;
		}

		if (!PageUptodate(page)) {
			error = lock_page_killable(page);
			if (unlikely(error))
				goto readpage_error;
			if (!PageUptodate(page)) {
				if (page->mapping == NULL) {
					/*
					 * invalidate_mapping_pages got it
					 */
					unlock_page(page);
					put_page(page);
					goto find_page;
				}
				unlock_page(page);
				shrink_readahead_size_eio(filp, ra);
				error = -EIO;
				goto readpage_error;
			}
			unlock_page(page);
		}

		goto page_ok;

readpage_error:
		/* UHHUH! A synchronous read error occurred. Report it */
		put_page(page);
		goto out;

no_cached_page:
		/*
		 * Ok, it wasn't cached, so we need to create a new
		 * page..
		 */
		page = page_cache_alloc(mapping);
		if (!page) {
			error = -ENOMEM;
			goto out;
		}
		error = add_to_page_cache_lru(page, mapping, index,
				mapping_gfp_constraint(mapping, GFP_KERNEL));
		if (error) {
			put_page(page);
			if (error == -EEXIST) {
				error = 0;
				goto find_page;
			}
			goto out;
		}
		goto readpage;
	}

would_block:
	error = -EAGAIN;
out:
	ra->prev_pos = prev_index;
	ra->prev_pos <<= PAGE_SHIFT;
	ra->prev_pos |= prev_offset;

	*ppos = ((loff_t)index << PAGE_SHIFT) + offset;
	file_accessed(filp);
	return written ? written : error;
}

ssize_t
diag_generic_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	size_t count = iov_iter_count(iter);
	ssize_t retval = 0;

	if (!count)
		goto out; /* skip atime */

	if (iocb->ki_flags & IOCB_DIRECT) {
		struct file *file = iocb->ki_filp;
		struct address_space *mapping = file->f_mapping;
		struct inode *inode = mapping->host;
		loff_t size;

		size = i_size_read(inode);
		if (iocb->ki_flags & IOCB_NOWAIT) {
			if (filemap_range_has_page(mapping, iocb->ki_pos,
						   iocb->ki_pos + count - 1))
				return -EAGAIN;
		} else {
			retval = filemap_write_and_wait_range(mapping,
						iocb->ki_pos,
					        iocb->ki_pos + count - 1);
			if (retval < 0)
				goto out;
		}

		file_accessed(file);

		retval = mapping->a_ops->direct_IO(iocb, iter);
		if (retval >= 0) {
			iocb->ki_pos += retval;
			count -= retval;
		}
		iov_iter_revert(iter, count - iov_iter_count(iter));

		/*
		 * Btrfs can have a short DIO read if we encounter
		 * compressed extents, so if there was an error, or if
		 * we've already read everything we wanted to, or if
		 * there was a short read because we hit EOF, go ahead
		 * and return.  Otherwise fallthrough to buffered io for
		 * the rest of the read.  Buffered reads will not work for
		 * DAX files, so don't bother trying.
		 */
		if (retval < 0 || !count || iocb->ki_pos >= size ||
		    IS_DAX(inode))
			goto out;
	}

	retval = diag_generic_file_buffered_read(iocb, iter, retval);
out:
	return retval;
}

#ifdef CONFIG_FS_DAX
static ssize_t ext4_dax_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (!inode_trylock_shared(inode)) {
		if (iocb->ki_flags & IOCB_NOWAIT)
			return -EAGAIN;
		inode_lock_shared(inode);
	}
	/*
	 * Recheck under inode lock - at this point we are sure it cannot
	 * change anymore
	 */
	if (!IS_DAX(inode)) {
		inode_unlock_shared(inode);
		/* Fallback to buffered IO in case we cannot support DAX */
		return diag_generic_file_read_iter(iocb, to);
	}
	ret = orig_dax_iomap_rw(iocb, to, orig_ext4_iomap_ops);
	inode_unlock_shared(inode);

	file_accessed(iocb->ki_filp);
	return ret;
}
#endif

static ssize_t diag_ext4_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	if (unlikely(ext4_forced_shutdown(EXT4_SB(file_inode(iocb->ki_filp)->i_sb))))
		return -EIO;

	if (!iov_iter_count(to))
		return 0; /* skip atime */

#ifdef CONFIG_FS_DAX
	if (IS_DAX(file_inode(iocb->ki_filp))) {
		ssize_t ret;

		ret = ext4_dax_read_iter(iocb, to);
		if (ret > 0)
			hook_rw(0, iocb->ki_filp, ret);
		return ret;
	}
#endif
	return generic_file_read_iter(iocb, to);
}

static ssize_t new_ext4_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	ssize_t ret = 0;

	atomic64_inc_return(&diag_nr_running);
	ret = diag_ext4_file_read_iter(iocb, to);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}
#endif


static int __activate_rw_top(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&rw_top_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	rw_top_alloced = 1;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 12, 0)
	JUMP_CHECK(do_sync_write);
	JUMP_CHECK(generic_file_aio_read);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(4, 10, 0)
	JUMP_CHECK(__generic_file_write_iter);
	JUMP_CHECK(ext4_file_read_iter);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(4, 20, 0)
	JUMP_CHECK(__generic_file_write_iter);
	JUMP_CHECK(ext4_file_read_iter);
#endif
	
	get_online_cpus();
	mutex_lock(orig_text_mutex);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 12, 0)
	JUMP_INSTALL(do_sync_write);
	JUMP_INSTALL(generic_file_aio_read);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(4, 10, 0)
	JUMP_INSTALL(__generic_file_write_iter);
	JUMP_INSTALL(ext4_file_read_iter);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(4, 20, 0)
	JUMP_INSTALL(__generic_file_write_iter);
	JUMP_INSTALL(ext4_file_read_iter);
#endif
	mutex_unlock(orig_text_mutex);
	put_online_cpus();

	hook_kprobe(&diag_kprobe_page_cache_read, "page_cache_read",
				kprobe_page_cache_read_pre, NULL);

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_rw_top(void)
{
	u64 nr_running;
	
	get_online_cpus();
	mutex_lock(orig_text_mutex);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 12, 0)
	JUMP_REMOVE(do_sync_write);
	JUMP_REMOVE(generic_file_aio_read);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(4, 10, 0)
	JUMP_REMOVE(__generic_file_write_iter);
	JUMP_REMOVE(ext4_file_read_iter);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(4, 20, 0)
	JUMP_REMOVE(__generic_file_write_iter);
	JUMP_REMOVE(ext4_file_read_iter);
#endif
	mutex_unlock(orig_text_mutex);
	put_online_cpus();

	unhook_kprobe(&diag_kprobe_page_cache_read);

	synchronize_sched();
	msleep(10);
	nr_running = atomic64_read(&diag_nr_running);
	while (nr_running > 0)
	{
		msleep(10);
		nr_running = atomic64_read(&diag_nr_running);
	}
}

int activate_rw_top(void)
{
	if (!rw_top_settings.activated)
		rw_top_settings.activated = __activate_rw_top();

	return rw_top_settings.activated;
}

int deactivate_rw_top(void)
{
	if (rw_top_settings.activated)
		__deactivate_rw_top();
	rw_top_settings.activated = 0;

	return 0;
}

static int diag_compare_file(const void *one, const void *two)
{
	struct file_info *__one = *(struct file_info **)one;
	struct file_info *__two = *(struct file_info **)two;

	if (atomic64_read(&__one->rw_size[RW_ALL]) > atomic64_read(&__two->rw_size[RW_ALL]))
		return -1;
	if (atomic64_read(&__one->rw_size[RW_ALL]) < atomic64_read(&__two->rw_size[RW_ALL]))
		return 1;

	return 0;
}

static int do_show(void)
{
	int i;
	struct file_info *file_info;
	int file_count = 0;
	struct rw_top_detail detail;
	unsigned long flags;

	if (!rw_top_settings.activated)
		return 0;

	mutex_lock(&file_mutex);
	memset(file_buf, 0, sizeof(struct file_info *) * MAX_FILE_COUNT);
	list_for_each_entry(file_info, &file_list, list) {
		if (file_count < MAX_FILE_COUNT) {
			file_buf[file_count] = file_info;
			file_count++;
			} else {
				break;
		}
	}
	sort(&file_buf[0], (size_t)file_count, (size_t)sizeof(struct file_info *),
		&diag_compare_file, NULL);

	detail.id = get_cycles();
	detail.et_type = et_rw_top_detail;
	for (i = 0; i < min_t(int, file_count, rw_top_settings.top); i++)
	{
		file_info = file_buf[i];
		detail.seq = i;
		detail.r_size = atomic64_read(&file_info->rw_size[RW_READ]);
		detail.w_size = atomic64_read(&file_info->rw_size[RW_WRITE]);
		detail.map_size = atomic64_read(&file_info->rw_size[RW_FILEMAP_FAULT]);
		detail.rw_size = atomic64_read(&file_info->rw_size[RW_ALL]);
		strncpy(detail.path_name, file_info->path_name, DIAG_PATH_LEN);
		diag_variant_buffer_spin_lock(&rw_top_variant_buffer, flags);
		diag_variant_buffer_reserve(&rw_top_variant_buffer, sizeof(struct rw_top_detail));
		diag_variant_buffer_write_nolock(&rw_top_variant_buffer, &detail, sizeof(struct rw_top_detail));
		diag_variant_buffer_seal(&rw_top_variant_buffer);
		diag_variant_buffer_spin_unlock(&rw_top_variant_buffer, flags);
	}
	mutex_unlock(&file_mutex);

	return 0;
}

static void do_dump(void)
{
	ssize_t ret;
	int i;
	unsigned long flags;
	struct file_info *files[NR_BATCH];
	struct file_info *file_info;
	int nr_found;
	unsigned long pos = 0;

	mutex_lock(&file_mutex);
	spin_lock_irqsave(&tree_lock, flags);
	INIT_LIST_HEAD(&file_list);
	do {
		nr_found = radix_tree_gang_lookup(&file_tree, (void **)files, pos, NR_BATCH);

		for (i = 0; i < nr_found; i++) {
			file_info = files[i];
			radix_tree_delete(&file_tree, (unsigned long)file_info->f_inode);
			pos = (unsigned long)file_info->f_inode + 1;
			INIT_LIST_HEAD(&file_info->list);
			list_add_tail(&file_info->list, &file_list);
		}
	} while (nr_found > 0);
	atomic64_set(&file_count_in_tree, 0);
	spin_unlock_irqrestore(&tree_lock, flags);
	mutex_unlock(&file_mutex);

	ret = do_show();

	mutex_lock(&file_mutex);
	while (!list_empty(&file_list)) {
        struct file_info *this = list_first_entry(&file_list,
										struct file_info, list);

		list_del_init(&this->list);
		kfree(this);
	}
	mutex_unlock(&file_mutex);
}

int rw_top_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_rw_top_settings settings;

	switch (id) {
	case DIAG_RW_TOP_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_rw_top_settings)) {
			ret = -EINVAL;
		} else if (rw_top_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				rw_top_settings = settings;
			}
		}
		break;
	case DIAG_RW_TOP_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_rw_top_settings)) {
			ret = -EINVAL;
		} else {
			settings = rw_top_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_RW_TOP_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!rw_top_alloced) {
			ret = -EINVAL;
		} else {
			do_dump();
			ret = copy_to_user_variant_buffer(&rw_top_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("rw-top");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_rw_top(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

static int lookup_syms(void)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 12, 0)
	LOOKUP_SYMS(mark_page_accessed);
	LOOKUP_SYMS(do_sync_write);
	LOOKUP_SYMS(file_read_actor);
	LOOKUP_SYMS(generic_segment_checks);
	LOOKUP_SYMS(generic_file_aio_read);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(4, 12, 0)
	LOOKUP_SYMS(__generic_file_write_iter);
	LOOKUP_SYMS(ext4_file_read_iter);
	LOOKUP_SYMS(dax_iomap_rw);
	LOOKUP_SYMS(ext4_iomap_ops);
	LOOKUP_SYMS(wait_on_page_bit_killable);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(4, 20, 0)
	LOOKUP_SYMS(__generic_file_write_iter);
	LOOKUP_SYMS(ext4_file_read_iter);
	LOOKUP_SYMS(dax_iomap_rw);
	LOOKUP_SYMS(ext4_iomap_ops);
#endif
	LOOKUP_SYMS(shmem_inode_operations);

	return 0;
}

int diag_rw_top_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&rw_top_variant_buffer, 1 * 1024 * 1024);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 12, 0)
	JUMP_INIT(do_sync_write);
	JUMP_INIT(generic_file_aio_read);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(4, 10, 0)
	JUMP_INIT(__generic_file_write_iter);
	JUMP_INIT(ext4_file_read_iter);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(4, 20, 0)
	JUMP_INIT(__generic_file_write_iter);
	JUMP_INIT(ext4_file_read_iter);
#endif

	INIT_RADIX_TREE(&file_tree, GFP_ATOMIC);

	if (rw_top_settings.activated)
		rw_top_settings.activated = __activate_rw_top();

	return 0;
}

void diag_rw_top_exit(void)
{
	int i;
	struct file_info *files[NR_BATCH];
	struct file_info *file_info;
	int nr_found;
	unsigned long pos = 0;

	if (rw_top_settings.activated)
		deactivate_rw_top();
	rw_top_settings.activated = 0;

	msleep(10);
	destroy_diag_variant_buffer(&rw_top_variant_buffer);
	msleep(10);

	rcu_read_lock();
	do {
		nr_found = radix_tree_gang_lookup(&file_tree, (void **)files, pos, NR_BATCH);
		for (i = 0; i < nr_found; i++) {
			file_info = files[i];
			radix_tree_delete(&file_tree, (unsigned long)file_info->f_inode);
			pos = (unsigned long)file_info->f_inode + 1;
			kfree(file_info);
		}
	} while (nr_found > 0);
	rcu_read_unlock();
}
#else
int diag_rw_top_init(void)
{
	return 0;
}

void diag_rw_top_exit(void)
{
	//
}
#endif
