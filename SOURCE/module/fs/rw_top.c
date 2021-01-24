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
#include <linux/file.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0) && LINUX_VERSION_CODE <= KERNEL_VERSION(5, 8, 0) \
	&& !defined(UBUNTU_1604)
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32) && LINUX_VERSION_CODE <= KERNEL_VERSION(5, 8, 0) \
	&& !defined(UBUNTU_1604)
static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_rw_top_settings rw_top_settings = {
	.top = 20,
	.device_name = "",
};

static unsigned long rw_top_alloced = 0;

static struct diag_variant_buffer rw_top_variant_buffer;

static struct kprobe diag_kprobe_filemap_fault;
static struct kprobe diag_kprobe_vfs_read;
static struct kprobe diag_kprobe_vfs_write;
static struct kprobe diag_kprobe_vfs_readv;
static struct kprobe diag_kprobe_vfs_writev;
static struct kprobe diag_kprobe_vfs_fsync_range;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
static struct kprobe diag_kprobe_aio_read;
static struct kprobe diag_kprobe_aio_write;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
DEFINE_ORIG_FUNC(unsigned long, sys_io_submit, 3,
		aio_context_t, ctx_id,
		long, nr,
                struct iocb __user * __user *, iocbpp);
long (*orig_do_io_submit)(aio_context_t ctx_id, long nr,
		  struct iocb __user *__user *iocbpp, bool compat);
#endif

enum rw_type {
	RW_READ,
	RW_WRITE,
	RW_FILEMAP_FAULT,
	RW_ALL,
	NR_RW_TYPE,
};

struct file_info {
	unsigned long rw_key;
	struct list_head list;
	struct inode *f_inode;
	char path_name[DIAG_PATH_LEN];
	char device_name[DIAG_DEVICE_LEN];
	unsigned long pid;
	char comm[TASK_COMM_LEN];
	atomic64_t rw_size[NR_RW_TYPE];
};

#define MAX_FILE_COUNT 300000
struct file_info *file_buf[MAX_FILE_COUNT];

static atomic64_t file_count_in_tree = ATOMIC64_INIT(0);
__maybe_unused static struct radix_tree_root file_tree;
__maybe_unused static DEFINE_SPINLOCK(tree_lock);
static LIST_HEAD(file_list);
static DEFINE_MUTEX(file_mutex);


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

static struct file_info *find_alloc_file_info(struct file *file,
		struct task_struct *task)
{
	struct file_info *info;
	char path_name[DIAG_PATH_LEN];
	char *ret_path;
	struct inode *f_inode;
	unsigned long rw_key;

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

	if (rw_top_settings.device_name[0] != 0
	    && strncmp(rw_top_settings.device_name, f_inode->i_sb->s_id, DIAG_DEVICE_LEN) != 0)
		return NULL;

	rw_key = task->pid | (unsigned long)f_inode;

	info = radix_tree_lookup(&file_tree, rw_key);
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

			info->rw_key = rw_key;
			info->f_inode = f_inode;
			strncpy(info->path_name, ret_path, DIAG_PATH_LEN);
			info->path_name[DIAG_PATH_LEN - 1] = 0;
			strncpy(info->device_name, f_inode->i_sb->s_id, DIAG_DEVICE_LEN);
			info->device_name[DIAG_DEVICE_LEN - 1] = 0;

			info->pid = task->pid;
			strncpy(info->comm, task->comm, TASK_COMM_LEN);
			info->comm[TASK_COMM_LEN - 1] = 0;

			spin_lock_irqsave(&tree_lock, flags);
			tmp = radix_tree_lookup(&file_tree, rw_key);
			if (tmp) {
				kfree(info);
				info = tmp;
			} else {
				radix_tree_insert(&file_tree, rw_key, info);
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

	info = find_alloc_file_info(file, current);
	if (info) {
		atomic64_add(count, &info->rw_size[rw_type]);
		atomic64_add(count, &info->rw_size[RW_ALL]);
		if (rw_top_settings.perf) {
			if (rw_top_settings.raw_stack) {
				struct rw_top_raw_perf *perf;

				perf = &diag_percpu_context[smp_processor_id()]->rw_top.raw_perf;
				perf->et_type = et_rw_top_raw_perf;
				perf->id = 0;
				perf->seq = 0;
				do_gettimeofday(&perf->tv);
				diag_task_brief(current, &perf->task);
				diag_task_kern_stack(current, &perf->kern_stack);
				diag_task_raw_stack(current, &perf->raw_stack);
				perf->proc_chains.chains[0][0] = 0;
				memcpy(perf->path_name, info->path_name, DIAG_PATH_LEN);
				memcpy(perf->device_name, info->device_name, DIAG_DEVICE_LEN);
				dump_proc_chains_simple(current, &perf->proc_chains);
				diag_variant_buffer_spin_lock(&rw_top_variant_buffer, flags);
				diag_variant_buffer_reserve(&rw_top_variant_buffer, sizeof(struct rw_top_raw_perf));
				diag_variant_buffer_write_nolock(&rw_top_variant_buffer, perf, sizeof(struct rw_top_raw_perf));
				diag_variant_buffer_seal(&rw_top_variant_buffer);
				diag_variant_buffer_spin_unlock(&rw_top_variant_buffer, flags);
			} else {
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
				memcpy(perf->device_name, info->device_name, DIAG_DEVICE_LEN);
				dump_proc_chains_simple(current, &perf->proc_chains);
				diag_variant_buffer_spin_lock(&rw_top_variant_buffer, flags);
				diag_variant_buffer_reserve(&rw_top_variant_buffer, sizeof(struct rw_top_perf));
				diag_variant_buffer_write_nolock(&rw_top_variant_buffer, perf, sizeof(struct rw_top_perf));
				diag_variant_buffer_seal(&rw_top_variant_buffer);
				diag_variant_buffer_spin_unlock(&rw_top_variant_buffer, flags);
			}
		}
	}
}

static int kprobe_filemap_fault_pre(struct kprobe *p, struct pt_regs *regs)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 18, 0) && !(defined(CENTOS_8U))
	struct vm_area_struct *vma = (void *)ORIG_PARAM1(regs);
	struct file *file = vma->vm_file;
#else
	struct vm_fault *vmf = (void *)ORIG_PARAM1(regs);
	struct file *file = vmf->vma->vm_file;
#endif

	hook_rw(2, file, PAGE_SIZE);

	return 0;
}

static int kprobe_vfs_read_pre(struct kprobe *p, struct pt_regs *regs)
{
	size_t count = ORIG_PARAM3(regs);
	struct file *file = (void *)ORIG_PARAM1(regs);

	hook_rw(0, file, count);

	return 0;
}

static int kprobe_vfs_write_pre(struct kprobe *p, struct pt_regs *regs)
{
	size_t count = ORIG_PARAM3(regs);
	struct file *file = (void *)ORIG_PARAM1(regs);

	hook_rw(1, file, count);

	return 0;
}

static int kprobe_vfs_fsync_range_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (void *)ORIG_PARAM1(regs);
	hook_rw(RW_WRITE, file, 1);

	return 0;
}

#ifndef MAX_RW_COUNT
#define MAX_RW_COUNT (INT_MAX & PAGE_MASK)
#endif

static size_t get_iov_size(struct iovec __user *uvector,
	unsigned long nr_segs)
{
	unsigned long seg;
	size_t ret = 0;
	struct iovec *iov;

	if (nr_segs > UIO_MAXIOV) {
		return 0;
	}

	iov = diag_percpu_context[smp_processor_id()]->rw_top.uvector;
	pagefault_disable();
	if (__copy_from_user_inatomic(iov, uvector, nr_segs * sizeof(*uvector))) {
		pagefault_enable();
		return 0;
	}
	pagefault_enable();

	for (seg = 0; seg < nr_segs; seg++) {
		ssize_t len = (ssize_t)iov[seg].iov_len;

		if (len < 0) {
			return 0;
		}
		
		if (len > MAX_RW_COUNT - ret) {
			len = MAX_RW_COUNT - ret;
			iov[seg].iov_len = len;
		}
		ret += len;
	}

	return ret;
}

static int kprobe_vfs_readv_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (void *)ORIG_PARAM1(regs);
	struct iovec __user *uvector = (void *)ORIG_PARAM2(regs);
	unsigned long vlen = (unsigned long)ORIG_PARAM3(regs);
	size_t len;

	len = get_iov_size(uvector, vlen);
	hook_rw(0, file, len);

	return 0;
}

static int kprobe_vfs_writev_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (void *)ORIG_PARAM1(regs);
	struct iovec __user *uvector = (void *)ORIG_PARAM2(regs);
	unsigned long vlen = (unsigned long)ORIG_PARAM3(regs);
	size_t len;

	len = get_iov_size(uvector, vlen);
	hook_rw(1, file, len);

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
static int kprobe_aio_read_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct kiocb *req = (void *)ORIG_PARAM1(regs);
	struct iocb *iocb = (void *)ORIG_PARAM2(regs);
	struct file *file;
	
	file = req->ki_filp;
	if (!file)
		return 0;

	hook_rw(0, file, iocb->aio_nbytes);

	return 0;
}

static int kprobe_aio_write_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct kiocb *req = (void *)ORIG_PARAM1(regs);
	struct iocb *iocb = (void *)ORIG_PARAM2(regs);
	struct file *file;

	file = req->ki_filp;
	if (!file)
		return 0;

	hook_rw(1, file, iocb->aio_nbytes);

	return 0;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static void hook_sys_io_submit(aio_context_t ctx_id, long nr,
                struct iocb __user * __user * iocbpp)
{
	int i;
	size_t len = 0;

	if (unlikely(nr < 0))
		return;

	if (unlikely(nr > UIO_MAXIOV))
		return;

	for (i = 0; i < nr; i++) {
		struct iocb __user *user_iocb;
		struct iocb tmp;
		struct file *filp;

		if (unlikely(__get_user(user_iocb, iocbpp + i))) {
			break;
		}

		if (unlikely(copy_from_user(&tmp, user_iocb, sizeof(tmp)))) {
			break;
		}

		len = tmp.aio_nbytes;
		filp = fget(tmp.aio_fildes);
		if (filp == NULL)
			break;
		hook_rw(tmp.aio_lio_opcode == IOCB_CMD_PWRITE || tmp.aio_lio_opcode == IOCB_CMD_PWRITEV ? 1 : 0,
			filp, tmp.aio_nbytes);
		fput(filp);
	}
	
}

unsigned long new_sys_io_submit(aio_context_t ctx_id, long nr,
                struct iocb __user * __user * iocbpp)
{
	unsigned long ret;

	atomic64_inc_return(&diag_nr_running);
	hook_sys_io_submit(ctx_id, nr, iocbpp);
	ret = orig_do_io_submit(ctx_id, nr, iocbpp, 0);
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

	hook_kprobe(&diag_kprobe_filemap_fault, "filemap_fault",
				kprobe_filemap_fault_pre, NULL);
	hook_kprobe(&diag_kprobe_vfs_read, "vfs_read",
				kprobe_vfs_read_pre, NULL);
	hook_kprobe(&diag_kprobe_vfs_write, "vfs_write",
				kprobe_vfs_write_pre, NULL);
	hook_kprobe(&diag_kprobe_vfs_readv, "vfs_readv",
				kprobe_vfs_readv_pre, NULL);
	hook_kprobe(&diag_kprobe_vfs_writev, "vfs_writev",
				kprobe_vfs_writev_pre, NULL);
	hook_kprobe(&diag_kprobe_vfs_fsync_range, "vfs_fsync_range",
				kprobe_vfs_fsync_range_pre, NULL);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	hook_kprobe(&diag_kprobe_aio_read, "aio_read",
				kprobe_aio_read_pre, NULL);
	hook_kprobe(&diag_kprobe_aio_write, "aio_write",
				kprobe_aio_write_pre, NULL);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	JUMP_INSTALL(sys_io_submit);
#endif
	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_rw_top(void)
{
	u64 nr_running;

	unhook_kprobe(&diag_kprobe_filemap_fault);
	unhook_kprobe(&diag_kprobe_vfs_read);
	unhook_kprobe(&diag_kprobe_vfs_write);
	unhook_kprobe(&diag_kprobe_vfs_readv);
	unhook_kprobe(&diag_kprobe_vfs_writev);
	unhook_kprobe(&diag_kprobe_vfs_fsync_range);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	unhook_kprobe(&diag_kprobe_aio_read);
	unhook_kprobe(&diag_kprobe_aio_write);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	JUMP_REMOVE(sys_io_submit);
#endif
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
		strncpy(detail.device_name, file_info->device_name, DIAG_DEVICE_LEN);
		detail.pid = file_info->pid;
		strncpy(detail.comm, file_info->comm, TASK_COMM_LEN);
		detail.comm[TASK_COMM_LEN - 1] = 0;
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
			radix_tree_delete(&file_tree, file_info->rw_key);
			pos = (unsigned long)file_info->rw_key + 1;
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
	int ret = 0;
	struct diag_rw_top_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_RW_TOP_SET:
		if (rw_top_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_rw_top_settings));
			if (!ret) {
				rw_top_settings = settings;
			}
		}
		break;
	case CMD_RW_TOP_SETTINGS:
		settings = rw_top_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_rw_top_settings));
		break;
	case CMD_RW_TOP_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));

		if (!rw_top_alloced) {
			ret = -EINVAL;
		} else if (!ret){
			do_dump();
			ret = copy_to_user_variant_buffer(&rw_top_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("rw-top");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

static int lookup_syms(void)
{
	LOOKUP_SYMS(shmem_inode_operations);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	LOOKUP_SYMS(do_io_submit);
	LOOKUP_SYMS(sys_io_submit);
#endif
	return 0;
}

int diag_rw_top_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&rw_top_variant_buffer, 50 * 1024 * 1024);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	JUMP_INIT(sys_io_submit);
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
			radix_tree_delete(&file_tree, (unsigned long)file_info->rw_key);
			pos = (unsigned long)file_info->rw_key + 1;
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
