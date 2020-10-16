/*
 * Linux内核诊断工具--内核态fs-shm功能
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
#include <linux/sort.h>
#include <linux/fsnotify.h>
#include <linux/backing-dev.h>
#include <linux/aio.h>
#include <linux/fdtable.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0) && LINUX_VERSION_CODE <= KERNEL_VERSION(4, 4, 0)
#include <linux/iomap.h>
#endif

#include <asm/irq_regs.h>
#include <asm/unistd.h>

#if !defined(DIAG_ARM64)
#include <asm/asm-offsets.h>
#endif

#include "internal.h"
#include "pub/trace_file.h"

#include "uapi/fs_shm.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) && LINUX_VERSION_CODE <= KERNEL_VERSION(4, 20, 0)
static atomic64_t diag_nr_running = ATOMIC64_INIT(0);

struct diag_fs_shm_settings fs_shm_settings = {
	.top = 100,
};

static unsigned long fs_shm_alloced = 0;

static struct diag_variant_buffer shm_variant_buffer;

#define DIAG_PATH_LEN 100
struct file_info {
	struct list_head list;
	struct inode *f_inode;
	char path_name[DIAG_PATH_LEN];
	int pid;
	char comm[TASK_COMM_LEN];
	char cgroup_name[255];
	u64 f_size;
};

#define MAX_FILE_COUNT 300000
static struct file_info *file_buf[MAX_FILE_COUNT];
static int file_count = 0;
static DEFINE_MUTEX(file_mutex);

static struct inode_operations *orig_shmem_inode_operations;

static int need_trace(struct file *file)
{
	struct path *path;

	if (!fs_shm_settings.activated)
		return 0;

	if (!file)
		return 0;

	path = &file->f_path;
	if (path->dentry && path->dentry->d_op && path->dentry->d_op->d_dname)
		return 0;

	if (file->f_inode && file->f_inode->i_op != orig_shmem_inode_operations)
		return 0;

	return 1;
}

static struct file_info *alloc_file_info(struct file *file)
{
	struct file_info *info;
	char path_name[DIAG_PATH_LEN];
	char *ret_path;
	struct inode *f_inode;

	if (!file)
		return NULL;
	f_inode = file->f_inode;

	if (f_inode == NULL)
		return NULL;

	info = kmalloc(sizeof(struct file_info), GFP_ATOMIC | __GFP_ZERO);
	if (info) {
		memset(path_name, 0, DIAG_PATH_LEN);
		ret_path = d_path(&file->f_path, path_name, sizeof(path_name) / sizeof(path_name[0]));
		if (IS_ERR(ret_path)) {
			return NULL;
		}

		info->f_inode = f_inode;
		strncpy(info->path_name, ret_path, DIAG_PATH_LEN);
		info->path_name[DIAG_PATH_LEN - 1] = 0;
		info->f_size = f_inode->i_size;
	}

	return info;
}

static int dump_file(const void *t, struct file *file, unsigned fd)
{
	struct file_info *info;
	struct task_struct *p = (void *)t;
	char cgroup_buf[255];

	if (!need_trace(file))
		return 0;

	if (file_count >= MAX_FILE_COUNT)
		return 1;

	info = alloc_file_info(file);
	if (info) {
		memcpy(info->comm, p->comm, TASK_COMM_LEN);
		info->comm[TASK_COMM_LEN - 1] = 0;
		diag_cgroup_name(p, cgroup_buf, 255, 0);
		memcpy(info->cgroup_name, cgroup_buf, sizeof(info->cgroup_name));
		info->pid = p->pid;
		file_buf[file_count] = info;
		file_count++;
	}

	return 0;
}

static int diag_compare_file(const void *one, const void *two)
{
	struct file_info *__one = *(struct file_info **)one;
	struct file_info *__two = *(struct file_info **)two;

	if (__one->f_size > __two->f_size)
		return -1;
	if (__one->f_size < __two->f_size)
		return 1;

	return 0;
}

static void do_dump(void)
{
	struct task_struct *p;
	struct file_info *file_info;
	int i;
	struct fs_shm_detail detail;
	unsigned long flags;

	mutex_lock(&file_mutex);
	file_count = 0;
	rcu_read_lock();
	for_each_process(p) {
		task_lock(p);
		iterate_fd(p->files, 0, dump_file, p);
		task_unlock(p);
	}
	rcu_read_unlock();

	sort(&file_buf[0], (size_t)file_count, (size_t)sizeof(struct file_info *),
		&diag_compare_file, NULL);

	detail.id = get_cycles();
	detail.et_type = et_fs_shm_detail;
	for (i = 0; i < min_t(int, file_count, fs_shm_settings.top); i++)
	{
		file_info = file_buf[i];
		detail.seq = i;
		detail.f_size = file_info->f_size;
		strncpy(detail.cgroup_name, file_info->cgroup_name, CGROUP_NAME_LEN);
		detail.pid = file_info->pid;
		strncpy(detail.comm, file_info->comm, TASK_COMM_LEN);
		strncpy(detail.path_name, file_info->path_name, DIAG_PATH_LEN);
		diag_variant_buffer_spin_lock(&shm_variant_buffer, flags);
		diag_variant_buffer_reserve(&shm_variant_buffer, sizeof(struct fs_shm_detail));
		diag_variant_buffer_write_nolock(&shm_variant_buffer, &detail, sizeof(struct fs_shm_detail));
		diag_variant_buffer_seal(&shm_variant_buffer);
		diag_variant_buffer_spin_unlock(&shm_variant_buffer, flags);
	}

	for (i = 0; i < file_count; i++)
	{
		file_info = file_buf[i];
		kfree(file_info);
	}

	mutex_unlock(&file_mutex);
}

static int __activate_fs_shm(void)
{
	int ret = 0;
	ret = alloc_diag_variant_buffer(&shm_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	fs_shm_alloced = 1;

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_fs_shm(void)
{
	u64 nr_running;

	synchronize_sched();
	msleep(10);
	nr_running = atomic64_read(&diag_nr_running);

	while (nr_running > 0)
	{
		msleep(10);
		nr_running = atomic64_read(&diag_nr_running);
	}
}

int activate_fs_shm(void)
{
	if (!fs_shm_settings.activated)
		fs_shm_settings.activated = __activate_fs_shm();

	return fs_shm_settings.activated;
}

int deactivate_fs_shm(void)
{
	if (fs_shm_settings.activated)
		__deactivate_fs_shm();
	fs_shm_settings.activated = 0;

	return 0;
}

static int lookup_syms(void)
{
	LOOKUP_SYMS(shmem_inode_operations);

	return 0;
}

int fs_shm_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_fs_shm_settings settings;

	switch (id) {
	case DIAG_FS_SHM_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_fs_shm_settings)) {
			ret = -EINVAL;
		} else if (fs_shm_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				fs_shm_settings = settings;
			}
		}
		break;
	case DIAG_FS_SHM_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_fs_shm_settings)) {
			ret = -EINVAL;
		} else {
			settings = fs_shm_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_FS_SHM_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!fs_shm_alloced) {
			ret = -EINVAL;
		} else {
			do_dump();
			ret = copy_to_user_variant_buffer(&shm_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("fs-shm");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_fs_shm(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_fs_shm_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_FS_SHM_SET:
		if (fs_shm_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_fs_shm_settings));
			if (!ret) {
				fs_shm_settings = settings;
			}
		}
		break;
	case CMD_FS_SHM_SETTINGS:
		settings = fs_shm_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_fs_shm_settings));
		break;
	case CMD_FS_SHM_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));
		if (!fs_shm_alloced) {
			ret = -EINVAL;
		} else if (!ret){
			do_dump();
			ret = copy_to_user_variant_buffer(&shm_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("fs-shm");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_fs_shm_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&shm_variant_buffer, 1 * 1024 * 1024);
	if (fs_shm_settings.activated)
		fs_shm_settings.activated = __activate_fs_shm();

	return 0;
}

void diag_fs_shm_exit(void)
{
	if (fs_shm_settings.activated)
		deactivate_fs_shm();
	fs_shm_settings.activated = 0;
	destroy_diag_variant_buffer(&shm_variant_buffer);
}

#else
int diag_fs_shm_init(void)
{
	return 0;
}

void diag_fs_shm_exit(void)
{
	//
}
#endif

