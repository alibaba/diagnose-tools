/*
 * Linux内核诊断工具--内核态文件系统公共函数实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/fdtable.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#endif
#include "pub/fs_utils.h"
#include "symbol.h"
#include "internal.h"
#include "uapi/ali_diagnose.h"

void diag_inode_short_name(struct inode *inode, char *path_name, int size)
{
	struct dentry *dentry;

	if (!orig_d_find_any_alias || path_name == NULL || size <= 0)
		return;

	dentry = orig_d_find_any_alias(inode);
	if (dentry) {
		strncpy(path_name, dentry->d_name.name, min(size, (int)dentry->d_name.len));
		path_name[size - 1] = 0;
		dput(dentry);
	}
}

struct __inode_full_name {
	struct inode *inode;
	char path_name[DIAG_PATH_LEN];
};

static void *__full_name_file(struct task_struct *tsk, struct file *file, void *data)
{
	struct __inode_full_name *tmp = data;;

	if (!file || !file->f_path.dentry || !file->f_path.dentry->d_inode)
		return NULL;
	
	if (file->f_path.dentry->d_inode == tmp->inode) {
		diag_get_file_path(file, tmp->path_name, DIAG_PATH_LEN);
		return file;
	}


	return NULL;
}

void diag_inode_full_name(struct inode *inode, char *path_name, int size)
{
	struct task_struct *tsk;
	struct radix_tree_root proc_tree;
	struct task_struct *batch[NR_BATCH];
	int nr_found;
	unsigned long pos;
	int i;
	struct __inode_full_name tmp;

	if (path_name == NULL || size <= 0)
		return;

	memset(&tmp, 0, sizeof(struct __inode_full_name));
	tmp.inode = inode;
	
	INIT_RADIX_TREE(&proc_tree, GFP_ATOMIC);
	for_each_process(tsk) {
		radix_tree_insert(&proc_tree, (unsigned long)tsk, tsk);
		get_task_struct(tsk);
	}

	pos = 0;
	do {
		nr_found = radix_tree_gang_lookup(&proc_tree, (void **)batch, pos, NR_BATCH);
		for (i = 0; i < nr_found; i++) {
			tsk = batch[i];
			radix_tree_delete(&proc_tree, (unsigned long)tsk);
			pos = (unsigned long)tsk + 1;
			for_each_files_task(tsk, __full_name_file, &tmp);
			put_task_struct(tsk);
		}
	} while (nr_found > 0);

	strncpy(path_name, tmp.path_name, size);
}

void diag_inode_brief(struct inode *inode, struct diag_inode_detail *detail)
{
	if (!detail)
		return;

	memset(detail, 0, sizeof(struct diag_inode_detail));
	if (!inode)
		return;

	detail->inode_number = inode->i_ino;
	detail->inode_mode = inode->i_mode;
	detail->inode_nlink = inode->i_nlink;
	detail->inode_count = atomic_read(&inode->i_count);
	detail->inode_size = inode->i_size;
	detail->inode_blocks = inode->i_blocks;
	if (inode->i_sb) {
		detail->inode_block_bytes = inode->i_sb->s_blocksize * detail->inode_blocks;
	} else {
		detail->inode_block_bytes = 0;
	}
}

char *diag_get_file_path(struct file *file, char *path_name, int len)
{
	char *ret_path;

	if (!path_name || !len) {
		return NULL;
	}
	memset(path_name, 0, len);

	if (!file)
		return NULL;

	ret_path = d_path(&file->f_path, path_name, len);
	if (IS_ERR(ret_path)) {
		return NULL;
	}

	strncpy(path_name, ret_path, len);

	return path_name;
}

void *for_each_files_task(struct task_struct *tsk,
	diag_cb_file cb, void *data)
{
	struct files_struct *files;
	struct file *file;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned int fd;
	void *retval;

	retval = NULL;
	if (!tsk)
		goto out_no_task;

	get_task_struct(tsk);
	files = orig_get_files_struct(tsk);
	if (!files)
		goto out;

	rcu_read_lock();
	for (fd = 0; fd < files_fdtable(files)->max_fds; fd++) {
		file = fcheck_files(files, fd);
		if (!file)
			continue;

		rcu_read_unlock();
		retval = cb(tsk, file, data);
		if (retval)
			break;
	}
	rcu_read_unlock();
	orig_put_files_struct(files);

	mm = get_task_mm(tsk);
	if (mm) {
		down_read(&mm->mmap_sem);

		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			if (vma->vm_file) {
				retval = cb(tsk, vma->vm_file, data);
				if (retval)
					break;
			}
		}

		up_read(&mm->mmap_sem);

		mmput(mm);
	}
out:
	put_task_struct(tsk);
out_no_task:
	return retval;
}

