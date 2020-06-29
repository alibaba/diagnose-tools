/*
 * Linux内核诊断工具--内核态uprobe公共函数实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/fdtable.h>
#include "pub/uprobe.h"

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 33)
int hook_uprobe(int fd, loff_t offset, struct diag_uprobe *consumer)
{
	return -ENOSYS;
}

void unhook_uprobe(struct diag_uprobe *consumer)
{
}
#else

#include "pub/fs_utils.h"
#include "symbol.h"

int hook_uprobe(int fd, loff_t offset, struct diag_uprobe *diag_uprobe)
{
	struct files_struct *files;
	struct file *file;
	struct inode *inode;
	int ret = -EINVAL;

	if (!diag_uprobe)
		goto out;

	diag_uprobe->register_status = 0;
	files = orig_get_files_struct(current);
	if (!files)
		goto out;

	file = fcheck_files(files, fd);
	if (!file)
		goto out_put;

	if (file && file->f_path.dentry && file->f_path.dentry->d_inode) {
		inode = file->f_path.dentry->d_inode;
		ret = uprobe_register(inode, offset, &diag_uprobe->uprobe_consumer);
		if (!ret) {
			diag_uprobe->register_status = 1;
			diag_uprobe->inode = inode;
        	diag_uprobe->offset = offset;
			diag_get_file_path(file, diag_uprobe->file_name, 255);
		}
	}

out_put:
	orig_put_files_struct(files);
out:
	return -ENOSYS;
}

void unhook_uprobe(struct diag_uprobe *diag_uprobe)
{
	if (!diag_uprobe)
		return;

	if (diag_uprobe->register_status == 0)
		return;

	uprobe_unregister(diag_uprobe->inode, diag_uprobe->offset, &diag_uprobe->uprobe_consumer);
	diag_uprobe->register_status = 0;
}

#endif
