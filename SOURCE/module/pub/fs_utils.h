/*
 * Linux内核诊断工具--内核态文件系统公共函数头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef __DIAG_PUB_FS_UTILS_H
#define __DIAG_PUB_FS_UTILS_H

#include <linux/version.h>
#include <linux/sched.h>
#include <linux/fs.h>

typedef void * (*diag_cb_file)(struct task_struct *tsk,
	struct file *file, void *data);
extern void *for_each_files_task(struct task_struct *tsk,
	diag_cb_file cb, void *data);

extern char *diag_get_file_path(struct file *file, char *path_name, int len);

struct diag_inode_detail;
extern void diag_inode_short_name(struct inode *inode, char *path_name, int size);
extern void diag_inode_full_name(struct inode *inode, char *path_name, int size);
extern void diag_inode_brief(struct inode *inode, struct diag_inode_detail *detail);

#endif /* __DIAG_PUB_FS_UTILS_H */

