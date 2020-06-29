/*
 * Linux内核诊断工具--内核态uprobe公共函数头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef __DIAG_PUB_UPROBE_H
#define __DIAG_PUB_UPROBE_H

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 33)
struct uprobe_consumer {
};

#else

#include <linux/uprobes.h>
#include <linux/version.h>

#endif

struct uprobe_consumer;
struct inode;

struct diag_uprobe {
        struct uprobe_consumer uprobe_consumer;
        int register_status;
        struct inode *inode;
        loff_t offset;
        char file_name[255];
};

extern int hook_uprobe(int fd, loff_t offset,
        struct diag_uprobe *consumer);
extern void unhook_uprobe(struct diag_uprobe *consumer);

#endif /* __DIAG_PUB_UPROBE_H */
