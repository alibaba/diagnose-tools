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

#ifndef __DIAG_IO_INTERNAL_H
#define __DIAG_IO_INTERNAL_H
int diag_bio_init(void);
int diag_blk_dev_init(void);
int diag_vfs_init(void);
void diag_bio_exit(void);
void diag_blk_dev_exit(void);
void diag_vfs_exit(void);
extern int diag_nvme_init(void);
extern void diag_nvme_exit(void);
#endif /* __DIAG_IO_INTERNAL_H */
