/*
 * Linux内核诊断工具--内核态文件系统相关功能头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef __DIAG_FS_INTERNAL_H
#define __DIAG_FS_INTERNAL_H

int diag_fs_orphan_init(void);
void diag_fs_orphan_exit(void);
int diag_rw_top_init(void);
void diag_rw_top_exit(void);
int diag_fs_shm_init(void);
void diag_fs_shm_exit(void);
int diag_fs_cache_init(void);
void diag_fs_cache_exit(void);
#endif /* __DIAG_fS_INTERNAL_H */
