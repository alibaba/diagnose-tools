/*
 * Linux内核诊断工具--用户接口API
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef UAPI_FS_CACHE_H
#define UAPI_FS_CACHE_H

#include <linux/ioctl.h>

int fs_cache_syscall(struct pt_regs *regs, long id);

#define DIAG_FS_CACHE_SET (DIAG_BASE_SYSCALL_FS_CACHE)
#define DIAG_FS_CACHE_SETTINGS (DIAG_FS_CACHE_SET + 1)
#define DIAG_FS_CACHE_DUMP (DIAG_FS_CACHE_SETTINGS + 1)
#define DIAG_FS_CACHE_DROP (DIAG_FS_CACHE_DUMP + 1)


struct diag_fs_cache_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int top;
	unsigned int size;
};

struct fs_cache_detail {
	int et_type;
	int seq;
	void *f_inode;
	char path_name[DIAG_PATH_LEN];
	unsigned long id;
	unsigned long f_size;
	unsigned long cache_nr_pages;
};

#define CMD_FS_CACHE_SET (0)
#define CMD_FS_CACHE_SETTINGS (CMD_FS_CACHE_SET + 1)
#define CMD_FS_CACHE_DUMP (CMD_FS_CACHE_SETTINGS + 1)
#define CMD_FS_CACHE_DROP (CMD_FS_CACHE_DUMP + 1)
#define DIAG_IOCTL_FS_CACHE_SET _IOWR(DIAG_IOCTL_TYPE_FS_CACHE, CMD_FS_CACHE_SET, struct diag_fs_cache_settings)
#define DIAG_IOCTL_FS_CACHE_SETTINGS _IOWR(DIAG_IOCTL_TYPE_FS_CACHE, CMD_FS_CACHE_SETTINGS, struct diag_fs_cache_settings)
#define DIAG_IOCTL_FS_CACHE_DUMP _IOWR(DIAG_IOCTL_TYPE_FS_CACHE, CMD_FS_CACHE_DUMP, struct diag_ioctl_dump_param)
#define DIAG_IOCTL_FS_CACHE_DROP _IOWR(DIAG_IOCTL_TYPE_FS_CACHE, CMD_FS_CACHE_DROP, unsigned long)

#endif /* UAPI_FS_CACHE_H */
