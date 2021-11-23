/*
 * Linux内核诊断工具--用户接口API
 *
 * Copyright (C) 2021 Alibaba Ltd.
 *
 * 作者: Wen Yang <simon.wy@alibaba-inc.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef UAPI_MEMCG_STATS_H
#define UAPI_MEMCG_STATS_H

#include <linux/ioctl.h>

#define DIAG_MEMCG_STATS_SET (DIAG_BASE_SYSCALL_MEMCG_STATS)
#define DIAG_MEMCG_STATS_SETTINGS (DIAG_MEMCG_STATS_SET + 1)
#define DIAG_MEMCG_STATS_DUMP (DIAG_MEMCG_STATS_SETTINGS + 1)

#define CMD_MEMCG_STATS_SET (0)
#define CMD_MEMCG_STATS_SETTINGS (CMD_MEMCG_STATS_SET + 1)
#define CMD_MEMCG_STATS_DUMP (CMD_MEMCG_STATS_SETTINGS + 1)

#define DIAG_IOCTL_MEMCG_STATS_SET _IOWR(DIAG_IOCTL_TYPE_MEMCG_STATS, CMD_MEMCG_STATS_SET, struct diag_memcg_stats_settings)
#define DIAG_IOCTL_MEMCG_STATS_SETTINGS _IOWR(DIAG_IOCTL_TYPE_MEMCG_STATS, CMD_MEMCG_STATS_SETTINGS, struct diag_memcg_stats_settings)
#define DIAG_IOCTL_MEMCG_STATS_DUMP _IOWR(DIAG_IOCTL_TYPE_MEMCG_STATS, CMD_MEMCG_STATS_DUMP, struct diag_ioctl_dump_param)

struct diag_memcg_stats_settings {
	unsigned int activated;
	unsigned int verbose;
};

#define MEMCG_NAME_LEN 256
struct diag_memcg_stats_summary {
	int et_type;
	unsigned long addr;
	unsigned long flags;
	unsigned int dying;
	unsigned int pages;
	unsigned long timestamp;
	char name[MEMCG_NAME_LEN];
};

struct diag_memcg_stats_detail {
	int et_type;
	unsigned long key;
	unsigned long cg_addr;
	unsigned long ino;
	unsigned long timestamp;
	unsigned int dev;
	unsigned int pages;
	char name[MEMCG_NAME_LEN];
	char mnt_dir[MEMCG_NAME_LEN];
};

#endif /* UAPI_MEMCG_STATS_H */
