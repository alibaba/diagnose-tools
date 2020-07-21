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

#ifndef UAPI_FS_ORPHAN_H
#define UAPI_FS_ORPHAN_H

#include <linux/ioctl.h>

struct diag_fs_orphan_settings {
	unsigned int activated;
	unsigned int verbose;
	char devname[255];
};

struct fs_orphan_summary {
	int et_type;
	struct diag_inode_detail inode;
};

struct fs_orphan_detail {
	int et_type;
	struct diag_inode_detail inode;
	char path_name[255];
	struct diag_task_detail task;
	struct diag_proc_chains_detail proc_chains;
};

#define CMD_FS_ORPHAN_SET (0)
#define CMD_FS_ORPHAN_SETTINGS (CMD_FS_ORPHAN_SET + 1)
#define CMD_FS_ORPHAN_DUMP (CMD_FS_ORPHAN_SETTINGS + 1)
#define DIAG_IOCTL_FS_ORPHAN_SET _IOWR(DIAG_IOCTL_TYPE_FS_ORPHAN, CMD_FS_ORPHAN_SET, struct diag_fs_orphan_settings)
#define DIAG_IOCTL_FS_ORPHAN_SETTINGS _IOWR(DIAG_IOCTL_TYPE_FS_ORPHAN, CMD_FS_ORPHAN_SETTINGS, struct diag_fs_orphan_settings)
#define DIAG_IOCTL_FS_ORPHAN_DUMP _IOWR(DIAG_IOCTL_TYPE_FS_ORPHAN, CMD_FS_ORPHAN_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_FS_ORPHAN_H */
