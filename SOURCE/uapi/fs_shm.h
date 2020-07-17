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

#ifndef UAPI_FS_SHM_H
#define UAPI_FS_SHM_H

#include <linux/ioctl.h>

struct diag_fs_shm_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int top;
};

struct fs_shm_detail {
	int et_type;
	int seq;
	unsigned long id;
	unsigned long f_size;
	char cgroup_name[CGROUP_NAME_LEN];
	unsigned long pid;
	char comm[TASK_COMM_LEN];
	char path_name[DIAG_PATH_LEN];
};

#define CMD_FS_SHM_SET (0)
#define CMD_FS_SHM_SETTINGS (CMD_FS_SHM_SET + 1)
#define CMD_FS_SHM_DUMP (CMD_FS_SHM_SETTINGS + 1)
#define DIAG_IOCTL_FS_SHM_SET _IOWR(DIAG_IOCTL_TYPE_FS_SHM, CMD_FS_SHM_SET, struct diag_fs_shm_settings)
#define DIAG_IOCTL_FS_SHM_SETTINGS _IOWR(DIAG_IOCTL_TYPE_FS_SHM, CMD_FS_SHM_SETTINGS, struct diag_fs_shm_settings)
#define DIAG_IOCTL_FS_SHM_DUMP _IOWR(DIAG_IOCTL_TYPE_FS_SHM, CMD_FS_SHM_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_FS_SHM_H */
