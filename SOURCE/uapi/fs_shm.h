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

int fs_shm_syscall(struct pt_regs *regs, long id);

//#define DIAG_FS_SHM_ACTIVATE (DIAG_BASE_SYSCALL_FS_SHM)
//#define DIAG_FS_SHM_DEACTIVATE (DIAG_FS_SHM_ACTIVATE + 1)
#define DIAG_FS_SHM_SET (DIAG_BASE_SYSCALL_FS_SHM)
#define DIAG_FS_SHM_SETTINGS (DIAG_FS_SHM_SET + 1)
#define DIAG_FS_SHM_DUMP (DIAG_FS_SHM_SETTINGS + 1)

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

#endif /* UAPI_FS_SHM_H */
