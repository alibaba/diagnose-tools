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

int fs_orphan_syscall(struct pt_regs *regs, long id);

//#define DIAG_FS_ORPHAN_ACTIVATE (DIAG_BASE_SYSCALL_FS_ORPHAN)
//#define DIAG_FS_ORPHAN_DEACTIVATE (DIAG_FS_ORPHAN_ACTIVATE + 1)
#define DIAG_FS_ORPHAN_SET (DIAG_BASE_SYSCALL_FS_ORPHAN)
#define DIAG_FS_ORPHAN_SETTINGS (DIAG_FS_ORPHAN_SET + 1)
#define DIAG_FS_ORPHAN_DUMP (DIAG_FS_ORPHAN_SETTINGS + 1)

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

#endif /* UAPI_FS_ORPHAN_H */
