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

#ifndef UAPI_ALLOC_TOP_H
#define UAPI_ALLOC_TOP_H

int alloc_top_syscall(struct pt_regs *regs, long id);

//#define DIAG_ALLOC_TOP_ACTIVATE (DIAG_BASE_SYSCALL_ALLOC_TOP)
//#define DIAG_ALLOC_TOP_DEACTIVATE (DIAG_ALLOC_TOP_ACTIVATE + 1)
#define DIAG_ALLOC_TOP_SET (DIAG_BASE_SYSCALL_ALLOC_TOP)
#define DIAG_ALLOC_TOP_SETTINGS (DIAG_ALLOC_TOP_SET + 1)
#define DIAG_ALLOC_TOP_DUMP (DIAG_ALLOC_TOP_SETTINGS + 1)

struct diag_alloc_top_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int top;
};

struct alloc_top_detail {
	int et_type;
	int seq;
	unsigned long id;
	unsigned long tgid;
	char comm[TASK_COMM_LEN];
	char cgroup_name[CGROUP_NAME_LEN];
	unsigned long page_count;
};

#endif /* UAPI_ALLOC_TOP_H */
