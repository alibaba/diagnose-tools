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

#ifndef UAPI_RW_TOP_H
#define UAPI_RW_TOP_H

int rw_top_syscall(struct pt_regs *regs, long id);

//#define DIAG_RW_TOP_ACTIVATE (DIAG_BASE_SYSCALL_RW_TOP)
//#define DIAG_RW_TOP_DEACTIVATE (DIAG_RW_TOP_ACTIVATE + 1)
#define DIAG_RW_TOP_SET (DIAG_BASE_SYSCALL_RW_TOP)
#define DIAG_RW_TOP_SETTINGS (DIAG_RW_TOP_SET + 1)
#define DIAG_RW_TOP_DUMP (DIAG_RW_TOP_SETTINGS + 1)

struct diag_rw_top_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int top;
	unsigned int shm;
	unsigned int perf;
};

struct rw_top_detail {
	int et_type;
	int seq;
	unsigned long id;
	unsigned long r_size;
	unsigned long w_size;
	unsigned long map_size;
	unsigned long rw_size;
	char path_name[DIAG_PATH_LEN];
};

struct rw_top_perf {
	int et_type;
	unsigned long id;
	unsigned long seq;
	struct timeval tv;
	struct diag_proc_chains_detail proc_chains;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
	char path_name[DIAG_PATH_LEN];
};

#endif /* UAPI_RW_TOP_H */
