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

#ifndef UAPI_PERF_H
#define UAPI_PERF_H

int perf_syscall(struct pt_regs *regs, long id);

//#define DIAG_PERF_ACTIVATE (DIAG_BASE_SYSCALL_PERF)
//#define DIAG_PERF_DEACTIVATE (DIAG_PERF_ACTIVATE + 1)
#define DIAG_PERF_SET (DIAG_BASE_SYSCALL_PERF)
#define DIAG_PERF_SETTINGS (DIAG_PERF_SET + 1)
#define DIAG_PERF_DUMP (DIAG_PERF_SETTINGS + 1)

struct diag_perf_settings {
	unsigned int activated;
	unsigned int style;
	unsigned int verbose;
	unsigned int tgid;
	unsigned int pid;
	char comm[TASK_COMM_LEN];
	char cpus[512];
	unsigned int idle;
	unsigned int bvt;
	unsigned int sys;
};

struct perf_detail {
	int et_type;
	unsigned long id;
	unsigned long seq;
	struct timeval tv;
	struct diag_proc_chains_detail proc_chains;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
};

#endif /* UAPI_PERF_H */
