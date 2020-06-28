/*
 * Linux内核诊断工具--用户接口API
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 2
 *
 */

#ifndef UAPI_UTILIZATION_H
#define UAPI_UTILIZATION_H

int utilization_syscall(struct pt_regs *regs, long id);

//#define DIAG_UTILIZATION_ACTIVATE (DIAG_BASE_SYSCALL_UTILIZATION)
//#define DIAG_UTILIZATION_DEACTIVATE (DIAG_UTILIZATION_ACTIVATE + 1)
#define DIAG_UTILIZATION_SET (DIAG_BASE_SYSCALL_UTILIZATION)
#define DIAG_UTILIZATION_SETTINGS (DIAG_UTILIZATION_SET + 1)
#define DIAG_UTILIZATION_DUMP (DIAG_UTILIZATION_SETTINGS + 1)
#define DIAG_UTILIZATION_ISOLATE (DIAG_UTILIZATION_DUMP + 1)
#define DIAG_UTILIZATION_SAMPLE (DIAG_UTILIZATION_ISOLATE + 1)

struct diag_utilization_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int style;
	unsigned int sample;
	char cpus[512];
};

struct utilization_detail {
	int et_type;
	struct timeval tv;
	struct diag_task_detail task;
	struct diag_proc_chains_detail proc_chains;
	unsigned long exec;
	unsigned long pages;
	unsigned long wild;
};

#endif /* UAPI_UTILIZATION_H */
