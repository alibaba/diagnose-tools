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

#include <linux/ioctl.h>

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

#define CMD_PERF_SET (0)
#define CMD_PERF_SETTINGS (CMD_PERF_SET + 1)
#define CMD_PERF_DUMP (CMD_PERF_SETTINGS + 1)
#define DIAG_IOCTL_PERF_SET _IOWR(DIAG_IOCTL_TYPE_PERF, CMD_PERF_SET, struct diag_perf_settings)
#define DIAG_IOCTL_PERF_SETTINGS _IOWR(DIAG_IOCTL_TYPE_PERF, CMD_PERF_SETTINGS, struct diag_perf_settings)
#define DIAG_IOCTL_PERF_DUMP _IOWR(DIAG_IOCTL_TYPE_PERF, CMD_PERF_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_PERF_H */
