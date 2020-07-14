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

#ifndef UAPI_UTILIZATION_H
#define UAPI_UTILIZATION_H

#include <linux/ioctl.h>

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

struct diag_ioctl_utilization_isolate {
	int cpu;
	char __user *user_buf;
	size_t __user user_buf_len;
};

#define CMD_UTILIZATION_SET (0)
#define CMD_UTILIZATION_SETTINGS (CMD_UTILIZATION_SET + 1)
#define CMD_UTILIZATION_DUMP (CMD_UTILIZATION_SETTINGS + 1)
#define CMD_UTILIZATION_ISOLATE (CMD_UTILIZATION_DUMP + 1)
#define CMD_UTILIZATION_SAMPLE (CMD_UTILIZATION_ISOLATE + 1)
#define DIAG_IOCTL_UTILIZATION_SET _IOWR(DIAG_IOCTL_TYPE_UTILIZATION, CMD_UTILIZATION_SET, struct diag_utilization_settings)
#define DIAG_IOCTL_UTILIZATION_SETTINGS _IOWR(DIAG_IOCTL_TYPE_UTILIZATION, CMD_UTILIZATION_SETTINGS, struct diag_utilization_settings)
#define DIAG_IOCTL_UTILIZATION_DUMP _IOWR(DIAG_IOCTL_TYPE_UTILIZATION, CMD_UTILIZATION_DUMP, struct diag_ioctl_dump_param)
#define DIAG_IOCTL_UTILIZATION_ISOLATE _IOWR(DIAG_IOCTL_TYPE_UTILIZATION, CMD_UTILIZATION_ISOLATE, struct diag_ioctl_utilization_isolate)
#define DIAG_IOCTL_UTILIZATION_SAMPLE _IOWR(DIAG_IOCTL_TYPE_UTILIZATION, CMD_UTILIZATION_SAMPLE, int)

#endif /* UAPI_UTILIZATION_H */
