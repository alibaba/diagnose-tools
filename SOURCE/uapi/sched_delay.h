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

#ifndef UAPI_SCHED_DELAY_H
#define UAPI_SCHED_DELAY_H

#include <linux/ioctl.h>

int sched_delay_syscall(struct pt_regs *regs, long id);

#define DIAG_SCHED_DELAY_SET (DIAG_BASE_SYSCALL_SCHED_DELAY)
#define DIAG_SCHED_DELAY_SETTINGS (DIAG_SCHED_DELAY_SET + 1)
#define DIAG_SCHED_DELAY_DUMP (DIAG_SCHED_DELAY_SETTINGS + 1)

struct diag_sched_delay_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int tgid;
	unsigned int pid;
	unsigned int bvt;
	char comm[TASK_COMM_LEN];
	unsigned int threshold_ms;
};

struct sched_delay_rq {
	int et_type;
	unsigned long id;
	unsigned long seq;
	struct timeval tv;
	int cpu;
	int nr_running;
};

struct sched_delay_dither {
	int et_type;
	unsigned long id;
	unsigned long seq;
	struct timeval tv;
	unsigned long delay_ms;
	unsigned long now, queued;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
	struct diag_proc_chains_detail proc_chains;
};

#define CMD_SCHED_DELAY_SET (0)
#define CMD_SCHED_DELAY_SETTINGS (CMD_SCHED_DELAY_SET + 1)
#define CMD_SCHED_DELAY_DUMP (CMD_SCHED_DELAY_SETTINGS + 1)
#define DIAG_IOCTL_SCHED_DELAY_SET _IOR(DIAG_IOCTL_TYPE_SCHED_DELAY, CMD_SCHED_DELAY_SET, struct diag_sched_delay_settings)
#define DIAG_IOCTL_SCHED_DELAY_SETTINGS _IOW(DIAG_IOCTL_TYPE_SCHED_DELAY, CMD_SCHED_DELAY_SETTINGS, struct diag_sched_delay_settings)
#define DIAG_IOCTL_SCHED_DELAY_DUMP _IOR(DIAG_IOCTL_TYPE_SCHED_DELAY, CMD_SCHED_DELAY_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_SCHED_DELAY_H */
