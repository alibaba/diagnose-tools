/*
 * Linux内核诊断工具--用户接口API
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Wen Yang <simon.wy@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef UAPI_TASK_MONITOR_H
#define UAPI_TASK_MONITOR_H

#include <linux/ioctl.h>

int task_monitor_syscall(struct pt_regs *regs, long id);

#define DIAG_TASK_MONITOR_SET (DIAG_BASE_SYSCALL_TASK_MONITOR)
#define DIAG_TASK_MONITOR_SETTINGS (DIAG_TASK_MONITOR_SET + 1)
#define DIAG_TASK_MONITOR_DUMP (DIAG_TASK_MONITOR_SETTINGS + 1)

struct diag_task_monitor_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int style;
	unsigned int interval;
	unsigned int threshold_task_a;
	unsigned int threshold_task_r;
	unsigned int threshold_task_d;
};

struct task_monitor_summary {
	int et_type;
	unsigned long id;
	struct diag_timespec tv;
	unsigned int task_a;
	unsigned int task_r;
	unsigned int task_d;
};

struct task_monitor_detail {
	int et_type;
	unsigned long id;
	struct diag_timespec tv;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
	struct diag_proc_chains_detail proc_chains;
};

#define CMD_TASK_MONITOR_SET (0)
#define CMD_TASK_MONITOR_SETTINGS (CMD_TASK_MONITOR_SET + 1)
#define CMD_TASK_MONITOR_DUMP (CMD_TASK_MONITOR_SETTINGS + 1)
#define DIAG_IOCTL_TASK_MONITOR_SET _IOWR(DIAG_IOCTL_TYPE_TASK_MONITOR, CMD_TASK_MONITOR_SET, struct diag_task_monitor_settings)
#define DIAG_IOCTL_TASK_MONITOR_SETTINGS _IOWR(DIAG_IOCTL_TYPE_TASK_MONITOR, CMD_TASK_MONITOR_SETTINGS, struct diag_task_monitor_settings)
#define DIAG_IOCTL_TASK_MONITOR_DUMP _IOWR(DIAG_IOCTL_TYPE_TASK_MONITOR, CMD_TASK_MONITOR_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_TASK_MONITOR_H */
