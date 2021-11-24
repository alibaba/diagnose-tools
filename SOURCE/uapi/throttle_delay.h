/*
 * Linux内核诊断工具--用户接口API
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Xiongwei Jiang <xiongwei.jiang@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef UAPI_THROTTLE_DELAY_H
#define UAPI_THROTTLE_DELAY_H

#include <linux/ioctl.h>

int throttle_delay_syscall(struct pt_regs *regs, long id);

#define DIAG_THROTTLE_DELAY_SET (DIAG_BASE_SYSCALL_THROTTLE_DELAY)
#define DIAG_THROTTLE_DELAY_SETTINGS (DIAG_THROTTLE_DELAY_SET + 1)
#define DIAG_THROTTLE_DELAY_DUMP (DIAG_THROTTLE_DELAY_SETTINGS + 1)

struct diag_throttle_delay_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int tgid;
	unsigned int pid;
	unsigned int bvt;
	char comm[TASK_COMM_LEN];
	unsigned int threshold_ms;
};

struct throttle_delay_rq {
	int et_type;
	unsigned long id;
	unsigned long seq;
	struct diag_timespec tv;
	int cpu;
	int nr_running;
};

struct throttle_delay_dither {
	int et_type;
	unsigned long id;
	unsigned long seq;
	struct diag_timespec tv;
	unsigned long delay_ms;
	unsigned long now, dequeued;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
	struct diag_proc_chains_detail proc_chains;
};

#define CMD_THROTTLE_DELAY_SET (0)
#define CMD_THROTTLE_DELAY_SETTINGS (CMD_THROTTLE_DELAY_SET + 1)
#define CMD_THROTTLE_DELAY_DUMP (CMD_THROTTLE_DELAY_SETTINGS + 1)
#define DIAG_IOCTL_THROTTLE_DELAY_SET _IOR(DIAG_IOCTL_TYPE_THROTTLE_DELAY, CMD_THROTTLE_DELAY_SET, struct diag_throttle_delay_settings)
#define DIAG_IOCTL_THROTTLE_DELAY_SETTINGS _IOW(DIAG_IOCTL_TYPE_THROTTLE_DELAY, CMD_THROTTLE_DELAY_SETTINGS, struct diag_throttle_delay_settings)
#define DIAG_IOCTL_THROTTLE_DELAY_DUMP _IOR(DIAG_IOCTL_TYPE_THROTTLE_DELAY, CMD_THROTTLE_DELAY_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_THROTTLE_DELAY_H */
