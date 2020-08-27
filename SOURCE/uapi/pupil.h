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

#ifndef UAPI_PUPIL_H
#define UAPI_PUPIL_H

#include <linux/ioctl.h>

struct pupil_task_info {
	int et_type;
	int pid;
	struct timeval tv;
};

int pupil_syscall(struct pt_regs *regs, long id);

#define DIAG_PUPIL_TASK_DUMP (DIAG_BASE_SYSCALL_PUPIL)
#define DIAG_PUPIL_TASK_PID (DIAG_PUPIL_TASK_DUMP + 1)

struct pupil_task_detail {
	int et_type;
	struct timeval tv;
	unsigned long pid;
	struct diag_proc_chains_detail proc_chains;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
	struct diag_raw_stack_detail raw_stack;
};

int pupil_task_info(int argc, char **argv);

#define CMD_PUPIL_TASK_DUMP (0)
#define CMD_PUPIL_TASK_PID (CMD_PUPIL_TASK_DUMP + 1)
#define DIAG_IOCTL_PUPIL_TASK_DUMP _IOWR(DIAG_IOCTL_TYPE_PUPIL, CMD_PUPIL_TASK_DUMP, struct diag_ioctl_dump_param)
#define DIAG_IOCTL_PUPIL_TASK_PID _IOWR(DIAG_IOCTL_TYPE_PUPIL, CMD_PUPIL_TASK_PID, int)

#endif /* UAPI_PUPIL_H */
