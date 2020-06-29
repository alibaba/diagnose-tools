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

struct pupil_task_info {
	int et_type;
	int pid;
	struct timeval tv;
};

int pupil_syscall(struct pt_regs *regs, long id);

#define DIAG_PUPIL_TASK_DUMP (DIAG_BASE_SYSCALL_PUPIL)
#define DIAG_PUPIL_TASK_PID (DIAG_PUPIL_TASK_DUMP + 1)
#define DIAG_PUPIL_TASK_TGID (DIAG_PUPIL_TASK_PID + 1)

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
#endif /* UAPI_PUPIL_H */
