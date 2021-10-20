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

#ifndef UAPI_SYS_COST_H
#define UAPI_SYS_COST_H

#include <linux/ioctl.h>

int sys_cost_syscall(struct pt_regs *regs, long id);

#define DIAG_SYS_COST_SET (DIAG_BASE_SYSCALL_SYS_COST)
#define DIAG_SYS_COST_SETTINGS (DIAG_SYS_COST_SET + 1)
#define DIAG_SYS_COST_DUMP (DIAG_SYS_COST_SETTINGS + 1)

struct diag_sys_cost_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int tgid;
	unsigned int pid;
	char comm[TASK_COMM_LEN];
};

#define USER_NR_syscalls_virt 500

struct sys_cost_detail {
	int et_type;
	struct diag_timespec tv;
	unsigned long cpu;
	unsigned long count[USER_NR_syscalls_virt];
	unsigned long cost[USER_NR_syscalls_virt];
};

#define CMD_SYS_COST_SET (0)
#define CMD_SYS_COST_SETTINGS (CMD_SYS_COST_SET + 1)
#define CMD_SYS_COST_DUMP (CMD_SYS_COST_SETTINGS + 1)
#define DIAG_IOCTL_SYS_COST_SET _IOR(DIAG_IOCTL_TYPE_SYS_COST, CMD_SYS_COST_SET, struct diag_sys_cost_settings)
#define DIAG_IOCTL_SYS_COST_SETTINGS _IOW(DIAG_IOCTL_TYPE_SYS_COST, CMD_SYS_COST_SETTINGS, struct diag_sys_cost_settings)
#define DIAG_IOCTL_SYS_COST_DUMP _IOR(DIAG_IOCTL_TYPE_SYS_COST, CMD_SYS_COST_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_SYS_COST_H */
