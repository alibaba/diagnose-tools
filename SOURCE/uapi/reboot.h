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

#ifndef UAPI_REBOOT_H
#define UAPI_REBOOT_H

int reboot_syscall(struct pt_regs *regs, long id);

//#define DIAG_REBOOT_ACTIVATE (DIAG_BASE_SYSCALL_REBOOT)
//#define DIAG_REBOOT_DEACTIVATE (DIAG_REBOOT_ACTIVATE + 1)
#define DIAG_REBOOT_VERBOSE (DIAG_BASE_SYSCALL_REBOOT)
#define DIAG_REBOOT_SETTINGS (DIAG_REBOOT_VERBOSE + 1)

#define CMD_REBOOT_VERBOSE (0)
#define CMD_REBOOT_SETTINGS (CMD_REBOOT_VERBOSE + 1)

#define DIAG_IOCTL_REBOOT_VERBOSE _IOWR(DIAG_IOCTL_TYPE_REBOOT, CMD_REBOOT_VERBOSE, unsigned int)
#define DIAG_IOCTL_REBOOT_SETTINGS _IOWR(DIAG_IOCTL_TYPE_REBOOT, CMD_REBOOT_SETTINGS, struct diag_reboot_settings)

struct diag_reboot_settings {
	unsigned int activated;
	unsigned int verbose;
};

struct reboot_detail {
	int et_type;
	struct diag_timespec tv;
	struct diag_proc_chains_detail proc_chains;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
};

#endif /* UAPI_REBOOT_H */
