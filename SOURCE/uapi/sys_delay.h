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

#ifndef UAPI_SYS_DELAY_H
#define UAPI_SYS_DELAY_H

#include <linux/ioctl.h>

int sys_delay_syscall(struct pt_regs *regs, long id);

//#define DIAG_SYS_DELAY_ACTIVATE (DIAG_BASE_SYSCALL_SYS_DELAY)
//#define DIAG_SYS_DELAY_DEACTIVATE (DIAG_SYS_DELAY_ACTIVATE + 1)
#define DIAG_SYS_DELAY_SET (DIAG_BASE_SYSCALL_SYS_DELAY)
#define DIAG_SYS_DELAY_SETTINGS (DIAG_SYS_DELAY_SET + 1)
#define DIAG_SYS_DELAY_DUMP (DIAG_SYS_DELAY_SETTINGS + 1)
#define DIAG_SYS_DELAY_TEST (DIAG_SYS_DELAY_DUMP + 1)

struct diag_sys_delay_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int style;
	unsigned int threshold_ms;
};

struct sys_delay_detail {
	int et_type;
	struct timeval tv;
	unsigned long delay_ns;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
	struct diag_proc_chains_detail proc_chains;
	struct diag_raw_stack_detail raw_stack;
};

#define CMD_SYS_DELAY_SET (0)
#define CMD_SYS_DELAY_SETTINGS (CMD_SYS_DELAY_SET + 1)
#define CMD_SYS_DELAY_DUMP (CMD_SYS_DELAY_SETTINGS + 1)
#define CMD_SYS_DELAY_TEST (CMD_SYS_DELAY_DUMP + 1)
#define DIAG_IOCTL_SYS_DELAY_SET _IOWR(DIAG_IOCTL_TYPE_SYS_DELAY, CMD_SYS_DELAY_SET, struct diag_sys_delay_settings)
#define DIAG_IOCTL_SYS_DELAY_SETTINGS _IOWR(DIAG_IOCTL_TYPE_SYS_DELAY, CMD_SYS_DELAY_SETTINGS, struct diag_sys_delay_settings)
#define DIAG_IOCTL_SYS_DELAY_DUMP _IOWR(DIAG_IOCTL_TYPE_SYS_DELAY, CMD_SYS_DELAY_DUMP, struct diag_ioctl_dump_param)
#define DIAG_IOCTL_SYS_DELAY_TEST _IOWR(DIAG_IOCTL_TYPE_SYS_DELAY, CMD_SYS_DELAY_TEST, int)

#endif /* UAPI_SYS_DELAY_H */
