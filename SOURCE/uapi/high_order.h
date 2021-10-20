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

#ifndef UAPI_HIGH_ORDER_H
#define UAPI_HIGH_ORDER_H

#include <linux/ioctl.h>

int high_order_syscall(struct pt_regs *regs, long id);

//#define DIAG_HIGH_ORDER_ACTIVATE (DIAG_BASE_SYSCALL_HIGH_ORDER)
//#define DIAG_HIGH_ORDER_DEACTIVATE (DIAG_HIGH_ORDER_ACTIVATE + 1)
#define DIAG_HIGH_ORDER_SET (DIAG_BASE_SYSCALL_HIGH_ORDER)
#define DIAG_HIGH_ORDER_SETTINGS (DIAG_HIGH_ORDER_SET + 1)
#define DIAG_HIGH_ORDER_DUMP (DIAG_HIGH_ORDER_SETTINGS + 1)
#define DIAG_HIGH_ORDER_TEST (DIAG_HIGH_ORDER_DUMP + 1)

struct diag_high_order_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int order;
};

struct high_order_detail {
	int et_type;
	unsigned long id;
	unsigned long seq;
	struct diag_timespec tv;
	int order;
	struct diag_proc_chains_detail proc_chains;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
};

#define CMD_HIGH_ORDER_SET (0)
#define CMD_HIGH_ORDER_SETTINGS (CMD_HIGH_ORDER_SET + 1)
#define CMD_HIGH_ORDER_DUMP (CMD_HIGH_ORDER_SETTINGS + 1)
#define CMD_HIGH_ORDER_TEST (CMD_HIGH_ORDER_DUMP + 1)
#define DIAG_IOCTL_HIGH_ORDER_SET _IOWR(DIAG_IOCTL_TYPE_HIGH_ORDER, CMD_HIGH_ORDER_SET, struct diag_high_order_settings)
#define DIAG_IOCTL_HIGH_ORDER_SETTINGS _IOWR(DIAG_IOCTL_TYPE_HIGH_ORDER, CMD_HIGH_ORDER_SETTINGS, struct diag_high_order_settings)
#define DIAG_IOCTL_HIGH_ORDER_DUMP _IOWR(DIAG_IOCTL_TYPE_HIGH_ORDER, CMD_HIGH_ORDER_DUMP, struct diag_ioctl_dump_param)
#define DIAG_IOCTL_HIGH_ORDER_TEST _IOWR(DIAG_IOCTL_TYPE_HIGH_ORDER, CMD_HIGH_ORDER_TEST, int)

#endif /* UAPI_HIGH_ORDER_H */
