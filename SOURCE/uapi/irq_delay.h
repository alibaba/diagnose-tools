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

#ifndef UAPI_IRQ_DELAY_H
#define UAPI_IRQ_DELAY_H

#include <linux/ioctl.h>

int irq_delay_syscall(struct pt_regs *regs, long id);

//#define DIAG_IRQ_DELAY_ACTIVATE (DIAG_BASE_SYSCALL_IRQ_DELAY)
//#define DIAG_IRQ_DELAY_DEACTIVATE (DIAG_IRQ_DELAY_ACTIVATE + 1)
#define DIAG_IRQ_DELAY_SET (DIAG_BASE_SYSCALL_IRQ_DELAY)
#define DIAG_IRQ_DELAY_SETTINGS (DIAG_IRQ_DELAY_SET + 1)
#define DIAG_IRQ_DELAY_DUMP (DIAG_IRQ_DELAY_SETTINGS + 1)
#define DIAG_IRQ_DELAY_TEST (DIAG_IRQ_DELAY_DUMP + 1)

struct diag_irq_delay_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int threshold;
};

struct irq_delay_detail {
	int et_type;
	struct timeval tv;
	int cpu;
	unsigned long delay_ns;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
};

#define CMD_IRQ_DELAY_SET (0)
#define CMD_IRQ_DELAY_SETTINGS (CMD_IRQ_DELAY_SET + 1)
#define CMD_IRQ_DELAY_DUMP (CMD_IRQ_DELAY_SETTINGS + 1)
#define CMD_IRQ_DELAY_TEST (CMD_IRQ_DELAY_DUMP + 1)
#define DIAG_IOCTL_IRQ_DELAY_SET _IOWR(DIAG_IOCTL_TYPE_IRQ_DELAY, CMD_IRQ_DELAY_SET, struct diag_irq_delay_settings)
#define DIAG_IOCTL_IRQ_DELAY_SETTINGS _IOWR(DIAG_IOCTL_TYPE_IRQ_DELAY, CMD_IRQ_DELAY_SETTINGS, struct diag_irq_delay_settings)
#define DIAG_IOCTL_IRQ_DELAY_DUMP _IOWR(DIAG_IOCTL_TYPE_IRQ_DELAY, CMD_IRQ_DELAY_DUMP, struct diag_ioctl_dump_param)
#define DIAG_IOCTL_IRQ_DELAY_TEST _IOWR(DIAG_IOCTL_TYPE_IRQ_DELAY, CMD_IRQ_DELAY_TEST, int)

#endif /* UAPI_IRQ_DELAY_H */
