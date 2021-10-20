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

#ifndef UAPI_IRQ_TRACE_H
#define UAPI_IRQ_TRACE_H

#include <linux/ioctl.h>

int irq_trace_syscall(struct pt_regs *regs, long id);

//#define DIAG_IRQ_TRACE_ACTIVATE (DIAG_BASE_SYSCALL_IRQ_TRACE)
//#define DIAG_IRQ_TRACE_DEACTIVATE (DIAG_IRQ_TRACE_ACTIVATE + 1)
#define DIAG_IRQ_TRACE_SET (DIAG_BASE_SYSCALL_IRQ_TRACE)
#define DIAG_IRQ_TRACE_SETTINGS (DIAG_IRQ_TRACE_SET + 1)
#define DIAG_IRQ_TRACE_DUMP (DIAG_IRQ_TRACE_SETTINGS + 1)

struct diag_irq_trace_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned long threshold_irq, threshold_sirq, threshold_timer;
};

struct irq_trace_detail {
	int et_type;
	struct diag_timespec tv;
	int cpu;
	int source;
	void *func;
	unsigned long time;
};

struct irq_trace_sum {
	int et_type;
	struct diag_timespec tv;
	unsigned long irq_count;
	unsigned long irq_runs;
	unsigned long sirq_count[DIAG_NR_SOFTIRQS];
	unsigned long sirq_runs[DIAG_NR_SOFTIRQS];
	unsigned long timer_count;
	unsigned long timer_runs;
};

#define CMD_IRQ_TRACE_SET (0)
#define CMD_IRQ_TRACE_SETTINGS (CMD_IRQ_TRACE_SET + 1)
#define CMD_IRQ_TRACE_DUMP (CMD_IRQ_TRACE_SETTINGS + 1)
#define DIAG_IOCTL_IRQ_TRACE_SET _IOWR(DIAG_IOCTL_TYPE_IRQ_TRACE, CMD_IRQ_TRACE_SET, struct diag_irq_trace_settings)
#define DIAG_IOCTL_IRQ_TRACE_SETTINGS _IOWR(DIAG_IOCTL_TYPE_IRQ_TRACE, CMD_IRQ_TRACE_SETTINGS, struct diag_irq_trace_settings)
#define DIAG_IOCTL_IRQ_TRACE_DUMP _IOWR(DIAG_IOCTL_TYPE_IRQ_TRACE, CMD_IRQ_TRACE_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_IRQ_TRACE_H */
