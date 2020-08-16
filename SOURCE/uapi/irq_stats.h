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

#ifndef UAPI_IRQ_STATS_H
#define UAPI_IRQ_STATS_H

#include <linux/ioctl.h>

int irq_stats_syscall(struct pt_regs *regs, long id);

//#define DIAG_IRQ_STATS_ACTIVATE (DIAG_BASE_SYSCALL_IRQ_STATS)
//#define DIAG_IRQ_STATS_DEACTIVATE (DIAG_IRQ_STATS_ACTIVATE + 1)
#define DIAG_IRQ_STATS_SET (DIAG_BASE_SYSCALL_IRQ_STATS)
#define DIAG_IRQ_STATS_SETTINGS (DIAG_IRQ_STATS_SET + 1)
#define DIAG_IRQ_STATS_DUMP (DIAG_IRQ_STATS_SETTINGS + 1)

struct diag_irq_stats_settings {
	unsigned int activated;
	unsigned int verbose;
};

struct irq_stats_header {
	int et_type;
	unsigned long id;
	struct timeval tv;
};

struct irq_stats_irq_summary {
	int et_type;
	int cpu;
	unsigned long id;
	unsigned long irq_cnt;
	unsigned long irq_run_total;
	unsigned long max_irq;
	unsigned long max_irq_time;
};

struct irq_stats_irq_detail {
	int et_type;
	int cpu;
	unsigned long id;
	unsigned int		irq;
	void *handler;
	unsigned long irq_cnt;
	unsigned long irq_run_total;
};

struct irq_stats_softirq_summary {
	int et_type;
	int cpu;
	unsigned long id;
	unsigned long softirq_cnt[DIAG_NR_SOFTIRQS];
	unsigned long softirq_cnt_d[DIAG_NR_SOFTIRQS];
    unsigned long sortirq_run_total[DIAG_NR_SOFTIRQS];
	unsigned long sortirq_run_total_d[DIAG_NR_SOFTIRQS];
};

struct irq_stats_timer_summary {
	int et_type;
	int cpu;
	unsigned long id;
	unsigned long timer_cnt;
    unsigned long timer_run_total;
	void *max_func;
    unsigned long max_time;
};

#define CMD_IRQ_STATS_SET (0)
#define CMD_IRQ_STATS_SETTINGS (CMD_IRQ_STATS_SET + 1)
#define CMD_IRQ_STATS_DUMP (CMD_IRQ_STATS_SETTINGS + 1)
#define DIAG_IOCTL_IRQ_STATS_SET _IOWR(DIAG_IOCTL_TYPE_IRQ_STATS, CMD_IRQ_STATS_SET, struct diag_irq_stats_settings)
#define DIAG_IOCTL_IRQ_STATS_SETTINGS _IOWR(DIAG_IOCTL_TYPE_IRQ_STATS, CMD_IRQ_STATS_SETTINGS, struct diag_irq_stats_settings)
#define DIAG_IOCTL_IRQ_STATS_DUMP _IOWR(DIAG_IOCTL_TYPE_IRQ_STATS, CMD_IRQ_STATS_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_IRQ_STATS_H */
