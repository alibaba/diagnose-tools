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

#ifndef UAPI_RUN_TRACE_H
#define UAPI_RUN_TRACE_H

#include <linux/ioctl.h>

struct event_common_header {
	int et_type;
	int seq;
	unsigned long id;
	unsigned long delta_ns;
	struct timeval start_tv;
	struct timeval tv;
	struct diag_task_detail task;
};

struct event_start {
	struct event_common_header header;
};

struct event_stop {
	struct event_common_header header;
	unsigned long duration_ns;
};

struct event_stop_raw_stack {
	struct event_common_header header;
	unsigned long duration_ns;
	struct diag_raw_stack_detail raw_stack;
};

struct event_sched_in {
	struct event_common_header header;
	struct diag_kern_stack_detail kern_stack;
};

struct event_sched_wakeup {
	struct event_common_header header;
	struct diag_kern_stack_detail kern_stack;
};

struct event_sched_out {
	struct event_common_header header;
	struct diag_kern_stack_detail kern_stack;
};

struct event_sys_enter {
	struct event_common_header header;
	long syscall_id;
	struct diag_user_stack_detail user_stack;
};

struct event_sys_exit {
	struct event_common_header header;
};

struct event_irq_handler_entry {
	struct event_common_header header;
	int irq;
};

struct event_irq_handler_exit {
	struct event_common_header header;
	int irq;
};

struct event_softirq_entry {
	struct event_common_header header;
	int nr_sirq;
};

struct event_softirq_exit {
	struct event_common_header header;
	int nr_sirq;
};

struct event_timer_expire_entry {
	struct event_common_header header;
	void *func;
};

struct event_timer_expire_exit {
	struct event_common_header header;
	void *func;
};

struct event_run_trace_perf {
	int et_type;
	int seq;
	unsigned long id;
	unsigned long delta_ns;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
};

struct diag_run_trace_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int threshold_us;
	unsigned int timer_us;
	unsigned int buf_size_k;
	int syscall_count;
	int threads_count;
};

struct diag_run_trace_monitor_syscall {
	int pid;
	unsigned int syscall;
	unsigned int threshold;
};

struct diag_run_trace_uprobe {
	unsigned long offset_start;
	unsigned long offset_stop;
	unsigned long tgid;
	unsigned long fd_start, fd_stop;
};

#define CMD_RUN_TRACE_SET (0)
#define CMD_RUN_TRACE_SETTINGS (CMD_RUN_TRACE_SET + 1)
#define CMD_RUN_TRACE_DUMP (CMD_RUN_TRACE_SETTINGS + 1)
#define CMD_RUN_TRACE_START (CMD_RUN_TRACE_DUMP + 1)
#define CMD_RUN_TRACE_STOP (CMD_RUN_TRACE_START + 1)
#define CMD_RUN_TRACE_MONITOR_SYSCALL (CMD_RUN_TRACE_STOP + 1)
#define CMD_RUN_TRACE_CLEAR_SYSCALL (CMD_RUN_TRACE_MONITOR_SYSCALL + 1)
#define CMD_RUN_TRACE_UPROBE (CMD_RUN_TRACE_CLEAR_SYSCALL + 1)
#define DIAG_IOCTL_RUN_TRACE_SET _IOWR(DIAG_IOCTL_TYPE_RUN_TRACE, CMD_RUN_TRACE_SET, struct diag_run_trace_settings)
#define DIAG_IOCTL_RUN_TRACE_SETTINGS _IOWR(DIAG_IOCTL_TYPE_RUN_TRACE, CMD_RUN_TRACE_SETTINGS, struct diag_run_trace_settings)
#define DIAG_IOCTL_RUN_TRACE_DUMP _IOWR(DIAG_IOCTL_TYPE_RUN_TRACE, CMD_RUN_TRACE_DUMP, struct diag_ioctl_dump_param)
#define DIAG_IOCTL_RUN_TRACE_START _IOWR(DIAG_IOCTL_TYPE_RUN_TRACE, CMD_RUN_TRACE_START, int)
#define DIAG_IOCTL_RUN_TRACE_STOP _IO(DIAG_IOCTL_TYPE_RUN_TRACE, CMD_RUN_TRACE_STOP)
#define DIAG_IOCTL_RUN_TRACE_MONITOR_SYSCALL _IOWR(DIAG_IOCTL_TYPE_RUN_TRACE,\
			CMD_RUN_TRACE_MONITOR_SYSCALL, struct diag_run_trace_monitor_syscall)
#define DIAG_IOCTL_RUN_TRACE_CLEAR_SYSCALL _IOWR(DIAG_IOCTL_TYPE_RUN_TRACE, CMD_RUN_TRACE_CLEAR_SYSCALL, int)
#define DIAG_IOCTL_RUN_TRACE_UPROBE _IOWR(DIAG_IOCTL_TYPE_RUN_TRACE,\
			CMD_RUN_TRACE_UPROBE, struct diag_run_trace_uprobe)
#endif /* UAPI_RUN_TRACE_H */
