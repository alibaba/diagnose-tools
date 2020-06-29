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

#ifndef UAPI_MUTEX_MONITOR_H
#define UAPI_MUTEX_MONITOR_H

int mutex_monitor_syscall(struct pt_regs *regs, long id);

//#define DIAG_MUTEX_MONITOR_ACTIVATE (DIAG_BASE_SYSCALL_MUTEX_MONITOR)
//#define DIAG_MUTEX_MONITOR_DEACTIVATE (DIAG_MUTEX_MONITOR_ACTIVATE + 1)
#define DIAG_MUTEX_MONITOR_SET (DIAG_BASE_SYSCALL_MUTEX_MONITOR)
#define DIAG_MUTEX_MONITOR_SETTINGS (DIAG_MUTEX_MONITOR_SET + 1)
#define DIAG_MUTEX_MONITOR_DUMP (DIAG_MUTEX_MONITOR_SETTINGS + 1)
#define DIAG_MUTEX_MONITOR_TEST (DIAG_MUTEX_MONITOR_DUMP + 1)

struct diag_mutex_monitor_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int style;
	unsigned int threshold;
};

struct mutex_monitor_detail {
	int et_type;
	struct timeval tv;
	unsigned long delay_ns;
	void *lock;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
	struct diag_proc_chains_detail proc_chains;
};

#endif /* UAPI_MUTEX_MONITOR_H */
