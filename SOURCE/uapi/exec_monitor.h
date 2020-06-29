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

#ifndef UAPI_EXEC_MONITOR_H
#define UAPI_EXEC_MONITOR_H

int exec_monitor_syscall(struct pt_regs *regs, long id);

//#define DIAG_EXEC_MONITOR_ACTIVATE (DIAG_BASE_SYSCALL_EXEC_MONITOR)
//#define DIAG_EXEC_MONITOR_DEACTIVATE (DIAG_EXEC_MONITOR_ACTIVATE + 1)
#define DIAG_EXEC_MONITOR_SET (DIAG_BASE_SYSCALL_EXEC_MONITOR)
#define DIAG_EXEC_MONITOR_SETTINGS (DIAG_EXEC_MONITOR_SET + 1)
#define DIAG_EXEC_MONITOR_DUMP (DIAG_EXEC_MONITOR_SETTINGS + 1)

struct diag_exec_monitor_settings {
	unsigned int activated;
	unsigned int verbose;
};

struct exec_monitor_detail {
	int et_type;
	struct timeval tv;
	char filename[256];
	struct diag_proc_chains_detail proc_chains;
	struct diag_task_detail task;
};

#endif /* UAPI_EXEC_MONITOR_H */
