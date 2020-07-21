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

#include <linux/ioctl.h>

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


#define CMD_MUTEX_MONITOR_SET (0)
#define CMD_MUTEX_MONITOR_SETTINGS (CMD_MUTEX_MONITOR_SET + 1)
#define CMD_MUTEX_MONITOR_DUMP (CMD_MUTEX_MONITOR_SETTINGS + 1)
#define CMD_MUTEX_MONITOR_TEST (CMD_MUTEX_MONITOR_DUMP + 1)
#define DIAG_IOCTL_MUTEX_MONITOR_SET _IOWR(DIAG_IOCTL_TYPE_MUTEX_MONITOR, CMD_MUTEX_MONITOR_SET, struct diag_mutex_monitor_settings)
#define DIAG_IOCTL_MUTEX_MONITOR_SETTINGS _IOWR(DIAG_IOCTL_TYPE_MUTEX_MONITOR, CMD_MUTEX_MONITOR_SETTINGS, struct diag_mutex_monitor_settings)
#define DIAG_IOCTL_MUTEX_MONITOR_DUMP _IOWR(DIAG_IOCTL_TYPE_MUTEX_MONITOR, CMD_MUTEX_MONITOR_DUMP, struct diag_ioctl_dump_param)
#define DIAG_IOCTL_MUTEX_MONITOR_TEST _IOWR(DIAG_IOCTL_TYPE_MUTEX_MONITOR, CMD_MUTEX_MONITOR_TEST, int)

#endif /* UAPI_MUTEX_MONITOR_H */
