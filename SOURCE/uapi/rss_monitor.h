/*
* Linux内核诊断工具--用户接口API
*
* Copyright (C) 2020 Alibaba Ltd.
*
* 作者: Jiyun Fan <fanjiyun.fjy@alibaba-inc.com>
*
* License terms: GNU General Public License (GPL) version 3
*
*/
#ifndef UAPI_RSS_MONITOR_H
#define UAPI_RSS_MONITOR_H

#include <linux/ioctl.h>

int rss_monitor_syscall(struct pt_regs *regs, long id);

#define DIAG_RSS_MONITOR_SET (DIAG_BASE_SYSCALL_RSS_MONITOR)
#define DIAG_RSS_MONITOR_SETTINGS (DIAG_RSS_MONITOR_SET + 1)
#define DIAG_RSS_MONITOR_DUMP (DIAG_RSS_MONITOR_SETTINGS + 1)

struct diag_rss_monitor_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int tgid;
	unsigned int pid;
	unsigned long time_threshold;
	unsigned long raw_stack;
};

struct rss_monitor_detail {
	int et_type;
	unsigned long addr;
	unsigned long alloc_len;
	unsigned long  delta_time;
	struct diag_timespec tv;
	struct diag_task_detail task;
	//struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
};

struct rss_monitor_raw_stack_detail {
	int et_type;
	unsigned long addr;
	unsigned long alloc_len;
	unsigned long  delta_time;
	struct diag_timespec tv;
	struct diag_task_detail task;
	//struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
	struct diag_raw_stack_detail raw_stack;
};

#define CMD_RSS_MONITOR_SET (0)
#define CMD_RSS_MONITOR_SETTINGS (CMD_RSS_MONITOR_SET + 1)
#define CMD_RSS_MONITOR_DUMP (CMD_RSS_MONITOR_SETTINGS + 1)
#define DIAG_IOCTL_RSS_MONITOR_SET _IOWR(DIAG_IOCTL_TYPE_RSS_MONITOR, CMD_RSS_MONITOR_SET, struct diag_rss_monitor_settings)
#define DIAG_IOCTL_RSS_MONITOR_SETTINGS _IOWR(DIAG_IOCTL_TYPE_RSS_MONITOR, CMD_RSS_MONITOR_SETTINGS, struct diag_rss_monitor_settings)
#define DIAG_IOCTL_RSS_MONITOR_DUMP _IOWR(DIAG_IOCTL_TYPE_RSS_MONITOR, CMD_RSS_MONITOR_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_RSS_MONITOR_H */
