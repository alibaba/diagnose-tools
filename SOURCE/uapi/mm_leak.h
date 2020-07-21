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

#ifndef UAPI_MM_LEAK_H
#define UAPI_MM_LEAK_H

#include <linux/ioctl.h>

struct diag_mm_leak_settings {
	unsigned int activated;
	unsigned int verbose;
};

struct mm_leak_detail {
	int et_type;
	struct timeval tv;
	int seq;
	unsigned long id;
	struct diag_kern_stack_detail kern_stack;
};

#define CMD_MM_LEAK_VERBOSE (0)
#define CMD_MM_LEAK_THRESHOLD_LOAD (CMD_MM_LEAK_VERBOSE + 1)
#define CMD_MM_LEAK_THRESHOLD_LOAD_R (CMD_MM_LEAK_THRESHOLD_LOAD + 1)
#define CMD_MM_LEAK_THRESHOLD_LOAD_D (CMD_MM_LEAK_THRESHOLD_LOAD_R + 1)
#define CMD_MM_LEAK_THRESHOLD_TASK_D (CMD_MM_LEAK_THRESHOLD_LOAD_D + 1)
#define CMD_MM_LEAK_DUMP (CMD_MM_LEAK_THRESHOLD_TASK_D + 1)
#define CMD_MM_LEAK_SETTINGS (CMD_MM_LEAK_DUMP + 1)
#define DIAG_IOCTL_MM_LEAK_VERBOSE _IOWR(DIAG_IOCTL_TYPE_MM_LEAK, CMD_MM_LEAK_VERBOSE, unsigned int)
#define DIAG_IOCTL_MM_LEAK_SETTINGS _IOWR(DIAG_IOCTL_TYPE_MM_LEAK, CMD_MM_LEAK_SETTINGS, struct diag_mm_leak_settings)
#define DIAG_IOCTL_MM_LEAK_DUMP _IOWR(DIAG_IOCTL_TYPE_MM_LEAK, CMD_MM_LEAK_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_MM_LEAK_H */
