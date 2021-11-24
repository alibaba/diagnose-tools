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

int mm_leak_syscall(struct pt_regs *regs, long id);

#define DIAG_MM_LEAK_DUMP (DIAG_BASE_SYSCALL_MM_LEAK)
#define DIAG_MM_LEAK_SETTINGS (DIAG_MM_LEAK_DUMP + 1)
#define DIAG_MM_LEAK_SET (DIAG_MM_LEAK_SETTINGS + 1)

struct diag_mm_leak_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned long time_threshold;
	unsigned int max_bytes;
	unsigned int min_bytes;
};

struct mm_leak_detail {
	int et_type;
	struct diag_timespec tv;
	int seq;
	unsigned long id;
	void *addr;
	size_t bytes_req;
	size_t bytes_alloc;
	unsigned long delta_time;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
};

#define CMD_MM_LEAK_DUMP (0)
#define CMD_MM_LEAK_SETTINGS (CMD_MM_LEAK_DUMP + 1)
#define CMD_MM_LEAK_SET (CMD_MM_LEAK_SETTINGS + 1)
#define DIAG_IOCTL_MM_LEAK_SETTINGS _IOWR(DIAG_IOCTL_TYPE_MM_LEAK, CMD_MM_LEAK_SETTINGS, struct diag_mm_leak_settings)
#define DIAG_IOCTL_MM_LEAK_DUMP _IOWR(DIAG_IOCTL_TYPE_MM_LEAK, CMD_MM_LEAK_DUMP, struct diag_ioctl_dump_param)
#define DIAG_IOCTL_MM_LEAK_SET _IOWR(DIAG_IOCTL_TYPE_MM_LEAK, CMD_MM_LEAK_SET, struct diag_mm_leak_settings)

#endif /* UAPI_MM_LEAK_H */
