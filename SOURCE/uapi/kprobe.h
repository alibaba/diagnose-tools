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

#ifndef UAPI_KPROBE_H
#define UAPI_KPROBE_H

#include <linux/ioctl.h>

struct diag_kprobe_settings {
	unsigned int activated;
	unsigned int verbose;
	char cpus[255];
	char comm[TASK_COMM_LEN];
	unsigned int tgid;
	unsigned int pid;
	char func[255];
	unsigned long dump_style;
	unsigned long raw_stack;
	unsigned int sample_step;
};

struct kprobe_detail {
	int et_type;
	struct timeval tv;
	struct diag_proc_chains_detail proc_chains;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
};

struct kprobe_raw_stack_detail {
	int et_type;
	struct timeval tv;
	struct diag_proc_chains_detail proc_chains;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
	struct diag_raw_stack_detail raw_stack;
};

#define CMD_KPROBE_SET (0)
#define CMD_KPROBE_SETTINGS (CMD_KPROBE_SET + 1)
#define CMD_KPROBE_DUMP (CMD_KPROBE_SETTINGS + 1)
#define DIAG_IOCTL_KPROBE_SET _IOWR(DIAG_IOCTL_TYPE_KPROBE, CMD_KPROBE_SET, struct diag_kprobe_settings)
#define DIAG_IOCTL_KPROBE_SETTINGS _IOWR(DIAG_IOCTL_TYPE_KPROBE, CMD_KPROBE_SETTINGS, struct diag_kprobe_settings)
#define DIAG_IOCTL_KPROBE_DUMP _IOWR(DIAG_IOCTL_TYPE_KPROBE, CMD_KPROBE_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_KPROBE_H */
