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

#ifndef UAPI_RW_SEM_H
#define UAPI_RW_SEM_H

#include <linux/ioctl.h>

int rw_sem_syscall(struct pt_regs *regs, long id);

//#define DIAG_RW_SEM_ACTIVATE (DIAG_BASE_SYSCALL_RW_SEM)
//#define DIAG_RW_SEM_DEACTIVATE (DIAG_RW_SEM_ACTIVATE + 1)
#define DIAG_RW_SEM_SET (DIAG_BASE_SYSCALL_RW_SEM)
#define DIAG_RW_SEM_SETTINGS (DIAG_RW_SEM_SET + 1)
#define DIAG_RW_SEM_DUMP (DIAG_RW_SEM_SETTINGS + 1)
#define DIAG_RW_SEM_TEST (DIAG_RW_SEM_DUMP + 1)

struct diag_rw_sem_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int style;
	unsigned int threshold;
};

struct rw_sem_detail {
	int et_type;
	struct diag_timespec tv;
	unsigned long delay_ns;
	void *lock;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
	struct diag_proc_chains_detail proc_chains;
};


#define CMD_RW_SEM_SET (0)
#define CMD_RW_SEM_SETTINGS (CMD_RW_SEM_SET + 1)
#define CMD_RW_SEM_DUMP (CMD_RW_SEM_SETTINGS + 1)
#define CMD_RW_SEM_TEST (CMD_RW_SEM_DUMP + 1)
#define DIAG_IOCTL_RW_SEM_SET _IOWR(DIAG_IOCTL_TYPE_RW_SEM, CMD_RW_SEM_SET, struct diag_rw_sem_settings)
#define DIAG_IOCTL_RW_SEM_SETTINGS _IOWR(DIAG_IOCTL_TYPE_RW_SEM, CMD_RW_SEM_SETTINGS, struct diag_rw_sem_settings)
#define DIAG_IOCTL_RW_SEM_DUMP _IOWR(DIAG_IOCTL_TYPE_RW_SEM, CMD_RW_SEM_DUMP, struct diag_ioctl_dump_param)
#define DIAG_IOCTL_RW_SEM_TEST _IOWR(DIAG_IOCTL_TYPE_RW_SEM, CMD_RW_SEM_TEST, int)

#endif /* UAPI_RW_SEM_H */
