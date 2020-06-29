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

int kprobe_syscall(struct pt_regs *regs, long id);

//#define DIAG_KPROBE_ACTIVATE (DIAG_BASE_SYSCALL_KPROBE)
//#define DIAG_KPROBE_DEACTIVATE (DIAG_KPROBE_ACTIVATE + 1)
#define DIAG_KPROBE_SET (DIAG_BASE_SYSCALL_KPROBE)
#define DIAG_KPROBE_SETTINGS (DIAG_KPROBE_SET + 1)
#define DIAG_KPROBE_DUMP (DIAG_KPROBE_SETTINGS + 1)

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
#endif /* UAPI_KPROBE_H */
