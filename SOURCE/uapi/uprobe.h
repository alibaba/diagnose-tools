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

#ifndef UAPI_UPROBE_H
#define UAPI_UPROBE_H

int uprobe_syscall(struct pt_regs *regs, long id);

#define DIAG_UPROBE_SET (DIAG_BASE_SYSCALL_UPROBE)
#define DIAG_UPROBE_SETTINGS (DIAG_UPROBE_SET + 1)
#define DIAG_UPROBE_DUMP (DIAG_UPROBE_SETTINGS + 1)

struct diag_uprobe_param_define {
	char param_name[255];
	/**
	 * 1~5
	 */
	unsigned long param_idx;
	/**
	 * 0 -> 未定义
	 * 1 -> int
	 * 2 -> string
	 * 3 -> memory
	 */
	unsigned long type;
	/**
	 * -1~-5 -> 由参数来决定其长度
	 * -255 -> 自动探测字符串长度
	 * 正数 -> 固定大小
	 */
	signed long size;
};

struct diag_uprobe_param_value {
	unsigned long type;
	union {
		unsigned long int_value;
		struct {
			unsigned long len;
			char data[255];
		} buf;
	};
};

struct diag_uprobe_settings {
	unsigned int activated;
	unsigned int verbose;
	char cpus[255];
	char comm[255];
	unsigned int tgid;
	unsigned int pid;
	char file_name[255];
	int fd;
	unsigned int offset;
	struct diag_uprobe_param_define params[DIAG_UPROBE_MAX_PARAMS];
};

struct uprobe_detail {
	int et_type;
	struct timeval tv;
	struct diag_proc_chains_detail proc_chains;
	struct diag_task_detail task;
	struct diag_user_stack_detail user_stack;
	struct diag_uprobe_param_value values[DIAG_UPROBE_MAX_PARAMS];
};

struct uprobe_raw_stack_detail {
	int et_type;
	struct timeval tv;
	struct diag_proc_chains_detail proc_chains;
	struct diag_task_detail task;
	struct diag_user_stack_detail user_stack;
	struct diag_raw_stack_detail raw_stack;
	struct diag_uprobe_param_value values[DIAG_UPROBE_MAX_PARAMS];
};
#endif /* UAPI_UPROBE_H */
