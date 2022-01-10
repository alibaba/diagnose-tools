/*
 * Linux内核诊断工具--用户接口API
 * 
 * Copyright (C) 2022 Alibaba Ltd.
 *
 * 作者: Yang Wei <albin.yangwei@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef UAPI_TCP_CONNECT_H
#define UAPI_TCP_CONNECT_H

#include <linux/ioctl.h>
int tcp_connect_syscall(struct pt_regs *regs, long id);

#define DIAG_TCP_CONNECT_SET (DIAG_BASE_SYSCALL_TCP_CONNECT)
#define DIAG_TCP_CONNECT_SETTINGS (DIAG_TCP_CONNECT_SET + 1)
#define DIAG_TCP_CONNECT_DUMP (DIAG_TCP_CONNECT_SETTINGS + 1)

struct diag_tcp_connect_settings {
	unsigned int activated;
	unsigned int verbose;
};

enum connect_type {
	TCPCONNECT = 1,
	TCPACCEPT = 2,
	TCPCLOSE = 3,
};

struct tcp_connect_detail {
	int et_type;
	enum connect_type con_type;
	struct diag_timespec tv;
	unsigned int laddr;
	unsigned int raddr;
	unsigned short lport;
	unsigned short rport;
	char comm[TASK_COMM_LEN];
	char cgroup[CGROUP_NAME_LEN];
};

#define CMD_TCP_CONNECT_SET (0)
#define CMD_TCP_CONNECT_SETTINGS (CMD_TCP_CONNECT_SET + 1)
#define CMD_TCP_CONNECT_DUMP (CMD_TCP_CONNECT_SETTINGS + 1)
#define DIAG_IOCTL_TCP_CONNECT_SET _IOWR(DIAG_IOCTL_TYPE_TCP_CONNECT, CMD_TCP_CONNECT_SET, struct diag_tcp_connect_settings)
#define DIAG_IOCTL_TCP_CONNECT_SETTINGS _IOWR(DIAG_IOCTL_TYPE_TCP_CONNECT, CMD_TCP_CONNECT_SETTINGS, struct diag_tcp_connect_settings)
#define DIAG_IOCTL_TCP_CONNECT_SET_DUMP _IOWR(DIAG_IOCTL_TYPE_TCP_CONNECT, CMD_TCP_CONNECT_DUMP, struct diag_ioctl_dump_param)

#endif

