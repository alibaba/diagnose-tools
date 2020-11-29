/*
 * Linux内核诊断工具--用户接口API
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 * 作者: Wllabs <wllabs@163.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef UAPI_NET_BANDWIDTH_H
#define UAPI_NET_BANDWIDTH_H

#include <linux/ioctl.h>

int net_bandwidth_syscall(struct pt_regs *regs, long id);

enum net_direction {
	NET_IN,
	NET_OUT
};

enum net_bandwidth_step
{
	NET_RECV_SKB,
	NET_SEND_SKB,
	NET_COUNT,
};

#define DIAG_NET_BANDWIDTH_SET (DIAG_BASE_SYSCALL_NET_BANDWIDTH)
#define DIAG_NET_BANDWIDTH_SETTINGS (DIAG_NET_BANDWIDTH_SET + 1)
#define DIAG_NET_BANDWIDTH_DUMP (DIAG_NET_BANDWIDTH_SETTINGS + 1)

#define DIAG_IPPROTO_TCP 6
#define DIAG_IPPROTO_UDP 17

struct diag_net_bandwidth_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int saddr;
	unsigned int sport;
	unsigned int daddr;
	unsigned int dport;
	unsigned int arrange_by_peer;
};

struct net_bandwidth_detail {
	int et_type;
	int protocol;
	int saddr;
	int sport;
	int daddr;
	int dport;
	unsigned long packages[NET_COUNT];
	unsigned long sum_truesize[NET_COUNT];
};

#define CMD_NET_BANDWIDTH_SET (0)
#define CMD_NET_BANDWIDTH_SETTINGS (CMD_NET_BANDWIDTH_SET + 1)
#define CMD_NET_BANDWIDTH_DUMP (CMD_NET_BANDWIDTH_SETTINGS + 1)
#define DIAG_IOCTL_NET_BANDWIDTH_SET _IOWR(DIAG_IOCTL_TYPE_NET_BANDWIDTH, CMD_NET_BANDWIDTH_SET, struct diag_net_bandwidth_settings)
#define DIAG_IOCTL_NET_BANDWIDTH_SETTINGS _IOWR(DIAG_IOCTL_TYPE_NET_BANDWIDTH, CMD_NET_BANDWIDTH_SETTINGS, struct diag_net_bandwidth_settings)
#define DIAG_IOCTL_NET_BANDWIDTH_DUMP _IOWR(DIAG_IOCTL_TYPE_NET_BANDWIDTH, CMD_NET_BANDWIDTH_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_NET_BANDWIDTH_H */
