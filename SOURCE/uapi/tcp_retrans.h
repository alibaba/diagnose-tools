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

#ifndef UAPI_TCP_RETRANS_H
#define UAPI_TCP_RETRANS_H

#include <linux/ioctl.h>

struct diag_tcp_retrans_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int saddr;
	unsigned int sport;
	unsigned int daddr;
	unsigned int dport;
};

struct tcp_retrans_summary {
	int et_type;
	unsigned long alloc_count;
	unsigned long nr_tcp_retransmit_skb;
	unsigned long nr_tcp_rtx_synack;
	unsigned long tcp_dupack;
	unsigned long tcp_send_dupack;
};

struct tcp_retrans_detail {
	int et_type;
	int src_addr;
	int src_port;
	int dest_addr;
	int dest_port;
	int syncack_count;
	int skb_count;
};

struct tcp_retrans_trace {
	int et_type;
	int src_addr;
	int src_port;
	int dest_addr;
	int dest_port;
	int sync_or_skb;
	struct timeval tv;
};

#define CMD_TCP_RETRANS_SET (0)
#define CMD_TCP_RETRANS_SETTINGS (CMD_TCP_RETRANS_SET + 1)
#define CMD_TCP_RETRANS_DUMP (CMD_TCP_RETRANS_SETTINGS + 1)
#define DIAG_IOCTL_TCP_RETRANS_SET _IOWR(DIAG_IOCTL_TYPE_TCP_RETRANS, CMD_TCP_RETRANS_SET, struct diag_tcp_retrans_settings)
#define DIAG_IOCTL_TCP_RETRANS_SETTINGS _IOWR(DIAG_IOCTL_TYPE_TCP_RETRANS, CMD_TCP_RETRANS_SETTINGS, struct diag_tcp_retrans_settings)
#define DIAG_IOCTL_TCP_RETRANS_SET_DUMP _IOWR(DIAG_IOCTL_TYPE_TCP_RETRANS, CMD_TCP_RETRANS_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_TCP_RETRANS_H */
