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

#ifndef UAPI_DROP_PACKET_H
#define UAPI_DROP_PACKET_H

#include <linux/ioctl.h>

int drop_packet_syscall(struct pt_regs *regs, long id);

enum pk_direction {
	IN,
	OUT
};

enum packet_step
{
	ETH_RECV,
	GRO_RECV,
	GRO_RECV_ERR,
	RECV_SKB,
	RECV_SKB_DROP,
	IP_RCV,
	IP_RCV_FINISH,
	DST_INPUT,
	LOCAL_DELIVER,
	LOCAL_DELIVER_FINISH,
	UDP_RCV,
	TCP_V4_RCV,
	RCV_STEP = TCP_V4_RCV,
	SEND_SKB,
	TRACK_COUNT,
};

static __attribute__((unused)) const char *packet_steps_str[TRACK_COUNT] = {
	"ETH_RECV",
	"GRO_RECV",
	"GRO_RECV_ERR",
	"RECV_SKB",
	"RECV_SKB_DROP",
	"IP_RCV",
	"IP_RCV_FINISH",
	"DST_INPUT",
	"LOCAL_DELIVER",
	"LOCAL_DELIVER_FINISH",
	"UDP_RCV",
	"TCP_V4_RCV",
	"SEND_SKB",
};

#define DIAG_DROP_PACKET_SET (DIAG_BASE_SYSCALL_DROP_PACKET)
#define DIAG_DROP_PACKET_SETTINGS (DIAG_DROP_PACKET_SET + 1)
#define DIAG_DROP_PACKET_DUMP (DIAG_DROP_PACKET_SETTINGS + 1)

#define DIAG_IPPROTO_TCP 6
#define DIAG_IPPROTO_UDP 17

struct diag_drop_packet_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int saddr;
	unsigned int sport;
	unsigned int daddr;
	unsigned int dport;
	unsigned int arrange_by_peer;
};

struct drop_packet_detail {
	int et_type;
	int protocol;
	int saddr;
	int sport;
	int daddr;
	int dport;
	unsigned long packages[TRACK_COUNT];
	unsigned long sum_truesize[TRACK_COUNT];
	unsigned long sum_len[TRACK_COUNT];
	unsigned long sum_datalen[TRACK_COUNT];
};

#define CMD_DROP_PACKET_SET (0)
#define CMD_DROP_PACKET_SETTINGS (CMD_DROP_PACKET_SET + 1)
#define CMD_DROP_PACKET_DUMP (CMD_DROP_PACKET_SETTINGS + 1)
#define DIAG_IOCTL_DROP_PACKET_SET _IOWR(DIAG_IOCTL_TYPE_DROP_PACKET, CMD_DROP_PACKET_SET, struct diag_drop_packet_settings)
#define DIAG_IOCTL_DROP_PACKET_SETTINGS _IOWR(DIAG_IOCTL_TYPE_DROP_PACKET, CMD_DROP_PACKET_SETTINGS, struct diag_drop_packet_settings)
#define DIAG_IOCTL_DROP_PACKET_DUMP _IOWR(DIAG_IOCTL_TYPE_DROP_PACKET, CMD_DROP_PACKET_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_DROP_PACKET_H */
