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

#ifndef UAPI_PING_DELAY_H
#define UAPI_PING_DELAY_H

#define DIAG_PING_DELAY_SET (DIAG_BASE_SYSCALL_PING_DELAY)
#define DIAG_PING_DELAY_SETTINGS (DIAG_PING_DELAY_SET + 1)
#define DIAG_PING_DELAY_DUMP (DIAG_PING_DELAY_SETTINGS + 1)

enum ping_delay_packet_step
{
	PD_ETH_RECV,
	PD_GRO_RECV,
	PD_GRO_RECV_ERR,
	PD_RECV_SKB,
	PD_RECV_SKB_DROP,
	PD_IP_RCV,
	PD_IP_RCV_FINISH,
	PD_DST_INPUT,
	PD_LOCAL_DELIVER,
	PD_LOCAL_DELIVER_FINISH,
	PD_ICMP_RCV,
	PD_RCV_STEP = PD_ICMP_RCV,
	PD_SEND_SKB,
	PD_TRACK_COUNT,
};

#ifndef __maybe_unused
# define __maybe_unused		__attribute__((unused))
#endif

__maybe_unused static const char *ping_delay_packet_steps_str[PD_TRACK_COUNT] = {
	"PD_ETH_RECV",
	"PD_GRO_RECV",
	"PD_GRO_RECV_ERR",
	"PD_RECV_SKB",
	"PD_RECV_SKB_DROP",
	"PD_IP_RCV",
	"PD_IP_RCV_FINISH",
	"PD_DST_INPUT",
	"PD_LOCAL_DELIVER",
	"PD_LOCAL_DELIVER_FINISH",
	"PD_ICMP_RCV",
	"PD_SEND_SKB",
};

enum {
	ping_delay_event_enter_irq,
	ping_delay_event_exit_irq,
	ping_delay_event_enter_softirq,
	ping_delay_event_exit_softirq,
};

struct diag_ping_delay_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int addr;
};

struct ping_delay_summary {
	int et_type;
	struct timeval tv;
	int saddr;
	int daddr;
	int echo_id;
	int echo_sequence;
	unsigned long time_stamp[PD_TRACK_COUNT];
};

struct ping_delay_detail {
	int et_type;
	struct timeval tv;
	int saddr;
	int daddr;
	int echo_id;
	int echo_sequence;
	unsigned int step;
};

struct ping_delay_event {
	int et_type;
	struct timeval tv;
	int action;
	unsigned long func;
};

#endif /* UAPI_PING_DELAY_H */
