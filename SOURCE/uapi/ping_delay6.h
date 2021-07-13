/*
 * Linux内核诊断工具--用户接口API
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Yang Wei <albin.yangwei@alibaba-inc.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef UAPI_PING_DELAY6_H
#define UAPI_PING_DELAY6_H

#include <linux/ioctl.h>

#define DIAG_PING_DELAY6_SET (DIAG_BASE_SYSCALL_PING_DELAY6)
#define DIAG_PING_DELAY6_SETTINGS (DIAG_PING_DELAY6_SET + 1)
#define DIAG_PING_DELAY6_DUMP (DIAG_PING_DELAY6_SETTINGS + 1)

enum ping_delay6_packet_step
{
	PD_ETH_RECV,
	PD_GRO_RECV,
	PD_GRO_RECV_ERR,
	PD_RECV_SKB,
	PD_RECV_SKB_DROP,
	PD_IP6_RCV,
	PD_IP6_RCV_FINISH,
	PD_DST_INPUT,
	PD_IP6_INPUT,
	PD_ICMP6_RCV,
	PD_RCV_STEP = PD_ICMP6_RCV,
	PD_DST_OUTPUT,
	PD_QUEUE_XMIT,
	PD_DEV_XMIT,
	PD_TRACK_COUNT,
};

#ifndef __maybe_unused
# define __maybe_unused		__attribute__((unused))
#endif

__maybe_unused static const char *ping_delay6_packet_steps_str[PD_TRACK_COUNT] = {
	"PD_ETH_RECV",
	"PD_GRO_RECV",
	"PD_GRO_RECV_ERR",
	"PD_RECV_SKB",
	"PD_RECV_SKB_DROP",
	"PD_IP6_RCV",
	"PD_IP6_RCV_FINISH",
	"PD_DST_INPUT",
	"PD_IP6_INPUT",
	"PD_ICMP6_RCV",
	"PD_DST_OUTPUT",
	"PD_QUEUE_XMIT",
	"PD_DEV_XMIT",
};

enum {
	ping_delay6_event_enter_irq,
	ping_delay6_event_exit_irq,
	ping_delay6_event_enter_softirq,
	ping_delay6_event_exit_softirq,
};

struct diag_ping_delay6_settings {
	unsigned int activated;
	unsigned int verbose;
	struct in6_addr addr;
};

struct ping_delay6_summary {
	int et_type;
	struct diag_timespec tv;
	struct in6_addr saddr;
	struct in6_addr daddr;
	int echo_id;
	int echo_sequence;
	unsigned long time_stamp[PD_TRACK_COUNT];
};

struct ping_delay6_detail {
	int et_type;
	struct diag_timespec tv;
	struct in6_addr saddr;
	struct in6_addr daddr;
	int echo_id;
	int echo_sequence;
	unsigned int step;
};

struct ping_delay6_event {
	int et_type;
	struct diag_timespec tv;
	int action;
	unsigned long func;
};

#define CMD_PING_DELAY6_SET (0)
#define CMD_PING_DELAY6_SETTINGS (CMD_PING_DELAY6_SET + 1)
#define CMD_PING_DELAY6_DUMP (CMD_PING_DELAY6_SETTINGS + 1)
#define DIAG_IOCTL_PING_DELAY6_SET _IOWR(DIAG_IOCTL_TYPE_PING_DELAY6, CMD_PING_DELAY6_SET, struct diag_ping_delay6_settings)
#define DIAG_IOCTL_PING_DELAY6_SETTINGS _IOWR(DIAG_IOCTL_TYPE_PING_DELAY6, CMD_PING_DELAY6_SETTINGS, struct diag_ping_delay6_settings)
#define DIAG_IOCTL_PING_DELAY6_DUMP _IOWR(DIAG_IOCTL_TYPE_PING_DELAY6, CMD_PING_DELAY6_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_PING_DELAY6_H */
