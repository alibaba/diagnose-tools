/*
 * Linux内核诊断工具--内核态网络功能头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

extern int diag_tcp_retrans_init(void);
extern void diag_tcp_retrans_exit(void);
extern int diag_net_drop_packet_init(void);
extern void diag_net_drop_packet_exit(void);
extern int diag_net_reqsk_init(void);
extern void diag_net_reqsk_exit(void);
extern int diag_net_packet_corruption_init(void);
extern void diag_net_packet_corruption_exit(void);
extern int diag_net_redis_ixgbe_init(void);
extern void diag_net_redis_ixgbe_exit(void);
extern int diag_net_ping_delay_init(void);
extern void diag_net_ping_delay_exit(void);
extern int diag_net_net_bandwidth_init(void);
extern void diag_net_net_bandwidth_exit(void);
