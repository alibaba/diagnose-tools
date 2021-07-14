/*
 * Linux内核诊断工具--内核态ping-delay6功能
 *
 * Copyright (C) 2021 Alibaba Ltd.
 *
 * 作者: Yang Wei <albin.yangwei@alibaba-inc.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/module.h>
#include <linux/stacktrace.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/tracepoint.h>
#include <trace/events/irq.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <trace/events/napi.h>
#include <linux/rtc.h>
#include <linux/time.h>
#include <linux/version.h>
#include <linux/net.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmpv6.h>
#include <linux/netfilter.h>
#include <linux/cpu.h>
#include <net/tcp.h>
#include <net/protocol.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
#include <net/dst_metadata.h>
#else
#include <net/dst.h>
#endif

#include <net/xfrm.h>
#include <net/if_inet6.h>
#include <net/addrconf.h>
#include <linux/inetdevice.h>
#include <linux/snmp.h>

#include "internal.h"
#include "net_internal.h"
#include "pub/trace_file.h"
#include "pub/trace_point.h"
#include "pub/kprobe.h"
#include "uapi/ping_delay6.h"

#if defined(ALIOS_7U) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)

__maybe_unused static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
static struct diag_ping_delay6_settings ping_delay6_settings;

static unsigned int ping_delay6_alloced;

static struct softirq_action *orig_softirq_vec;

struct skb_info
{
	unsigned long key;
	const struct sk_buff *skb;
	struct in6_addr saddr;
	struct in6_addr daddr;
	int echo_id;
	int echo_sequence;
	cycles_t time_stamp[PD_TRACK_COUNT];

	struct list_head list;
	struct rcu_head rcu_head;
};

#define MAX_OBJ_COUNT 300000
static struct radix_tree_root skb_tree;
static atomic64_t obj_in_tree = ATOMIC64_INIT(0);
static DEFINE_SPINLOCK(tree_lock);
static DEFINE_MUTEX(skb_mutex);

static struct diag_variant_buffer ping_delay6_variant_buffer;

static struct kprobe kprobe_eth_type_trans;
static struct kprobe kprobe_napi_gro_receive;
static struct kprobe kprobe___netif_receive_skb_core;
static struct kprobe kprobe_ipv6_rcv;
static struct kprobe kprobe_ip6_input;
static struct kprobe kprobe_icmpv6_rcv;
static struct kprobe kprobe_dev_queue_xmit;

static void trace_events(int action, void *func)
{
	if (ping_delay6_settings.verbose) {
		unsigned long flags;
		struct ping_delay6_event event;

		event.et_type = et_ping_delay_event;
		do_diag_gettimeofday(&event.tv);
		event.func = (unsigned long)func;
		event.action = action;

		diag_variant_buffer_spin_lock(&ping_delay6_variant_buffer, flags);
		diag_variant_buffer_reserve(&ping_delay6_variant_buffer, sizeof(struct ping_delay6_event));
		diag_variant_buffer_write_nolock(&ping_delay6_variant_buffer, &event, sizeof(struct ping_delay6_event));
		diag_variant_buffer_seal(&ping_delay6_variant_buffer);
		diag_variant_buffer_spin_unlock(&ping_delay6_variant_buffer, flags);
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_irq_handler_entry_hit(int irq,
		struct irqaction *action)
#else
static void trace_irq_handler_entry_hit(void *ignore, int irq,
                struct irqaction *action)
#endif
{
	void *func = action->handler;
	trace_events(ping_delay6_event_enter_irq, func);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_irq_handler_exit_hit(int irq,
		struct irqaction *action, int ret)
#else
static void trace_irq_handler_exit_hit(void *ignore, int irq,
                struct irqaction *action, int ret)
#endif
{
	void *func = action->handler;
	trace_events(ping_delay6_event_exit_irq, func);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_softirq_entry_hit(struct softirq_action *h,
	struct softirq_action *softirq_vec)
#else
static void trace_softirq_entry_hit(void *ignore, unsigned long nr_sirq)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	unsigned long nr_sirq = h - softirq_vec;
#else
	struct softirq_action *h;
#endif
	void *func;

	if (nr_sirq >= NR_SOFTIRQS)
		return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	h = orig_softirq_vec + nr_sirq;
#endif
	func = h->action;
	trace_events(ping_delay6_event_enter_softirq, func);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static void trace_softirq_exit_hit(struct softirq_action *h,
	struct softirq_action *softirq_vec)
#else
static void trace_softirq_exit_hit(void *ignore, unsigned long nr_sirq)
#endif
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	unsigned long nr_sirq = h - softirq_vec;
#else
	struct softirq_action *h;
#endif
	void *func;

	if (nr_sirq >= NR_SOFTIRQS)
		return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	h = orig_softirq_vec + nr_sirq;
#endif
	func = h->action;
	trace_events(ping_delay6_event_exit_softirq, func);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)  //4.9.x 4.19.x
static void (*orig_ip6_route_input)(struct sk_buff *skb);
DEFINE_ORIG_FUNC(int, ip6_rcv_finish, 3,
				 struct net *, net,
				 struct sock *, sk,
				 struct sk_buff *, skb);
DEFINE_ORIG_FUNC(int, __ip6_local_out, 3,
				 struct net *, net,
				 struct sock *, sk,
				 struct sk_buff *, skb);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static void (*orig_ip6_route_input)(struct sk_buff *skb);
DEFINE_ORIG_FUNC(int, ip6_rcv_finish, 2,
				 struct sock *, sk,
				 struct sk_buff *, skb);
DEFINE_ORIG_FUNC(int, __ip6_local_out_sk, 2,
				 struct sock *, sk,
				 struct sk_buff *, skb);
#else  // < KERNEL_VERSION(3, 10, 0)

#endif

__maybe_unused static void move_to_list(struct list_head *skb_list)
{
	int i;
	unsigned long flags;
	struct skb_info *skbs[NR_BATCH];
	struct skb_info *skb_info;
	int nr_found;
	unsigned long pos = 0;

	INIT_LIST_HEAD(skb_list);

	mutex_lock(&skb_mutex);
	spin_lock_irqsave(&tree_lock, flags);
	do {
		nr_found = radix_tree_gang_lookup(&skb_tree, (void **)skbs, pos, NR_BATCH);

		for (i = 0; i < nr_found; i++) {
			skb_info = skbs[i];
			radix_tree_delete(&skb_tree, (unsigned long)skb_info->key);
			pos = (unsigned long)skb_info->key + 1;
			INIT_LIST_HEAD(&skb_info->list);
			list_add_tail(&skb_info->list, skb_list);
		}
	} while (nr_found > 0);
	atomic64_set(&obj_in_tree, 0);
	spin_unlock_irqrestore(&tree_lock, flags);
	mutex_unlock(&skb_mutex);
}

static void free_skb_info(struct rcu_head *rcu)
{
	struct skb_info *this = container_of(rcu, struct skb_info, rcu_head);

	kfree(this);
}

__maybe_unused static void diag_free_list(struct list_head *skb_list)
{
	while (!list_empty(skb_list))
	{
		struct skb_info *this = list_first_entry(skb_list, struct skb_info, list);

		list_del_init(&this->list);
		call_rcu(&this->rcu_head, free_skb_info);
	}
}

__maybe_unused static void clean_data(void)
{
	struct list_head header;

	move_to_list(&header);

	diag_free_list(&header);
}

__maybe_unused static struct skb_info *find_alloc_desc(const struct sk_buff *skb,
	struct in6_addr *saddr, struct in6_addr *daddr, int echo_id, int echo_sequence)
{
	struct skb_info *info = NULL;
	unsigned long key = (unsigned long)echo_id << 32 | echo_sequence;

	info = radix_tree_lookup(&skb_tree, key);
	if (!info && MAX_OBJ_COUNT > atomic64_read(&obj_in_tree)) {
		info = kmalloc(sizeof(struct skb_info), GFP_ATOMIC | __GFP_ZERO);
		if (info) {
			unsigned long flags;
			struct skb_info *tmp;

			info->key = key;
			info->skb = skb;
			info->saddr = *saddr;
			info->daddr = *daddr;
			info->echo_id = echo_id;
			info->echo_sequence = echo_sequence;
			INIT_LIST_HEAD(&info->list);

			spin_lock_irqsave(&tree_lock, flags);
			tmp = radix_tree_lookup(&skb_tree, key);
			if (tmp) {
				kfree(info);
				info = tmp;
			} else {
				radix_tree_insert(&skb_tree, key, info);
				atomic64_inc(&obj_in_tree);
			}
			spin_unlock_irqrestore(&tree_lock, flags);
		}
	}

	return info;
}

static noinline void inspect_packet(const struct sk_buff *skb, const struct ipv6hdr *ip6h, enum ping_delay6_packet_step step)
{
	struct in6_addr *source;
	struct in6_addr *dest;
	struct skb_info *skb_info;
	struct icmp6hdr *icmp6h = NULL;

	if (step >= PD_TRACK_COUNT)
		return;
	if (skb->len < sizeof(struct ipv6hdr) || !ip6h
	    || ip6h->payload_len < sizeof(struct icmp6hdr))
		return;

	if (ip6h->nexthdr != NEXTHDR_ICMP)
		return;

	icmp6h = (void *)ip6h + sizeof(struct ipv6hdr);
	source = (struct in6_addr *)&ip6h->saddr;
	dest = (struct in6_addr *)&ip6h->daddr;

	if (!ipv6_addr_any(&ping_delay6_settings.addr)) {
		if (!ipv6_addr_equal(&ping_delay6_settings.addr, source) && !ipv6_addr_equal(&ping_delay6_settings.addr, dest))
			return;
	}

	if (ping_delay6_settings.verbose) {
		unsigned long flags;
		struct ping_delay6_detail detail;

		detail.et_type = et_ping_delay_detail;
		do_diag_gettimeofday(&detail.tv);
		detail.saddr = *source;
		detail.daddr = *dest;
		detail.echo_id = be16_to_cpu(icmp6h->icmp6_identifier);
		detail.echo_sequence = be16_to_cpu(icmp6h->icmp6_sequence);
		detail.step = step;
		diag_variant_buffer_spin_lock(&ping_delay6_variant_buffer, flags);
		diag_variant_buffer_reserve(&ping_delay6_variant_buffer, sizeof(struct ping_delay6_detail));
		diag_variant_buffer_write_nolock(&ping_delay6_variant_buffer, &detail, sizeof(struct ping_delay6_detail));
		diag_variant_buffer_seal(&ping_delay6_variant_buffer);
		diag_variant_buffer_spin_unlock(&ping_delay6_variant_buffer, flags);
	}

	skb_info = find_alloc_desc(skb, source, dest,
		be16_to_cpu(icmp6h->icmp6_identifier),
		be16_to_cpu(icmp6h->icmp6_sequence));
	if (!skb_info)
		return;

	skb_info->time_stamp[step] = sched_clock();
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)

static int diag_ip6_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);
	void (*edemux)(struct sk_buff *skb);

	inspect_packet(skb, ip6h, PD_IP6_RCV_FINISH);

	/* if ingress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip6_rcv(skb);
	if (!skb)
		return NET_RX_SUCCESS;

	if (net->ipv4.sysctl_ip_early_demux && !skb_dst(skb) && skb->sk == NULL) {
		const struct inet6_protocol *ipprot;

		ipprot = rcu_dereference(inet6_protos[ipv6_hdr(skb)->nexthdr]);
		if (ipprot && (edemux = READ_ONCE(ipprot->early_demux)))
			edemux(skb);
	}
	if (!skb_valid_dst(skb))
		orig_ip6_route_input(skb);

	inspect_packet(skb, ip6h, PD_DST_INPUT);

	return dst_input(skb);
}

static int diag___ip6_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	int len;

	len = skb->len - sizeof(struct ipv6hdr);
	if (len > IPV6_MAXPLEN)
		len = 0;
	ipv6_hdr(skb)->payload_len = htons(len);
	IP6CB(skb)->nhoff = offsetof(struct ipv6hdr, nexthdr);

	/* if egress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip6_out(sk, skb);
	if (unlikely(!skb))
		return 0;

	skb->protocol = htons(ETH_P_IPV6);

	inspect_packet(skb, ipv6_hdr(skb), PD_DST_OUTPUT);

	return nf_hook(NFPROTO_IPV6, NF_INET_LOCAL_OUT,
		       net, sk, skb, NULL, skb_dst(skb)->dev,
		       dst_output);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)

static int diag_ip6_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);

	inspect_packet(skb, ip6h, PD_IP6_RCV_FINISH);

	/* if ingress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip6_rcv(skb);
	if (!skb)
		return NET_RX_SUCCESS;

	if (net->ipv4.sysctl_ip_early_demux && !skb_dst(skb) && skb->sk == NULL) {
		const struct inet6_protocol *ipprot;

		ipprot = rcu_dereference(inet6_protos[ipv6_hdr(skb)->nexthdr]);
		if (ipprot && ipprot->early_demux)
			ipprot->early_demux(skb);
	}
	if (!skb_valid_dst(skb))
		orig_ip6_route_input(skb);

	inspect_packet(skb, ip6h, PD_DST_INPUT);

	return dst_input(skb);
}

static int diag___ip6_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	int len;

	len = skb->len - sizeof(struct ipv6hdr);
	if (len > IPV6_MAXPLEN)
		len = 0;
	ipv6_hdr(skb)->payload_len = htons(len);
	IP6CB(skb)->nhoff = offsetof(struct ipv6hdr, nexthdr);

	/* if egress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip6_out(sk, skb);
	if (unlikely(!skb))
		return 0;

	skb->protocol = htons(ETH_P_IPV6);

	inspect_packet(skb, ipv6_hdr(skb), PD_DST_OUTPUT);

	return nf_hook(NFPROTO_IPV6, NF_INET_LOCAL_OUT,
		       net, sk, skb, NULL, skb_dst(skb)->dev,
		       dst_output);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)

static int diag_ip6_rcv_finish(struct sock *sk, struct sk_buff *skb)
{
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);

	inspect_packet(skb, ip6h, PD_IP6_RCV_FINISH);

	if (sysctl_ip_early_demux && !skb_dst(skb) && skb->sk == NULL) {
		const struct inet6_protocol *ipprot;

		ipprot = rcu_dereference(inet6_protos[ipv6_hdr(skb)->nexthdr]);
		if (ipprot && ipprot->early_demux)
			ipprot->early_demux(skb);
	}
	if (!skb_dst(skb))
		orig_ip6_route_input(skb);

	inspect_packet(skb, ip6h, PD_DST_INPUT);	

	return dst_input(skb);
}

static int diag___ip6_local_out_sk(struct sock *sk, struct sk_buff *skb)
{
	int len;

	len = skb->len - sizeof(struct ipv6hdr);
	if (len > IPV6_MAXPLEN)
		len = 0;
	ipv6_hdr(skb)->payload_len = htons(len);

	inspect_packet(skb, ipv6_hdr(skb), PD_DST_OUTPUT);

	return nf_hook(NFPROTO_IPV6, NF_INET_LOCAL_OUT, sk, skb,
		       NULL, skb_dst(skb)->dev, dst_output_sk);
}

#else  // < KERNEL_VERSION(3, 10, 0)

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
int new_ip6_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
int new_ip6_rcv_finish(struct sock *sk, struct sk_buff *skb)
#else
#endif
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	ret = diag_ip6_rcv_finish(net, sk, skb);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	ret = diag_ip6_rcv_finish(sk, skb);
#else
#endif
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
int new___ip6_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
int new___ip6_local_out_sk(struct sock *sk, struct sk_buff *skb)
#else
#endif
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)  //4.9.x 4.19.x
	ret = diag___ip6_local_out(net, sk, skb);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	ret = diag___ip6_local_out_sk(sk, skb);
#else
#endif
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
__maybe_unused static void trace_net_dev_xmit_hit(void *ignore, struct sk_buff *skb,
						  int rc, struct net_device *dev, unsigned int skb_len)
#else
__maybe_unused static void trace_net_dev_xmit_hit(struct sk_buff *skb,
						  int rc, struct net_device *dev, unsigned int skb_len)
#endif
{
	struct ipv6hdr *ip6h;

	if (!ping_delay6_settings.activated)
		return;

	if (rc != NETDEV_TX_OK)
		return;

	if (skb->protocol != cpu_to_be16(ETH_P_IPV6))
		return;

	ip6h = ipv6_hdr(skb);
	if (virt_addr_valid(ip6h)) {
		inspect_packet(skb, ip6h, PD_DEV_XMIT);
	}
}

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
__maybe_unused static void trace_net_dev_start_xmit_hit(void *ignore, struct sk_buff *skb, struct net_device *dev)
{
	struct ipv6hdr *ip6h;

	if (!ping_delay6_settings.activated)
		return;

	if (skb->protocol != cpu_to_be16(ETH_P_IPV6))
		return;

	ip6h = ipv6_hdr(skb);
	inspect_packet(skb, ip6h, PD_DEV_XMIT);
}
#endif

static int kprobe_eth_type_trans_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sk_buff *skb = (void *)ORIG_PARAM1(regs);
	struct ethhdr *eth;
	struct ipv6hdr *ip6h;

	if (!ping_delay6_settings.activated)
		return 0;

	eth = (struct ethhdr *)skb->data;
	if (eth->h_proto != cpu_to_be16(ETH_P_IPV6))
		return 0;

	ip6h = (struct ipv6hdr *)(skb->data + ETH_HLEN);
	inspect_packet(skb, ip6h, PD_ETH_RECV);

	return 0;
}

static int kprobe_napi_gro_receive_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sk_buff *skb = (void *)ORIG_PARAM2(regs);
	struct ipv6hdr *ip6h;

	if (!ping_delay6_settings.activated)
		return 0;

	if (skb->protocol != cpu_to_be16(ETH_P_IPV6))
		return 0;

	ip6h = (struct ipv6hdr *)skb->data;
	inspect_packet(skb, ip6h, PD_GRO_RECV);

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)

static struct list_head *orig_offload_base;
DEFINE_ORIG_FUNC(int, napi_gro_complete, 1,
	struct sk_buff *, skb);

static int diag_napi_gro_complete(struct sk_buff *skb)
{
	struct packet_offload *ptype;
	__be16 type = skb->protocol;
	struct list_head *head = orig_offload_base;
	int err = -ENOENT;

	BUILD_BUG_ON(sizeof(struct napi_gro_cb) > sizeof(skb->cb));

	if (NAPI_GRO_CB(skb)->count == 1) {
		skb_shinfo(skb)->gso_size = 0;
		goto out;
	}

	rcu_read_lock();
	list_for_each_entry_rcu(ptype, head, list) {
		if (ptype->type != type || !ptype->callbacks.gro_complete)
			continue;

		err = ptype->callbacks.gro_complete(skb, 0);
		break;
	}
	rcu_read_unlock();

	if (err) {
		WARN_ON(&ptype->list == head);

		if (type == cpu_to_be16(ETH_P_IPV6)) {
			struct ipv6hdr *ip6h = (struct ipv6hdr *)skb->data;
			inspect_packet(skb, ip6h, PD_GRO_RECV_ERR);
		}

		kfree_skb(skb);
		return NET_RX_SUCCESS;
	}

out:
	return netif_receive_skb(skb);
}

static int new_napi_gro_complete(struct sk_buff *skb)
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
	ret = diag_napi_gro_complete(skb);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)

static struct list_head *orig_offload_base;
static int (*orig_netif_receive_skb_internal)(struct sk_buff *skb);
DEFINE_ORIG_FUNC(int, napi_gro_complete, 1,
	struct sk_buff *, skb);

static int diag_napi_gro_complete(struct sk_buff *skb)
{
	struct packet_offload *ptype;
	__be16 type = skb->protocol;
	struct list_head *head = orig_offload_base;
	int err = -ENOENT;

	BUILD_BUG_ON(sizeof(struct napi_gro_cb) > sizeof(skb->cb));

	if (NAPI_GRO_CB(skb)->count == 1) {
		skb_shinfo(skb)->gso_size = 0;
		goto out;
	}

	rcu_read_lock();
	list_for_each_entry_rcu(ptype, head, list) {
		if (ptype->type != type || !ptype->callbacks.gro_complete)
			continue;

		err = ptype->callbacks.gro_complete(skb, 0);
		break;
	}
	rcu_read_unlock();

	if (err) {
		WARN_ON(&ptype->list == head);

		if (type == cpu_to_be16(ETH_P_IPV6)) {
			struct ipv6hdr *ip6h = (struct ipv6hdr *)skb->data;
			inspect_packet(skb, ip6h, PD_GRO_RECV_ERR);
		}

		kfree_skb(skb);
		return NET_RX_SUCCESS;
	}

out:
	return orig_netif_receive_skb_internal(skb);
}

static int new_napi_gro_complete(struct sk_buff *skb)
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
	ret = diag_napi_gro_complete(skb);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)

static struct list_head *orig_offload_base;
static int (*orig_netif_receive_skb_internal)(struct sk_buff *skb);
DEFINE_ORIG_FUNC(int, napi_gro_complete, 1,
	struct sk_buff *, skb);

static int diag_napi_gro_complete(struct sk_buff *skb)
{
    struct packet_offload *ptype;
    __be16 type = skb->protocol;
    struct list_head *head = orig_offload_base;
    int err = -ENOENT;

    BUILD_BUG_ON(sizeof(struct napi_gro_cb) > sizeof(skb->cb));

    if (NAPI_GRO_CB(skb)->count == 1) {
        skb_shinfo(skb)->gso_size = 0;
        goto out;
    }

    rcu_read_lock();
    list_for_each_entry_rcu(ptype, head, list) {
        if (ptype->type != type || !ptype->callbacks.gro_complete)
            continue;

        err = ptype->callbacks.gro_complete(skb, 0);
        break;
    }
    rcu_read_unlock();

    if (err) {
        WARN_ON(&ptype->list == head);

	if (type == cpu_to_be16(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)skb->data;
		inspect_packet(skb, ip6h, PD_GRO_RECV_ERR);
	}

        kfree_skb(skb);
        return NET_RX_SUCCESS;
    }

out:
    return orig_netif_receive_skb_internal(skb);
}

static int new_napi_gro_complete(struct sk_buff *skb)
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
	ret = diag_napi_gro_complete(skb);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)

static int (*orig___netif_receive_skb_core)(struct sk_buff *skb, bool pfmemalloc);
DEFINE_ORIG_FUNC(int, __netif_receive_skb, 1, struct sk_buff *, skb);

static int diag___netif_receive_skb(struct sk_buff *skb)
{
	int ret;

	if (sk_memalloc_socks() && skb_pfmemalloc(skb)) {
		unsigned long pflags = current->flags;

		/*
		 * PFMEMALLOC skbs are special, they should
		 * - be delivered to SOCK_MEMALLOC sockets only
		 * - stay away from userspace
		 * - have bounded memory usage
		 *
		 * Use PF_MEMALLOC as this saves us from propagating the allocation
		 * context down to all allocation sites.
		 */
		current->flags |= PF_MEMALLOC;
		ret = orig___netif_receive_skb_core(skb, true);
		tsk_restore_flags(current, pflags, PF_MEMALLOC);
	} else
		ret = orig___netif_receive_skb_core(skb, false);

	if (ret == NET_RX_DROP) {
		if (skb->protocol == cpu_to_be16(ETH_P_IPV6)) {
			struct ipv6hdr *ip6h = (struct ipv6hdr *)skb->data;
			inspect_packet(skb, ip6h, PD_RECV_SKB_DROP);
		}
	}

	return ret;
}

static int new___netif_receive_skb(struct sk_buff *skb)
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
	ret = diag___netif_receive_skb(skb);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)

static int (*orig___netif_receive_skb_core)(struct sk_buff *skb, bool pfmemalloc);
DEFINE_ORIG_FUNC(int, __netif_receive_skb, 1, struct sk_buff *, skb);

static int diag___netif_receive_skb(struct sk_buff *skb)
{
	int ret;

	if (sk_memalloc_socks() && skb_pfmemalloc(skb)) {
		unsigned long pflags = current->flags;

		/*
		 * PFMEMALLOC skbs are special, they should
		 * - be delivered to SOCK_MEMALLOC sockets only
		 * - stay away from userspace
		 * - have bounded memory usage
		 *
		 * Use PF_MEMALLOC as this saves us from propagating the allocation
		 * context down to all allocation sites.
		 */
		current->flags |= PF_MEMALLOC;
		ret = orig___netif_receive_skb_core(skb, true);
		tsk_restore_flags(current, pflags, PF_MEMALLOC);
	} else
		ret = orig___netif_receive_skb_core(skb, false);

	if (ret == NET_RX_DROP) {
		if (skb->protocol == cpu_to_be16(ETH_P_IPV6)) {
			struct ipv6hdr *ip6h = (struct ipv6hdr *)skb->data;
			inspect_packet(skb, ip6h, PD_RECV_SKB_DROP);
		}
	}

	return ret;
}

static int new___netif_receive_skb(struct sk_buff *skb)
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
	ret = diag___netif_receive_skb(skb);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)

static int (*orig___netif_receive_skb_one_core)(struct sk_buff *skb, bool pfmemalloc);
DEFINE_ORIG_FUNC(int, __netif_receive_skb, 1, struct sk_buff *, skb);

static inline unsigned int memalloc_noreclaim_save(void)
{
	unsigned int flags = current->flags & PF_MEMALLOC;
	current->flags |= PF_MEMALLOC;
	return flags;
}

static inline void memalloc_noreclaim_restore(unsigned int flags)
{
	current->flags = (current->flags & ~PF_MEMALLOC) | flags;
}

static int diag___netif_receive_skb(struct sk_buff *skb)
{
	int ret;

	if (sk_memalloc_socks() && skb_pfmemalloc(skb)) {
		unsigned int noreclaim_flag;

		/*
		 * PFMEMALLOC skbs are special, they should
		 * - be delivered to SOCK_MEMALLOC sockets only
		 * - stay away from userspace
		 * - have bounded memory usage
		 *
		 * Use PF_MEMALLOC as this saves us from propagating the allocation
		 * context down to all allocation sites.
		 */
		noreclaim_flag = memalloc_noreclaim_save();
		ret = orig___netif_receive_skb_one_core(skb, true);
		memalloc_noreclaim_restore(noreclaim_flag);
	} else
		ret = orig___netif_receive_skb_one_core(skb, false);

	if (ret == NET_RX_DROP) {
		if (skb->protocol == cpu_to_be16(ETH_P_IPV6)) {
			struct ipv6hdr *ip6h = (struct ipv6hdr *)skb->data;
			inspect_packet(skb, ip6h, PD_RECV_SKB_DROP);
		}
	}

	return ret;
}

static int new___netif_receive_skb(struct sk_buff *skb)
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
	ret = diag___netif_receive_skb(skb);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

#endif

static int kprobe___netif_receive_skb_core_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sk_buff *skb = (void *)ORIG_PARAM1(regs);
	struct ipv6hdr *ip6h;

	if (!ping_delay6_settings.activated)
		return 0;

	if (skb->protocol != cpu_to_be16(ETH_P_IPV6))
		return 0;

	ip6h = (struct ipv6hdr *)skb->data;
	inspect_packet(skb, ip6h, PD_RECV_SKB);

	return 0;
}

static int kprobe_ipv6_rcv_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sk_buff *skb = (void *)ORIG_PARAM1(regs);
	struct ipv6hdr *ip6h;

	if (!ping_delay6_settings.activated)
		return 0;

	if (skb->pkt_type == PACKET_OTHERHOST)
		return 0;

	ip6h = ipv6_hdr(skb);
	inspect_packet(skb, ip6h, PD_IP6_RCV);

	return 0;
}

static int kprobe_ip6_input_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sk_buff *skb = (void *)ORIG_PARAM1(regs);
	struct ipv6hdr *ip6h;

	if (!ping_delay6_settings.activated)
		return 0;

	ip6h = ipv6_hdr(skb);
	inspect_packet(skb, ip6h, PD_IP6_INPUT);

	return 0;
}

static int kprobe_icmpv6_rcv_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sk_buff *skb = (void *)ORIG_PARAM1(regs);
	struct ipv6hdr *ip6h;

	if (!ping_delay6_settings.activated)
		return 0;

	ip6h = ipv6_hdr(skb);
	inspect_packet(skb, ip6h, PD_ICMP6_RCV);

	return 0;
}

static int kprobe_dev_queue_xmit_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sk_buff *skb = (void *)ORIG_PARAM1(regs);
	struct ipv6hdr *ip6h;

	if (!ping_delay6_settings.activated)
		return 0;

	if (skb->protocol != cpu_to_be16(ETH_P_IPV6))
		return 0;

	ip6h = ipv6_hdr(skb);
	inspect_packet(skb, ip6h, PD_QUEUE_XMIT);

	return 0;
}

static int __activate_ping_delay6(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&ping_delay6_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	ping_delay6_alloced = 1;

	JUMP_CHECK(ip6_rcv_finish);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
	JUMP_CHECK(__ip6_local_out_sk);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)  //4.9.x 4.19.x
	JUMP_CHECK(__ip6_local_out);
#endif
	JUMP_CHECK(napi_gro_complete);
	JUMP_CHECK(__netif_receive_skb);

	clean_data();

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
	hook_tracepoint("net_dev_start_xmit", trace_net_dev_start_xmit_hit, NULL);
#else
	hook_tracepoint("net_dev_xmit", trace_net_dev_xmit_hit, NULL);
#endif

	hook_kprobe(&kprobe_dev_queue_xmit, "dev_queue_xmit",
				kprobe_dev_queue_xmit_pre, NULL);
	hook_kprobe(&kprobe_eth_type_trans, "eth_type_trans",
				kprobe_eth_type_trans_pre, NULL);
	hook_kprobe(&kprobe_napi_gro_receive, "napi_gro_receive",
				kprobe_napi_gro_receive_pre, NULL);
	hook_kprobe(&kprobe___netif_receive_skb_core, "__netif_receive_skb_core",
				kprobe___netif_receive_skb_core_pre, NULL);
	hook_kprobe(&kprobe_ipv6_rcv, "ipv6_rcv",
				kprobe_ipv6_rcv_pre, NULL);
	hook_kprobe(&kprobe_ip6_input, "ip6_input",
				kprobe_ip6_input_pre, NULL);
	hook_kprobe(&kprobe_icmpv6_rcv, "icmpv6_rcv",
				kprobe_icmpv6_rcv_pre, NULL);

	hook_tracepoint("irq_handler_entry", trace_irq_handler_entry_hit, NULL);
	hook_tracepoint("irq_handler_exit", trace_irq_handler_exit_hit, NULL);
	hook_tracepoint("softirq_entry", trace_softirq_entry_hit, NULL);
	hook_tracepoint("softirq_exit", trace_softirq_exit_hit, NULL);

	get_online_cpus();
	mutex_lock(orig_text_mutex);
	JUMP_INSTALL(ip6_rcv_finish);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
	JUMP_INSTALL(__ip6_local_out_sk);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)  //4.9.x 4.19.x
	JUMP_INSTALL(__ip6_local_out);
#endif
	JUMP_INSTALL(napi_gro_complete);
	JUMP_INSTALL(__netif_receive_skb);
	mutex_unlock(orig_text_mutex);
	put_online_cpus();

	return 1;

out_variant_buffer:
	return 0;
}

static void __deactivate_ping_delay6(void)
{
#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
	unhook_tracepoint("net_dev_start_xmit", trace_net_dev_start_xmit_hit, NULL);
#else
	unhook_tracepoint("net_dev_xmit", trace_net_dev_xmit_hit, NULL);
#endif
	unhook_kprobe(&kprobe_dev_queue_xmit);
	unhook_kprobe(&kprobe_eth_type_trans);
	unhook_kprobe(&kprobe_napi_gro_receive);
	unhook_kprobe(&kprobe___netif_receive_skb_core);
	unhook_kprobe(&kprobe_ipv6_rcv);
	unhook_kprobe(&kprobe_ip6_input);
	unhook_kprobe(&kprobe_icmpv6_rcv);

	unhook_tracepoint("irq_handler_entry", trace_irq_handler_entry_hit, NULL);
	unhook_tracepoint("irq_handler_exit", trace_irq_handler_exit_hit, NULL);
	unhook_tracepoint("softirq_entry", trace_softirq_entry_hit, NULL);
	unhook_tracepoint("softirq_exit", trace_softirq_exit_hit, NULL);

	get_online_cpus();

	mutex_lock(orig_text_mutex);
	JUMP_REMOVE(ip6_rcv_finish);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
	JUMP_REMOVE(__ip6_local_out_sk);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)  //4.9.x 4.19.x
	JUMP_REMOVE(__ip6_local_out);
#endif
	JUMP_REMOVE(napi_gro_complete);
	JUMP_REMOVE(__netif_receive_skb);
	mutex_unlock(orig_text_mutex);
	put_online_cpus();

	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0)
	{
		msleep(10);
	}

	clean_data();
}

int activate_ping_delay6(void)
{
	if (!ping_delay6_settings.activated)
		ping_delay6_settings.activated = __activate_ping_delay6();

	return ping_delay6_settings.activated;
}

int deactivate_ping_delay6(void)
{
	if (ping_delay6_settings.activated)
		__deactivate_ping_delay6();
	ping_delay6_settings.activated = 0;

	return 0;
}

static int lookup_syms(void)
{
	LOOKUP_SYMS(ip6_rcv_finish);
	LOOKUP_SYMS(ip6_route_input);
	LOOKUP_SYMS(offload_base);
	LOOKUP_SYMS(napi_gro_complete);
	LOOKUP_SYMS(__netif_receive_skb);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
	LOOKUP_SYMS(__ip6_local_out_sk);
	LOOKUP_SYMS(__netif_receive_skb_core);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	LOOKUP_SYMS(__ip6_local_out);
	LOOKUP_SYMS(netif_receive_skb_internal);
	LOOKUP_SYMS(__netif_receive_skb_core);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
	LOOKUP_SYMS(__ip6_local_out);
	LOOKUP_SYMS(netif_receive_skb_internal);
	LOOKUP_SYMS(__netif_receive_skb_one_core);
#endif
	LOOKUP_SYMS(softirq_vec);
	return 0;
}

static void jump_init(void)
{
	JUMP_INIT(ip6_rcv_finish);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
	JUMP_INIT(__ip6_local_out_sk);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)  //4.9.x 4.19.x
	JUMP_INIT(__ip6_local_out);
#endif
	JUMP_INIT(napi_gro_complete);
	JUMP_INIT(__netif_receive_skb);
}

static ssize_t dump_data(void)
{
	unsigned long flags;
	struct skb_info *this;
	struct list_head header;
	int i;
	struct ping_delay6_summary summary;

	move_to_list(&header);

	list_for_each_entry(this, &header, list) {
		summary.et_type = et_ping_delay_summary;
		do_diag_gettimeofday(&summary.tv);
		summary.saddr = this->saddr;
		summary.daddr = this->daddr;
		summary.echo_id = this->echo_id;
		summary.echo_sequence = this->echo_sequence;
		for (i = 0; i < PD_TRACK_COUNT; i++) {
			summary.time_stamp[i] = this->time_stamp[i];
		}
	
		diag_variant_buffer_spin_lock(&ping_delay6_variant_buffer, flags);
		diag_variant_buffer_reserve(&ping_delay6_variant_buffer, sizeof(struct ping_delay6_summary));
		diag_variant_buffer_write_nolock(&ping_delay6_variant_buffer, &summary, sizeof(struct ping_delay6_summary));
		diag_variant_buffer_seal(&ping_delay6_variant_buffer);
		diag_variant_buffer_spin_unlock(&ping_delay6_variant_buffer, flags);
	}

	diag_free_list(&header);

	return 0;
}

int ping_delay6_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_ping_delay6_settings settings;

	switch (id) {
	case DIAG_PING_DELAY6_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_ping_delay6_settings)) {
			ret = -EINVAL;
		} else if (ping_delay6_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				ping_delay6_settings = settings;
			}
		}
		break;
	case DIAG_PING_DELAY6_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_ping_delay6_settings)) {
			ret = -EINVAL;
		} else {
			settings = ping_delay6_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_PING_DELAY6_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);
		if (!ping_delay6_alloced) {
			ret = -EINVAL;
		} else {
			dump_data();
			ret = copy_to_user_variant_buffer(&ping_delay6_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("ping-delay6");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_ping_delay6(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_ping_delay6_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_PING_DELAY6_SET:
		if (ping_delay6_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_ping_delay6_settings));
			if (!ret) {
				ping_delay6_settings = settings;
			}
		}
		break;
	case CMD_PING_DELAY6_SETTINGS:
		settings = ping_delay6_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_ping_delay6_settings));
		break;
	case CMD_PING_DELAY6_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));

		if (!ping_delay6_alloced) {
			ret = -EINVAL;
		} else if(!ret){
			dump_data();
			ret = copy_to_user_variant_buffer(&ping_delay6_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("ping-delay6");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_net_ping_delay6_init(void)
{
	INIT_RADIX_TREE(&skb_tree, GFP_ATOMIC);

	if (lookup_syms())
		return -EINVAL;

	jump_init();

	init_diag_variant_buffer(&ping_delay6_variant_buffer, 1 * 1024 * 1024);

	if (ping_delay6_settings.activated)
		activate_ping_delay6();

	return 0;
}

void diag_net_ping_delay6_exit(void)
{
	destroy_diag_variant_buffer(&ping_delay6_variant_buffer);

	if (ping_delay6_settings.activated)
		deactivate_ping_delay6();
	ping_delay6_settings.activated = 0;

	return;
}

#else  //!(ALIOS_7U && < 5.10.0)

int diag_net_ping_delay6_init(void)
{
	return 0;
}

void diag_net_ping_delay6_exit(void)
{
}

#endif

