/*
 * Linux内核诊断工具--内核态ping-delay功能
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/module.h>
#include <linux/stacktrace.h>
#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/timex.h>
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
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
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
#include <net/icmp.h>
#include <linux/inetdevice.h>
#include <linux/snmp.h>

#include "internal.h"
#include "net_internal.h"
#include "pub/trace_file.h"
#include "pub/trace_point.h"
#include "pub/kprobe.h"
#include "uapi/ping_delay.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(XBY_UBUNTU_1604) \
	&& !defined(CENTOS_3_10_123_9_3) && !defined(UBUNTU_1604) && !defined(CENTOS_8U)

__maybe_unused static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_ping_delay_settings ping_delay_settings;

static unsigned int ping_delay_alloced;

static struct softirq_action *orig_softirq_vec;

struct skb_info
{
	unsigned long key;
	const struct sk_buff *skb;
	int saddr;
	int daddr;
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

static struct diag_variant_buffer ping_delay_variant_buffer;

static struct kprobe kprobe_eth_type_trans;
static struct kprobe kprobe_napi_gro_receive;
static struct kprobe kprobe___netif_receive_skb_core;
static struct kprobe kprobe_icmp_rcv;
static struct kprobe kprobe_dev_queue_xmit;

static void trace_events(int action, void *func)
{
	if (ping_delay_settings.verbose) {
		unsigned long flags;
		struct ping_delay_event event;

		event.et_type = et_ping_delay_event;
		do_gettimeofday(&event.tv);
		event.func = (unsigned long)func;
		event.action = action;

		diag_variant_buffer_spin_lock(&ping_delay_variant_buffer, flags);
		diag_variant_buffer_reserve(&ping_delay_variant_buffer, sizeof(struct ping_delay_event));
		diag_variant_buffer_write_nolock(&ping_delay_variant_buffer, &event, sizeof(struct ping_delay_event));
		diag_variant_buffer_seal(&ping_delay_variant_buffer);
		diag_variant_buffer_spin_unlock(&ping_delay_variant_buffer, flags);
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

	trace_events(ping_delay_event_enter_irq, func);
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

	trace_events(ping_delay_event_exit_irq, func);
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
	trace_events(ping_delay_event_enter_softirq, func);
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
	trace_events(ping_delay_event_exit_softirq, func);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
static int (*orig_ip_local_deliver_finish)(struct net *net,
	struct sock *sk, struct sk_buff *skb);

DEFINE_ORIG_FUNC(int, ip_local_deliver, 1,
	struct sk_buff *, skb);
DEFINE_ORIG_FUNC(int, ip_rcv_finish, 3,
				 struct net *, net,
				 struct sock *, sk,
				 struct sk_buff *, skb);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static int (*orig_ip_local_deliver_finish)(struct sock *sk, struct sk_buff *skb);

DEFINE_ORIG_FUNC(int, ip_rcv_finish, 2,
				 struct sock *, sk,
				 struct sk_buff *, skb);
DEFINE_ORIG_FUNC(int, ip_local_deliver, 1,
        struct sk_buff *, skb);
#else
static int (*orig_ip_local_deliver_finish)(struct sk_buff *skb);

DEFINE_ORIG_FUNC(int, ip_local_deliver, 1,
        struct sk_buff *, skb);

DEFINE_ORIG_FUNC(int, ip_rcv_finish, 1,
				 struct sk_buff *, skb);
#endif

DEFINE_ORIG_FUNC(int, ip_rcv, 4,
				 struct sk_buff *, skb,
				 struct net_device *, dev,
				 struct packet_type *, pt,
				 struct net_device *, orig_dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
DEFINE_ORIG_FUNC(int, ip_send_skb, 2,
				 struct net *, net,
				 struct sk_buff *, skb);
#else
DEFINE_ORIG_FUNC(int, ip_send_skb, 1,
				 struct sk_buff *, skb);
static int (*orig_ip_options_rcv_srr)(struct sk_buff *skb);
static int (*orig_ip_options_compile)(struct net *net,
	struct ip_options *opt, struct sk_buff *skb);
#endif

static struct net_protocol **orig_inet_protos;

static struct ip_rt_acct *(*orig_ip_rt_acct);

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
	int saddr, int daddr, int echo_id, int echo_sequence)
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
			info->saddr = saddr;
			info->daddr = daddr;
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

static void inspect_packet(const struct sk_buff *skb, const struct iphdr *iphdr, enum ping_delay_packet_step step)
{
	int source = 0;
	int dest = 0;
	struct skb_info *skb_info;
	struct icmphdr *icmph = NULL;

	if (step >= PD_TRACK_COUNT)
		return;

	if (iphdr->protocol == IPPROTO_ICMP) {

		icmph = (void *)iphdr + iphdr->ihl * 4;
		source = iphdr->saddr;
		dest = iphdr->daddr;
	} else
		return;

	if (ping_delay_settings.addr) {
	 	if (be32_to_cpu(source) != ping_delay_settings.addr && be32_to_cpu(dest) != ping_delay_settings.addr)
			return;
	}

	if (ping_delay_settings.verbose) {
		unsigned long flags;
		struct ping_delay_detail detail;

		detail.et_type = et_ping_delay_detail;
		do_gettimeofday(&detail.tv);
		detail.saddr = source;
		detail.daddr = dest;
		detail.echo_id = be16_to_cpu(icmph->un.echo.id);
		detail.echo_sequence = be16_to_cpu(icmph->un.echo.sequence);
		detail.step = step;
		diag_variant_buffer_spin_lock(&ping_delay_variant_buffer, flags);
		diag_variant_buffer_reserve(&ping_delay_variant_buffer, sizeof(struct ping_delay_detail));
		diag_variant_buffer_write_nolock(&ping_delay_variant_buffer, &detail, sizeof(struct ping_delay_detail));
		diag_variant_buffer_seal(&ping_delay_variant_buffer);
		diag_variant_buffer_spin_unlock(&ping_delay_variant_buffer, flags);
	}

	if (step > PD_TRACK_COUNT)
		return;
	skb_info = find_alloc_desc(skb, source, dest,
		be16_to_cpu(icmph->un.echo.id),
		be16_to_cpu(icmph->un.echo.sequence));
	if (!skb_info)
		return;

	skb_info->time_stamp[step] = sched_clock();
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
static int diag_ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */
	struct net *net = dev_net(skb->dev);
	const struct iphdr *iph;

	iph = ip_hdr(skb);
	inspect_packet(skb, iph, PD_LOCAL_DELIVER);

	if (ip_is_fragment(ip_hdr(skb))) {
		if (ip_defrag(net, skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}

	inspect_packet(skb, iph, PD_LOCAL_DELIVER_FINISH);

	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN,
		       net, NULL, skb, skb->dev, NULL,
		       orig_ip_local_deliver_finish);
}

static int diag_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	const struct iphdr *iph;
	struct net *net;
	u32 len;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;

	net = dev_net(dev);
	__IP_UPD_PO_STATS(net, IPSTATS_MIB_IN, skb->len);

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
	{
		__IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
		goto out;
	}

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;

	iph = ip_hdr(skb);

	/*
	 *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */

	if (iph->ihl < 5 || iph->version != 4)
		goto inhdr_error;

	BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
	BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
	BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
	__IP_ADD_STATS(net,
				   IPSTATS_MIB_NOECTPKTS + (iph->tos & INET_ECN_MASK),
				   max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

	if (!pskb_may_pull(skb, iph->ihl * 4))
		goto inhdr_error;

	iph = ip_hdr(skb);

	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto csum_error;

	len = ntohs(iph->tot_len);
	if (skb->len < len)
	{
		__IP_INC_STATS(net, IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	}
	else if (len < (iph->ihl * 4))
		goto inhdr_error;

	/* Our transport medium may have padded the buffer out. Now we know it
	 * is IP we can trim to the true length of the frame.
	 * Note this now means skb->len holds ntohs(iph->tot_len).
	 */
	if (pskb_trim_rcsum(skb, len))
	{
		__IP_INC_STATS(net, IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	skb->transport_header = skb->network_header + iph->ihl * 4;

	/* Remove any debris in the socket control block */
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));
	IPCB(skb)->iif = skb->skb_iif;

	/* Must drop socket now because of tproxy. */
	skb_orphan(skb);

	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
				   net, NULL, skb, dev, NULL,
				   orig_ip_rcv_finish);

csum_error:
	__IP_INC_STATS(net, IPSTATS_MIB_CSUMERRORS);
inhdr_error:
	__IP_INC_STATS(net, IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;
}

static inline bool ip_rcv_options(struct sk_buff *skb)
{
	struct ip_options *opt;
	const struct iphdr *iph;
	struct net_device *dev = skb->dev;

	/* It looks as overkill, because not all
	   IP options require packet mangling.
	   But it is the easiest for now, especially taking
	   into account that combination of IP options
	   and running sniffer is extremely rare condition.
					      --ANK (980813)
	*/
	if (skb_cow(skb, skb_headroom(skb)))
	{
		__IP_INC_STATS(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	iph = ip_hdr(skb);
	opt = &(IPCB(skb)->opt);
	opt->optlen = iph->ihl * 4 - sizeof(struct iphdr);

	if (ip_options_compile(dev_net(dev), opt, skb))
	{
		__IP_INC_STATS(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
		goto drop;
	}

	if (unlikely(opt->srr))
	{
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		if (in_dev)
		{
			if (!IN_DEV_SOURCE_ROUTE(in_dev))
			{
				if (IN_DEV_LOG_MARTIANS(in_dev))
					net_info_ratelimited("source route option %pI4 -> %pI4\n",
										 &iph->saddr,
										 &iph->daddr);
				goto drop;
			}
		}

		if (ip_options_rcv_srr(skb))
			goto drop;
	}

	return false;
drop:
	return true;
}

static int diag_ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;
	struct net_device *dev = skb->dev;

	/* if ingress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip_rcv(skb);
	if (!skb)
		return NET_RX_SUCCESS;

	if (net->ipv4.sysctl_ip_early_demux &&
		!skb_dst(skb) &&
		!skb->sk &&
		!ip_is_fragment(iph))
	{
		const struct net_protocol *ipprot;
		int protocol = iph->protocol;

		ipprot = rcu_dereference(orig_inet_protos[protocol]);
		if (ipprot && ipprot->early_demux)
		{
			ipprot->early_demux(skb);
			/* must reload iph, skb->head might have changed */
			iph = ip_hdr(skb);
		}
	}

	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */
	if (!skb_valid_dst(skb))
	{
		int err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
									   iph->tos, dev);
		if (unlikely(err))
		{
			if (err == -EXDEV)
				__NET_INC_STATS(net, LINUX_MIB_IPRPFILTER);
			goto drop;
		}
	}

#ifdef CONFIG_IP_ROUTE_CLASSID
	if (unlikely(skb_dst(skb)->tclassid))
	{
		struct ip_rt_acct *st = this_cpu_ptr(*orig_ip_rt_acct);
		u32 idx = skb_dst(skb)->tclassid;
		st[idx & 0xFF].o_packets++;
		st[idx & 0xFF].o_bytes += skb->len;
		st[(idx >> 16) & 0xFF].i_packets++;
		st[(idx >> 16) & 0xFF].i_bytes += skb->len;
	}
#endif

	if (iph->ihl > 5 && ip_rcv_options(skb))
		goto drop;

	rt = skb_rtable(skb);
	if (rt->rt_type == RTN_MULTICAST)
	{
		__IP_UPD_PO_STATS(net, IPSTATS_MIB_INMCAST, skb->len);
	}
	else if (rt->rt_type == RTN_BROADCAST)
	{
		__IP_UPD_PO_STATS(net, IPSTATS_MIB_INBCAST, skb->len);
	}
	else if (skb->pkt_type == PACKET_BROADCAST ||
			 skb->pkt_type == PACKET_MULTICAST)
	{
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		/* RFC 1122 3.3.6:
		 *
		 *   When a host sends a datagram to a link-layer broadcast
		 *   address, the IP destination address MUST be a legal IP
		 *   broadcast or IP multicast address.
		 *
		 *   A host SHOULD silently discard a datagram that is received
		 *   via a link-layer broadcast (see Section 2.4) but does not
		 *   specify an IP multicast or broadcast destination address.
		 *
		 * This doesn't explicitly say L2 *broadcast*, but broadcast is
		 * in a way a form of multicast and the most common use case for
		 * this is 802.11 protecting against cross-station spoofing (the
		 * so-called "hole-196" attack) so do it for both.
		 */
		if (in_dev &&
			IN_DEV_ORCONF(in_dev, DROP_UNICAST_IN_L2_MULTICAST))
			goto drop;
	}

	inspect_packet(skb, iph, PD_DST_INPUT);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int diag_ip_send_skb(struct net *net, struct sk_buff *skb)
{
	int err;
	const struct iphdr *iph;

	err = ip_local_out(net, skb->sk, skb);
	if (err)
	{
		if (err > 0)
			err = net_xmit_errno(err);
		if (err)
			IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
	}

	iph = ip_hdr(skb);
	inspect_packet(skb, iph, PD_SEND_SKB);

	return err;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
static int diag_ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */

	if (ip_is_fragment(ip_hdr(skb))) {
		if (ip_defrag(skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}

	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN, NULL, skb,
		       skb->dev, NULL,
		       orig_ip_local_deliver_finish);
}

/*
 * 	Main IP Receive routine.
 */
static int diag_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	const struct iphdr *iph;
	u32 len;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;

	IP_UPD_PO_STATS_BH(dev_net(dev), IPSTATS_MIB_IN, skb->len);

	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
	{
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto out;
	}

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;

	iph = ip_hdr(skb);

	/*
	 *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */

	if (iph->ihl < 5 || iph->version != 4)
		goto inhdr_error;

	BUILD_BUG_ON(IPSTATS_MIB_ECT1PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_1);
	BUILD_BUG_ON(IPSTATS_MIB_ECT0PKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_ECT_0);
	BUILD_BUG_ON(IPSTATS_MIB_CEPKTS != IPSTATS_MIB_NOECTPKTS + INET_ECN_CE);
	IP_ADD_STATS_BH(dev_net(dev),
					IPSTATS_MIB_NOECTPKTS + (iph->tos & INET_ECN_MASK),
					max_t(unsigned short, 1, skb_shinfo(skb)->gso_segs));

	if (!pskb_may_pull(skb, iph->ihl * 4))
		goto inhdr_error;

	iph = ip_hdr(skb);

	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto csum_error;

	len = ntohs(iph->tot_len);
	if (skb->len < len)
	{
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	}
	else if (len < (iph->ihl * 4))
		goto inhdr_error;

	/* Our transport medium may have padded the buffer out. Now we know it
	 * is IP we can trim to the true length of the frame.
	 * Note this now means skb->len holds ntohs(iph->tot_len).
	 */
	if (pskb_trim_rcsum(skb, len))
	{
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	skb->transport_header = skb->network_header + iph->ihl * 4;

	/* Remove any debris in the socket control block */
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));

	/* Must drop socket now because of tproxy. */
	skb_orphan(skb);

	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING, NULL, skb,
				   dev, NULL,
				   orig_ip_rcv_finish);

csum_error:
	IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_CSUMERRORS);
inhdr_error:
	IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;
}

static inline bool ip_rcv_options(struct sk_buff *skb)
{
	struct ip_options *opt;
	const struct iphdr *iph;
	struct net_device *dev = skb->dev;

	/* It looks as overkill, because not all
	   IP options require packet mangling.
	   But it is the easiest for now, especially taking
	   into account that combination of IP options
	   and running sniffer is extremely rare condition.
					      --ANK (980813)
	*/
	if (skb_cow(skb, skb_headroom(skb)))
	{
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	iph = ip_hdr(skb);
	opt = &(IPCB(skb)->opt);
	opt->optlen = iph->ihl * 4 - sizeof(struct iphdr);

	if (ip_options_compile(dev_net(dev), opt, skb))
	{
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
		goto drop;
	}

	if (unlikely(opt->srr))
	{
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		if (in_dev)
		{
			if (!IN_DEV_SOURCE_ROUTE(in_dev))
			{
				if (IN_DEV_LOG_MARTIANS(in_dev))
					net_info_ratelimited("source route option %pI4 -> %pI4\n",
										 &iph->saddr,
										 &iph->daddr);
				goto drop;
			}
		}

		if (ip_options_rcv_srr(skb))
			goto drop;
	}

	return false;
drop:
	return true;
}

static int diag_ip_rcv_finish(struct sock *sk, struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;

	if (sysctl_ip_early_demux && !skb_dst(skb) && skb->sk == NULL)
	{
		const struct net_protocol *ipprot;
		int protocol = iph->protocol;

		ipprot = rcu_dereference(orig_inet_protos[protocol]);
		if (ipprot && ipprot->early_demux)
		{
			ipprot->early_demux(skb);
			/* must reload iph, skb->head might have changed */
			iph = ip_hdr(skb);
		}
	}

	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */
	if (!skb_dst(skb))
	{
		int err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
									   iph->tos, skb->dev);
		if (unlikely(err))
		{
			if (err == -EXDEV)
				NET_INC_STATS_BH(dev_net(skb->dev),
								 LINUX_MIB_IPRPFILTER);
			goto drop;
		}
	}

#ifdef CONFIG_IP_ROUTE_CLASSID
	if (unlikely(skb_dst(skb)->tclassid))
	{
		struct ip_rt_acct *st = this_cpu_ptr(*orig_ip_rt_acct);
		u32 idx = skb_dst(skb)->tclassid;
		st[idx & 0xFF].o_packets++;
		st[idx & 0xFF].o_bytes += skb->len;
		st[(idx >> 16) & 0xFF].i_packets++;
		st[(idx >> 16) & 0xFF].i_bytes += skb->len;
	}
#endif

	if (iph->ihl > 5 && ip_rcv_options(skb))
		goto drop;

	rt = skb_rtable(skb);
	if (rt->rt_type == RTN_MULTICAST)
	{
		IP_UPD_PO_STATS_BH(dev_net(rt->dst.dev), IPSTATS_MIB_INMCAST,
						   skb->len);
	}
	else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS_BH(dev_net(rt->dst.dev), IPSTATS_MIB_INBCAST,
						   skb->len);

	inspect_packet(skb, iph, PD_DST_INPUT);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int diag_ip_send_skb(struct net *net, struct sk_buff *skb)
{
	int err;
	const struct iphdr *iph;

	err = ip_local_out(skb);
	if (err)
	{
		if (err > 0)
			err = net_xmit_errno(err);
		if (err)
			IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
	}

	iph = ip_hdr(skb);
	inspect_packet(skb, iph, PD_SEND_SKB);

	return err;
}
#else
/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
static int diag_ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */

	if (ip_hdr(skb)->frag_off & htons(IP_MF | IP_OFFSET)) {
		if (ip_defrag(skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}

	return NF_HOOK(PF_INET, NF_INET_LOCAL_IN, skb, skb->dev, NULL,
		       orig_ip_local_deliver_finish);
}

static int diag_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	struct iphdr *iph;
	u32 len;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;

	IP_UPD_PO_STATS_BH(dev_net(dev), IPSTATS_MIB_IN, skb->len);

	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
	{
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto out;
	}

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;

	iph = ip_hdr(skb);

	/*
	 *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */
	if (iph->ihl < 5 || iph->version != 4)
		goto inhdr_error;

	if (!pskb_may_pull(skb, iph->ihl * 4))
		goto inhdr_error;

	iph = ip_hdr(skb);

	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto inhdr_error;

	len = ntohs(iph->tot_len);
	if (skb->len < len)
	{
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	}
	else if (len < (iph->ihl * 4))
		goto inhdr_error;

	/* Our transport medium may have padded the buffer out. Now we know it
	 * is IP we can trim to the true length of the frame.
	 * Note this now means skb->len holds ntohs(iph->tot_len).
	 */
	if (pskb_trim_rcsum(skb, len))
	{
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	/* Remove any debris in the socket control block */
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));

	/* Must drop socket now because of tproxy. */
	skb_orphan(skb);

	return NF_HOOK(PF_INET, NF_INET_PRE_ROUTING, skb, dev, NULL,
				   orig_ip_rcv_finish);

inhdr_error:
	IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;
}

static inline int ip_rcv_options(struct sk_buff *skb)
{
	struct ip_options *opt;
	struct iphdr *iph;
	struct net_device *dev = skb->dev;

	/* It looks as overkill, because not all
	   IP options require packet mangling.
	   But it is the easiest for now, especially taking
	   into account that combination of IP options
	   and running sniffer is extremely rare condition.
					      --ANK (980813)
	*/
	if (skb_cow(skb, skb_headroom(skb)))
	{
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	iph = ip_hdr(skb);
	opt = &(IPCB(skb)->opt);
	opt->optlen = iph->ihl * 4 - sizeof(struct iphdr);

	if (orig_ip_options_compile(dev_net(dev), opt, skb))
	{
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
		goto drop;
	}

	if (unlikely(opt->srr))
	{
		struct in_device *in_dev = in_dev_get(dev);
		if (in_dev)
		{
			if (!IN_DEV_SOURCE_ROUTE(in_dev))
			{
				if (IN_DEV_LOG_MARTIANS(in_dev) &&
					net_ratelimit())
					printk(KERN_INFO "source route option %pI4 -> %pI4\n",
						   &iph->saddr, &iph->daddr);
				in_dev_put(in_dev);
				goto drop;
			}

			in_dev_put(in_dev);
		}

		if (orig_ip_options_rcv_srr(skb))
			goto drop;
	}

	return 0;
drop:
	return -1;
}

static int diag_ip_rcv_finish(struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;

	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */
	if (skb_dst(skb) == NULL)
	{
		int err = ip_route_input(skb, iph->daddr, iph->saddr, iph->tos,
								 skb->dev);
		if (unlikely(err))
		{
			if (err == -EHOSTUNREACH)
				IP_INC_STATS_BH(dev_net(skb->dev),
								IPSTATS_MIB_INADDRERRORS);
			else if (err == -ENETUNREACH)
				IP_INC_STATS_BH(dev_net(skb->dev),
								IPSTATS_MIB_INNOROUTES);
			goto drop;
		}
	}

#ifdef CONFIG_NET_CLS_ROUTE
	if (unlikely(skb_dst(skb)->tclassid))
	{
		struct ip_rt_acct *st = per_cpu_ptr(*orig_ip_rt_acct, smp_processor_id());
		u32 idx = skb_dst(skb)->tclassid;
		st[idx & 0xFF].o_packets++;
		st[idx & 0xFF].o_bytes += skb->len;
		st[(idx >> 16) & 0xFF].i_packets++;
		st[(idx >> 16) & 0xFF].i_bytes += skb->len;
	}
#endif

	if (iph->ihl > 5 && ip_rcv_options(skb))
		goto drop;

	rt = skb_rtable(skb);
	if (rt->rt_type == RTN_MULTICAST)
	{
		IP_UPD_PO_STATS_BH(dev_net(rt->u.dst.dev), IPSTATS_MIB_INMCAST,
						   skb->len);
	}
	else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS_BH(dev_net(rt->u.dst.dev), IPSTATS_MIB_INBCAST,
						   skb->len);

	inspect_packet(skb, iph, PD_DST_INPUT);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int diag_ip_send_skb(struct sk_buff *skb)
{
	struct net *net = sock_net(skb->sk);
	int err;
	const struct iphdr *iph = ip_hdr(skb);

	err = ip_local_out(skb);
	if (err)
	{
		if (err > 0)
			err = net_xmit_errno(err);
		if (err)
			IP_INC_STATS(net, IPSTATS_MIB_OUTDISCARDS);
	}

	inspect_packet(skb, iph, PD_SEND_SKB);

	return err;
}
#endif

static int new_ip_local_deliver(struct sk_buff *skb)
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
	ret = diag_ip_local_deliver(skb);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

int new_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
	ret = diag_ip_rcv(skb, dev, pt, orig_dev);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
int new_ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
int new_ip_rcv_finish(struct sock *sk, struct sk_buff *skb)
#else
int new_ip_rcv_finish(struct sk_buff *skb)
#endif
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	ret = diag_ip_rcv_finish(net, sk, skb);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	ret = diag_ip_rcv_finish(sk, skb);
#else
	ret = diag_ip_rcv_finish(skb);
#endif
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
int new_ip_send_skb(struct net *net, struct sk_buff *skb)
#else
int new_ip_send_skb(struct sk_buff *skb)
#endif
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	ret = diag_ip_send_skb(net, skb);
#else
	ret = diag_ip_send_skb(skb);
#endif
	atomic64_dec_return(&diag_nr_running);

	return ret;
}
static void trace_net_dev_xmit_hit(void *ignore, struct sk_buff *skb,
								   int rc, struct net_device *dev, unsigned int skb_len)
{
	struct iphdr *iphdr;

	if (!ping_delay_settings.activated)
		return;

	if (rc != NETDEV_TX_OK)
		return;

	iphdr = ip_hdr(skb);
	inspect_packet(skb, iphdr, PD_SEND_SKB);
}

static int kprobe_eth_type_trans_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sk_buff *skb = (void *)ORIG_PARAM1(regs);
	struct iphdr *iphdr;

	if (!ping_delay_settings.activated)
		return 0;

	iphdr = (struct iphdr *)(skb->data + ETH_HLEN);
	inspect_packet(skb, iphdr, PD_ETH_RECV);

	return 0;
}

static int kprobe_napi_gro_receive_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sk_buff *skb = (void *)ORIG_PARAM2(regs);
	struct iphdr *iphdr;

	if (!ping_delay_settings.activated)
		return 0;

	if (skb->protocol != cpu_to_be16(ETH_P_IP))
		return 0;

	iphdr = (struct iphdr *)skb->data;
	inspect_packet(skb, iphdr, PD_GRO_RECV);

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
#define PTYPE_HASH_SIZE	(16)
#define PTYPE_HASH_MASK	(PTYPE_HASH_SIZE - 1)
static struct list_head (*orig_ptype_base);
DEFINE_ORIG_FUNC(int, napi_gro_complete, 1,
        struct sk_buff *, skb);

static int diag_napi_gro_complete(struct sk_buff *skb)
{
	struct packet_type *ptype;
	__be16 type = skb->protocol;
	struct list_head *head = &orig_ptype_base[ntohs(type) & PTYPE_HASH_MASK];
	int err = -ENOENT;

	if (NAPI_GRO_CB(skb)->count == 1) {
		skb_shinfo(skb)->gso_size = 0;
		goto out;
	}

	rcu_read_lock();
	list_for_each_entry_rcu(ptype, head, list) {
		if (ptype->type != type || ptype->dev || !ptype->gro_complete)
			continue;

		err = ptype->gro_complete(skb);
		break;
	}
	rcu_read_unlock();

	if (err) {
		struct iphdr *iphdr;

		WARN_ON(&ptype->list == head);

		iphdr = (struct iphdr *)skb->data;
		inspect_packet(skb, iphdr, PD_GRO_RECV_ERR);

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

#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
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
		struct iphdr *iphdr;

		WARN_ON(&ptype->list == head);

		iphdr = (struct iphdr *)skb->data;
		inspect_packet(skb, iphdr, PD_GRO_RECV_ERR);

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
		struct iphdr *iphdr;

		WARN_ON(&ptype->list == head);

		iphdr = (struct iphdr *)skb->data;
		inspect_packet(skb, iphdr, PD_GRO_RECV_ERR);

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
static int diag_napi_gro_complete(struct sk_buff *skb)
{
    struct packet_offload *ptype;
    __be16 type = skb->protocol;
    struct list_head *head = &offload_base;
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
	struct iphdr *iphdr;

        WARN_ON(&ptype->list == head);

	iphdr = (struct iphdr *)skb->data;
	inspect_packet(skb, iphdr, PD_GRO_RECV_ERR);

        kfree_skb(skb);
        return NET_RX_SUCCESS;
    }

out:
    return netif_receive_skb_internal(skb);
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
static int (*orig_get_rps_cpu)(struct net_device *dev, struct sk_buff *skb,
		       struct rps_dev_flow **rflowp);
static int (*orig___netif_receive_skb)(struct sk_buff *skb);
static int (*orig_enqueue_to_backlog)(struct sk_buff *skb, int cpu,
			      unsigned int *qtail);
DEFINE_ORIG_FUNC(int, netif_receive_skb, 1, struct sk_buff *, skb);

static int diag_netif_receive_skb(struct sk_buff *skb)
{
	struct rps_dev_flow voidflow, *rflow = &voidflow;
	int cpu, ret;

	cpu = orig_get_rps_cpu(skb->dev, skb, &rflow);

	if (cpu >= 0)
		ret = orig_enqueue_to_backlog(skb, cpu, &rflow->last_qtail);
	else
		ret = orig___netif_receive_skb(skb);

	if (ret == NET_RX_DROP) {
		struct iphdr *iphdr;

		iphdr = (struct iphdr *)skb->data;
		inspect_packet(skb, iphdr, PD_RECV_SKB_DROP);
	}

	return ret;
}

static int new_netif_receive_skb(struct sk_buff *skb)
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
	ret = diag_netif_receive_skb(skb);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
static int (*orig___netif_receive_skb_core)(struct sk_buff *skb, bool pfmemalloc);
DEFINE_ORIG_FUNC(int, __netif_receive_skb, 1, struct sk_buff *, skb);

static int diag__netif_receive_skb(struct sk_buff *skb)
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
		struct iphdr *iphdr;

		iphdr = (struct iphdr *)skb->data;
		inspect_packet(skb, iphdr, PD_RECV_SKB_DROP);
	}

	return ret;
}

static int new___netif_receive_skb(struct sk_buff *skb)
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
	ret = diag__netif_receive_skb(skb);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
static int (*orig___netif_receive_skb_core)(struct sk_buff *skb, bool pfmemalloc);
DEFINE_ORIG_FUNC(int, __netif_receive_skb, 1, struct sk_buff *, skb);

static int diag__netif_receive_skb(struct sk_buff *skb)
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
		struct iphdr *iphdr;

		iphdr = (struct iphdr *)skb->data;
		inspect_packet(skb, iphdr, PD_RECV_SKB_DROP);
	}

	return ret;
}

static int new___netif_receive_skb(struct sk_buff *skb)
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
	ret = diag__netif_receive_skb(skb);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
static int (*orig___netif_receive_skb_one_core)(struct sk_buff *skb, bool pfmemalloc);
DEFINE_ORIG_FUNC(int, __netif_receive_skb, 1, struct sk_buff *, skb);

static int diag__netif_receive_skb(struct sk_buff *skb)
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
		struct iphdr *iphdr;

		iphdr = (struct iphdr *)skb->data;
		inspect_packet(skb, iphdr, PD_RECV_SKB_DROP);
	}

	return ret;
}

static int new___netif_receive_skb(struct sk_buff *skb)
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
	ret = diag__netif_receive_skb(skb);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}
#endif

static int kprobe___netif_receive_skb_core_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sk_buff *skb = (void *)ORIG_PARAM1(regs);
	struct iphdr *iphdr;

	if (!ping_delay_settings.activated)
		return 0;

	if (skb->protocol != cpu_to_be16(ETH_P_IP))
		return 0;

	iphdr = (struct iphdr *)skb->data;
	inspect_packet(skb, iphdr, PD_RECV_SKB);

	return 0;
}

__maybe_unused static int kprobe_ip_rcv_finish_pre(struct kprobe *p, struct pt_regs *regs)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
	struct sk_buff *skb = (void *)ORIG_PARAM2(regs);
#else
	struct sk_buff *skb = (void *)ORIG_PARAM3(regs);
#endif
	struct iphdr *iphdr;

	if (!ping_delay_settings.activated)
		return 0;

	if (skb->protocol != cpu_to_be16(ETH_P_IP))
		return 0;

	iphdr = ip_hdr(skb);
	inspect_packet(skb, iphdr, PD_IP_RCV_FINISH);

	return 0;
}

static int kprobe_icmp_rcv_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sk_buff *skb = (void *)ORIG_PARAM1(regs);
	struct iphdr *iphdr;

	if (!ping_delay_settings.activated)
		return 0;

	if (skb->protocol != cpu_to_be16(ETH_P_IP))
		return 0;

	iphdr = ip_hdr(skb);
	inspect_packet(skb, iphdr, PD_ICMP_RCV);

	return 0;
}

static int kprobe_dev_queue_xmit_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sk_buff *skb = (void *)ORIG_PARAM1(regs);
	struct iphdr *iphdr;

	if (!ping_delay_settings.activated)
		return 0;

	iphdr = ip_hdr(skb);
	if (iphdr->protocol != IPPROTO_ICMP)
		return 0;

	inspect_packet(skb, iphdr, PD_SEND_SKB);

	return 0;
}

static int __activate_ping_delay(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&ping_delay_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	ping_delay_alloced = 1;

	JUMP_CHECK(ip_local_deliver);
	JUMP_CHECK(ip_rcv);
	JUMP_CHECK(ip_rcv_finish);
	JUMP_CHECK(ip_send_skb);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	JUMP_CHECK(napi_gro_complete);
	JUMP_CHECK(netif_receive_skb);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
	JUMP_CHECK(napi_gro_complete);
	JUMP_CHECK(__netif_receive_skb);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	JUMP_CHECK(napi_gro_complete);
	JUMP_CHECK(__netif_receive_skb);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
#endif

	clean_data();

	hook_tracepoint("net_dev_xmit", trace_net_dev_xmit_hit, NULL);
	hook_kprobe(&kprobe_dev_queue_xmit, "dev_queue_xmit",
				kprobe_dev_queue_xmit_pre, NULL);
	hook_kprobe(&kprobe_eth_type_trans, "eth_type_trans",
				kprobe_eth_type_trans_pre, NULL);
	hook_kprobe(&kprobe_napi_gro_receive, "napi_gro_receive",
				kprobe_napi_gro_receive_pre, NULL);
	hook_kprobe(&kprobe___netif_receive_skb_core, "__netif_receive_skb_core",
				kprobe___netif_receive_skb_core_pre, NULL);
	hook_kprobe(&kprobe_icmp_rcv, "icmp_rcv",
				kprobe_icmp_rcv_pre, NULL);

	hook_tracepoint("irq_handler_entry", trace_irq_handler_entry_hit, NULL);
	hook_tracepoint("irq_handler_exit", trace_irq_handler_exit_hit, NULL);
	hook_tracepoint("softirq_entry", trace_softirq_entry_hit, NULL);
	hook_tracepoint("softirq_exit", trace_softirq_exit_hit, NULL);

	get_online_cpus();
	mutex_lock(orig_text_mutex);
	JUMP_INSTALL(ip_local_deliver);
	JUMP_INSTALL(ip_rcv);
	JUMP_INSTALL(ip_rcv_finish);
	JUMP_INSTALL(ip_send_skb);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	JUMP_INSTALL(napi_gro_complete);
	JUMP_INSTALL(netif_receive_skb);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
	JUMP_INSTALL(napi_gro_complete);
	JUMP_INSTALL(__netif_receive_skb);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	JUMP_INSTALL(napi_gro_complete);
	JUMP_INSTALL(__netif_receive_skb);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
#endif
	mutex_unlock(orig_text_mutex);
	put_online_cpus();

	return 1;

out_variant_buffer:
	return 0;
}

static void __deactivate_ping_delay(void)
{
	unhook_tracepoint("net_dev_xmit", trace_net_dev_xmit_hit, NULL);
	unhook_kprobe(&kprobe_dev_queue_xmit);
	unhook_kprobe(&kprobe_eth_type_trans);
	unhook_kprobe(&kprobe_napi_gro_receive);
	unhook_kprobe(&kprobe___netif_receive_skb_core);
	unhook_kprobe(&kprobe_icmp_rcv);

	unhook_tracepoint("irq_handler_entry", trace_irq_handler_entry_hit, NULL);
	unhook_tracepoint("irq_handler_exit", trace_irq_handler_exit_hit, NULL);
	unhook_tracepoint("softirq_entry", trace_softirq_entry_hit, NULL);
	unhook_tracepoint("softirq_exit", trace_softirq_exit_hit, NULL);

	get_online_cpus();
	mutex_lock(orig_text_mutex);
	JUMP_REMOVE(ip_local_deliver);
	JUMP_REMOVE(ip_rcv);
	JUMP_REMOVE(ip_rcv_finish);
	JUMP_REMOVE(ip_send_skb);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	JUMP_REMOVE(napi_gro_complete);
	JUMP_REMOVE(netif_receive_skb);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
	JUMP_REMOVE(napi_gro_complete);
	JUMP_REMOVE(__netif_receive_skb);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	JUMP_REMOVE(napi_gro_complete);
	JUMP_REMOVE(__netif_receive_skb);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
#endif
	mutex_unlock(orig_text_mutex);
	put_online_cpus();

	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0)
	{
		msleep(10);
	}

	clean_data();
}

int activate_ping_delay(void)
{
	if (!ping_delay_settings.activated)
		ping_delay_settings.activated = __activate_ping_delay();

	return ping_delay_settings.activated;
}

int deactivate_ping_delay(void)
{
	if (ping_delay_settings.activated)
		__deactivate_ping_delay();
	ping_delay_settings.activated = 0;

	return 0;
}

static int lookup_syms(void)
{
	LOOKUP_SYMS(inet_protos);
	LOOKUP_SYMS(ip_rcv_finish);
	LOOKUP_SYMS(ip_rcv);
	LOOKUP_SYMS(ip_rcv_finish);
	LOOKUP_SYMS(ip_send_skb);
	LOOKUP_SYMS(ip_local_deliver_finish);
	LOOKUP_SYMS(ip_local_deliver);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
	LOOKUP_SYMS(ip_options_rcv_srr);
	LOOKUP_SYMS(ip_options_compile);
	LOOKUP_SYMS(ptype_base);
	LOOKUP_SYMS(napi_gro_complete);
	LOOKUP_SYMS(get_rps_cpu);
	LOOKUP_SYMS(__netif_receive_skb);
	LOOKUP_SYMS(enqueue_to_backlog);
	LOOKUP_SYMS(netif_receive_skb);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
	LOOKUP_SYMS(offload_base);
	LOOKUP_SYMS(napi_gro_complete);
	LOOKUP_SYMS(__netif_receive_skb);
	LOOKUP_SYMS(__netif_receive_skb_core);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	LOOKUP_SYMS(offload_base);
	LOOKUP_SYMS(netif_receive_skb_internal);
	LOOKUP_SYMS(napi_gro_complete);
	LOOKUP_SYMS(__netif_receive_skb);
	LOOKUP_SYMS(__netif_receive_skb_core);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
	LOOKUP_SYMS(__netif_receive_skb);
	LOOKUP_SYMS(__netif_receive_skb_one_core);
#endif
	LOOKUP_SYMS(softirq_vec);
	return 0;
}

static void jump_init(void)
{
	JUMP_INIT(ip_local_deliver);
	JUMP_INIT(ip_rcv);
	JUMP_INIT(ip_rcv_finish);
	JUMP_INIT(ip_send_skb);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	JUMP_INIT(napi_gro_complete);
	JUMP_INIT(netif_receive_skb);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
	JUMP_INIT(napi_gro_complete);
	JUMP_INIT(__netif_receive_skb);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	JUMP_INIT(napi_gro_complete);
	JUMP_INIT(__netif_receive_skb);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
#endif
}

static ssize_t dump_data(void)
{
	unsigned long flags;
	struct skb_info *this;
	struct list_head header;
	int i;
	struct ping_delay_summary summary;

	move_to_list(&header);

	list_for_each_entry(this, &header, list) {
		summary.et_type = et_ping_delay_summary;
		do_gettimeofday(&summary.tv);
		summary.saddr = this->saddr;
		summary.daddr = this->daddr;
		summary.echo_id = this->echo_id;
		summary.echo_sequence = this->echo_sequence;
		for (i = 0; i < PD_TRACK_COUNT; i++) {
			summary.time_stamp[i] = this->time_stamp[i];
		}
	
		diag_variant_buffer_spin_lock(&ping_delay_variant_buffer, flags);
		diag_variant_buffer_reserve(&ping_delay_variant_buffer, sizeof(struct ping_delay_summary));
		diag_variant_buffer_write_nolock(&ping_delay_variant_buffer, &summary, sizeof(struct ping_delay_summary));
		diag_variant_buffer_seal(&ping_delay_variant_buffer);
		diag_variant_buffer_spin_unlock(&ping_delay_variant_buffer, flags);
	}

	diag_free_list(&header);

	return 0;
}

int ping_delay_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_ping_delay_settings settings;

	switch (id) {
	case DIAG_PING_DELAY_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_ping_delay_settings)) {
			ret = -EINVAL;
		} else if (ping_delay_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				ping_delay_settings = settings;
			}
		}
		break;
	case DIAG_PING_DELAY_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_ping_delay_settings)) {
			ret = -EINVAL;
		} else {
			settings = ping_delay_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_PING_DELAY_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!ping_delay_alloced) {
			ret = -EINVAL;
		} else {
			dump_data();
			ret = copy_to_user_variant_buffer(&ping_delay_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("ping-delay");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_ping_delay(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_ping_delay_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_PING_DELAY_SET:
		if (ping_delay_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_ping_delay_settings));
			if (!ret) {
				ping_delay_settings = settings;
			}
		}
		break;
	case CMD_PING_DELAY_SETTINGS:
		settings = ping_delay_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_ping_delay_settings));
		break;
	case CMD_PING_DELAY_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));

		if (!ping_delay_alloced) {
			ret = -EINVAL;
		} else if(!ret){
			dump_data();
			ret = copy_to_user_variant_buffer(&ping_delay_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("ping-delay");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_net_ping_delay_init(void)
{
	INIT_RADIX_TREE(&skb_tree, GFP_ATOMIC);

	if (lookup_syms())
		return -EINVAL;

	jump_init();

	init_diag_variant_buffer(&ping_delay_variant_buffer, 1 * 1024 * 1024);

	if (ping_delay_settings.activated)
		activate_ping_delay();

	return 0;
}

void diag_net_ping_delay_exit(void)
{
	destroy_diag_variant_buffer(&ping_delay_variant_buffer);

	if (ping_delay_settings.activated)
		deactivate_ping_delay();
	ping_delay_settings.activated = 0;

	return;
}
#else
int diag_net_ping_delay_init(void)
{
	return 0;
}

void diag_net_ping_delay_exit(void)
{
	//
}
#endif
