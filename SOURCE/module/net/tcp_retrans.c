/*
 * Linux内核诊断工具--内核态tcp-retrans功能
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
#include <linux/skbuff.h>
#include <net/tcp.h>

#include "internal.h"
#include "net_internal.h"
#include "pub/trace_file.h"
#include "pub/kprobe.h"
#include "pub/trace_point.h"

#include "uapi/tcp_retrans.h"

#define FLAG_DATA		0x01 /* Incoming frame contained data.		*/
#define FLAG_WIN_UPDATE		0x02 /* Incoming ACK was a window update.	*/
#define FLAG_DATA_ACKED		0x04 /* This ACK acknowledged new data.		*/
#define FLAG_RETRANS_DATA_ACKED	0x08 /* "" "" some of which was retransmitted.	*/
#define FLAG_SYN_ACKED		0x10 /* This ACK acknowledged SYN.		*/
#define FLAG_DATA_SACKED	0x20 /* New SACK.				*/
#define FLAG_ECE		0x40 /* ECE in this ACK				*/
#define FLAG_LOST_RETRANS	0x80 /* This ACK marks some retransmission lost */
#define FLAG_SLOWPATH		0x100 /* Do not skip RFC checks for window update.*/
#define FLAG_ORIG_SACK_ACKED	0x200 /* Never retransmitted data are (s)acked	*/
#define FLAG_SND_UNA_ADVANCED	0x400 /* Snd_una was changed (!= FLAG_DATA_ACKED) */
#define FLAG_DSACKING_ACK	0x800 /* SACK blocks contained D-SACK info */
#define FLAG_SACK_RENEGING	0x2000 /* snd_una advanced to a sacked seq */
#define FLAG_UPDATE_TS_RECENT	0x4000 /* tcp_replace_ts_recent() */

#define FLAG_ACKED		(FLAG_DATA_ACKED|FLAG_SYN_ACKED)
#define FLAG_NOT_DUP		(FLAG_DATA|FLAG_WIN_UPDATE|FLAG_ACKED)
#define FLAG_CA_ALERT		(FLAG_DATA_SACKED|FLAG_ECE)
#define FLAG_FORWARD_PROGRESS	(FLAG_ACKED|FLAG_DATA_SACKED)

#define TCP_REMNANT (TCP_FLAG_FIN|TCP_FLAG_URG|TCP_FLAG_SYN|TCP_FLAG_PSH)
#define TCP_HP_BITS (~(TCP_RESERVED_BITS|TCP_FLAG_PSH))

__maybe_unused static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_tcp_retrans_settings tcp_retrans_settings;

__maybe_unused static int tcp_retrans_alloced = 0;
__maybe_unused static atomic64_t diag_alloc_count = ATOMIC64_INIT(0);
__maybe_unused static atomic64_t diag_nr_tcp_retransmit_skb = ATOMIC64_INIT(0);
__maybe_unused static atomic64_t diag_nr_tcp_rtx_synack = ATOMIC64_INIT(0);
__maybe_unused static atomic64_t diag_tcp_dupack = ATOMIC64_INIT(0);
__maybe_unused static atomic64_t diag_tcp_send_dupack = ATOMIC64_INIT(0);

__maybe_unused static struct rb_root diag_tcp_retrans_tree = RB_ROOT;
__maybe_unused static DEFINE_SPINLOCK(diag_tcp_retrans_tree_lock);

struct diag_tcp_retrans {
	struct rb_node rb_node;
	struct list_head list;
	int src_addr;
	int src_port;
	int dest_addr;
	int dest_port;
	int syncack_count;
	int skb_count;
};

static struct diag_variant_buffer tcp_retrans_variant_buffer;

__maybe_unused static void clean_data(void)
{
	unsigned long flags;
	struct list_head header;
	struct rb_node *node;

	INIT_LIST_HEAD(&header);
	spin_lock_irqsave(&diag_tcp_retrans_tree_lock, flags);

	for (node = rb_first(&diag_tcp_retrans_tree); node; node = rb_next(node)) {
		struct diag_tcp_retrans *this = container_of(node,
				struct diag_tcp_retrans, rb_node);

		rb_erase(&this->rb_node, &diag_tcp_retrans_tree);
		INIT_LIST_HEAD(&this->list);
		list_add_tail(&this->list, &header);
	}
	diag_tcp_retrans_tree = RB_ROOT;

	spin_unlock_irqrestore(&diag_tcp_retrans_tree_lock, flags);

	while (!list_empty(&header)) {
		struct diag_tcp_retrans *this = list_first_entry(&header, struct diag_tcp_retrans, list);

		list_del_init(&this->list);
		kfree(this);
	}
}

__maybe_unused static int compare_desc(struct diag_tcp_retrans *desc, struct diag_tcp_retrans *this)
{
	if (desc->src_addr < this->src_addr)
		return -1;
	if (desc->src_addr > this->src_addr)
		return 1;
	if (desc->src_port < this->src_port)
		return -1;
	if (desc->src_port > this->src_port)
		return 1;
	if (desc->dest_addr < this->dest_addr)
		return -1;
	if (desc->dest_addr > this->dest_addr)
		return 1;
	if (desc->dest_port < this->dest_port)
		return -1;
	if (desc->dest_port > this->dest_port)
		return 1;

	return 0;
}

__maybe_unused static struct diag_tcp_retrans *__find_alloc_desc(struct diag_tcp_retrans *desc)
{
	struct diag_tcp_retrans *this;
	struct rb_node **node, *parent;
	int compare_ret;

	node = &diag_tcp_retrans_tree.rb_node;
	parent = NULL;

	while (*node != NULL)
	{
		parent = *node;
		this = container_of(parent, struct diag_tcp_retrans, rb_node);
		compare_ret = compare_desc(desc, this);

		if (compare_ret < 0)
			node = &parent->rb_left;
		else if (compare_ret > 0)
			node = &parent->rb_right;
		else
		{
			return this;
		}
	}

	this = kmalloc(sizeof(struct diag_tcp_retrans), GFP_ATOMIC);
	if (!this) {
		atomic64_inc_return(&diag_alloc_count);
		return this;
	}

	memset(this, 0, sizeof(struct diag_tcp_retrans));
	this->src_addr = desc->src_addr;
	this->src_port = desc->src_port;
	this->dest_addr = desc->dest_addr;
	this->dest_port = desc->dest_port;
	rb_link_node(&this->rb_node, parent, node);
	rb_insert_color(&this->rb_node, &diag_tcp_retrans_tree);

	return this;
}

#if !defined(CENTOS_3_10_862) && !defined(CENTOS_3_10_957) \
	&& !defined(CENTOS_3_10_1062) && !defined(CENTOS_3_10_1127)
int diag_tcp_retrans_init(void)
{
	return 0;
}

void diag_tcp_retrans_exit(void)
{
}
#else
__maybe_unused static void trace_retransmit_synack(struct sock *sk, struct request_sock *req)
{
	unsigned long flags;
	struct diag_tcp_retrans *desc;
	struct diag_tcp_retrans tmp;
	struct inet_sock *sock = inet_sk(sk);

	if (!tcp_retrans_settings.activated)
		return;

	if (sk->sk_protocol == IPPROTO_TCP) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 33)
		tmp.src_port = be16_to_cpu(sock->sport);
		tmp.dest_port = be16_to_cpu(sock->dport);
		tmp.src_addr = sock->saddr;
		tmp.dest_addr = sock->daddr;
#else
		tmp.src_port = be16_to_cpu(sock->inet_num);
		tmp.dest_port = be16_to_cpu(sock->inet_dport);
		tmp.src_addr = sock->inet_rcv_saddr;
		tmp.dest_addr = sock->inet_daddr;
#endif
	} else {
		return;
	}

	spin_lock_irqsave(&diag_tcp_retrans_tree_lock, flags);
	desc = __find_alloc_desc(&tmp);
	if (desc) {
		desc->syncack_count++;
	}
	spin_unlock_irqrestore(&diag_tcp_retrans_tree_lock, flags);

	if (tcp_retrans_settings.verbose & 1) {
		struct tcp_retrans_trace trace;
		unsigned long flags;

		trace.et_type = et_tcp_retrans_trace;
		do_gettimeofday(&trace.tv);
		trace.src_addr = tmp.src_addr;
		trace.src_port = tmp.src_port;
		trace.dest_addr = tmp.dest_addr;
		trace.dest_port = tmp.dest_port;
		trace.sync_or_skb = 1;
		diag_variant_buffer_spin_lock(&tcp_retrans_variant_buffer, flags);
		diag_variant_buffer_reserve(&tcp_retrans_variant_buffer, sizeof(struct tcp_retrans_trace));
		diag_variant_buffer_write_nolock(&tcp_retrans_variant_buffer, &trace, sizeof(struct tcp_retrans_trace));
		diag_variant_buffer_seal(&tcp_retrans_variant_buffer);
		diag_variant_buffer_spin_unlock(&tcp_retrans_variant_buffer, flags);
	}
}

__maybe_unused static void trace_retransmit_skb(struct sock *sk, struct sk_buff *skb)
{
	unsigned long flags;
	struct diag_tcp_retrans *desc;
	struct diag_tcp_retrans tmp;
	struct inet_sock *sock = inet_sk(sk);

	if (!tcp_retrans_settings.activated)
		return;

	if (sk->sk_protocol == IPPROTO_TCP) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 33)
		tmp.src_port = be16_to_cpu(sock->sport);
		tmp.dest_port = be16_to_cpu(sock->dport);
		tmp.src_addr = sock->saddr;
		tmp.dest_addr = sock->daddr;
#else
		tmp.src_port = be16_to_cpu(sock->inet_num);
		tmp.dest_port = be16_to_cpu(sock->inet_dport);
		tmp.src_addr = sock->inet_rcv_saddr;
		tmp.dest_addr = sock->inet_daddr;
#endif
	} else {
		return;
	}

	spin_lock_irqsave(&diag_tcp_retrans_tree_lock, flags);
	desc = __find_alloc_desc(&tmp);
	if (desc) {
		desc->skb_count++;
	}
	spin_unlock_irqrestore(&diag_tcp_retrans_tree_lock, flags);

	if (tcp_retrans_settings.verbose & 1) {
		struct tcp_retrans_trace trace;
		unsigned long flags;

		trace.et_type = et_tcp_retrans_trace;
		do_gettimeofday(&trace.tv);
		trace.src_addr = tmp.src_addr;
		trace.src_port = tmp.src_port;
		trace.dest_addr = tmp.dest_addr;
		trace.dest_port = tmp.dest_port;
		trace.sync_or_skb = 0;
		diag_variant_buffer_spin_lock(&tcp_retrans_variant_buffer, flags);
		diag_variant_buffer_reserve(&tcp_retrans_variant_buffer, sizeof(struct tcp_retrans_trace));
		diag_variant_buffer_write_nolock(&tcp_retrans_variant_buffer, &trace, sizeof(struct tcp_retrans_trace));
		diag_variant_buffer_seal(&tcp_retrans_variant_buffer);
		diag_variant_buffer_spin_unlock(&tcp_retrans_variant_buffer, flags);
	}
}

int *orig_sysctl_tcp_retrans_collapse;
static int (*orig_tcp_init_tso_segs)(const struct sock *sk, struct sk_buff *skb,
		unsigned int mss_now);
static void (*orig_tcp_adjust_pcount)(struct sock *sk, const struct sk_buff *skb, int decr);
static int (*orig_tcp_transmit_skb)(struct sock *sk, struct sk_buff *skb, int clone_it,
		gfp_t gfp_mask);
static int (*orig_tcp_trim_head)(struct sock *, struct sk_buff *, u32);
static int (*orig_tcp_fragment)(struct sock *sk, struct sk_buff *skb, u32 len,
		unsigned int mss_now);
static unsigned int (*orig_tcp_current_mss)(struct sock *sk);

DEFINE_ORIG_FUNC(int, tcp_rtx_synack, 2, struct sock *, sk, struct request_sock *, req);
DEFINE_ORIG_FUNC(int, __tcp_retransmit_skb, 2, struct sock *, sk, struct sk_buff *, skb);

/* Thanks to skb fast clones, we can detect if a prior transmit of
 * a packet is still in a qdisc or driver queue.
 * In this case, there is very little point doing a retransmit !
 * Note: This is called from BH context only.
 */
static bool skb_still_in_host_queue(const struct sock *sk,
		const struct sk_buff *skb)
{
	if (unlikely(skb_fclone_busy(sk, skb))) {
		NET_INC_STATS_BH(sock_net(sk),
				LINUX_MIB_TCPSPURIOUS_RTX_HOSTQUEUES);
		return true;
	}
	return false;
}

/* Check if coalescing SKBs is legal. */
static bool tcp_can_collapse(const struct sock *sk, const struct sk_buff *skb)
{
	if (tcp_skb_pcount(skb) > 1)
		return false;
	/* TODO: SACK collapsing could be used to remove this condition */
	if (skb_shinfo(skb)->nr_frags != 0)
		return false;
	if (skb_cloned(skb))
		return false;
	if (skb == tcp_send_head(sk))
		return false;
	/* Some heurestics for collapsing over SACK'd could be invented */
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
		return false;

	return true;
}

/* Collapses two adjacent SKB's during retransmission. */
static void tcp_collapse_retrans(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *next_skb = tcp_write_queue_next(sk, skb);
	int skb_size, next_skb_size;

	skb_size = skb->len;
	next_skb_size = next_skb->len;

	BUG_ON(tcp_skb_pcount(skb) != 1 || tcp_skb_pcount(next_skb) != 1);

#if defined(CENTOS_3_10_1062) || defined(CENTOS_3_10_1127)
	tcp_highest_sack_replace(sk, next_skb, skb);
#else
	tcp_highest_sack_combine(sk, next_skb, skb);
#endif

	tcp_unlink_write_queue(next_skb, sk);

	skb_copy_from_linear_data(next_skb, skb_put(skb, next_skb_size),
			next_skb_size);

	if (next_skb->ip_summed == CHECKSUM_PARTIAL)
		skb->ip_summed = CHECKSUM_PARTIAL;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		skb->csum = csum_block_add(skb->csum, next_skb->csum, skb_size);

	/* Update sequence range on original skb. */
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(next_skb)->end_seq;

	/* Merge over control information. This moves PSH/FIN etc. over */
	TCP_SKB_CB(skb)->tcp_flags |= TCP_SKB_CB(next_skb)->tcp_flags;

	/* All done, get rid of second SKB and account for it so
	 * packet counting does not break.
	 */
	TCP_SKB_CB(skb)->sacked |= TCP_SKB_CB(next_skb)->sacked & TCPCB_EVER_RETRANS;

	/* changed transmit queue under us so clear hints */
	tcp_clear_retrans_hints_partial(tp);
	if (next_skb == tp->retransmit_skb_hint)
		tp->retransmit_skb_hint = skb;

	orig_tcp_adjust_pcount(sk, next_skb, tcp_skb_pcount(next_skb));

	sk_wmem_free_skb(sk, next_skb);
}

/* Collapse packets in the retransmit queue to make to create
 * less packets on the wire. This is only done on retransmission.
 */
static void tcp_retrans_try_collapse(struct sock *sk, struct sk_buff *to,
		int space)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = to, *tmp;
	bool first = true;

	if (!*orig_sysctl_tcp_retrans_collapse)
		return;
	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)
		return;

	tcp_for_write_queue_from_safe(skb, tmp, sk) {
		if (!tcp_can_collapse(sk, skb))
			break;

		space -= skb->len;

		if (first) {
			first = false;
			continue;
		}

		if (space < 0)
			break;
		/* Punt if not enough space exists in the first SKB for
		 * the data in the second
		 */
		if (skb->len > skb_availroom(to))
			break;

		if (after(TCP_SKB_CB(skb)->end_seq, tcp_wnd_end(tp)))
			break;

		tcp_collapse_retrans(sk, to);
	}
}

int diag_tcp_rtx_synack(struct sock *sk, struct request_sock *req)
{
	const struct tcp_request_sock_ops *af_ops = tcp_rsk(req)->af_specific;
	struct flowi fl;
	int res;

	res = af_ops->send_synack(sk, NULL, &fl, req, 0, NULL);
	if (!res) {
		TCP_INC_STATS_BH(sock_net(sk), TCP_MIB_RETRANSSEGS);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPSYNRETRANS);
		/* launch */
		trace_retransmit_synack(sk, req);
	}

	return res;
}

/* This retransmits one SKB.  Policy decisions and retransmit queue
 * state updates are done by the caller.  Returns non-zero if an
 * error occurred which prevented the send.
 */
int diag__tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	unsigned int cur_mss;
	int err;

	/* Inconslusive MTU probe */
	if (icsk->icsk_mtup.probe_size) {
		icsk->icsk_mtup.probe_size = 0;
	}

	/* Do not sent more than we queued. 1/4 is reserved for possible
	 * copying overhead: fragmentation, tunneling, mangling etc.
	 */
	if (atomic_read(&sk->sk_wmem_alloc) >
			min(sk->sk_wmem_queued + (sk->sk_wmem_queued >> 2), sk->sk_sndbuf))
		return -EAGAIN;

	if (skb_still_in_host_queue(sk, skb))
		return -EBUSY;

	if (before(TCP_SKB_CB(skb)->seq, tp->snd_una)) {
#if defined(CENTOS_3_10_1062) || defined(CENTOS_3_10_1127)
        if (unlikely(before(TCP_SKB_CB(skb)->end_seq, tp->snd_una))) {
            WARN_ON_ONCE(1);
            return -EINVAL;
        }
#else
		if (before(TCP_SKB_CB(skb)->end_seq, tp->snd_una))
			BUG();
#endif
		if (orig_tcp_trim_head(sk, skb, tp->snd_una - TCP_SKB_CB(skb)->seq))
			return -ENOMEM;
	}

	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */

	cur_mss = orig_tcp_current_mss(sk);

	/* If receiver has shrunk his window, and skb is out of
	 * new window, do not retransmit it. The exception is the
	 * case, when window is shrunk to zero. In this case
	 * our retransmit serves as a zero window probe.
	 */
	if (!before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp)) &&
			TCP_SKB_CB(skb)->seq != tp->snd_una)
		return -EAGAIN;

	if (skb->len > cur_mss) {
		if (orig_tcp_fragment(sk, skb, cur_mss, cur_mss))
			return -ENOMEM; /* We'll try again later. */
	} else {
		int oldpcount = tcp_skb_pcount(skb);

		if (unlikely(oldpcount > 1)) {
			if (skb_unclone(skb, GFP_ATOMIC))
				return -ENOMEM;
			orig_tcp_init_tso_segs(sk, skb, cur_mss);
			orig_tcp_adjust_pcount(sk, skb, oldpcount - tcp_skb_pcount(skb));
		}
	}

	tcp_retrans_try_collapse(sk, skb, cur_mss);

	/* Make a copy, if the first transmission SKB clone we made
	 * is still in somebody's hands, else make a clone.
	 */

	/* make sure skb->data is aligned on arches that require it
	 * and check if ack-trimming & collapsing extended the headroom
	 * beyond what csum_start can cover.
	 */
	if (unlikely((NET_IP_ALIGN && ((unsigned long)skb->data & 3)) ||
				skb_headroom(skb) >= 0xFFFF)) {
#if defined(CENTOS_3_10_1062) || defined(CENTOS_3_10_1127)
        struct sk_buff *nskb;

        skb_mstamp_get(&skb->skb_mstamp);
        nskb = __pskb_copy(skb, MAX_TCP_HEADER, GFP_ATOMIC);
        err = nskb ? orig_tcp_transmit_skb(sk, nskb, 0, GFP_ATOMIC) :
                 -ENOBUFS;
#else
		struct sk_buff *nskb = __pskb_copy(skb, MAX_TCP_HEADER,
				GFP_ATOMIC);
		err = nskb ? orig_tcp_transmit_skb(sk, nskb, 0, GFP_ATOMIC) :
			-ENOBUFS;
#endif
	} else {
		err = orig_tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
	}

	if (likely(!err)) {
		TCP_SKB_CB(skb)->sacked |= TCPCB_EVER_RETRANS;
		/* Update global TCP statistics. */
		TCP_INC_STATS(sock_net(sk), TCP_MIB_RETRANSSEGS);
		if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)
			NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPSYNRETRANS);
		tp->total_retrans++;

		/* launch */
		trace_retransmit_skb(sk, skb);
	}
	return err;
}

int new_tcp_rtx_synack(struct sock *sk, struct request_sock *req)
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
	ret = diag_tcp_rtx_synack(sk, req);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

int new___tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb)
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
	ret = diag__tcp_retransmit_skb(sk, skb);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

static int __activate_tcp_retrans(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&tcp_retrans_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	tcp_retrans_alloced = 1;

	JUMP_CHECK(tcp_rtx_synack);
	JUMP_CHECK(__tcp_retransmit_skb);

	clean_data();
	atomic64_set(&diag_alloc_count, 0);
	get_online_cpus();
	mutex_lock(orig_text_mutex);
	JUMP_INSTALL(tcp_rtx_synack);
	JUMP_INSTALL(__tcp_retransmit_skb);
	mutex_unlock(orig_text_mutex);
	put_online_cpus();

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_tcp_retrans(void)
{
	get_online_cpus();
	mutex_lock(orig_text_mutex);
	JUMP_REMOVE(tcp_rtx_synack);
	JUMP_REMOVE(__tcp_retransmit_skb);
	mutex_unlock(orig_text_mutex);
	put_online_cpus();

	synchronize_sched();
	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0)
	{
		msleep(10);
	}

	clean_data();
}

static int lookup_syms(void)
{
	LOOKUP_SYMS(sysctl_tcp_retrans_collapse);
	LOOKUP_SYMS(tcp_adjust_pcount);
	LOOKUP_SYMS(tcp_init_tso_segs);
	LOOKUP_SYMS(tcp_adjust_pcount);
	LOOKUP_SYMS(tcp_transmit_skb);
	LOOKUP_SYMS(tcp_trim_head);
	LOOKUP_SYMS(tcp_fragment);
	LOOKUP_SYMS(tcp_current_mss);

	LOOKUP_SYMS(tcp_rtx_synack);
	LOOKUP_SYMS(__tcp_retransmit_skb);

	return 0;
}

static void jump_init(void)
{
	JUMP_INIT(tcp_rtx_synack);
	JUMP_INIT(__tcp_retransmit_skb);
}

static void do_dump(void)
{
	unsigned long flags;
	struct list_head header;
	struct rb_node *node;
	struct tcp_retrans_summary summary;
	struct tcp_retrans_detail detail;

	INIT_LIST_HEAD(&header);
	spin_lock_irqsave(&diag_tcp_retrans_tree_lock, flags);

	for (node = rb_first(&diag_tcp_retrans_tree); node; node = rb_next(node)) {
		struct diag_tcp_retrans *this = container_of(node,
				struct diag_tcp_retrans, rb_node);

		rb_erase(&this->rb_node, &diag_tcp_retrans_tree);
		INIT_LIST_HEAD(&this->list);
		list_add_tail(&this->list, &header);
	}
	diag_tcp_retrans_tree = RB_ROOT;

	spin_unlock_irqrestore(&diag_tcp_retrans_tree_lock, flags);

	synchronize_sched();

	summary.et_type = et_tcp_retrans_summary;
	summary.alloc_count = atomic64_read(&diag_alloc_count);
	summary.nr_tcp_retransmit_skb = atomic64_read(&diag_nr_tcp_retransmit_skb);
	summary.nr_tcp_rtx_synack = atomic64_read(&diag_nr_tcp_rtx_synack);
	summary.tcp_dupack = atomic64_read(&diag_tcp_dupack);
	summary.tcp_send_dupack = atomic64_read(&diag_tcp_send_dupack);
	diag_variant_buffer_spin_lock(&tcp_retrans_variant_buffer, flags);
	diag_variant_buffer_reserve(&tcp_retrans_variant_buffer, sizeof(struct tcp_retrans_summary));
	diag_variant_buffer_write_nolock(&tcp_retrans_variant_buffer, &summary, sizeof(struct tcp_retrans_summary));
	diag_variant_buffer_seal(&tcp_retrans_variant_buffer);
	diag_variant_buffer_spin_unlock(&tcp_retrans_variant_buffer, flags);

	detail.et_type = et_tcp_retrans_detail;
	while (!list_empty(&header)) {
		struct diag_tcp_retrans *this = list_first_entry(&header, struct diag_tcp_retrans, list);

		detail.src_addr = this->src_addr;
		detail.src_port = this->src_port;
		detail.dest_addr = this->dest_addr;
		detail.dest_port = this->dest_port;
		detail.syncack_count = this->syncack_count;
		detail.skb_count = this->skb_count;

		diag_variant_buffer_spin_lock(&tcp_retrans_variant_buffer, flags);
		diag_variant_buffer_reserve(&tcp_retrans_variant_buffer, sizeof(struct tcp_retrans_detail));
		diag_variant_buffer_write_nolock(&tcp_retrans_variant_buffer, &detail, sizeof(struct tcp_retrans_detail));
		diag_variant_buffer_seal(&tcp_retrans_variant_buffer);
		diag_variant_buffer_spin_unlock(&tcp_retrans_variant_buffer, flags);

		list_del_init(&this->list);
		kfree(this);
	}

	atomic64_set(&diag_nr_tcp_retransmit_skb, 0);
	atomic64_set(&diag_nr_tcp_rtx_synack, 0);
	atomic64_set(&diag_tcp_dupack, 0);
}

int activate_tcp_retrans(void)
{
	if (!tcp_retrans_settings.activated)
		tcp_retrans_settings.activated = __activate_tcp_retrans();

	return tcp_retrans_settings.activated;
}

int deactivate_tcp_retrans(void)
{
	if (tcp_retrans_settings.activated)
		__deactivate_tcp_retrans();
	tcp_retrans_settings.activated = 0;

	return 0;
}

int tcp_retrans_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_tcp_retrans_settings settings;

	switch (id) {
	case DIAG_TCP_RETRANS_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_tcp_retrans_settings)) {
			ret = -EINVAL;
		} else if (tcp_retrans_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				tcp_retrans_settings = settings;
			}
		}
		break;
	case DIAG_TCP_RETRANS_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_tcp_retrans_settings)) {
			ret = -EINVAL;
		} else {
			settings.activated = tcp_retrans_settings.activated;
			settings.verbose = tcp_retrans_settings.verbose;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_TCP_RETRANS_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!tcp_retrans_alloced) {
			ret = -EINVAL;
		} else {
			do_dump();
			ret = copy_to_user_variant_buffer(&tcp_retrans_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("tcp-retrans");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_tcp_retrans(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

int diag_tcp_retrans_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&tcp_retrans_variant_buffer, 1 * 1024 * 1024);
	jump_init();

	if (tcp_retrans_settings.activated)
		tcp_retrans_settings.activated = __activate_tcp_retrans();

	return 0;
}

void diag_tcp_retrans_exit(void)
{
	if (tcp_retrans_settings.activated)
		__deactivate_tcp_retrans();
	tcp_retrans_settings.activated = 0;
	destroy_diag_variant_buffer(&tcp_retrans_variant_buffer);

	return;
}
#endif
