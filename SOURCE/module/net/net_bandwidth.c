/*
 * Linux内核诊断工具--内核态net-bandwidth功能
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 * 作者: Wllabs <wllabs@163.com>
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

#include "uapi/net_bandwidth.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0) && !defined(XBY_UBUNTU_1604) \
	&& !defined(CENTOS_3_10_123_9_3)

__maybe_unused static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_net_bandwidth_settings net_bandwidth_settings;
static int net_bandwidth_alloced = 0;

struct conn_info
{
	int protocol;
	int saddr;
	int sport;
	int daddr;
	int dport;
	unsigned long conn_key;

	atomic64_t packages[NET_COUNT];
	atomic64_t sum_truesize[NET_COUNT];

	struct list_head list;
	struct rcu_head rcu_head;
};

static struct radix_tree_root conn_tree;
static DEFINE_SPINLOCK(tree_lock);
static DEFINE_MUTEX(conn_mutex);

static struct diag_variant_buffer net_bandwidth_variant_buffer;

static struct kprobe kprobe___netif_receive_skb_core;

__maybe_unused static void move_to_list(struct list_head *conn_list)
{
	int i;
	unsigned long flags;
	struct conn_info *conns[NR_BATCH];
	struct conn_info *conn_info;
	int nr_found;
	unsigned long pos = 0;

	INIT_LIST_HEAD(conn_list);

	mutex_lock(&conn_mutex);
	spin_lock_irqsave(&tree_lock, flags);
	do {
		nr_found = radix_tree_gang_lookup(&conn_tree, (void **)conns, pos, NR_BATCH);

		for (i = 0; i < nr_found; i++) {
			conn_info = conns[i];
			radix_tree_delete(&conn_tree, (unsigned long)conn_info->conn_key);
			pos = (unsigned long)conn_info->conn_key + 1;
			INIT_LIST_HEAD(&conn_info->list);
			list_add_tail(&conn_info->list, conn_list);
		}
	} while (nr_found > 0);
	spin_unlock_irqrestore(&tree_lock, flags);
	mutex_unlock(&conn_mutex);
}

static void free_conn_info(struct rcu_head *rcu)
{
	struct conn_info *this = container_of(rcu, struct conn_info, rcu_head);

	kfree(this);
}

__maybe_unused static void diag_free_list(struct list_head *conn_list)
{
	while (!list_empty(conn_list))
	{
		struct conn_info *this = list_first_entry(conn_list, struct conn_info, list);

		list_del_init(&this->list);
		call_rcu(&this->rcu_head, free_conn_info);
	}
}

__maybe_unused static void clean_data(void)
{
	struct list_head header;

	move_to_list(&header);

	diag_free_list(&header);
}

__maybe_unused static struct conn_info *find_alloc_desc(int direct,
	__u8	protocol,
	unsigned int saddr,
	unsigned int sport,
	unsigned int daddr,
	unsigned int dport)
{
	struct conn_info *info = NULL;
	u64 conn_key;

	if (direct == NET_IN && !net_bandwidth_settings.arrange_by_peer)
		conn_key = (u64)daddr << 32 | dport;
	else
		conn_key = (u64)saddr << 32 | sport;

	info = radix_tree_lookup(&conn_tree, conn_key);
	if (!info) {
		info = kmalloc(sizeof(struct conn_info), GFP_ATOMIC | __GFP_ZERO);
		if (info) {
			unsigned long flags;
			struct conn_info *tmp;

			info->conn_key = conn_key;
			info->protocol = protocol;
			info->saddr = saddr;
			info->sport = sport;
			info->daddr = daddr;
			info->dport = dport;

			INIT_LIST_HEAD(&info->list);

			spin_lock_irqsave(&tree_lock, flags);
			tmp = radix_tree_lookup(&conn_tree, conn_key);
			if (tmp) {
				kfree(info);
				info = tmp;
			} else {
				radix_tree_insert(&conn_tree, conn_key, info);
			}
			spin_unlock_irqrestore(&tree_lock, flags);
		}
	}

	return info;
}

static void inspect_packet(const struct sk_buff *skb, const struct iphdr *iphdr, enum net_bandwidth_step step)
{
	int source = 0;
	int dest = 0;
	struct conn_info *conn_info;

	if (step >= NET_COUNT)
		return;

	if (iphdr->protocol == IPPROTO_UDP)
	{
		struct udphdr *uh;

		uh = (void *)iphdr + iphdr->ihl * 4;
		source = be16_to_cpu(uh->source);
		dest = be16_to_cpu(uh->dest);
	}
	else if (iphdr->protocol == IPPROTO_TCP)
	{
		struct tcphdr *th;

		th = (void *)iphdr + iphdr->ihl * 4;
		source = be16_to_cpu(th->source);
		dest = be16_to_cpu(th->dest);
	} else
		return;

	conn_info = find_alloc_desc(step <= NET_RECV_SKB ? NET_IN : NET_OUT,
		iphdr->protocol, iphdr->saddr, source, iphdr->daddr, dest);
	if (!conn_info)
		return;

	atomic64_inc(&conn_info->packages[step]);
	atomic64_add(skb->truesize, &conn_info->sum_truesize[step]);
}

static void trace_net_dev_xmit_hit(void *ignore, struct sk_buff *skb,
								   int rc, struct net_device *dev, unsigned int skb_len)
{
	struct iphdr *iphdr;

	if (!net_bandwidth_settings.activated)
		return;

	if (rc != NETDEV_TX_OK)
		return;

	iphdr = ip_hdr(skb);
	inspect_packet(skb, iphdr, NET_SEND_SKB);
}

static int kprobe___netif_receive_skb_core_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct sk_buff *skb = (void *)ORIG_PARAM1(regs);
	struct iphdr *iphdr;

	if (!net_bandwidth_settings.activated)
		return 0;

	if (skb->protocol != cpu_to_be16(ETH_P_IP))
		return 0;

	iphdr = (struct iphdr *)skb->data;
	inspect_packet(skb, iphdr, NET_RECV_SKB);

	return 0;
}

int __activate_net_bandwidth(void)
{
	int ret = 1;

	ret = alloc_diag_variant_buffer(&net_bandwidth_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	net_bandwidth_alloced = 1;

	clean_data();

	hook_tracepoint("net_dev_xmit", trace_net_dev_xmit_hit, NULL);

	hook_kprobe(&kprobe___netif_receive_skb_core, "__netif_receive_skb_core",
				kprobe___netif_receive_skb_core_pre, NULL);

	get_online_cpus();
	mutex_lock(orig_text_mutex);
	mutex_unlock(orig_text_mutex);
	put_online_cpus();

	return 1;
out_variant_buffer:
	return 0;
}

void __deactivate_net_bandwidth(void)
{
	unhook_tracepoint("net_dev_xmit", trace_net_dev_xmit_hit, NULL);

	unhook_kprobe(&kprobe___netif_receive_skb_core);

	get_online_cpus();
	mutex_lock(orig_text_mutex);
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
	return 0;
}

int activate_net_bandwidth(void)
{
	if (!net_bandwidth_settings.activated)
		net_bandwidth_settings.activated = __activate_net_bandwidth();

	return net_bandwidth_settings.activated;
}

int deactivate_net_bandwidth(void)
{
	if (net_bandwidth_settings.activated)
		__deactivate_net_bandwidth();
	net_bandwidth_settings.activated = 0;

	return 0;
}

static void do_dump(void)
{
	struct conn_info *this;
	struct list_head header;
	int i;
	struct net_bandwidth_detail detail;
	unsigned long flags;

	move_to_list(&header);

	list_for_each_entry(this, &header, list)
	{
		detail.et_type = et_net_bandwidth_detail;
		detail.protocol = this->protocol;
		detail.saddr = this->saddr;
		detail.sport = this->sport;
		detail.daddr = this->daddr;
		detail.dport = this->dport;

		for (i = 0; i < NET_COUNT; i++) {
			detail.packages[i] = atomic64_read(&this->packages[i]);
			detail.sum_truesize[i] = atomic64_read(&this->sum_truesize[i]);
		}
		diag_variant_buffer_spin_lock(&net_bandwidth_variant_buffer, flags);
		diag_variant_buffer_reserve(&net_bandwidth_variant_buffer, sizeof(struct net_bandwidth_detail));
		diag_variant_buffer_write_nolock(&net_bandwidth_variant_buffer, &detail, sizeof(struct net_bandwidth_detail));
		diag_variant_buffer_seal(&net_bandwidth_variant_buffer);
		diag_variant_buffer_spin_unlock(&net_bandwidth_variant_buffer, flags);
	}

	diag_free_list(&header);
}

int net_bandwidth_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_net_bandwidth_settings settings;

	switch (id) {
	case DIAG_NET_BANDWIDTH_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_net_bandwidth_settings)) {
			ret = -EINVAL;
		} else if (net_bandwidth_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				net_bandwidth_settings = settings;
			}
		}
		break;
	case DIAG_NET_BANDWIDTH_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_net_bandwidth_settings)) {
			ret = -EINVAL;
		} else {
			settings.activated = net_bandwidth_settings.activated;
			settings.verbose = net_bandwidth_settings.verbose;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_NET_BANDWIDTH_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!net_bandwidth_alloced) {
			ret = -EINVAL;
		} else {
			do_dump();
			ret = copy_to_user_variant_buffer(&net_bandwidth_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("drop-packet");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_net_bandwidth(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_net_bandwidth_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_NET_BANDWIDTH_SET:
		if (net_bandwidth_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_net_bandwidth_settings));
			if (!ret) {
				net_bandwidth_settings = settings;
			}
		}
		break;
	case CMD_NET_BANDWIDTH_SETTINGS:
		settings.activated = net_bandwidth_settings.activated;
		settings.verbose = net_bandwidth_settings.verbose;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_net_bandwidth_settings));
		break;
	case CMD_NET_BANDWIDTH_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));

		if (!net_bandwidth_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			do_dump();
			ret = copy_to_user_variant_buffer(&net_bandwidth_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("net-bandwidth");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_net_net_bandwidth_init(void)
{
	INIT_RADIX_TREE(&conn_tree, GFP_ATOMIC);

	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&net_bandwidth_variant_buffer, 20 * 1024 * 1024);

	if (net_bandwidth_settings.activated)
		net_bandwidth_settings.activated = __activate_net_bandwidth();

	return 0;
}

void diag_net_net_bandwidth_exit(void)
{
	if (net_bandwidth_settings.activated)
		deactivate_net_bandwidth();
	net_bandwidth_settings.activated = 0;
	destroy_diag_variant_buffer(&net_bandwidth_variant_buffer);

	return;
}
#else
int diag_net_net_bandwidth_init(void)
{
	return 0;
}

void diag_net_net_bandwidth_exit(void)
{
	//
}
#endif
