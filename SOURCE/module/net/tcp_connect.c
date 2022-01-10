/*
 * Linux内核诊断工具--内核态tcp-connect功能
 *
 * Copyright (C) 2022 Alibaba Ltd.
 *
 * 作者: Yang Wei <albin.yangwei@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <linux/rtc.h>
#include <linux/time.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/tcp.h>
#include <net/protocol.h>

#include "uapi/ali_diagnose.h"
#include "uapi/tcp_connect.h"
#include "pub/variant_buffer.h"
#include "pub/kprobe.h"
#include "internal.h"

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 9, 0)

static struct kprobe kprobe_tcp_connect;
static struct kretprobe kretprobe_inet_csk_accept;
static struct kprobe kprobe_tcp_close;

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
static struct diag_variant_buffer tcp_connect_variant_buffer;
static struct diag_tcp_connect_settings tcp_connect_settings;
static unsigned int tcp_connect_alloced;

static int kprobe_tcp_connect_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct tcp_connect_detail detail;
	unsigned long flags;
	struct sock *sk;

	atomic64_inc(&diag_nr_running);

	detail.et_type = et_tcp_connect_detail;
	detail.con_type = TCPCONNECT;
	do_diag_gettimeofday(&detail.tv);

	sk = (struct sock *) ORIG_PARAM1(regs);
	detail.raddr = sk->sk_daddr;
	detail.laddr = sk->sk_rcv_saddr;
	detail.rport = ntohs(sk->sk_dport);
	detail.lport = sk->sk_num;
	strncpy(detail.comm, current->comm, TASK_COMM_LEN);
	detail.comm[TASK_COMM_LEN - 1] = 0;
	diag_cgroup_name(current, detail.cgroup, CGROUP_NAME_LEN, 0);
	detail.cgroup[CGROUP_NAME_LEN - 1] = 0;

	diag_variant_buffer_spin_lock(&tcp_connect_variant_buffer, flags);
	diag_variant_buffer_reserve(&tcp_connect_variant_buffer, sizeof(struct tcp_connect_detail));
	diag_variant_buffer_write_nolock(&tcp_connect_variant_buffer, &detail, sizeof(struct tcp_connect_detail));
	diag_variant_buffer_seal(&tcp_connect_variant_buffer);
	diag_variant_buffer_spin_unlock(&tcp_connect_variant_buffer, flags);

	atomic64_dec(&diag_nr_running);

	return 0;
}

static int kretprobe_inet_csk_accept_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tcp_connect_detail detail;
	unsigned long flags;
	struct sock *sk;

	sk = (struct sock *)regs_return_value(regs);
	if (!sk)
		return 0;

	atomic64_inc(&diag_nr_running);

	detail.et_type = et_tcp_connect_detail;
	detail.con_type = TCPACCEPT;
	do_diag_gettimeofday(&detail.tv);

	detail.raddr = sk->sk_daddr;
	detail.laddr = sk->sk_rcv_saddr;
	detail.rport = ntohs(sk->sk_dport);
	detail.lport = sk->sk_num;

	strncpy(detail.comm, current->comm, TASK_COMM_LEN);
	detail.comm[TASK_COMM_LEN - 1] = 0;
	diag_cgroup_name(current, detail.cgroup, CGROUP_NAME_LEN, 0);
	detail.cgroup[CGROUP_NAME_LEN - 1] = 0;

	diag_variant_buffer_spin_lock(&tcp_connect_variant_buffer, flags);
	diag_variant_buffer_reserve(&tcp_connect_variant_buffer, sizeof(struct tcp_connect_detail));
	diag_variant_buffer_write_nolock(&tcp_connect_variant_buffer, &detail, sizeof(struct tcp_connect_detail));
	diag_variant_buffer_seal(&tcp_connect_variant_buffer);
	diag_variant_buffer_spin_unlock(&tcp_connect_variant_buffer, flags);

	atomic64_dec(&diag_nr_running);

	return 0;
}

static int kprobe_tcp_close_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct tcp_connect_detail detail;
	unsigned long flags; 
	struct sock *sk;

	atomic64_inc(&diag_nr_running);

	detail.et_type = et_tcp_connect_detail;
	detail.con_type = TCPCLOSE;
	do_diag_gettimeofday(&detail.tv);

	sk = (struct sock *) ORIG_PARAM1(regs);
	detail.raddr = sk->sk_daddr;
	detail.laddr = sk->sk_rcv_saddr;
	detail.rport = ntohs(sk->sk_dport);
	detail.lport = sk->sk_num;
	strncpy(detail.comm, current->comm, TASK_COMM_LEN);
	detail.comm[TASK_COMM_LEN - 1] = 0;
	diag_cgroup_name(current, detail.cgroup, CGROUP_NAME_LEN, 0);
	detail.cgroup[CGROUP_NAME_LEN - 1] = 0;

	diag_variant_buffer_spin_lock(&tcp_connect_variant_buffer, flags);
	diag_variant_buffer_reserve(&tcp_connect_variant_buffer, sizeof(struct tcp_connect_detail));
	diag_variant_buffer_write_nolock(&tcp_connect_variant_buffer, &detail, sizeof(struct tcp_connect_detail));
	diag_variant_buffer_seal(&tcp_connect_variant_buffer);
	diag_variant_buffer_spin_unlock(&tcp_connect_variant_buffer, flags);

        atomic64_dec(&diag_nr_running);

	return 0;
}

static int __activate_tcp_connect(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&tcp_connect_variant_buffer);
	if (ret)
		goto out_variant_buffer;

	tcp_connect_alloced = 1;

	ret = hook_kprobe(&kprobe_tcp_connect, "tcp_connect",
			  kprobe_tcp_connect_pre, NULL);
	if (ret) {
		printk("aprof: failed to hook tcp_connect, ret=%d\n", ret);
		goto out_variant_buffer;;
	}

	ret = hook_kretprobe(&kretprobe_inet_csk_accept, "inet_csk_accept",
			     NULL, kretprobe_inet_csk_accept_return, 0);
	if (ret) {
		printk("aprof: failed to hoot inet_csk_accept, ret:%d\n", ret);
		goto err_unhook_tcp_connect;
	}

	ret = hook_kprobe(&kprobe_tcp_close, "tcp_close",
			  kprobe_tcp_close_pre, NULL);
	if (ret) {
		printk("aprof: failed to hoot tcp_close, ret:%d\n", ret);
		goto err_unhook_inet_csk_accept;
	}

	return 1;


err_unhook_inet_csk_accept:
	unhook_kretprobe(&kretprobe_inet_csk_accept);
err_unhook_tcp_connect:
	unhook_kprobe(&kprobe_tcp_connect);
out_variant_buffer:
	return 0;
}

static void __deactivate_tcp_connect(void)
{
	unhook_kprobe(&kprobe_tcp_connect);
	unhook_kretprobe(&kretprobe_inet_csk_accept);
	unhook_kprobe(&kprobe_tcp_close);

	synchronize_sched();
	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0)
		msleep(20);
}

int activate_tcp_connect(void)
{
	if (!tcp_connect_settings.activated)
		tcp_connect_settings.activated = __activate_tcp_connect();

	return tcp_connect_settings.activated;
}

int deactivate_tcp_connect(void)
{
	if (tcp_connect_settings.activated)
		__deactivate_tcp_connect();

	tcp_connect_settings.activated = 0;
	return 0;
}

int tcp_connect_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_tcp_connect_settings settings;

	switch (id) {
	case DIAG_TCP_CONNECT_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_tcp_connect_settings)) {
			ret = -EINVAL;
		} else if (tcp_connect_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				tcp_connect_settings = settings;
			}
		}
		break;
	case DIAG_TCP_CONNECT_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_tcp_connect_settings)) {
			ret = -EINVAL;
		} else {
			settings.activated = tcp_connect_settings.activated;
			settings.verbose = tcp_connect_settings.verbose;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_TCP_CONNECT_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!tcp_connect_alloced) {
			ret = -EINVAL;
		} else {
			ret = copy_to_user_variant_buffer(&tcp_connect_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("tcp-connect");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_tcp_connect(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_tcp_connect_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_TCP_CONNECT_SET:
		if (tcp_connect_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_tcp_connect_settings));
			if (!ret) {
				tcp_connect_settings = settings;
			}
		}
		break;
	case CMD_TCP_CONNECT_SETTINGS:
		settings.activated = tcp_connect_settings.activated;
		settings.verbose = tcp_connect_settings.verbose;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_tcp_connect_settings));
		break;
	case CMD_TCP_CONNECT_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));

		if (!tcp_connect_alloced) {
			ret = -EINVAL;
		} else if (!ret){
			ret = copy_to_user_variant_buffer(&tcp_connect_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("tcp-connect");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_net_tcp_connect_init(void)
{
	init_diag_variant_buffer(&tcp_connect_variant_buffer, 2 * 1024 * 1024);

	if (tcp_connect_settings.activated)
		activate_tcp_connect();

	return 0;
}


void diag_net_tcp_connect_exit(void)
{
	if (tcp_connect_settings.activated)
		deactivate_tcp_connect();
	tcp_connect_settings.activated = 0;

	destroy_diag_variant_buffer(&tcp_connect_variant_buffer);
	return;
}

#else

int diag_net_tcp_connect_init(void)
{
	return 0;
}

void diag_net_tcp_connect_exit(void)
{
}

int activate_tcp_connect(void)
{
	return 0;
}

int deactivate_tcp_connect(void)
{
	return 0;
}

int tcp_connect_syscall(struct pt_regs *regs, long id)
{
	return 0;
}

long diag_ioctl_tcp_connect(unsigned int cmd, unsigned long arg)
{
	return 0;
}

#endif

