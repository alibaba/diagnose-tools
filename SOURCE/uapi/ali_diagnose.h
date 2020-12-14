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

#ifndef UAPI_DIAG_H
#define UAPI_DIAG_H

#include <linux/ptrace.h>
#include <linux/ioctl.h>

struct pt_regs;

#ifndef __KERNEL__
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

#define __user

static inline long diag_call_ioctl(unsigned long request, unsigned long arg)
{
	long ret = 0;
	int fd;

	fd = open("/dev/diagnose-tools", O_RDWR, 0);
	if (fd < 0) {
		printf("open /dev/diagnose-tools error!\n");
		return -EEXIST;
	}

	ret = ioctl(fd, request, arg);
	if (ret < 0) {
		printf("call cmd %lx fail, ret is %ld\n", request, ret);
		goto err;
	}

err:
	close(fd);

	return ret;
}

extern unsigned long run_in_host;
#endif

#define XBY_VERSION					"diagnose-tools 2.1-rc3"
#define DIAG_VERSION		((2 << 24) | (1 << 16) | 0x0003)

#define DIAG_DEV_NAME "diagnose-tools"

#define DIAG_IOCTL_TYPE_TEST 1
#define DIAG_IOCTL_TYPE_VERSION (DIAG_IOCTL_TYPE_TEST + 1)
#define DIAG_IOCTL_TYPE_PUPIL (DIAG_IOCTL_TYPE_VERSION + 1)
#define DIAG_IOCTL_TYPE_RUN_TRACE (DIAG_IOCTL_TYPE_PUPIL + 1)
#define DIAG_IOCTL_TYPE_LOAD_MONITOR (DIAG_IOCTL_TYPE_RUN_TRACE + 1)
#define DIAG_IOCTL_TYPE_PERF (DIAG_IOCTL_TYPE_LOAD_MONITOR + 1)
#define DIAG_IOCTL_TYPE_EXIT_MONITOR (DIAG_IOCTL_TYPE_PERF + 1)
#define DIAG_IOCTL_TYPE_TCP_RETRANS (DIAG_IOCTL_TYPE_EXIT_MONITOR + 1)
#define DIAG_IOCTL_TYPE_RW_TOP (DIAG_IOCTL_TYPE_TCP_RETRANS + 1)
#define DIAG_IOCTL_TYPE_SYS_DELAY (DIAG_IOCTL_TYPE_RW_TOP + 1)
#define DIAG_IOCTL_TYPE_IRQ_DELAY (DIAG_IOCTL_TYPE_SYS_DELAY + 1)
#define DIAG_IOCTL_TYPE_MUTEX_MONITOR (DIAG_IOCTL_TYPE_IRQ_DELAY + 1)
#define DIAG_IOCTL_TYPE_UTILIZATION (DIAG_IOCTL_TYPE_MUTEX_MONITOR + 1)
#define DIAG_IOCTL_TYPE_ALLOC_TOP (DIAG_IOCTL_TYPE_UTILIZATION + 1)
#define DIAG_IOCTL_TYPE_DROP_PACKET (DIAG_IOCTL_TYPE_ALLOC_TOP + 1)
#define DIAG_IOCTL_TYPE_FS_ORPHAN (DIAG_IOCTL_TYPE_DROP_PACKET + 1)
#define DIAG_IOCTL_TYPE_EXEC_MONITOR (DIAG_IOCTL_TYPE_FS_ORPHAN + 1)
#define DIAG_IOCTL_TYPE_FS_SHM (DIAG_IOCTL_TYPE_EXEC_MONITOR + 1)
#define DIAG_IOCTL_TYPE_IRQ_STATS (DIAG_IOCTL_TYPE_FS_SHM + 1)
#define DIAG_IOCTL_TYPE_KPROBE (DIAG_IOCTL_TYPE_IRQ_STATS + 1)
#define DIAG_IOCTL_TYPE_MM_LEAK (DIAG_IOCTL_TYPE_KPROBE + 1)
#define DIAG_IOCTL_TYPE_IRQ_TRACE (DIAG_IOCTL_TYPE_MM_LEAK + 1)
#define DIAG_IOCTL_TYPE_SCHED_DELAY (DIAG_IOCTL_TYPE_IRQ_TRACE + 1)
#define DIAG_IOCTL_TYPE_REBOOT (DIAG_IOCTL_TYPE_SCHED_DELAY + 1)
#define DIAG_IOCTL_TYPE_PING_DELAY (DIAG_IOCTL_TYPE_REBOOT + 1)
#define DIAG_IOCTL_TYPE_UPROBE (DIAG_IOCTL_TYPE_PING_DELAY + 1)
#define DIAG_IOCTL_TYPE_SYS_COST (DIAG_IOCTL_TYPE_UPROBE + 1)
#define DIAG_IOCTL_TYPE_FS_CACHE (DIAG_IOCTL_TYPE_SYS_COST + 1)
#define DIAG_IOCTL_TYPE_HIGH_ORDER (DIAG_IOCTL_TYPE_FS_CACHE + 1)
#define DIAG_IOCTL_TYPE_D (DIAG_IOCTL_TYPE_HIGH_ORDER + 1)
#define DIAG_IOCTL_TYPE_NET_BANDWIDTH (DIAG_IOCTL_TYPE_D + 1)
#define DIAG_IOCTL_TYPE_SIG_INFO (DIAG_IOCTL_TYPE_NET_BANDWIDTH + 1)
#define DIAG_IOCTL_TYPE_END (DIAG_IOCTL_TYPE_SIG_INFO + 1)

long diag_ioctl_sys_delay(unsigned int cmd, unsigned long arg);
long diag_ioctl_sys_cost(unsigned int cmd, unsigned long arg);
long diag_ioctl_sched_delay(unsigned int cmd, unsigned long arg);
long diag_ioctl_irq_delay(unsigned int cmd, unsigned long arg);
long diag_ioctl_irq_stats(unsigned int cmd, unsigned long arg);
long diag_ioctl_irq_trace(unsigned int cmd, unsigned long arg);
long diag_ioctl_load_monitor(unsigned int cmd, unsigned long arg);
long diag_ioctl_run_trace(unsigned int cmd, unsigned long arg);
long diag_ioctl_perf(unsigned int cmd, unsigned long arg);
long diag_ioctl_kprobe(unsigned int cmd, unsigned long arg);
long diag_ioctl_uprobe(unsigned int cmd, unsigned long arg);
long diag_ioctl_utilization(unsigned int cmd, unsigned long arg);
long diag_ioctl_exit_monitor(unsigned int cmd, unsigned long arg);
long diag_ioctl_mutex_monitor(unsigned int cmd, unsigned long arg);
long diag_ioctl_exec_monitor(unsigned int cmd, unsigned long arg);
long diag_ioctl_alloc_top(unsigned int cmd, unsigned long arg);
long diag_ioctl_high_order(unsigned int cmd, unsigned long arg);
long diag_ioctl_drop_packet(unsigned int cmd, unsigned long arg);
long diag_ioctl_tcp_retrans(unsigned int cmd, unsigned long arg);
long diag_ioctl_ping_delay(unsigned int cmd, unsigned long arg);
long diag_ioctl_rw_top(unsigned int cmd, unsigned long arg);
long diag_ioctl_fs_shm(unsigned int cmd, unsigned long arg);
long diag_ioctl_fs_orphan(unsigned int cmd, unsigned long arg);
long diag_ioctl_fs_cache(unsigned int cmd, unsigned long arg);
long diag_ioctl_mm_leak(unsigned int cmd, unsigned long arg);
long diag_ioctl_pupil_task(unsigned int cmd, unsigned long arg);
long diag_ioctl_reboot(unsigned int cmd, unsigned long arg);
long diag_ioctl_net_bandwidth(unsigned int cmd, unsigned long arg);
long diag_ioctl_sig_info(unsigned int cmd, unsigned long arg);

struct diag_ioctl_test {
	int in;
	int out;
};

#ifndef __KERNEL__
#define __user
#endif
struct diag_ioctl_dump_param {
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
};

struct diag_ioctl_dump_param_cycle {
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	size_t __user cycle;
};

#define DIAG_IOCTL_TEST_IOCTL _IOWR(DIAG_IOCTL_TYPE_TEST, 1, struct diag_ioctl_test)
#define DIAG_IOCTL_VERSION_ALL _IO(DIAG_IOCTL_TYPE_VERSION, 1)

#define BACKTRACE_DEPTH 30
#define DIAG_USER_STACK_SIZE (16 * 1024)
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif
#define CGROUP_NAME_LEN 32
#define PROCESS_CHAINS_COUNT 10
#define PROCESS_ARGV_LEN 128

#define DIAG_PATH_LEN 100

#define DIAG_NR_SOFTIRQS 15

#include "uapi/variant_buffer.h"

#define DIAG_UPROBE_MAX_PARAMS 5

#define DIAG_BASE_SYSCALL 761203000
#define DIAG_SYSCALL_INTERVAL 50
#define DIAG_EVENT_TYPE_INTERVAL 50
/**
 * 有几个被占用，从10开始
 */
#define DIAG_SYSCALL_VERSION (DIAG_BASE_SYSCALL + 10)
/// 000
#define DIAG_BASE_SYSCALL_PUPIL \
	(DIAG_BASE_SYSCALL + DIAG_SYSCALL_INTERVAL)

/// 050
#define DIAG_BASE_SYSCALL_RUN_TRACE \
	(DIAG_BASE_SYSCALL_PUPIL + DIAG_SYSCALL_INTERVAL)

/// 100
#define DIAG_BASE_SYSCALL_LOAD_MONITOR \
	(DIAG_BASE_SYSCALL_RUN_TRACE + DIAG_SYSCALL_INTERVAL)

/// 150
#define DIAG_BASE_SYSCALL_PERF \
	(DIAG_BASE_SYSCALL_LOAD_MONITOR + DIAG_SYSCALL_INTERVAL)

/// 200
#define DIAG_BASE_SYSCALL_EXIT_MONITOR \
	(DIAG_BASE_SYSCALL_PERF + DIAG_SYSCALL_INTERVAL)

/// 250
#define DIAG_BASE_SYSCALL_TCP_RETRANS \
	(DIAG_BASE_SYSCALL_EXIT_MONITOR + DIAG_SYSCALL_INTERVAL)

/// 300
#define DIAG_BASE_SYSCALL_RW_TOP \
	(DIAG_BASE_SYSCALL_TCP_RETRANS + DIAG_SYSCALL_INTERVAL)

/// 350
#define DIAG_BASE_SYSCALL_SYS_DELAY \
	(DIAG_BASE_SYSCALL_RW_TOP + DIAG_SYSCALL_INTERVAL)

/// 400
#define DIAG_BASE_SYSCALL_IRQ_DELAY \
	(DIAG_BASE_SYSCALL_SYS_DELAY + DIAG_SYSCALL_INTERVAL)

/// 450
#define DIAG_BASE_SYSCALL_MUTEX_MONITOR \
	(DIAG_BASE_SYSCALL_IRQ_DELAY + DIAG_SYSCALL_INTERVAL)

/// 500
#define DIAG_BASE_SYSCALL_UTILIZATION \
	(DIAG_BASE_SYSCALL_MUTEX_MONITOR + DIAG_SYSCALL_INTERVAL)

/// 550
#define DIAG_BASE_SYSCALL_DUMMY3 \
	(DIAG_BASE_SYSCALL_UTILIZATION + DIAG_SYSCALL_INTERVAL)

/// 600
#define DIAG_BASE_SYSCALL_ALLOC_TOP \
	(DIAG_BASE_SYSCALL_DUMMY3 + DIAG_SYSCALL_INTERVAL)

/// 650
#define DIAG_BASE_SYSCALL_DROP_PACKET \
	(DIAG_BASE_SYSCALL_ALLOC_TOP + DIAG_SYSCALL_INTERVAL)

/// 700
#define DIAG_BASE_SYSCALL_FS_ORPHAN \
	(DIAG_BASE_SYSCALL_DROP_PACKET + DIAG_SYSCALL_INTERVAL)

/// 750
#define DIAG_BASE_SYSCALL_EXEC_MONITOR \
	(DIAG_BASE_SYSCALL_FS_ORPHAN + DIAG_SYSCALL_INTERVAL)

/// 800
#define DIAG_BASE_SYSCALL_FS_SHM \
	(DIAG_BASE_SYSCALL_EXEC_MONITOR + DIAG_SYSCALL_INTERVAL)

/// 850
#define DIAG_BASE_SYSCALL_IRQ_STATS \
	(DIAG_BASE_SYSCALL_FS_SHM + DIAG_SYSCALL_INTERVAL)

/// 900
#define DIAG_BASE_SYSCALL_KPROBE \
	(DIAG_BASE_SYSCALL_IRQ_STATS + DIAG_SYSCALL_INTERVAL)

/// 950
#define DIAG_BASE_SYSCALL_MM_LEAK \
	(DIAG_BASE_SYSCALL_KPROBE + DIAG_SYSCALL_INTERVAL)

/// 1000
#define DIAG_BASE_SYSCALL_IRQ_TRACE \
	(DIAG_BASE_SYSCALL_MM_LEAK + DIAG_SYSCALL_INTERVAL)

/// 1050
#define DIAG_BASE_SYSCALL_DUMMY1 \
	(DIAG_BASE_SYSCALL_IRQ_TRACE + DIAG_SYSCALL_INTERVAL)

/// 1100
#define DIAG_BASE_SYSCALL_DUMMY2 \
	(DIAG_BASE_SYSCALL_DUMMY1 + DIAG_SYSCALL_INTERVAL)

/// 1150
#define DIAG_BASE_SYSCALL_SCHED_DELAY \
	(DIAG_BASE_SYSCALL_DUMMY2 + DIAG_SYSCALL_INTERVAL)

/// 1200
#define DIAG_BASE_SYSCALL_REBOOT \
	(DIAG_BASE_SYSCALL_SCHED_DELAY + DIAG_SYSCALL_INTERVAL)

/// 1250
#define DIAG_BASE_SYSCALL_DUMMY4 \
	(DIAG_BASE_SYSCALL_REBOOT + DIAG_SYSCALL_INTERVAL)

/// 1300
#define DIAG_BASE_SYSCALL_PING_DELAY \
	(DIAG_BASE_SYSCALL_DUMMY4 + DIAG_SYSCALL_INTERVAL)

/// 1350
#define DIAG_BASE_SYSCALL_UPROBE \
	(DIAG_BASE_SYSCALL_PING_DELAY + DIAG_SYSCALL_INTERVAL)

/// 1400
#define DIAG_BASE_SYSCALL_SYS_COST \
	(DIAG_BASE_SYSCALL_UPROBE + DIAG_SYSCALL_INTERVAL)

/// 1450
#define DIAG_BASE_SYSCALL_FS_CACHE \
	(DIAG_BASE_SYSCALL_SYS_COST + DIAG_SYSCALL_INTERVAL)

/// 1500
#define DIAG_BASE_SYSCALL_HIGH_ORDER \
	(DIAG_BASE_SYSCALL_FS_CACHE + DIAG_SYSCALL_INTERVAL)

/// 1550
#define DIAG_BASE_SYSCALL_D \
	(DIAG_BASE_SYSCALL_HIGH_ORDER + DIAG_SYSCALL_INTERVAL)

/// 1600
#define DIAG_BASE_SYSCALL_NET_BANDWIDTH \
	(DIAG_BASE_SYSCALL_D + DIAG_SYSCALL_INTERVAL)

/// 1650
#define DIAG_BASE_SYSCALL_SIG_INFO \
	(DIAG_BASE_SYSCALL_NET_BANDWIDTH + DIAG_SYSCALL_INTERVAL)

#define DIAG_SYSCALL_END (DIAG_BASE_SYSCALL + DIAG_SYSCALL_INTERVAL * 1000)

enum diag_record_id {
	et_diag_diag = 761203000,

	et_pupil_base = et_diag_diag + DIAG_EVENT_TYPE_INTERVAL,
	et_pupil_task,
	et_pupil_dump_stack,
	et_pupil_exist_pid,
	et_pupil_exist_comm,

	et_alloc_load_base = et_pupil_base + DIAG_EVENT_TYPE_INTERVAL,
	et_alloc_load_summary,
	et_alloc_load_detail,
	et_alloc_load_stop,

	et_alloc_top_base = et_alloc_load_base + DIAG_EVENT_TYPE_INTERVAL,
	et_alloc_top_detail,

	et_drop_packet_base = et_alloc_top_base + DIAG_EVENT_TYPE_INTERVAL,
	et_drop_packet_summary,
	et_drop_packet_detail,

	et_fs_orphan_base = et_drop_packet_base + DIAG_EVENT_TYPE_INTERVAL,
	et_fs_orphan_summary,
	et_fs_orphan_detail,

	et_exec_monitor_base = et_fs_orphan_base + DIAG_EVENT_TYPE_INTERVAL,
	et_exec_monitor_detail,
	et_exec_monitor_perf,

	et_exit_monitor_base = et_exec_monitor_base + DIAG_EVENT_TYPE_INTERVAL,
	et_exit_monitor_detail,
	et_exit_monitor_map,

	et_fs_shm_base = et_exit_monitor_base + DIAG_EVENT_TYPE_INTERVAL,
	et_fs_shm_detail,

	et_irq_delay_base = et_fs_shm_base + DIAG_EVENT_TYPE_INTERVAL,
	et_irq_delay_detail,

	et_irq_stats_base = et_irq_delay_base + DIAG_EVENT_TYPE_INTERVAL,
	et_irq_stats_header,
	et_irq_stats_irq_summary,
	et_irq_stats_irq_detail,
	et_irq_stats_softirq_summary,
	et_irq_stats_timer_summary,

	et_irq_trace_base = et_irq_stats_base + DIAG_EVENT_TYPE_INTERVAL,
	et_irq_trace_detail,
	et_irq_trace_sum,

	et_kprobe_base = et_irq_trace_base + DIAG_EVENT_TYPE_INTERVAL,
	et_kprobe_detail,
	et_kprobe_raw_detail,

	et_load_monitor_base = et_kprobe_base + DIAG_EVENT_TYPE_INTERVAL,
	et_load_monitor_detail,
	et_load_monitor_task,

	et_mm_leak_base = et_load_monitor_base + DIAG_EVENT_TYPE_INTERVAL,
	et_mm_leak_detail,

	et_mutex_monitor_base = et_mm_leak_base + DIAG_EVENT_TYPE_INTERVAL,
	et_mutex_monitor_detail,

	et_perf_base = et_mutex_monitor_base + DIAG_EVENT_TYPE_INTERVAL,
	et_perf_detail,
	et_perf_raw_detail,

	et_proc_monitor_base = et_perf_base + DIAG_EVENT_TYPE_INTERVAL,
	et_proc_monitor_summary,
	et_proc_monitor_detail,

	et_run_trace_base = et_proc_monitor_base + DIAG_EVENT_TYPE_INTERVAL,
	et_run_trace,
	et_start,
	et_sched_in,
	et_sched_out,
	et_sched_wakeup,
	et_sys_enter,
	et_sys_exit,
	et_irq_handler_entry,
	et_irq_handler_exit,
	et_softirq_entry,
	et_softirq_exit,
	et_timer_expire_entry,
	et_timer_expire_exit,
	et_run_trace_perf,
	et_stop,
	et_stop_raw_stack,

	et_runq_info_base = et_run_trace_base + DIAG_EVENT_TYPE_INTERVAL,
	et_runq_info_summary,
	et_runq_info_detail,

	et_rw_top_base = et_runq_info_base + DIAG_EVENT_TYPE_INTERVAL,
	et_rw_top_detail,
	et_rw_top_perf,

	et_sys_delay_base = et_rw_top_base + DIAG_EVENT_TYPE_INTERVAL,
	et_sys_delay_detail,

	et_tcp_retrans_base = et_sys_delay_base + DIAG_EVENT_TYPE_INTERVAL,
	et_tcp_retrans_summary,
	et_tcp_retrans_detail,
	et_tcp_retrans_trace,

	et_utilization_base = et_tcp_retrans_base + DIAG_EVENT_TYPE_INTERVAL,
	et_utilization_detail,

	et_sched_delay_base = et_utilization_base + DIAG_EVENT_TYPE_INTERVAL,
	et_sched_delay_dither,
	et_sched_delay_rq,

	et_reboot_base = et_sched_delay_base + DIAG_EVENT_TYPE_INTERVAL,
	et_reboot_detail,

	et_df_du_base = et_reboot_base + DIAG_EVENT_TYPE_INTERVAL,
	et_df_du_detail,

	et_ping_delay_base = et_df_du_base + DIAG_EVENT_TYPE_INTERVAL,
	et_ping_delay_summary,
	et_ping_delay_detail,
	et_ping_delay_event,

	et_uprobe_base = et_ping_delay_base + DIAG_EVENT_TYPE_INTERVAL,
	et_uprobe_detail,
	et_uprobe_raw_detail,

	et_sys_cost_base = et_uprobe_base + DIAG_EVENT_TYPE_INTERVAL,
	et_sys_cost_detail,

	et_fs_cache = et_sys_cost_base + DIAG_EVENT_TYPE_INTERVAL,
	et_fs_cache_detail,

	et_high_order = et_fs_cache + DIAG_EVENT_TYPE_INTERVAL,
	et_high_order_detail,

	et_d = et_high_order + DIAG_EVENT_TYPE_INTERVAL,
	et_d_detail,

	et_net_bandwidth_base = et_d + DIAG_EVENT_TYPE_INTERVAL,
	et_net_bandwidth_summary,
	et_net_bandwidth_detail,

	et_sig_info_base = et_net_bandwidth_base + DIAG_EVENT_TYPE_INTERVAL,
	et_sig_info_detail,

	et_count
};

struct diag_proc_chains_detail {
	unsigned int full_argv[PROCESS_CHAINS_COUNT];
	char chains[PROCESS_CHAINS_COUNT][PROCESS_ARGV_LEN];
	unsigned int tgid[PROCESS_CHAINS_COUNT];
};

struct diag_task_detail {
	char cgroup_buf[CGROUP_NAME_LEN];
	char cgroup_cpuset[CGROUP_NAME_LEN];
	int pid;
	int tgid;
	int container_pid;
	int container_tgid;
	long state;
	char comm[TASK_COMM_LEN];
};

struct diag_kern_stack_detail {
	unsigned long stack[BACKTRACE_DEPTH];
};

struct diag_user_stack_detail {
#if defined(DIAG_ARM64)
	struct user_pt_regs regs;
#else
	struct pt_regs regs;
#endif
	unsigned long ip;
	unsigned long bp;
	unsigned long sp;
	unsigned long stack[BACKTRACE_DEPTH];
};

struct diag_raw_stack_detail {
#if defined(DIAG_ARM64)
	struct user_pt_regs regs;
#else
	struct pt_regs regs;
#endif
	unsigned long ip;
	unsigned long bp;
	unsigned long sp;
	unsigned long stack_size;
	unsigned long stack[DIAG_USER_STACK_SIZE / sizeof(unsigned long)];
};

struct diag_inode_detail {
	unsigned long inode_number;
	unsigned long inode_mode;
	unsigned long inode_nlink;
	unsigned long inode_count;
	unsigned long inode_size;
	unsigned long inode_blocks;
	unsigned long inode_block_bytes;
};

static inline void extract_variant_buffer(char *buf, unsigned int len, int (*func)(void *, unsigned int, void *), void *arg)
{
	unsigned int pos = 0;
	struct diag_variant_buffer_head *head;
	void *rec;
	int rec_len;

	while (pos < len) {
		head = (struct diag_variant_buffer_head *)(buf + pos);
		if (pos + sizeof(struct diag_variant_buffer_head) >= len)
			break;
		if (head->magic != DIAG_VARIANT_BUFFER_HEAD_MAGIC_SEALED)
			break;
		if (head->len < sizeof(struct diag_variant_buffer_head))
			break;

		rec = (void *)(buf + pos + sizeof(struct diag_variant_buffer_head));
		rec_len = head->len - sizeof(struct diag_variant_buffer_head);
		func(rec, rec_len, arg);

		pos += head->len;
	}
}

#endif /* UAPI_DIAG_H */
