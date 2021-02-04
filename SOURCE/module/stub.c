/*
 * Linux内核诊断工具--内核态桩函数实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include "internal.h"

#include "uapi/pupil.h"
#include "uapi/run_trace.h"
#include "uapi/load_monitor.h"
#include "uapi/perf.h"
#include "uapi/exit_monitor.h"
#include "uapi/tcp_retrans.h"
#include "uapi/rw_top.h"
#include "uapi/sys_delay.h"
#include "uapi/irq_delay.h"
#include "uapi/mutex_monitor.h"
#include "uapi/utilization.h"
#include "uapi/alloc_top.h"
#include "uapi/drop_packet.h"
#include "uapi/fs_orphan.h"
#include "uapi/exec_monitor.h"
#include "uapi/fs_shm.h"
#include "uapi/irq_stats.h"
#include "uapi/irq_trace.h"
#include "uapi/kprobe.h"
#include "uapi/mm_leak.h"

int __weak diag_net_init(void)
{
	return 0;
}

void __weak diag_net_exit(void)
{
}

int __weak diag_net_packet_corruption_init(void)
{
	return 0;
}

void __weak diag_net_packet_corruption_exit(void)
{
	//
}

int __weak diag_nvme_init(void)
{
	return 0;
}

void __weak diag_nvme_exit(void)
{
}

int __weak alidiagnose_xby_debug_init(void)
{
	return 0;
}

void __weak alidiagnose_xby_debug_exit(void)
{
}

int __weak diag_stack_trace_init(void)
{
	return 0;
}

void __weak diag_stack_trace_exit(void)
{
	//
}

int __weak diag_irq_stats_init(void)
{
	return 0;
}

void __weak diag_irq_stats_exit(void)
{
	//
}

int __weak diag_irq_delay_init(void)
{
	return 0;
}

void __weak diag_irq_delay_exit(void)
{
	//
}

int __weak diag_sched_delay_init(void)
{
	return 0;
}

void __weak diag_sched_delay_exit(void)
{
	//
}

int __weak diag_load_init(void)
{
	return 0;
}

void __weak diag_load_exit(void)
{
	//
}

int __weak diag_exit_init(void)
{
	return 0;
}

void __weak diag_exit_exit(void)
{
	//
}

int __weak diag_sys_delay_init(void)
{
	return 0;
}

void __weak diag_sys_delay_exit(void)
{
	//
}

int __weak diag_runq_info_init(void)
{
	return 0;
}

void __weak diag_runq_info_exit(void)
{
	//
}

int __weak diag_rcu_init(void)
{
	return 0;
}

void __weak diag_rcu_exit(void)
{
	//
}

int __weak diag_sys_loop_init(void)
{
	return 0;
}

void __weak diag_sys_loop_exit(void)
{
	//
}

int __weak diag_mutex_init(void)
{
	return 0;
}

void __weak diag_mutex_exit(void)
{
	//
}

int __weak diag_timer_init(void)
{
	return 0;
}

void __weak diag_timer_exit(void)
{
	//
}

int __weak diag_exec_init(void)
{
	return 0;
}

void __weak diag_exec_exit(void)
{
	//
}

int __weak diag_kern_demo_init(void)
{
	return 0;
}

void __weak diag_kern_demo_exit(void)
{
	//
}

int __weak diag_sys_cost_init(void)
{
	return 0;
}

void __weak diag_sys_cost_exit(void)
{
	//
}

int __weak diag_task_time_init(void)
{
	return 0;
}

void __weak diag_task_time_exit(void)
{
	//
}

void __weak sys_loop_timer(struct diag_percpu_context *context)
{
	//
}

void __weak kern_task_runs_timer(struct diag_percpu_context *context)
{
	//
}

void __weak perf_timer(struct diag_percpu_context *context)
{
	//
}

void __weak utilization_timer(struct diag_percpu_context *context)
{
	//
}

int __weak diag_pupil_init(void)
{
	return 0;
}

void __weak diag_pupil_exit(void)
{
	//
}

int __weak diag_alloc_page_init(void)
{
	return 0;
}

void __weak diag_alloc_page_exit(void)
{
	//
}

int __weak diag_memory_leak_init(void)
{
	return 0;
}

void __weak diag_memory_leak_exit(void)
{
	//
}

int __weak diag_tcp_retrans_init(void)
{
	return 0;
}

void __weak diag_tcp_retrans_exit(void)
{
	//
}

int __weak diag_net_drop_packet_init(void)
{
	return 0;
}

void __weak diag_net_drop_packet_exit(void)
{
	//
}

int __weak diag_net_reqsk_init(void)
{
	return 0;
}

void __weak diag_net_reqsk_exit(void)
{
	//
}

int __weak diag_bio_init(void)
{
	return 0;
}

void __weak diag_bio_exit(void)
{
	//
}

int __weak diag_blk_dev_init(void)
{
	return 0;
}

void __weak diag_blk_dev_exit(void)
{
	//
}

int __weak diag_vfs_init(void)
{
	return 0;
}

void __weak diag_vfs_exit(void)
{
	//
}

int __weak diag_task_runs_init(void)
{
	return 0;
}

void __weak diag_task_runs_exit(void)
{
	//
}

int __weak diag_fs_init(void)
{
	return 0;
}

void __weak diag_fs_exit(void)
{
}

int __weak diag_kern_perf_init(void)
{
	return 0;
}

void __weak diag_kern_perf_exit(void)
{
}

int __weak diag_run_trace_init(void)
{
	return 0;
}

void __weak diag_run_trace_exit(void)
{
	//
}

int __weak diag_lock_init(void)
{
	return 0;
}

void __weak diag_lock_exit(void)
{
}

int __weak diag_mm_page_fault_init(void)
{
	return 0;
}

void __weak diag_mm_page_fault_exit(void)
{
}

int __weak diag_alloc_top_init(void)
{
	return 0;
}

void __weak diag_alloc_top_exit(void)
{
	//
}

int __weak diag_net_redis_ixgbe_init(void)
{
	return 0;
}

void __weak diag_net_redis_ixgbe_exit(void)
{
	//
}

int __weak diag_rw_top_init(void)
{
	return 0;
}

void __weak diag_rw_top_exit(void)
{
	//
}

int __weak diag_irq_trace_init(void)
{
	return 0;
}

void __weak diag_irq_trace_exit(void)
{
	//
}

int __weak diag_fs_shm_init(void)
{
	return 0;
}

void __weak diag_fs_shm_exit(void)
{
	//
}

int __weak diag_net_ping_delay_init(void)
{
	return 0;
}

void __weak diag_net_ping_delay_exit(void)
{
	//
}

int __weak diag_sys_broken_init(void)
{
	return 0;
}

void __weak diag_sys_broken_exit(void)
{
	//
}

int __weak diag_kprobe_init(void)
{
	return 0;
}

void __weak diag_kprobe_exit(void)
{
	//
}

int __weak diag_utilization_init(void)
{
	return 0;
}

void __weak diag_utilization_exit(void)
{
	//
}

int __weak diag_net_net_bandwidth_init(void)
{
	return 0;
}

void __weak diag_net_net_bandwidth_exit(void)
{
	//
}

int __weak diag_sig_info_init(void)
{
	return 0;
}

void __weak diag_sig_info_exit(void)
{
	//
}

int __weak exit_monitor_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak pupil_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak irq_delay_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak load_monitor_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak mutex_monitor_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak run_trace_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak rw_top_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak sys_delay_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak tcp_retrans_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak utilization_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak alloc_top_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak drop_packet_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak exec_monitor_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak fs_shm_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak irq_stats_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak irq_trace_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak kprobe_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak mm_leak_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak net_bandwidth_syscall(struct pt_regs *regs, long id)
{
        return -ENOSYS;
}

int __weak sig_info_syscall(struct pt_regs *regs, long id)
{
        return -ENOSYS;
}

int __weak activate_run_trace(void)
{
	return -EINVAL;
}

int __weak deactivate_run_trace(void)
{
	return -EINVAL;
}

int __weak activate_load_monitor(void)
{
	return -EINVAL;
}

int __weak deactivate_load_monitor(void)
{
	return -EINVAL;
}

int __weak activate_perf(void)
{
	return -EINVAL;
}

int __weak deactivate_exit_monitor(void)
{
	return -EINVAL;
}

int __weak activate_exit_monitor(void)
{
	return -EINVAL;
}

int __weak deactivate_perf(void)
{
	return -EINVAL;
}

int __weak activate_tcp_retrans(void)
{
	return -EINVAL;
}

int __weak deactivate_tcp_retrans(void)
{
	return -EINVAL;
}

int __weak activate_sys_delay(void)
{
	return -EINVAL;
}

int __weak deactivate_sys_delay(void)
{
	return -EINVAL;
}

int __weak activate_irq_delay(void)
{
	return -EINVAL;
}

int __weak deactivate_irq_delay(void)
{
	return -EINVAL;
}

int __weak activate_mutex_monitor(void)
{
	return -EINVAL;
}

int __weak deactivate_mutex_monitor(void)
{
	return -EINVAL;
}

int __weak activate_utilization(void)
{
	return -EINVAL;
}

int __weak deactivate_utilization(void)
{
	return -EINVAL;
}

int __weak activate_irq_stats(void)
{
	return -EINVAL;
}

int __weak deactivate_irq_stats(void)
{
	return -EINVAL;
}

int __weak activate_irq_trace(void)
{
	return -EINVAL;
}

int __weak deactivate_irq_trace(void)
{
	return -EINVAL;
}

int __weak activate_runq_info(void)
{
	return -EINVAL;
}

int __weak deactivate_runq_info(void)
{
	return -EINVAL;
}

int __weak activate_exec_monitor(void)
{
	return -EINVAL;
}

int __weak deactivate_exec_monitor(void)
{
	return -EINVAL;
}

int __weak activate_kprobe(void)
{
	return -EINVAL;
}

int __weak deactivate_kprobe(void)
{
	return -EINVAL;
}

int __weak activate_mm_leak(void)
{
	return -EINVAL;
}

int __weak deactivate_mm_leak(void)
{
	return -EINVAL;
}

int __weak activate_alloc_top(void)
{
	return -EINVAL;
}

int __weak deactivate_alloc_top(void)
{
	return -EINVAL;
}

int __weak activate_rw_top(void)
{
	return -EINVAL;
}

int __weak deactivate_rw_top(void)
{
	return -EINVAL;
}

int __weak activate_fs_shm(void)
{
	return -EINVAL;
}

int __weak deactivate_fs_shm(void)
{
	return -EINVAL;
}

int __weak activate_drop_packet(void)
{
	return -EINVAL;
}

int __weak deactivate_drop_packet(void)
{
	return -EINVAL;
}

int __weak sched_delay_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak activate_sched_delay(void)
{
	return -EINVAL;
}

int __weak deactivate_sched_delay(void)
{
	return -EINVAL;
}

int __weak activate_reboot(void)
{
	return -EINVAL;
}

int __weak deactivate_reboot(void)
{
	return -EINVAL;
}

int __weak diag_xby_test_init(void)
{
	return 0;
}

void __weak diag_xby_test_exit(void)
{
	//
}

int __weak fs_orphan_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak activate_fs_orphan(void)
{
	return -EINVAL;
}

int __weak deactivate_fs_orphan(void)
{
	return -EINVAL;
}

int __weak diag_fs_orphan_init(void)
{
	return 0;
}

void __weak diag_fs_orphan_exit(void)
{
}

int __weak ping_delay_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak activate_ping_delay(void)
{
	return -EINVAL;
}

int __weak deactivate_ping_delay(void)
{
	return -EINVAL;
}

int __weak diag_ping_delay_init(void)
{
	return 0;
}

void __weak diag_ping_delay_exit(void)
{
}

int __weak activate_uprobe(void)
{
	return -EINVAL;
}

int __weak deactivate_uprobe(void)
{
	return -EINVAL;
}

int __weak diag_uprobe_init(void)
{
	return 0;
}

void __weak diag_uprobe_exit(void)
{
}

int __weak fs_cache_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak activate_fs_cache(void)
{
	return -EINVAL;
}

int __weak deactivate_fs_cache(void)
{
	return -EINVAL;
}

int __weak diag_fs_cache_init(void)
{
	return 0;
}

void __weak diag_fs_cache_exit(void)
{
}

int __weak high_order_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak activate_high_order(void)
{
	return -EINVAL;
}

int __weak deactivate_high_order(void)
{
	return -EINVAL;
}

int __weak diag_high_order_init(void)
{
	return 0;
}

void __weak diag_high_order_exit(void)
{
}

long __weak diag_ioctl_sys_delay(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_sys_cost(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_sched_delay(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_irq_delay(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_irq_stats(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_irq_trace(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_load_monitor(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_run_trace(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_perf(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_kprobe(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_uprobe(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_utilization(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_exit_monitor(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_mutex_monitor(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_exec_monitor(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_alloc_top(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_high_order(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_drop_packet(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_tcp_retrans(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_ping_delay(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_rw_top(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_fs_shm(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_fs_orphan(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_fs_cache(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_reboot(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_net_bandwidth(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

long __weak diag_ioctl_sig_info(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

int __weak perf_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak deactivate_net_bandwidth(void)
{
	return -EINVAL;
}

int __weak activate_net_bandwidth(void)
{
	return -EINVAL;
}


int __weak diag_task_monitor_init(void)
{
	return 0;
}

void __weak diag_task_monitor_exit(void)
{
	//
}

long __weak diag_ioctl_task_monitor(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

int __weak task_monitor_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

int __weak deactivate_task_monitor(void)
{
	return -EINVAL;
}

int __weak activate_task_monitor(void)
{
	return -EINVAL;
}

void __weak task_monitor_timer(struct diag_percpu_context *context)
{
        return;
}
