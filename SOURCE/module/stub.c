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


#define DIAG_WEAK_FUNC_INIT_EXIT(name)                                \
    int __weak diag_##name##_init(void) { return 0; }                 \
    void __weak diag_##name##_exit(void) { return; }

#define DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(name)                           \
    int __weak activate_##name(void) { return -ENOTSUPP; }             \
    int __weak deactivate_##name(void) { return -ENOTSUPP; }           \
    long __weak diag_ioctl_##name(unsigned int cmd, unsigned long arg) \
                { return -ENOTSUPP; }

DIAG_WEAK_FUNC_INIT_EXIT(net)
DIAG_WEAK_FUNC_INIT_EXIT(net_packet_corruption)
DIAG_WEAK_FUNC_INIT_EXIT(net_redis_ixgbe)
DIAG_WEAK_FUNC_INIT_EXIT(net_reqsk)

DIAG_WEAK_FUNC_INIT_EXIT(vfs)
DIAG_WEAK_FUNC_INIT_EXIT(fs)
DIAG_WEAK_FUNC_INIT_EXIT(bio)
DIAG_WEAK_FUNC_INIT_EXIT(blk_dev)
DIAG_WEAK_FUNC_INIT_EXIT(nvme)

DIAG_WEAK_FUNC_INIT_EXIT(rcu)
DIAG_WEAK_FUNC_INIT_EXIT(lock)
DIAG_WEAK_FUNC_INIT_EXIT(stack_trace)
DIAG_WEAK_FUNC_INIT_EXIT(sys_loop)
DIAG_WEAK_FUNC_INIT_EXIT(timer)
DIAG_WEAK_FUNC_INIT_EXIT(kern_demo)
DIAG_WEAK_FUNC_INIT_EXIT(sys_cost)
DIAG_WEAK_FUNC_INIT_EXIT(task_time)
DIAG_WEAK_FUNC_INIT_EXIT(task_runs)
DIAG_WEAK_FUNC_INIT_EXIT(pupil)

DIAG_WEAK_FUNC_INIT_EXIT(alloc_page)
DIAG_WEAK_FUNC_INIT_EXIT(mm_page_fault)
DIAG_WEAK_FUNC_INIT_EXIT(sys_broken)


DIAG_WEAK_FUNC_INIT_EXIT(run_trace)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(run_trace)

DIAG_WEAK_FUNC_INIT_EXIT(load)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(load_monitor)

DIAG_WEAK_FUNC_INIT_EXIT(exit)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(exit_monitor)

DIAG_WEAK_FUNC_INIT_EXIT(tcp_retrans)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(tcp_retrans)
int __weak tcp_retrans_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

DIAG_WEAK_FUNC_INIT_EXIT(sys_delay)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(sys_delay)

DIAG_WEAK_FUNC_INIT_EXIT(irq_delay)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(irq_delay)

DIAG_WEAK_FUNC_INIT_EXIT(mutex)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(mutex_monitor)

DIAG_WEAK_FUNC_INIT_EXIT(utilization)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(utilization)
int __weak utilization_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}
void __weak utilization_timer(struct diag_percpu_context *context)
{
    //
}

DIAG_WEAK_FUNC_INIT_EXIT(irq_stats)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(irq_stats)

DIAG_WEAK_FUNC_INIT_EXIT(irq_trace)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(irq_trace)

DIAG_WEAK_FUNC_INIT_EXIT(runq_info)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(runq_info)

DIAG_WEAK_FUNC_INIT_EXIT(exec)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(exec_monitor)

DIAG_WEAK_FUNC_INIT_EXIT(kprobe)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(kprobe)

DIAG_WEAK_FUNC_INIT_EXIT(memory_leak)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(mm_leak)

DIAG_WEAK_FUNC_INIT_EXIT(alloc_top)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(alloc_top)

DIAG_WEAK_FUNC_INIT_EXIT(rw_top)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(rw_top)
int __weak rw_top_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

DIAG_WEAK_FUNC_INIT_EXIT(fs_shm)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(fs_shm)
int __weak fs_shm_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

DIAG_WEAK_FUNC_INIT_EXIT(net_drop_packet)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(drop_packet)
int __weak drop_packet_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}


DIAG_WEAK_FUNC_INIT_EXIT(sched_delay)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(sched_delay)
int __weak sched_delay_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

DIAG_WEAK_FUNC_INIT_EXIT(reboot)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(reboot)

DIAG_WEAK_FUNC_INIT_EXIT(xby_test)

DIAG_WEAK_FUNC_INIT_EXIT(fs_orphan)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(fs_orphan)
int __weak fs_orphan_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

DIAG_WEAK_FUNC_INIT_EXIT(net_ping_delay)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(ping_delay)
int __weak ping_delay_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

DIAG_WEAK_FUNC_INIT_EXIT(net_ping_delay6)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(ping_delay6)
int __weak ping_delay6_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

DIAG_WEAK_FUNC_INIT_EXIT(ping_uprobe)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(ping_uprobe)

DIAG_WEAK_FUNC_INIT_EXIT(fs_cache)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(fs_cache)
int __weak fs_cache_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}


DIAG_WEAK_FUNC_INIT_EXIT(high_order)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(high_order)
int __weak high_order_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

DIAG_WEAK_FUNC_INIT_EXIT(sig_info)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(sig_info)

DIAG_WEAK_FUNC_INIT_EXIT(kern_perf)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(perf)
int __weak perf_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}
void __weak perf_timer(struct diag_percpu_context *context)
{
    //
}

DIAG_WEAK_FUNC_INIT_EXIT(net_bandwidth)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(net_bandwidth)
int __weak net_bandwidth_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

DIAG_WEAK_FUNC_INIT_EXIT(task_monitor)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(task_monitor)
int __weak task_monitor_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}
void __weak task_monitor_timer(struct diag_percpu_context *context)
{
        return;
}

DIAG_WEAK_FUNC_INIT_EXIT(throttle_delay)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(throttle_delay)
int __weak throttle_delay_syscall(struct pt_regs *regs, long id)
{
    return -EINVAL;
}

DIAG_WEAK_FUNC_INIT_EXIT(rw_sem)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(rw_sem)
int __weak rw_sem_syscall(struct pt_regs *regs, long id)
{
        return -ENOSYS;
}

DIAG_WEAK_FUNC_INIT_EXIT(rss_monitor)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(rss_monitor)
int __weak rss_monitor_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

DIAG_WEAK_FUNC_INIT_EXIT(memcg_stats)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(memcg_stats)
int __weak memcg_stats_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

DIAG_WEAK_FUNC_INIT_EXIT(pmu)
DIAG_WEAK_FUNC_ACT_DEACT_IOCTL(pmu)
int __weak pmu_syscall(struct pt_regs *regs, long id)
{
	return -ENOSYS;
}

void __weak sys_loop_timer(struct diag_percpu_context *context)
{
    //
}

