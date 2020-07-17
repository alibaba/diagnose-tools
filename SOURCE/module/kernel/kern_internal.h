/*
 * Linux内核诊断工具--内核态kernel功能头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

extern int diag_irq_stats_init(void);
extern void diag_irq_stats_exit(void);
extern int diag_irq_delay_init(void);
extern void diag_irq_delay_exit(void);
extern int diag_irq_delay_init(void);
extern void diag_irq_delay_exit(void);
extern int diag_sched_delay_init(void);
extern void diag_sched_delay_exit(void);
extern int diag_load_init(void);
extern void diag_load_exit(void);
extern int diag_exit_init(void);
extern void diag_exit_exit(void);
extern int diag_sys_delay_init(void);
extern void diag_sys_delay_exit(void);
extern int diag_runq_info_init(void);
extern void diag_runq_info_exit(void);
extern int diag_rcu_init(void);
extern void diag_rcu_exit(void);
extern int diag_sys_loop_init(void);
extern void diag_sys_loop_exit(void);
extern int diag_mutex_init(void);
extern void diag_mutex_exit(void);
extern int diag_timer_init(void);
extern void diag_timer_exit(void);
extern int diag_exec_init(void);
extern void diag_exec_exit(void);
extern int diag_kern_demo_init(void);
extern void diag_kern_demo_exit(void);
extern int diag_sys_cost_init(void);
extern void diag_sys_cost_exit(void);
extern int diag_task_time_init(void);
extern void diag_task_time_exit(void);
extern int diag_task_runs_init(void);
extern void diag_task_runs_exit(void);
extern int diag_kern_perf_init(void);
extern void diag_kern_perf_exit(void);
extern int diag_run_trace_init(void);
extern void diag_run_trace_exit(void);
extern int diag_lock_init(void);
extern void diag_lock_exit(void);
extern int diag_irq_trace_init(void);
extern void diag_irq_trace_exit(void);
extern int diag_sys_broken_init(void);
extern void diag_sys_broken_exit(void);
extern int diag_kprobe_init(void);
extern void diag_kprobe_exit(void);
extern int diag_utilization_init(void);
extern void diag_utilization_exit(void);
extern int diag_reboot_init(void);
extern void diag_reboot_exit(void);

