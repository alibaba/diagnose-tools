/*
 * Linux内核诊断工具--内核态入口
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/syscalls.h>
#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/timex.h>
#include <linux/tracepoint.h>
#include <trace/events/irq.h>
#include <trace/events/napi.h>
#include <linux/proc_fs.h>	/* Necessary because we use the proc fs */
#include <asm/uaccess.h>	/* for copy_from_user */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <linux/semaphore.h>
#include <linux/vmalloc.h>

#include "pub/trace_file.h"
#include "pub/trace_point.h"

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
#include "uapi/sched_delay.h"
#include "uapi/reboot.h"

unsigned long diag_timer_period = 10;

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_trace_file controller_file;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
static DECLARE_MUTEX(controller_sem);
#else
static DEFINE_SEMAPHORE(controller_sem);
#endif

struct diag_percpu_context *diag_percpu_context[NR_CPUS];
unsigned long diag_ignore_jump_check = 0;

static ssize_t controller_file_read(struct diag_trace_file *trace_file,
		struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	diag_trace_file_mutex_lock(trace_file);

	diag_trace_file_printk_nolock(trace_file, "功能设置：\n");

	diag_trace_file_mutex_unlock(trace_file);

	return 0;
}

static ssize_t controller_file_write(struct diag_trace_file *trace_file,
		struct file *file, const char __user *buf, size_t count,
		loff_t *offs)
{
	int ret;
	char cmd[255];
	char chr[256];

	if (count < 1 || count >= 255 || *offs)
		return -EINVAL;

	if (copy_from_user(chr, buf, 256))
		return -EFAULT;
	chr[255] = 0;

	ret = sscanf(chr, "%255s", cmd);
	if (ret <= 0)
		return -EINVAL;

	if (strcmp(cmd, "activate") == 0) {
		char func[255];

		ret = sscanf(chr, "%255s %255s", cmd, func);
		if (ret != 2)
			return -EINVAL;
		down(&controller_sem);
		if (strcmp(func, "run-trace") == 0) {
			activate_run_trace();
		} else if (strcmp(func, "drop-packet") == 0) {
			activate_drop_packet();
		} else if (strcmp(func, "load-monitor") == 0) {
			activate_load_monitor();
		} else if (strcmp(func, "perf") == 0) {
			activate_perf();
		} else if (strcmp(func, "exit-monitor") == 0) {
			activate_exit_monitor();
		} else if (strcmp(func, "tcp-retrans") == 0) {
			activate_tcp_retrans();
		} else if (strcmp(func, "sys-delay") == 0) {
			activate_sys_delay();
		} else if (strcmp(func, "irq-delay") == 0) {
			activate_irq_delay();
		} else if (strcmp(func, "mutex-monitor") == 0) {
			activate_mutex_monitor();
		} else if (strcmp(func, "utilization") == 0) {
			activate_utilization();
		} else if (strcmp(func, "irq-stats") == 0) {
			activate_irq_stats();
		} else if (strcmp(func, "irq-trace") == 0) {
			activate_irq_trace();
		} else if (strcmp(func, "exec-monitor") == 0) {
			activate_exec_monitor();
		} else if (strcmp(func, "kprobe") == 0) {
			activate_kprobe();
		} else if (strcmp(func, "mm-leak") == 0) {
			activate_mm_leak();
		} else if (strcmp(func, "alloc-top") == 0) {
			activate_alloc_top();
		} else if (strcmp(func, "rw-top") == 0) {
			activate_rw_top();
		} else if (strcmp(func, "fs-shm") == 0) {
			activate_fs_shm();
		} else if (strcmp(func, "drop-packet") == 0) {
			activate_drop_packet();
		} else if (strcmp(func, "sched-delay") == 0) {
			activate_sched_delay();
		} else if (strcmp(func, "reboot") == 0) {
			activate_reboot();
		} else if (strcmp(func, "fs-orphan") == 0) {
			activate_fs_orphan();
		} else if (strcmp(func, "ping-delay") == 0) {
			activate_ping_delay();
		} else if (strcmp(func, "uprobe") == 0) {
			activate_uprobe();
		} else if (strcmp(func, "sys-cost") == 0) {
			activate_sys_cost();
		} else if (strcmp(func, "fs-cache") == 0) {
			activate_fs_cache();
		} else if (strcmp(func, "high-order") == 0) {
			activate_high_order();
		}
		up(&controller_sem);
		printk("diagnose-tools %s %s\n", cmd, func);
	} else if (strcmp(cmd, "deactivate") == 0) {
		char func[255];

		ret = sscanf(chr, "%255s %255s", cmd, func);
		if (ret != 2)
			return -EINVAL;
		down(&controller_sem);
		if (strcmp(func, "run-trace") == 0) {
			deactivate_run_trace();
		} else if (strcmp(func, "load-monitor") == 0) {
			deactivate_load_monitor();
		} else if (strcmp(func, "perf") == 0) {
			deactivate_perf();
		} else if (strcmp(func, "exit-monitor") == 0) {
			deactivate_exit_monitor();
		} else if (strcmp(func, "tcp-retrans") == 0) {
			deactivate_tcp_retrans();
		} else if (strcmp(func, "sys-delay") == 0) {
			deactivate_sys_delay();
		} else if (strcmp(func, "irq-delay") == 0) {
			deactivate_irq_delay();
		} else if (strcmp(func, "mutex-monitor") == 0) {
			deactivate_mutex_monitor();
		} else if (strcmp(func, "utilization") == 0) {
			deactivate_utilization();
		} else if (strcmp(func, "irq-stats") == 0) {
			deactivate_irq_stats();
		} else if (strcmp(func, "irq-trace") == 0) {
			deactivate_irq_trace();
		} else if (strcmp(func, "exec-monitor") == 0) {
			deactivate_exec_monitor();
		} else if (strcmp(func, "kprobe") == 0) {
			deactivate_kprobe();
		} else if (strcmp(func, "mm-leak") == 0) {
			deactivate_mm_leak();
		} else if (strcmp(func, "alloc-top") == 0) {
			deactivate_alloc_top();
		} else if (strcmp(func, "rw-top") == 0) {
			deactivate_rw_top();
		} else if (strcmp(func, "fs-shm") == 0) {
			deactivate_fs_shm();
		} else if (strcmp(func, "drop-packet") == 0) {
			deactivate_drop_packet();
		} else if (strcmp(func, "sched-delay") == 0) {
			deactivate_sched_delay();
		} else if (strcmp(func, "reboot") == 0) {
			deactivate_reboot();
		} else if (strcmp(func, "fs-orphan") == 0) {
			deactivate_fs_orphan();
		} else if (strcmp(func, "ping-delay") == 0) {
			deactivate_ping_delay();
		} else if (strcmp(func, "uprobe") == 0) {
			deactivate_uprobe();
		} else if (strcmp(func, "sys-cost") == 0) {
			deactivate_sys_cost();
		} else if (strcmp(func, "fs-cache") == 0) {
			deactivate_fs_cache();
		} else if (strcmp(func, "high-order") == 0) {
			deactivate_high_order();
		}

		up(&controller_sem);
		printk("diagnose-tools %s %s\n", cmd, func);
	}

	return count;
}

int diag_linux_proc_init(void)
{
	struct proc_dir_entry *pe;
	int ret;

	pe = diag_proc_mkdir("ali-linux", NULL);
	//if (!pe)
	//	return -ENOMEM;

	pe = diag_proc_mkdir("ali-linux/diagnose", NULL);
	//if (!pe)
	//	return -ENOMEM;

	ret = init_diag_trace_file(&controller_file,
			"ali-linux/diagnose/controller",
			20 * 1024,
			controller_file_read,
			controller_file_write);

	if (ret)
		goto out_controller_file;
	
	return 0;
out_controller_file:
	return ret;
}

void diag_linux_proc_exit(void)
{
	//remove_proc_entry("ali-linux/diagnose", NULL);
	//remove_proc_entry("ali-linux", NULL);
	destroy_diag_trace_file(&controller_file);
}

unsigned long (*__kallsyms_lookup_name)(const char *name);
static int symbol_walk_callback(void *data, const char *name,
	struct module *mod, unsigned long addr)
{
	if (strcmp(name, "kallsyms_lookup_name") == 0) {
		__kallsyms_lookup_name = (void *)addr;
		return addr;
	}

	return 0;
}

static void diag_cb_sys_enter(void *data, struct pt_regs *regs, long id)
{
	if (id >= DIAG_BASE_SYSCALL) {
		int ret = -ENOSYS;

		down(&controller_sem);
		if (id == DIAG_VERSION) {
			ret = DIAG_VERSION;
		} else if (id >= DIAG_BASE_SYSCALL_PUPIL
		   && id < DIAG_BASE_SYSCALL_PUPIL + DIAG_SYSCALL_INTERVAL) {
			ret = pupil_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_RUN_TRACE
		   && id < DIAG_BASE_SYSCALL_RUN_TRACE + DIAG_SYSCALL_INTERVAL) {
			ret = run_trace_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_LOAD_MONITOR
		   && id < DIAG_BASE_SYSCALL_LOAD_MONITOR + DIAG_SYSCALL_INTERVAL) {
			ret = load_monitor_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_PERF
		   && id < DIAG_BASE_SYSCALL_PERF + DIAG_SYSCALL_INTERVAL) {
			ret = perf_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_EXIT_MONITOR
		   && id < DIAG_BASE_SYSCALL_EXIT_MONITOR + DIAG_SYSCALL_INTERVAL) {
			ret = exit_monitor_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_TCP_RETRANS
		   && id < DIAG_BASE_SYSCALL_TCP_RETRANS + DIAG_SYSCALL_INTERVAL) {
			ret = tcp_retrans_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_SYS_DELAY
		   && id < DIAG_BASE_SYSCALL_SYS_DELAY + DIAG_SYSCALL_INTERVAL) {
			ret = sys_delay_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_IRQ_DELAY
		   && id < DIAG_BASE_SYSCALL_IRQ_DELAY + DIAG_SYSCALL_INTERVAL) {
			ret = irq_delay_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_MUTEX_MONITOR
		   && id < DIAG_BASE_SYSCALL_MUTEX_MONITOR + DIAG_SYSCALL_INTERVAL) {
			ret = mutex_monitor_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_UTILIZATION
		   && id < DIAG_BASE_SYSCALL_UTILIZATION + DIAG_SYSCALL_INTERVAL) {
			ret = utilization_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_IRQ_STATS
		   && id < DIAG_BASE_SYSCALL_IRQ_STATS + DIAG_SYSCALL_INTERVAL) {
			ret = irq_stats_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_IRQ_TRACE
		   && id < DIAG_BASE_SYSCALL_IRQ_TRACE + DIAG_SYSCALL_INTERVAL) {
			ret = irq_trace_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_EXEC_MONITOR
		   && id < DIAG_BASE_SYSCALL_EXEC_MONITOR + DIAG_SYSCALL_INTERVAL) {
			ret = exec_monitor_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_KPROBE
		   && id < DIAG_BASE_SYSCALL_KPROBE + DIAG_SYSCALL_INTERVAL) {
			ret = kprobe_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_MM_LEAK
		   && id < DIAG_BASE_SYSCALL_MM_LEAK + DIAG_SYSCALL_INTERVAL) {
			ret = mm_leak_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_ALLOC_TOP
		   && id < DIAG_BASE_SYSCALL_ALLOC_TOP + DIAG_SYSCALL_INTERVAL) {
			ret = alloc_top_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_FS_ORPHAN
		   && id < DIAG_BASE_SYSCALL_FS_ORPHAN + DIAG_SYSCALL_INTERVAL) {
			ret = fs_orphan_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_RW_TOP
		   && id < DIAG_BASE_SYSCALL_RW_TOP + DIAG_SYSCALL_INTERVAL) {
			ret = rw_top_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_FS_SHM
		   && id < DIAG_BASE_SYSCALL_FS_SHM + DIAG_SYSCALL_INTERVAL) {
			ret = fs_shm_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_DROP_PACKET
		   && id < DIAG_BASE_SYSCALL_DROP_PACKET + DIAG_SYSCALL_INTERVAL) {
			ret = drop_packet_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_SCHED_DELAY
		   && id < DIAG_BASE_SYSCALL_SCHED_DELAY + DIAG_SYSCALL_INTERVAL) {
			ret = sched_delay_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_REBOOT
		   && id < DIAG_BASE_SYSCALL_REBOOT + DIAG_SYSCALL_INTERVAL) {
			ret = reboot_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_PING_DELAY
		   && id < DIAG_BASE_SYSCALL_PING_DELAY + DIAG_SYSCALL_INTERVAL) {
			ret = ping_delay_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_UPROBE
		   && id < DIAG_BASE_SYSCALL_UPROBE + DIAG_SYSCALL_INTERVAL) {
			ret = uprobe_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_SYS_COST
		   && id < DIAG_BASE_SYSCALL_SYS_COST + DIAG_SYSCALL_INTERVAL) {
			ret = sys_cost_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_FS_CACHE
		   && id < DIAG_BASE_SYSCALL_FS_CACHE + DIAG_SYSCALL_INTERVAL) {
			ret = fs_cache_syscall(regs, id);
		} else if (id >= DIAG_BASE_SYSCALL_HIGH_ORDER
		   && id < DIAG_BASE_SYSCALL_HIGH_ORDER + DIAG_SYSCALL_INTERVAL) {
			ret = high_order_syscall(regs, id);
		}
		
		up(&controller_sem);
		if (ret != -ENOSYS) {
			__user int *ret_ptr = (void *)ORIG_PARAM1(regs);

			if (ret_ptr) {
				ret = copy_to_user(ret_ptr, &ret, sizeof(int));
			}
		}
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
static void trace_sys_enter_hit(struct pt_regs *regs, long id)
#else
static void trace_sys_enter_hit(void *__data, struct pt_regs *regs, long id)
#endif
{
	atomic64_inc_return(&diag_nr_running);
	diag_cb_sys_enter(NULL, regs, id);
	cb_sys_enter_run_trace(NULL, regs, id);
	cb_sys_enter_sys_delay(NULL, regs, id);
	cb_sys_enter_sys_cost(NULL, regs, id);
	atomic64_dec_return(&diag_nr_running);
}

static int __init diagnosis_init(void)
{
	int ret = 0;
	char cgroup_buf[256];
	int i;

	ret = kallsyms_on_each_symbol(symbol_walk_callback, NULL);
	if (!ret || !__kallsyms_lookup_name) {
		ret = -EINVAL;
		goto out;
	}

	ret = alidiagnose_symbols_init();
	if (ret)
		goto out;

	diag_cgroup_name(current, cgroup_buf, 255, 0);
	if ((strlen(cgroup_buf) > 1 && strcmp("user.slice", cgroup_buf) != 0 && strcmp("system.slice", cgroup_buf) != 0
	    && strcmp("sshd.service", cgroup_buf) != 0 && strcmp("tianji", cgroup_buf) != 0)
	  || (strlen(cgroup_buf) == 1 && cgroup_buf[0] != '/')) {
		printk(KERN_ALERT "diagnose-tools: insmod in %s\n", cgroup_buf);
	}

	ret = -ENOMEM;
	memset(diag_percpu_context, 0, NR_CPUS * sizeof(struct diag_percpu_context *));
	for (i = 0; i < num_possible_cpus(); i++) {
		diag_percpu_context[i] = vmalloc(sizeof(struct diag_percpu_context));
		if (diag_percpu_context[i] == NULL)
			goto out_percpu_context;
		memset(diag_percpu_context[i], 0,  sizeof(struct diag_percpu_context));
	}

	ret = diag_linux_proc_init();
	if (ret)
		goto out_proc;

	ret = diag_kernel_init();
	if (ret)
		goto out_kern;

	ret = diag_net_init();
	if (ret)
		goto out_net;

	ret = diag_io_init();
	if (ret)
		goto out_io;

	ret = diag_stack_trace_init();
	if (ret)
		goto out_stack_trace;

	ret = diag_mm_init();
	if (ret)
		goto out_mm;

	ret = diag_pupil_init();
	if (ret)
		goto out_pupil;

	ret = diag_fs_init();
	if (ret)
		goto out_fs;

	ret = diag_xby_test_init();
	if (ret)
		goto out_xby_test;

	ret = diag_dev_init();
	if (ret)
		goto out_dev;

	hook_tracepoint("sys_enter", trace_sys_enter_hit, NULL);
	printk("diagnose-tools in diagnosis_init\n");

	return 0;

out_dev:
	diag_xby_test_exit();
out_xby_test:
	diag_fs_exit();
out_fs:
	diag_pupil_exit();
out_pupil:
	diag_mm_exit();
out_mm:
	diag_stack_trace_exit();
out_stack_trace:
	diag_io_exit();
out_io:
	diag_net_exit();
out_net:
	diag_kernel_exit();
out_kern:
	diag_linux_proc_exit();
out_proc:
	alidiagnose_symbols_exit();
out_percpu_context:
	for (i = 0; i < num_possible_cpus(); i++) {
		if (diag_percpu_context[i] != NULL)
			vfree(diag_percpu_context[i]);
	}
out:
	return ret;
}

static void __exit diagnosis_exit(void)
{
	int i;

	printk("diagnose-tools in diagnosis_exit\n");

	diag_linux_proc_exit();
	msleep(20);

	diag_dev_cleanup();
	unhook_tracepoint("sys_enter", trace_sys_enter_hit, NULL);
	synchronize_sched();

	/**
	 * 在JUMP_REMOVE和atomic64_read之间存在微妙的竞态条件
	 * 因此这里的msleep并非多余的。
	 */
	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0)
		msleep(20);

	diag_xby_test_exit();
	msleep(20);

	diag_kernel_exit();
	msleep(20);

	diag_net_exit();
	msleep(20);

	diag_io_exit();
	msleep(20);

	diag_stack_trace_exit();
	msleep(20);

	diag_mm_exit();
	msleep(20);

	diag_pupil_exit();
	msleep(20);

	diag_fs_exit();
	msleep(20);

	alidiagnose_symbols_exit();
	msleep(20);

	synchronize_sched();

	for (i = 0; i < num_possible_cpus(); i++) {
		if (diag_percpu_context[i] != NULL)
			vfree(diag_percpu_context[i]);
	}
}

module_init(diagnosis_init);
module_exit(diagnosis_exit);

module_param(diag_timer_period, ulong, S_IRUGO | S_IWUSR);
module_param(diag_ignore_jump_check, ulong, S_IRUGO | S_IWUSR);
MODULE_DESCRIPTION("Alibaba performance monitor module");
MODULE_AUTHOR("Baoyou Xie <baoyou.xie@linux.alibaba.com>");
MODULE_LICENSE("GPL v2");
