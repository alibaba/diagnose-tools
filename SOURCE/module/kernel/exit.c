/*
 * Linux内核诊断工具--内核态exit-monitor功能
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/version.h>
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
#include <linux/rbtree.h>
#include <linux/cpu.h>
#include <linux/syscalls.h>
#include <linux/vmalloc.h>
#include <linux/profile.h>
#if KERNEL_VERSION(4, 15, 0) <= LINUX_VERSION_CODE
#include <linux/sched/mm.h>
#endif

#include <asm/irq_regs.h>

#include "internal.h"
#include "pub/trace_file.h"
#include "pub/variant_buffer.h"
#include "pub/kprobe.h"
#include "pub/fs_utils.h"

#include "uapi/exit_monitor.h"

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_exit_monitor_settings exit_monitor_settings;

static unsigned int exec_monitor_alloced = 0;

static unsigned int exit_monitor_event_id = 0;
static unsigned int exit_monitor_event_seq = 0;

static struct diag_variant_buffer exit_monitor_variant_buffer;

static int hook_sched_process_exit(struct task_struct *p)
{
	struct task_struct *leader;
	unsigned long flags;
	static struct exit_monitor_detail *detail;
	static struct exit_monitor_map *map;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct file *file;

	if (!exit_monitor_settings.activated)
		return 0;

	if ((strcmp(exit_monitor_settings.comm, "") == 0) && (exit_monitor_settings.tgid == 0))
		return 0;

	leader = p->group_leader ? p->group_leader : p;
	if ((strcmp(exit_monitor_settings.comm, "") != 0) && (strcmp(exit_monitor_settings.comm, "none") != 0)
			&& (strcmp(exit_monitor_settings.comm, leader->comm) != 0))
		return 0;

	if ((exit_monitor_settings.tgid != 0) && (leader->pid != exit_monitor_settings.tgid))
		return 0;

	exit_monitor_event_seq++;

	mm = get_task_mm(current);
	if (mm) {
		down_read(&mm->mmap_sem);
		for (vma = mm->mmap; vma; vma = vma->vm_next) {
			file = vma->vm_file;
			if (file) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 33)
				struct inode *inode = vma->vm_file->f_path.dentry->d_inode;
#else
				struct inode *inode = file_inode(vma->vm_file);
#endif

				map = &diag_percpu_context[smp_processor_id()]->exit_monitor_map;
				map->et_type = et_exit_monitor_map;
				do_gettimeofday(&map->tv);
				map->dev = inode->i_sb->s_dev;
				map->ino = inode->i_ino;
				map->pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
				map->start = vma->vm_start;
				map->end = vma->vm_end;
				map->flags = vma->vm_flags;
				diag_get_file_path(file, map->file_name, 255);

				map->id = exit_monitor_event_id;
				map->seq = exit_monitor_event_seq;
				diag_task_brief(current, &map->task);
				diag_variant_buffer_spin_lock(&exit_monitor_variant_buffer, flags);
				diag_variant_buffer_reserve(&exit_monitor_variant_buffer,
						sizeof(struct exit_monitor_map));
				diag_variant_buffer_write_nolock(&exit_monitor_variant_buffer,
						map, sizeof(struct exit_monitor_map));
				diag_variant_buffer_seal(&exit_monitor_variant_buffer);
				diag_variant_buffer_spin_unlock(&exit_monitor_variant_buffer, flags);
			}
		}
		up_read(&mm->mmap_sem);
		mmput(mm);
	}

	diag_variant_buffer_spin_lock(&exit_monitor_variant_buffer, flags);
	detail = &diag_percpu_context[smp_processor_id()]->exit_monitor_detail;
	detail->et_type = et_exit_monitor_detail;
	detail->id = exit_monitor_event_id;
	detail->seq = exit_monitor_event_seq;
	do_gettimeofday(&detail->tv);
	diag_task_brief(current, &detail->task);
	diag_task_kern_stack(current, &detail->kern_stack);
	diag_task_user_stack(current, &detail->user_stack);
	diag_task_raw_stack(current, &detail->raw_stack);

	diag_variant_buffer_reserve(&exit_monitor_variant_buffer, sizeof(struct exit_monitor_detail));
	diag_variant_buffer_write_nolock(&exit_monitor_variant_buffer, detail, sizeof(struct exit_monitor_detail));
	diag_variant_buffer_seal(&exit_monitor_variant_buffer);
	diag_variant_buffer_spin_unlock(&exit_monitor_variant_buffer, flags);

	return 0;
}

static int
task_exit_notify(struct notifier_block *self, unsigned long val, void *data)
{
	atomic64_inc_return(&diag_nr_running);
	hook_sched_process_exit(current);
	atomic64_dec_return(&diag_nr_running);

	return 0;
}

static struct notifier_block task_exit_nb = {
	.notifier_call	= task_exit_notify,
};

static int __activate_exit_monitor(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&exit_monitor_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	exec_monitor_alloced = 1;

	profile_event_register(PROFILE_TASK_EXIT, &task_exit_nb);
	exit_monitor_event_id++;
	return 1;
out_variant_buffer:
	return 0;
}

int activate_exit_monitor(void)
{
	if (!exit_monitor_settings.activated)
		exit_monitor_settings.activated = __activate_exit_monitor();

	return exit_monitor_settings.activated;
}

static void __deactivate_exit_monitor(void)
{
	profile_event_unregister(PROFILE_TASK_EXIT, &task_exit_nb);

	synchronize_sched();
	msleep(10);
	while (atomic64_read(&diag_nr_running) > 0) {
		msleep(10);
	}
}

int deactivate_exit_monitor(void)
{
	if (exit_monitor_settings.activated)
		__deactivate_exit_monitor();
	exit_monitor_settings.activated = 0;

	return 0;
}

long diag_ioctl_exit_monitor(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_exit_monitor_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_EXIT_MONITOR_SET:
		if (exit_monitor_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_exit_monitor_settings));
			if (!ret) {
				exit_monitor_settings = settings;
			}
		}
		break;
	case CMD_EXIT_MONITOR_SETTINGS:
		settings = exit_monitor_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_exit_monitor_settings));
		break;
	case CMD_EXIT_MONITOR_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));

		if (!exec_monitor_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			ret = copy_to_user_variant_buffer(&exit_monitor_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("exit-monitor");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_exit_init(void)
{
	init_diag_variant_buffer(&exit_monitor_variant_buffer, 1 * 1024 * 1024);
 	if (exit_monitor_settings.activated)
		__activate_exit_monitor();

	return 0;
}

void diag_exit_exit(void)
{
	if (exit_monitor_settings.activated)
		deactivate_exit_monitor();
	exit_monitor_settings.activated = 0;
	destroy_diag_variant_buffer(&exit_monitor_variant_buffer);
}
