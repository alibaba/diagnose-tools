/*
 * Linux内核诊断工具--内核态alloc-top功能
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

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
#include <linux/percpu_counter.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#include <linux/context_tracking.h>
#endif
#include <linux/sort.h>

#include <asm/irq_regs.h>
#include <asm/unistd.h>

#if !defined(DIAG_ARM64)
#include <asm/asm-offsets.h>
#endif

//#include <asm/traps.h>

#include "internal.h"
#include "pub/trace_file.h"
#include "pub/trace_point.h"

#include "uapi/alloc_top.h"

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_alloc_top_settings alloc_top_settings = {
	.top = 20,
};

static int alloc_top_alloced;

struct task_info {
	struct list_head list;
	struct task_struct *tsk;
	pid_t tgid;
	char comm[TASK_COMM_LEN];
	char cgroup_name[256];
	atomic64_t page_count;
};

#define MAX_TASK_COUNT 300000
struct task_info *task_buf[MAX_TASK_COUNT];

static atomic64_t task_count_in_tree = ATOMIC64_INIT(0);
__maybe_unused static struct radix_tree_root task_tree;
__maybe_unused static DEFINE_SPINLOCK(tree_lock);
static LIST_HEAD(task_list);
static DEFINE_MUTEX(task_mutex);

static struct diag_variant_buffer alloc_top_variant_buffer;

static int need_trace(struct task_struct *tsk)
{
	if (!alloc_top_settings.activated)
		return 0;

	return 1;
}

static struct task_info *find_alloc_task_info(struct task_struct *task)
{
	struct task_info *info;
	struct task_struct *leader;
	char cgroup_buf[256];

	if (task == NULL)
		return NULL;

	leader = task->group_leader ? task->group_leader : task;
	info = radix_tree_lookup(&task_tree, (unsigned long)leader);
	if (!info && MAX_TASK_COUNT > atomic64_read(&task_count_in_tree)) {
		info = kmalloc(sizeof(struct task_info), GFP_ATOMIC | __GFP_ZERO);
		if (info) {
			unsigned long flags;
			struct task_info *tmp;

			diag_cgroup_name(current, cgroup_buf, TASK_COMM_LEN, 0);
			info->tsk = leader;
			info->tgid = leader->pid;
			strncpy(info->comm, leader->comm, TASK_COMM_LEN);
			info->comm[TASK_COMM_LEN - 1] = 0;
			strncpy(info->cgroup_name, cgroup_buf, 255);
			info->cgroup_name[255] = 0;

			spin_lock_irqsave(&tree_lock, flags);
			tmp = radix_tree_lookup(&task_tree, (unsigned long)leader);
			if (tmp) {
				kfree(info);
				info = tmp;
			} else {
				radix_tree_insert(&task_tree, (unsigned long)leader, info);
				atomic64_inc(&task_count_in_tree);
			}
			spin_unlock_irqrestore(&tree_lock, flags);
		}
	}

	return info;
}

__maybe_unused static struct task_info *takeout_task_info(struct task_struct *task)
{
	unsigned long flags;
	struct task_info *info = NULL;

	if (task == NULL)
		return NULL;

	spin_lock_irqsave(&tree_lock, flags);
	info = radix_tree_delete(&task_tree, (unsigned long)task);
	if (info)
		atomic64_dec(&task_count_in_tree);
	spin_unlock_irqrestore(&tree_lock, flags);

	return info;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
static void trace_sched_process_exit_hit(struct task_struct *p)
#else
static void trace_sched_process_exit_hit(void *__data, struct task_struct *p)
#endif
{
	struct task_info *info;

	if (p != p->group_leader)
		return;

	info = takeout_task_info(p);
	if (info)
		kfree(info);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static void trace_mm_page_alloc_hit(void *ignore, struct page *page,
		unsigned int order, gfp_t gfp_flags, int migratetype)
#else
static void trace_mm_page_alloc_hit(struct page *page,
		unsigned int order, gfp_t gfp_flags, int migratetype)
#endif
{
	struct task_info *info;
	unsigned int pages = 1 << order;

	//atomic64_add(pages, &xby_debug1);
	if (in_interrupt())
		return;

	//atomic64_add(pages, &xby_debug2);
	if ((gfp_flags & GFP_ATOMIC) == GFP_ATOMIC)
		return;
	
	//atomic64_add(pages, &xby_debug3);
	if (!need_trace(current))
		return;

	info = find_alloc_task_info(current);

	//atomic64_add(pages, &xby_debug4);
	if (!info)
		return;

	atomic64_add(pages, &info->page_count);
	//atomic64_add(pages, &xby_debug5);
}

static int __activate_alloc_top(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&alloc_top_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	alloc_top_alloced = 1;

	hook_tracepoint("mm_page_alloc", trace_mm_page_alloc_hit, NULL);
	hook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_alloc_top(void)
{
	unhook_tracepoint("mm_page_alloc", trace_mm_page_alloc_hit, NULL);
	unhook_tracepoint("sched_process_exit", trace_sched_process_exit_hit, NULL);
	synchronize_sched();
	msleep(10);
	while (atomic64_read(&diag_nr_running) > 0) {
		msleep(10);
	}
}

int activate_alloc_top(void)
{
	if (!alloc_top_settings.activated)
		alloc_top_settings.activated = __activate_alloc_top();

	return alloc_top_settings.activated;
}

int deactivate_alloc_top(void)
{
	if (alloc_top_settings.activated)
		__deactivate_alloc_top();
	alloc_top_settings.activated = 0;

	return 0;
}

static int diag_compare_task(const void *one, const void *two)
{
	struct task_info *__one = *(struct task_info **)one;
	struct task_info *__two = *(struct task_info **)two;

	if (atomic64_read(&__one->page_count) > atomic64_read(&__two->page_count))
		return -1;
	if (atomic64_read(&__one->page_count) < atomic64_read(&__two->page_count))
		return 1;

	return 0;
}

static int do_show(void)
{
	int i;
	struct task_info *task_info;
	int task_count = 0;
	struct alloc_top_detail detail;
	unsigned long flags;

	if (!alloc_top_settings.activated)
		return 0;

	mutex_lock(&task_mutex);
	memset(task_buf, 0, sizeof(struct task_info *) * MAX_TASK_COUNT);
	list_for_each_entry(task_info, &task_list, list) {
		if (task_count < MAX_TASK_COUNT) {
			task_buf[task_count] = task_info;
			task_count++;
			} else {
				break;
		}
	}
	sort(&task_buf[0], (size_t)task_count, (size_t)sizeof(struct task_info *),
		&diag_compare_task, NULL);

	detail.id = get_cycles();
	detail.et_type = et_alloc_top_detail;
	for (i = 0; i < min_t(int, task_count, alloc_top_settings.top); i++)
	{
		task_info = task_buf[i];
		detail.seq = i;
		detail.tgid = task_info->tgid;
		strncpy(detail.comm, task_info->comm, TASK_COMM_LEN);
		detail.page_count = atomic64_read(&task_info->page_count);
		strncpy(detail.cgroup_name, task_info->cgroup_name, CGROUP_NAME_LEN);

		diag_variant_buffer_spin_lock(&alloc_top_variant_buffer, flags);
		diag_variant_buffer_reserve(&alloc_top_variant_buffer, sizeof(struct alloc_top_detail));
		diag_variant_buffer_write_nolock(&alloc_top_variant_buffer, &detail, sizeof(struct alloc_top_detail));
		diag_variant_buffer_seal(&alloc_top_variant_buffer);
		diag_variant_buffer_spin_unlock(&alloc_top_variant_buffer, flags);
	}

	mutex_unlock(&task_mutex);

	return 0;
}

static void do_dump(void)
{
	ssize_t ret;
	int i;
	unsigned long flags;
	struct task_info *tasks[NR_BATCH];
	struct task_info *task_info;
	int nr_found;
	unsigned long pos = 0;

	mutex_lock(&task_mutex);
	spin_lock_irqsave(&tree_lock, flags);
	INIT_LIST_HEAD(&task_list);
	do {
		nr_found = radix_tree_gang_lookup(&task_tree, (void **)tasks, pos, NR_BATCH);

		for (i = 0; i < nr_found; i++) {
			task_info = tasks[i];
			radix_tree_delete(&task_tree, (unsigned long)task_info->tsk);
			pos = (unsigned long)task_info->tsk + 1;
			INIT_LIST_HEAD(&task_info->list);
			list_add_tail(&task_info->list, &task_list);
		}
	} while (nr_found > 0);
	atomic64_set(&task_count_in_tree, 0);
	spin_unlock_irqrestore(&tree_lock, flags);
	mutex_unlock(&task_mutex);

	ret = do_show();

	mutex_lock(&task_mutex);
	while (!list_empty(&task_list)) {
        struct task_info *this = list_first_entry(&task_list,
										struct task_info, list);

		list_del_init(&this->list);
		kfree(this);
	}
	mutex_unlock(&task_mutex);
}

int alloc_top_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_alloc_top_settings settings;

	switch (id) {
	case DIAG_ALLOC_TOP_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_alloc_top_settings)) {
			ret = -EINVAL;
		} else if (alloc_top_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				alloc_top_settings = settings;
			}
		}
		break;
	case DIAG_ALLOC_TOP_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_alloc_top_settings)) {
			ret = -EINVAL;
		} else {
			settings = alloc_top_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_ALLOC_TOP_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!alloc_top_alloced) {
			ret = -EINVAL;
		} else {
			do_dump();
			ret = copy_to_user_variant_buffer(&alloc_top_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("alloc-top");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_alloc_top(unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

int diag_alloc_top_init(void)
{
	INIT_RADIX_TREE(&task_tree, GFP_ATOMIC);

	init_diag_variant_buffer(&alloc_top_variant_buffer, 1 * 1024 * 1024);
	if (alloc_top_settings.activated)
		alloc_top_settings.activated = __activate_alloc_top();

	return 0;
}

void diag_alloc_top_exit(void)
{
	int i;
	struct task_info *tasks[NR_BATCH];
	struct task_info *task_info;
	int nr_found;
	unsigned long pos = 0;

	if (alloc_top_settings.activated)
		deactivate_alloc_top();
	alloc_top_settings.activated = 0;

	msleep(20);

	rcu_read_lock();
	do {
		nr_found = radix_tree_gang_lookup(&task_tree, (void **)tasks, pos, NR_BATCH);
		for (i = 0; i < nr_found; i++) {
			task_info = tasks[i];
			radix_tree_delete(&task_tree, (unsigned long)task_info->tsk);
			pos = (unsigned long)task_info->tsk + 1;
			kfree(task_info);
		}
	} while (nr_found > 0);
	rcu_read_unlock();

	destroy_diag_variant_buffer(&alloc_top_variant_buffer);
}
