/*
 * Linux内核诊断工具--内核态mm-leak功能
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
#include <linux/list.h>
#include <linux/version.h>
#include <linux/sort.h>
#include <linux/vmalloc.h>

#include "internal.h"
#include "mm_internal.h"
#include "pub/trace_file.h"
#include "pub/variant_buffer.h"
#include "pub/trace_point.h"
#include "pub/mem_pool.h"
#include "uapi/mm_leak.h"

struct mm_block_desc {
	void *addr;
	u64 stamp;
	size_t bytes_req;
	size_t bytes_alloc;
	struct diag_task_detail task;
	unsigned long trace_buf[BACKTRACE_DEPTH];
};

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_mm_leak_settings mm_leak_settings;
static int mm_leak_alloced;
static unsigned long last_dump_addr = 0;
/**
 * 防止重入
 */
static DEFINE_PER_CPU(int, tracing_nest_count);

static struct radix_tree_root mm_leak_tree;
static DEFINE_SPINLOCK(tree_lock);

static struct ali_mem_pool mem_pool;

static struct diag_variant_buffer mm_leak_variant_buffer;

static void *alloc_desc(void)
{
	void *ret;

	ret = ali_mem_pool_alloc(&mem_pool);

	return ret;
}

static void free_desc(struct mm_block_desc *desc)
{
	ali_mem_pool_free(&mem_pool, desc);
}

static void __maybe_unused clean_data(void)
{
	int nr_found;
	struct mm_block_desc *batch[NR_BATCH];
	unsigned long pos = 0;
	int i;
	struct mm_block_desc *desc;

	rcu_read_lock();

	do {
		nr_found = radix_tree_gang_lookup(&mm_leak_tree, (void **)batch, pos, NR_BATCH);
		for (i = 0; i < nr_found; i++) {
			desc = batch[i];
			pos = (unsigned long)desc->addr + 1;
			radix_tree_delete(&mm_leak_tree, (unsigned long)desc->addr);
			free_desc(desc);
		}
	} while (nr_found > 0);

	rcu_read_unlock();
}

static struct mm_block_desc *find_alloc_desc(void *addr)
{
	unsigned long flags;
	struct mm_block_desc *desc;
	int ret;

	if (addr == NULL)
		return NULL;

	desc = radix_tree_lookup(&mm_leak_tree, (unsigned long)addr);
	if (!desc) {
		desc = alloc_desc();
		ret = 0;

		if (desc) {
			struct mm_block_desc *tmp;

			desc->addr = addr;
			diagnose_save_stack_trace(current, desc->trace_buf);
			diag_task_brief(current, &desc->task);

			spin_lock_irqsave(&tree_lock, flags);
			tmp = radix_tree_lookup(&mm_leak_tree, (unsigned long)addr);
			if (tmp) {
				free_desc(desc);
				desc = tmp;
			} else {
				radix_tree_insert(&mm_leak_tree, (unsigned long)addr, desc);
			}
			spin_unlock_irqrestore(&tree_lock, flags);
		}
	}

	return desc;
}

static struct mm_block_desc *takeout_desc(void *addr)
{
	unsigned long flags;
	struct mm_block_desc *desc = NULL;

	spin_lock_irqsave(&tree_lock, flags);
	desc = radix_tree_delete(&mm_leak_tree, (unsigned long)addr);
	spin_unlock_irqrestore(&tree_lock, flags);

	return desc;
}

#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
static void trace_kmem_cache_alloc_hit(void *__data, unsigned long call_site, const void *ptr,
	   size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags)
#else
static void trace_kmem_cache_alloc_hit(unsigned long call_site, const void *ptr,
	   size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags)
#endif
{
	unsigned long flags;
	struct mm_block_desc *desc;

	if (mm_leak_settings.max_bytes > 0 && bytes_alloc > mm_leak_settings.max_bytes)
		return;

	if (bytes_alloc < mm_leak_settings.min_bytes)
		return;

	local_irq_save(flags);

	if (per_cpu(tracing_nest_count, smp_processor_id()) > 0)
		goto out;

	/**
	 * 虽然find_alloc_desc调用了alloc_desc，但是此句仍然不可少
	 * 因为基树可能分配内存，导致重入本函数
	 */
	per_cpu(tracing_nest_count, smp_processor_id()) += 1;
	desc = find_alloc_desc((void *)ptr);
	if (desc) {
		desc->stamp = sched_clock();
		desc->bytes_req = bytes_req;
		desc->bytes_alloc = bytes_alloc;
	}
	per_cpu(tracing_nest_count, smp_processor_id()) -= 1;

out:
	local_irq_restore(flags);
}

#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
static void trace_kmem_cache_free_hit(void *ignore, unsigned long call_site, const void *ptr)
#else
static void trace_kmem_cache_free_hit(unsigned long call_site, const void *ptr)
#endif
{
	unsigned long flags;
	struct mm_block_desc *desc;

	local_irq_save(flags);

	if (per_cpu(tracing_nest_count, smp_processor_id()) > 0)
		goto out;

	per_cpu(tracing_nest_count, smp_processor_id()) += 1;

	desc = takeout_desc((void *)ptr);
	if (desc) {
		free_desc(desc);
	}

	per_cpu(tracing_nest_count, smp_processor_id()) -= 1;

out:
	local_irq_restore(flags);
}

static int __activate_mm_leak(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&mm_leak_variant_buffer);
	if (ret)
		goto out_variant_buffer;

	mm_leak_alloced = 1;

	hook_tracepoint("kmem_cache_alloc", trace_kmem_cache_alloc_hit, NULL);
	hook_tracepoint("kmem_cache_free", trace_kmem_cache_free_hit, NULL);

	return 1;
out_variant_buffer:
	return 0;
}

int activate_mm_leak(void)
{
	if (!mm_leak_settings.activated)
		mm_leak_settings.activated = __activate_mm_leak();

	return mm_leak_settings.activated;
}

static int __deactivate_mm_leak(void)
{
	unhook_tracepoint("kmem_cache_alloc", trace_kmem_cache_alloc_hit, NULL);
	unhook_tracepoint("kmem_cache_free", trace_kmem_cache_free_hit, NULL);

	synchronize_sched();
	/**
	 * 在JUMP_REMOVE和atomic64_read之间存在微妙的竞态条件
	 * 因此这里的msleep并非多余的。
	 */
	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0)
		msleep(20);

	clean_data();

	return 0;
}

int deactivate_mm_leak(void)
{
	if (mm_leak_settings.activated)
		__deactivate_mm_leak();
	mm_leak_settings.activated = 0;

	return 0;
}

static void do_dump(void)
{
	int nr_found;
	struct mm_block_desc *batch[NR_BATCH];
	unsigned long pos = last_dump_addr + 1;
	int i, j;
	struct mm_block_desc *desc;
	unsigned long flags;
	int count = 0;
	u64 now = sched_clock();
	u64 delta_time;

	rcu_read_lock();

	do {
		nr_found = radix_tree_gang_lookup(&mm_leak_tree, (void **)batch, pos, NR_BATCH);
		for (i = 0; i < nr_found; i++) {
			static struct mm_leak_detail detail;

			desc = batch[i];
			last_dump_addr = (unsigned long)desc->addr;
			pos = (unsigned long)desc->addr + 1;

			delta_time = now - desc->stamp;
			if (delta_time < (u64)mm_leak_settings.time_threshold * 1000 * 1000 * 1000)
				continue;
	
			detail.et_type = et_mm_leak_detail;
			do_diag_gettimeofday(&detail.tv);
			for (j = 0; j < BACKTRACE_DEPTH; j++) {
				detail.kern_stack.stack[j] = desc->trace_buf[j];
			}
			detail.task = desc->task;
			detail.addr = (void *)desc->addr;
			detail.bytes_req = desc->bytes_req;
			detail.bytes_alloc = desc->bytes_alloc;
			detail.delta_time = delta_time / (1000 * 1000 * 1000); //s

			spin_lock_irqsave(&tree_lock, flags);
			desc = radix_tree_delete(&mm_leak_tree, (unsigned long)desc->addr);
			spin_unlock_irqrestore(&tree_lock, flags);
			if (desc) {
				free_desc(desc);
			}

			diag_variant_buffer_spin_lock(&mm_leak_variant_buffer, flags);
			diag_variant_buffer_reserve(&mm_leak_variant_buffer, sizeof(struct mm_leak_detail));
			diag_variant_buffer_write_nolock(&mm_leak_variant_buffer,
				&detail, sizeof(struct mm_leak_detail));
			diag_variant_buffer_seal(&mm_leak_variant_buffer);
			diag_variant_buffer_spin_unlock(&mm_leak_variant_buffer, flags);

			count++;
		}
		if (count >= 10000)
			break;
	} while (nr_found > 0);

	rcu_read_unlock();
}

int mm_leak_syscall(struct pt_regs *regs, long id)
{
	int __user *ptr_len;
	void __user *buf;
	size_t __user buf_len;
	size_t size;
	int ret = 0;
	unsigned long cycle;
	struct diag_mm_leak_settings settings;

	switch (id) {
	case DIAG_MM_LEAK_SET:
		buf = (void __user *)SYSCALL_PARAM1(regs);
		buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (buf_len != sizeof(struct diag_mm_leak_settings)) {
			ret = -EINVAL;
		} else if (mm_leak_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, buf, buf_len);
			if (!ret) {
				  mm_leak_settings = settings;
			}
		}
		break;
	case DIAG_MM_LEAK_SETTINGS:
		buf = (void __user *)SYSCALL_PARAM1(regs);
		size = (size_t)SYSCALL_PARAM2(regs);

		if (size != sizeof(struct diag_mm_leak_settings)) {
			ret = -EINVAL;
		} else {
			settings = mm_leak_settings;
			ret = copy_to_user(buf, &settings, size);
		}
		break;
	case DIAG_MM_LEAK_DUMP:
		ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		buf = (void __user *)SYSCALL_PARAM2(regs);
		size = (size_t)SYSCALL_PARAM3(regs);
		cycle = SYSCALL_PARAM3(regs);

		if (cycle) {
			last_dump_addr = 0;
		}
		if (!mm_leak_alloced) {
			ret = -EINVAL;
		} else {
			do_dump();
			ret = copy_to_user_variant_buffer(&mm_leak_variant_buffer, ptr_len, buf, size);
			record_dump_cmd("mm-leak");
		}

		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_mm_leak(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_mm_leak_settings settings;
	struct diag_ioctl_dump_param_cycle dump_param;

	switch (cmd) {
	case CMD_MM_LEAK_SET:
		if (mm_leak_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_mm_leak_settings));
			if (!ret) {
				mm_leak_settings = settings;
			}
		}
		break;
	case CMD_MM_LEAK_SETTINGS:
		settings = mm_leak_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_mm_leak_settings));
		break;
	case CMD_MM_LEAK_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param_cycle));
		if (!mm_leak_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			if (dump_param.cycle) {
				last_dump_addr = 0;
			}
			do_dump();
			ret = copy_to_user_variant_buffer(&mm_leak_variant_buffer, 
				dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("mm-leak");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_memory_leak_init(void)
{
	int ret = 0;

	init_diag_variant_buffer(&mm_leak_variant_buffer, 5 * 1024 * 1024);
	INIT_RADIX_TREE(&mm_leak_tree, GFP_ATOMIC);

	ali_mem_pool_init(&mem_pool, sizeof(struct mm_block_desc));
	ret = ali_mem_pool_putin(&mem_pool, 1 * 10000);
	if (ret) {
		goto out_destroy_variant_buffer;
	}

	if (mm_leak_settings.activated)
		__activate_mm_leak();

	return 0;
out_destroy_variant_buffer:
	destroy_diag_variant_buffer(&mm_leak_variant_buffer);
	return ret;
}

void diag_memory_leak_exit(void)
{
	if (mm_leak_settings.activated)
		deactivate_mm_leak();

	clean_data();

	destroy_diag_variant_buffer(&mm_leak_variant_buffer);
	ali_mem_pool_destroy(&mem_pool);
}
