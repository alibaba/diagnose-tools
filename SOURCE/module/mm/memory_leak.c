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
#include "uapi/mm_leak.h"

struct alloc_desc {
	const void *addr;
	unsigned long trace_buf[BACKTRACE_DEPTH];
};

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
static int mm_leak_alloced;
static unsigned long last_dump_addr = 0;
/**
 * 防止重入
 */
static DEFINE_PER_CPU(int, tracing_nest_count);

static struct radix_tree_root mm_leak_tree;
static DEFINE_SPINLOCK(tree_lock);

static unsigned int mm_leak_activated = 0;
static unsigned int mm_leak_verbose;

static struct diag_variant_buffer mm_leak_variant_buffer;

static void *internal_kmalloc(size_t size, gfp_t flags)
{
	void *ret;

	per_cpu(tracing_nest_count, smp_processor_id()) += 1;
	ret = kmalloc(size, flags);
	per_cpu(tracing_nest_count, smp_processor_id()) -= 1;

	return ret;
}

static void internal_kfree(void *addr)
{
	per_cpu(tracing_nest_count, smp_processor_id()) += 1;
	kfree(addr);
	per_cpu(tracing_nest_count, smp_processor_id()) -= 1;
}

static void __maybe_unused clean_data(void)
{
	int nr_found;
	struct alloc_desc *batch[NR_BATCH];
	unsigned long pos = 0;
	int i;
	struct alloc_desc *desc;
	unsigned long flags;

	rcu_read_lock();

	do {
		nr_found = radix_tree_gang_lookup(&mm_leak_tree, (void **)batch, pos, NR_BATCH);
		for (i = 0; i < nr_found; i++) {
			desc = batch[i];
			pos = (unsigned long)desc->addr + 1;
			spin_lock_irqsave(&tree_lock, flags);
			radix_tree_delete(&mm_leak_tree, (unsigned long)desc->addr);
			spin_unlock_irqrestore(&tree_lock, flags);
			internal_kfree(desc);
		}
	} while (nr_found > 0);

	rcu_read_unlock();
}

__maybe_unused static struct alloc_desc *find_desc(void *addr)
{
	struct alloc_desc *desc;
	unsigned long flags;

	if (addr == NULL)
		return NULL;

	desc = radix_tree_lookup(&mm_leak_tree, (unsigned long)addr);
	if (!desc) {
		spin_lock_irqsave(&tree_lock, flags);
		desc = radix_tree_lookup(&mm_leak_tree, (unsigned long)addr);
		spin_unlock_irqrestore(&tree_lock, flags);
	}

	return desc;
}

static struct alloc_desc *find_alloc_desc(const void *addr)
{
	struct alloc_desc *desc;
	int ret;

	if (addr == NULL)
		return NULL;

	desc = radix_tree_lookup(&mm_leak_tree, (unsigned long)addr);
	if (!desc) {
		desc = internal_kmalloc(sizeof(struct alloc_desc), GFP_ATOMIC | __GFP_ZERO);
		ret = 0;

		if (desc) {
			unsigned long flags;
			struct alloc_desc *tmp;

			desc->addr = addr;
			diagnose_save_stack_trace(current, desc->trace_buf);

			spin_lock_irqsave(&tree_lock, flags);
			tmp = radix_tree_lookup(&mm_leak_tree, (unsigned long)addr);
			if (tmp) {
				internal_kfree(desc);
				desc = tmp;
			} else {
				radix_tree_insert(&mm_leak_tree, (unsigned long)addr, desc);
			}
			spin_unlock_irqrestore(&tree_lock, flags);
		}
	}

	return desc;
}

static struct alloc_desc *takeout_desc(void *addr)
{
	unsigned long flags;
	struct alloc_desc *desc = NULL;

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
	struct alloc_desc *desc;

	local_irq_save(flags);

	if (per_cpu(tracing_nest_count, smp_processor_id()) > 0)
		goto out;

	per_cpu(tracing_nest_count, smp_processor_id()) += 1;
	desc = find_alloc_desc(ptr);

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
	struct alloc_desc *desc;

	local_irq_save(flags);

	if (per_cpu(tracing_nest_count, smp_processor_id()) > 0)
		goto out;

	per_cpu(tracing_nest_count, smp_processor_id()) += 1;

	desc = takeout_desc((void *)ptr);
	if (desc) {
		kfree(desc);
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
	if (!mm_leak_activated)
		mm_leak_activated = __activate_mm_leak();

	return mm_leak_activated;
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
	if (mm_leak_activated)
		__deactivate_mm_leak();
	mm_leak_activated = 0;

	return 0;
}

static void do_dump(void)
{
	int nr_found;
	struct alloc_desc *batch[NR_BATCH];
	unsigned long pos = last_dump_addr + 1;
	int i, j;
	struct alloc_desc *desc;
	unsigned long flags;
	int count = 0;

	rcu_read_lock();

	do {
		nr_found = radix_tree_gang_lookup(&mm_leak_tree, (void **)batch, pos, NR_BATCH);
		for (i = 0; i < nr_found; i++) {
			static struct mm_leak_detail detail;

			desc = batch[i];
			last_dump_addr = (unsigned long)desc->addr;
			pos = (unsigned long)desc->addr + 1;
			spin_lock_irqsave(&tree_lock, flags);
			radix_tree_delete(&mm_leak_tree, (unsigned long)desc->addr);
			spin_unlock_irqrestore(&tree_lock, flags);
	
			detail.et_type = et_mm_leak_detail;
			do_gettimeofday(&detail.tv);
			for (j = 0; j < BACKTRACE_DEPTH; j++) {
				detail.kern_stack.stack[j] = desc->trace_buf[j];
			}

			diag_variant_buffer_spin_lock(&mm_leak_variant_buffer, flags);
			diag_variant_buffer_reserve(&mm_leak_variant_buffer, sizeof(struct mm_leak_detail));
			diag_variant_buffer_write_nolock(&mm_leak_variant_buffer,
				&detail, sizeof(struct mm_leak_detail));
			diag_variant_buffer_seal(&mm_leak_variant_buffer);
			diag_variant_buffer_spin_unlock(&mm_leak_variant_buffer, flags);

			internal_kfree(desc);

			count++;
			if (count >= 10000)
				break;
		}
	} while (nr_found > 0);

	rcu_read_unlock();
}

long diag_ioctl_mm_leak(unsigned int cmd, unsigned long arg)
{
	unsigned int verbose;
	int ret = 0;
	struct diag_mm_leak_settings settings;
	struct diag_ioctl_dump_param_cycle dump_param;

	switch (cmd) {
	case CMD_MM_LEAK_VERBOSE:
		ret = copy_from_user(&verbose, (void *)arg, sizeof(unsigned int));
		if (!ret) {
			mm_leak_verbose = verbose;
		}
		break;
	case CMD_MM_LEAK_SETTINGS:
		settings.activated = mm_leak_activated;
		settings.verbose = mm_leak_verbose;
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
	init_diag_variant_buffer(&mm_leak_variant_buffer, 5 * 1024 * 1024);
	INIT_RADIX_TREE(&mm_leak_tree, GFP_ATOMIC);

	if (mm_leak_activated)
		activate_mm_leak();

	return 0;
}

void diag_memory_leak_exit(void)
{
	if (mm_leak_activated)
		deactivate_mm_leak();

	clean_data();
}
