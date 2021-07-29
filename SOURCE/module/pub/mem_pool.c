/*
 * Linux内核诊断工具--内核态内存池功能
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Wen Yang <simon.wy@linux.alibaba.com>
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
#include <asm/irq_regs.h>

#include "mem_pool.h"

int ali_mem_pool_putin(struct ali_mem_pool *mem_pool, unsigned long count)
{
	unsigned long flags;
	int i;
	unsigned long size;
	struct mem_pool_obj *obj;
	unsigned long addr;
	int ret = -ENOMEM;

	size = sizeof(struct mem_pool_obj) + mem_pool->obj_size;

	if (count >= MAX_MEM_POOL_COUNT || !count) {
		return -EINVAL;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
	obj = __vmalloc(size * count, GFP_KERNEL | __GFP_ZERO, PAGE_KERNEL);
#else
	obj = __vmalloc(size * count, GFP_KERNEL | __GFP_ZERO);
#endif

	addr = (unsigned long)obj;
	if (obj) {
		spin_lock_irqsave(&mem_pool->mm_lock, flags);

		INIT_LIST_HEAD(&obj->block);
		list_add(&obj->block, &mem_pool->block_list);
		for (i = 0; i < count; i++) {
			INIT_LIST_HEAD(&obj->list);
			list_add(&obj->list, &mem_pool->mm_list);
			addr += size;
			obj = (void *)addr;
		}

		spin_unlock_irqrestore(&mem_pool->mm_lock, flags);

		ret = 0;
	}

	return ret;
}

void ali_mem_pool_destroy(struct ali_mem_pool *mem_pool)
{
	unsigned long flags;

	spin_lock_irqsave(&mem_pool->mm_lock, flags);

	while (!list_empty(&mem_pool->block_list)) {
		struct mem_pool_obj *block = list_first_entry(&mem_pool->block_list, struct mem_pool_obj, block);
		list_del_init(&block->block);
		spin_unlock_irqrestore(&mem_pool->mm_lock, flags);
		vfree(block);
		spin_lock_irqsave(&mem_pool->mm_lock, flags);
	}
	spin_unlock_irqrestore(&mem_pool->mm_lock, flags);
}

void *ali_mem_pool_alloc(struct ali_mem_pool *mem_pool)
{
	unsigned long flags;
	struct mem_pool_obj *ret = NULL;

	spin_lock_irqsave(&mem_pool->mm_lock, flags);

	if (!list_empty(&mem_pool->mm_list)) {
		ret = list_first_entry(&mem_pool->mm_list, struct mem_pool_obj, list);
		list_del_init(&ret->list);
	}

	spin_unlock_irqrestore(&mem_pool->mm_lock, flags);

	return ret ? (void *)ret->dummy : NULL;
}

void ali_mem_pool_free(struct ali_mem_pool *mem_pool, void *obj)
{
	unsigned long flags;
	struct mem_pool_obj *pool = container_of(obj, struct mem_pool_obj, dummy);

	spin_lock_irqsave(&mem_pool->mm_lock, flags);

	INIT_LIST_HEAD(&pool->list);
	list_add(&pool->list, &mem_pool->mm_list);

	spin_unlock_irqrestore(&mem_pool->mm_lock, flags);
}
