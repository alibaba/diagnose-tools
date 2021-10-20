/*
 * Linux内核诊断工具--内核态内存池公共函数头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef __APROF_PUB_MEM_POOL_H
#define __APROF_PUB_MEM_POOL_H

#include <linux/spinlock.h>
#include <linux/list.h>

#define MAX_MEM_POOL_COUNT 20000

struct mem_pool_obj {
	struct list_head block;
	struct list_head list;
	char dummy[0];
};

struct ali_mem_pool {
	spinlock_t mm_lock;
	struct list_head mm_list;
	struct list_head block_list;
	unsigned int obj_size;
};

static inline void ali_mem_pool_init(struct ali_mem_pool *mem_pool, int obj_size)
{
	mem_pool->obj_size = obj_size;
	spin_lock_init(&mem_pool->mm_lock);
	INIT_LIST_HEAD(&mem_pool->mm_list);
	INIT_LIST_HEAD(&mem_pool->block_list);
}
extern void ali_mem_pool_destroy(struct ali_mem_pool *mem_pool);
extern int ali_mem_pool_putin(struct ali_mem_pool *mem_pool, unsigned long count);
extern void *ali_mem_pool_alloc(struct ali_mem_pool *mem_pool);
extern void ali_mem_pool_free(struct ali_mem_pool *mem_pool, void *obj);

#endif /* __APROF_PUB_MEM_POOL_H */
