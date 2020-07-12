/*
 * Linux内核诊断工具--内核态tracepoint公共函数实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/rwsem.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/tracepoint.h>
#include <linux/rculist.h>

#include "pub/trace_point.h"

struct cb_sys_enter_node {
	cb_sys_enter cb;
	void *data;
	struct list_head list;
};

static DECLARE_RWSEM(sys_enter_sem);
static LIST_HEAD(sys_enter_list);

static struct cb_sys_enter_node* __lookup_cb_sys_enter(cb_sys_enter cb, void *data)
{
	struct cb_sys_enter_node *pos;
	struct cb_sys_enter_node *found = NULL;

	list_for_each_entry_rcu(pos, &sys_enter_list, list) {
		if (pos->cb == cb && pos->data == data) {
			found = pos;
			break;
		}
	}

	return found;
}

int diag_register_cb_sys_enter(cb_sys_enter cb, void *data)
{
	struct cb_sys_enter_node *found = NULL;
	int ret = 0;

	down_write(&sys_enter_sem);
	found = __lookup_cb_sys_enter(cb, data);
	if (found) {
		ret = -EEXIST;
	} else {
		struct cb_sys_enter_node *node;

		node = kmalloc(sizeof(struct cb_sys_enter_node), GFP_ATOMIC);
		if (node == NULL) {
			ret = -ENOMEM;
		} else {
			INIT_LIST_HEAD(&node->list);
			node->cb = cb;
			node->data = data;
			list_add_tail_rcu(&node->list, &sys_enter_list);
		}
	}
	up_write(&sys_enter_sem);

	return ret;
}

int diag_unregister_cb_sys_enter(cb_sys_enter cb, void *data)
{
	struct cb_sys_enter_node *found = NULL;
	int ret = 0;

	down_write(&sys_enter_sem);
	found = __lookup_cb_sys_enter(cb, data);
	if (found) {
		list_del_rcu(&found->list);
	} else {
		ret = -EEXIST;
	}
	up_write(&sys_enter_sem);

	if (found) {
#if KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE
		synchronize_rcu();
#else
		synchronize_sched();
#endif
		kfree(found);
	}
	return 0;
}

int diag_call_sys_enter(struct pt_regs *regs, long id)
{
	struct cb_sys_enter_node *pos;

	//down_read(&sys_enter_sem);
	list_for_each_entry_rcu(pos, &sys_enter_list, list) {
		pos->cb(pos->data, regs, id);
	}
	//up_read(&sys_enter_sem);

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
int hook_tracepoint(const char *name, void *probe, void *data)
{
	return tracepoint_probe_register(name, probe);
}

int unhook_tracepoint(const char *name, void *probe, void *data)
{
	int ret = 0;

	do {
		ret = tracepoint_probe_unregister(name, probe);
	} while (ret == -ENOMEM);

	return ret;
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 15, 0)
int hook_tracepoint(const char *name, void *probe, void *data)
{
	return tracepoint_probe_register(name, probe, data);
}

int unhook_tracepoint(const char *name, void *probe, void *data)
{
	int ret = 0;

	do {
		ret = tracepoint_probe_unregister(name, probe, data);
	} while (ret == -ENOMEM);

	return ret;
}
#else
static struct tracepoint *tp_ret;
static void probe_tracepoint(struct tracepoint *tp, void *priv)
{
	char *n = priv;

	if (strcmp(tp->name, n) == 0)
		tp_ret = tp;
}

static struct tracepoint *find_tracepoint(const char *name)
{
	tp_ret = NULL;
	for_each_kernel_tracepoint(probe_tracepoint, (void *)name);

	return tp_ret;
}

int hook_tracepoint(const char *name, void *probe, void *data)
{
	struct tracepoint *tp;

	tp = find_tracepoint(name);
	if (!tp)
		return 0;

	return tracepoint_probe_register(tp, probe, data);
}

int unhook_tracepoint(const char *name, void *probe, void *data)
{
	struct tracepoint *tp;
	int ret = 0;

	tp = find_tracepoint(name);
	if (!tp)
		return 0;

	do {
		ret = tracepoint_probe_unregister(tp, probe, data);
	} while (ret == -ENOMEM);

	return ret;
}
#endif
