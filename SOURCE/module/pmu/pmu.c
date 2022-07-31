/*
 * Linux内核诊断工具--内核态pmu功能
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
#include <linux/radix-tree.h>
#include <linux/cpu.h>
#include <linux/syscalls.h>
#include <linux/vmalloc.h>
#include <asm/irq_regs.h>

#include "uapi/pmu.h"
#include "pub/trace_file.h"
#include "pub/variant_buffer.h"
#include "pub/trace_point.h"
#include "pub/cgroup.h"
#include "pub/mem_pool.h"
#include "pmu/pmu.h"
#include "pmu/debug.h"

atomic64_t pmu_nr_running = ATOMIC64_INIT(0);
struct diag_pmu_settings effective_pmu_settings = {0};
struct diag_pmu_settings pmu_settings = {0};

struct ali_mem_pool mem_pool;
struct diag_variant_buffer pmu_variant_buffer;

static DEFINE_SPINLOCK(tree_lock);
struct radix_tree_root pmu_cgroup_tree;

DEFINE_PER_CPU(struct work_struct, dump_pmu_works);

#if defined (APROF_ARM64)
void (*orig_armpmu_read)(struct perf_event *event) = NULL;
#else
u64 (*orig_x86_perf_event_update)(struct perf_event *event) = NULL;
#endif

static struct perf_event_attr pmu_attrs[PMU_INDEX_MAX] =
{
	[PMU_INDEX_CYCLES] = {
		.type           = PERF_TYPE_HARDWARE,
		.config         = PERF_COUNT_HW_CPU_CYCLES,
		.size           = sizeof(struct perf_event_attr),
		.pinned         = 1,
		.disabled       = 0,
	},
	[PMU_INDEX_INSTRUCTIONS] = {
		.type           = PERF_TYPE_HARDWARE,
		.config         = PERF_COUNT_HW_INSTRUCTIONS,
		.size           = sizeof(struct perf_event_attr),
		.pinned         = 1,
		.disabled       = 0,
	},
	[PMU_INDEX_REF_CYCLES] = {
		.type           = PERF_TYPE_HARDWARE,
		.config         = PERF_COUNT_HW_REF_CPU_CYCLES,
		.size           = sizeof(struct perf_event_attr),
		.pinned         = 1,
		.disabled       = 0,
	},
	[PMU_INDEX_BRANCH_MISSES] = {
		.type           = PERF_TYPE_HARDWARE,
		.config         = PERF_COUNT_HW_BRANCH_MISSES,
		.size           = sizeof(struct perf_event_attr),
		.pinned         = 1,
		.disabled       = 0,
	},

#if defined (APROF_ARM64)
	[PMU_INDEX_RAW_EVENT1] = {
		.type           = PERF_TYPE_RAW,
		.config         = 16395,
		.size           = sizeof(struct perf_event_attr),
		.pinned         = 1,
		.disabled       = 0,
	},
#else
	[PMU_INDEX_LLC_MISSES] = {
		.type           = PERF_TYPE_HARDWARE,
		.config         = PERF_COUNT_HW_CACHE_MISSES,
		.size           = sizeof(struct perf_event_attr),
		.pinned         = 1,
		.disabled       = 0,
	},
#endif

	[PMU_INDEX_RAW_EVENT1] = {
		.type           = PERF_TYPE_RAW,
		.config         = 0x151,
		.size           = sizeof(struct perf_event_attr),
		.pinned         = 0,
		.disabled       = 0,
	},
	[PMU_INDEX_RAW_EVENT2] = {
		.type           = PERF_TYPE_RAW,
		.config         = 0x3f24,
		.size           = sizeof(struct perf_event_attr),
		.pinned         = 0,
		.disabled       = 0,
	},
};

void diag_pmu_radix_init(void)
{
	unsigned long flags;

	spin_lock_irqsave(&tree_lock, flags);
	INIT_RADIX_TREE(&pmu_cgroup_tree, GFP_ATOMIC);
	spin_unlock_irqrestore(&tree_lock, flags);
}

void diag_pmu_pool_init(void)
{
	int size;

	size = sizeof(struct pmu_cgroup) + sizeof(struct pmu_percpu) * num_possible_cpus();
	ali_mem_pool_init(&mem_pool, size);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,0)

static int pmu_cgroup_name(struct cgroup *cgrp, char *buf, size_t buflen)
{
    memset(buf, 0, buflen);

    if (orig_kernfs_name && cgrp) {
        return orig_kernfs_name(cgrp->kn, buf, buflen);
    } else {
        return 0;
    }
}

#else

static int pmu_cgroup_name(struct cgroup *cgrp, char *buf, size_t buflen)
{
    const char *name;
    memset(buf, 0, buflen);

    if (cgrp) {
        name = cgroup_name(cgrp);
        strncpy(buf, name, buflen);
        buf[buflen - 1] = 0;

        return strlen(buf);
    }

    return 0;
}
#endif

void pmu_attach_cgroup(struct cgroup *cgrp)
{
	unsigned long flags;
	struct pmu_cgroup *info;
	struct pmu_cgroup *tmp;

	info = radix_tree_lookup(&pmu_cgroup_tree, (unsigned long)cgrp);
	if (info)
		return;

	tmp = ali_mem_pool_alloc(&mem_pool);
	if (tmp) {
		tmp->cgrp = cgrp;

		spin_lock_irqsave(&tree_lock, flags);

		info = radix_tree_lookup(&pmu_cgroup_tree, (unsigned long)cgrp);
		if (info) {
			ali_mem_pool_free(&mem_pool, tmp);
		} else {
			radix_tree_insert(&pmu_cgroup_tree, (unsigned long)cgrp, tmp);
			info = tmp;
			pmu_debug_nr_cgroup_inc();
		}

		spin_unlock_irqrestore(&tree_lock, flags);

		pmu_cgroup_name(cgrp, info->cgrp_buf, CGROUP_NAME_LEN);
		info->cgrp_buf[CGROUP_NAME_LEN - 1] = 0;
	}
}

void pmu_detach_cgroup(struct cgroup *cgrp)
{
	unsigned long flags;
	struct pmu_cgroup *info;

	if (!cgrp)
		return;

	spin_lock_irqsave(&tree_lock, flags);

	info = radix_tree_lookup(&pmu_cgroup_tree, (unsigned long)cgrp);
	if (info) {
		info->cgrp = NULL;
		radix_tree_delete(&pmu_cgroup_tree, (unsigned long)cgrp);
		pmu_debug_nr_cgroup_dec();
	}

	spin_unlock_irqrestore(&tree_lock, flags);

	if (info) {
		ali_mem_pool_free(&mem_pool, info);
	}
}

static void pmu_release_perf_event(struct perf_event **event)
{
	if (event && *event) {
		printk_ratelimited(KERN_DEBUG "pmu: release perf_event(type=%d,"
				"config=0x%llx) on cpu[%d]\n", (*event)->attr.type,
				(*event)->attr.config, (*event)->cpu);

		perf_event_disable(*event);
		perf_event_release_kernel(*event);
		*event = NULL;
	}
}

static int pmu_destroy_counter(unsigned int cpu)
{
	struct diag_percpu_context *context = get_percpu_context_cpu(cpu);
	int index;

	for (index = 0; index < PMU_INDEX_MAX; ++index)
		pmu_release_perf_event(&context->pmu.events[index]);

	return 0;
}

static struct perf_event *pmu_create_perf_event(struct perf_event_attr *attr,
		int cpu)
{
	struct perf_event *event;

	event = perf_event_create_kernel_counter(attr, cpu, NULL, NULL, NULL);
	if (IS_ERR(event)) {
		printk_ratelimited(KERN_ERR "pmu: failed to create perf_event(type=%d,"
				"config=0x%llx) on cpu[%d], ret=%ld\n", attr->type, attr->config,
				cpu, PTR_ERR(event));
		goto err_out;
	}

	printk_ratelimited(KERN_DEBUG "pmu: create perf_event(%d/0x%llx) on cpu[%d]"
			" successful, state=%d\n", attr->type, attr->config, cpu, event->state);

	perf_event_enable(event);

	return event;

err_out:
	return NULL;
}

static int _pmu_create_counter(int conf, int replace_config, int cpu,
		struct perf_event_attr *attr, struct perf_event **event)
{
	if (!conf || !event || *event)
		return 0;

	if (replace_config)
		attr->config = conf;

	*event = pmu_create_perf_event(attr, cpu);
	return *event ? 0 : -EAGAIN;
}

#if defined(PMU_DEBUG) && PMU_DEBUG > 0
  #if defined(DIAG_ARM64)
    #define APROF_FIXED_COUNTERS 2
  #else
    #define APROF_FIXED_COUNTERS 3
  #endif
#else
  #define APROF_FIXED_COUNTERS 2
#endif

static int pmu_create_core_events(int cpu)
{
	struct diag_percpu_context *context = get_percpu_context_cpu(cpu);
	int index;
	int ret;

	for (index = 0; index < APROF_FIXED_COUNTERS; ++index) {
		ret = _pmu_create_counter(pmu_settings.conf_fixed_counters, 0, cpu,
				&pmu_attrs[index], &context->pmu.events[index]);
		if (ret)
			goto err_out;
	}

	ret = _pmu_create_counter(pmu_settings.conf_branch_misses, 0, cpu,
			&pmu_attrs[PMU_INDEX_BRANCH_MISSES],
			&context->pmu.events[PMU_INDEX_BRANCH_MISSES]);
	if (ret)
		goto err_out;

	ret = _pmu_create_counter(pmu_settings.conf_last_cache_misses, 0, cpu,
			&pmu_attrs[PMU_INDEX_LLC_MISSES],
			&context->pmu.events[PMU_INDEX_LLC_MISSES]);
	if (ret)
		goto err_out;

	ret = _pmu_create_counter(pmu_settings.conf_raw_pmu_event1, 1, cpu,
			&pmu_attrs[PMU_INDEX_RAW_EVENT1],
			&context->pmu.events[PMU_INDEX_RAW_EVENT1]);
	if (ret)
		goto err_out;

	ret = _pmu_create_counter(pmu_settings.conf_raw_pmu_event2, 1, cpu,
			&pmu_attrs[PMU_INDEX_RAW_EVENT2],
			&context->pmu.events[PMU_INDEX_RAW_EVENT2]);
	if (ret)
		goto err_out;

	return 0;

err_out:
	pmu_destroy_counter(cpu);
	return ret;
}

void pmu_destroy_all_events(void)
{
	unsigned int cpu;

	get_online_cpus();
	for_each_online_cpu(cpu)
		pmu_destroy_counter(cpu);
	put_online_cpus();
}

int pmu_create_all_events(void)
{
	int cpu;
	int ret;

	get_online_cpus();

	for_each_online_cpu(cpu) {
		ret = pmu_create_core_events(cpu);
		if (ret) {
			put_online_cpus();
			goto err_out;
		}
	}

	put_online_cpus();

	return 0;

err_out:
	pmu_destroy_all_events();
	return ret;
}

struct cpuacct_impl {
	struct cgroup_subsys_state css;
	char internal[0];
};

static struct cpuacct * cb_attach_cpuacct_cgrp(struct cpuacct *acct, void *data)
{
	struct cpuacct_impl *impl;

	if (acct) {
		impl = (void *)acct;
		pmu_attach_cgroup(impl->css.cgroup);
	}

	return NULL;
}

static struct cpuacct * cb_detach_cpuacct_cgrp(struct cpuacct *acct, void *data)
{
	struct cpuacct_impl *impl;

	if (acct) {
		impl = (void *)acct;
		pmu_detach_cgroup(impl->css.cgroup);
	}

	return NULL;
}

void pmu_attach_all_cgroups(void)
{
	cpuacct_cgroup_walk_tree(cb_attach_cpuacct_cgrp, NULL);
}

void pmu_detach_all_cgroups(void)
{
	cpuacct_cgroup_walk_tree(cb_detach_cpuacct_cgrp, NULL);
}

static void pmu_walk_pmu_cgroup_tree(void (*callback)(struct pmu_cgroup *))
{
	struct pmu_cgroup *pmu_cgrps[NR_BATCH];
	struct pmu_cgroup *pmu_cgrp;
	unsigned long pos = 0;
	int nr_found;
	int i;

	rcu_read_lock();

	do {
		nr_found = radix_tree_gang_lookup(&pmu_cgroup_tree, (void **)pmu_cgrps, pos, NR_BATCH);

		for (i = 0; i < nr_found; i++) {
			pmu_cgrp = pmu_cgrps[i];
			callback(pmu_cgrp);
			pos = (unsigned long)pmu_cgrp->cgrp + 1;
		}
	} while (nr_found > 0);

	rcu_read_unlock();
}

static void pmu_clean_percpu_data(struct pmu_cgroup *pmu_cgrp)
{
	if (!pmu_cgrp)
		return;

	memset(&pmu_cgrp->percpu_data[0], 0,
			sizeof(struct pmu_percpu) * num_possible_cpus());
}

void pmu_clean_data(void)
{
	pmu_debug_init();
	pmu_walk_pmu_cgroup_tree(pmu_clean_percpu_data);
}

void pmu_read_and_clear_record(struct pmu_registers *data,
		struct pmu_percpu *record)
{
	data->instructions = record->sum.instructions;
	data->cycles = record->sum.cycles;
	data->ref_cycles = record->sum.ref_cycles;
	data->branch_misses = record->sum.branch_misses;
	data->last_cache_misses = record->sum.last_cache_misses;
	data->raw_pmu_event1 = record->sum.raw_pmu_event1;
	data->raw_pmu_event2 = record->sum.raw_pmu_event2;

	record->sum.instructions = 0;
	record->sum.cycles = 0;
	record->sum.ref_cycles = 0;
	record->sum.branch_misses = 0;
	record->sum.last_cache_misses = 0;
	record->sum.raw_pmu_event1 = 0;
	record->sum.raw_pmu_event2 = 0;
}

void pmu_fill_core_detail(struct diag_pmu_detail *detail,
		const struct pmu_registers *data, int cpu)
{
	detail->et_type = et_pmu_detail;
	detail->cpu = cpu;
	detail->instructions = data->instructions;
	detail->ref_cycles = data->ref_cycles;
	detail->cycles = data->cycles;
	detail->branch_misses = data->branch_misses;
	detail->last_cache_misses = data->last_cache_misses;
	detail->raw_pmu_event1 = data->raw_pmu_event1;
	detail->raw_pmu_event2 = data->raw_pmu_event2;
}

static void pmu_dump_local_core(struct pmu_cgroup *pmu_cgrp)
{
	struct pmu_registers data = {0};
	struct diag_pmu_detail *detail;
	struct pmu_percpu *record;
	unsigned long flags;

	if (!pmu_cgrp)
		return;

	preempt_disable();
	record = (struct pmu_percpu*)&(pmu_cgrp->percpu_data[smp_processor_id()]);
	pmu_read_and_clear_record(&data, record);
	if (pmu_settings.conf_fixed_counters && !data.instructions &&
	    !data.cycles && !data.ref_cycles)
		goto out;

	detail = &get_percpu_context()->pmu.detail;
	pmu_fill_core_detail(detail, &data, smp_processor_id());
	memcpy(&detail->cgrp_buf, &pmu_cgrp->cgrp_buf, CGROUP_NAME_LEN);

	diag_variant_buffer_spin_lock(&pmu_variant_buffer, flags);
	diag_variant_buffer_reserve(&pmu_variant_buffer, sizeof(*detail));
	diag_variant_buffer_write_nolock(&pmu_variant_buffer, detail, sizeof(*detail));
	diag_variant_buffer_seal(&pmu_variant_buffer);
	diag_variant_buffer_spin_unlock(&pmu_variant_buffer, flags);

out:
	preempt_enable();
	return;
}

static void pmu_dump_local(struct work_struct *work)
{
	pmu_walk_pmu_cgroup_tree(pmu_dump_local_core);
}

void diag_pmu_init_wq(void)
{
	int i;
	struct work_struct *dump_work;

	for_each_possible_cpu(i) {
		dump_work = per_cpu_ptr(&dump_pmu_works, i);
		INIT_WORK(dump_work, pmu_dump_local);
	}
}

static void dump_pmu_all(void)
{
	unsigned int cpu;

	if (!pmu_settings.activated)
		return;

	atomic64_inc_return(&pmu_nr_running);
	get_online_cpus();

	for_each_online_cpu(cpu)
		queue_work_on(cpu, system_wq, per_cpu_ptr(&dump_pmu_works, cpu));

	for_each_online_cpu(cpu)
		flush_work(per_cpu_ptr(&dump_pmu_works, cpu));

	put_online_cpus();
	atomic64_dec_return(&pmu_nr_running);
}

void diag_pmu_timer(struct diag_percpu_context *context)
{
	struct pmu_percpu *record;
	__maybe_unused cycles_t cycles_begin;
	__maybe_unused cycles_t cycles_find_record;
	__maybe_unused cycles_t cycles_update_record;
	__maybe_unused cycles_t cycles_end;

	if (!pmu_settings.activated ||
		!pmu_settings.sample ||
		!pmu_settings.style)
		return;

	pmu_debug_get_cycles(cycles_begin);

	record = pmu_find_record(current);
	if (record) {
		struct pmu_registers data = {0};

		pmu_debug_get_cycles(cycles_find_record);

		pmu_read_core_registers(&data);
		if (record->flags == PMU_FLAG_SCHED_IN) {
			pmu_acc_delta(record, &data);
		}

		pmu_debug_get_cycles(cycles_update_record);
		pmu_debug_get_cycles(cycles_end);
		pmu_debug_in_timer(cycles_begin, cycles_find_record, cycles_update_record, cycles_end);
	}
}

void pmu_do_dump(void)
{
	static DEFINE_MUTEX(mutex);

	if (!pmu_settings.activated || !pmu_settings.sample)
		return;

	mutex_lock(&mutex);
	dump_pmu_all();
	mutex_unlock(&mutex);
}
