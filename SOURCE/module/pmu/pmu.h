#ifndef APROF_PMU_H
#define APROF_PMU_H

#include <linux/list.h>
#include <linux/cache.h>
#include "internal.h"

#define PMU_FLAG_UNKNOWN      0
#define PMU_FLAG_SCHED_IN     1
#define PMU_FLAG_SCHED_OUT    2


struct pmu_registers {
	unsigned long instructions;
	unsigned long cycles;
	unsigned long ref_cycles;
	unsigned long branch_misses;
	unsigned long last_cache_misses;
	unsigned long raw_pmu_event1;
	unsigned long raw_pmu_event2;
};

struct pmu_percpu {
	struct pmu_registers last;
	struct pmu_registers sum;
	int flags;
	unsigned long __pad __attribute__ ((aligned (32)));
};

struct pmu_cgroup {
  struct cgroup *cgrp;
  unsigned long cpu_count;
  char cgrp_buf[CGROUP_NAME_LEN];
  struct pmu_percpu percpu_data[0] __attribute__ ((aligned (64)));
};

void pmu_read_and_clear_record(struct pmu_registers *data,
		struct pmu_percpu *record);

void diag_pmu_pool_init(void);
void diag_pmu_radix_init(void);
void diag_pmu_init_wq(void);

void pmu_do_dump(void);

int pmu_create_all_events(void);
void pmu_destroy_all_events(void);

void pmu_clean_data(void);
void pmu_attach_all_cgroups(void);
void pmu_detach_all_cgroups(void);

void pmu_fill_core_detail(struct diag_pmu_detail *detail,
		const struct pmu_registers *data, int cpu);

void pmu_detach_cgroup(struct cgroup *tsk);
void pmu_attach_cgroup(struct cgroup *tsk);

int pmu_cpuhp_register(void);
void pmu_cpuhp_unregister(void);

struct perf_event;

#if defined(APROF_ARM64)
extern void (*orig_armpmu_read)(struct perf_event *event);
#else
extern u64 (*orig_x86_perf_event_update)(struct perf_event *event);
#endif

extern struct diag_pmu_settings pmu_settings;

static inline void pmu_refresh_counters(struct pmu_percpu *record,
		const struct pmu_registers *data)
{
	record->last.instructions = data->instructions;
	record->last.cycles = data->cycles;
	record->last.ref_cycles = data->ref_cycles;
	record->last.branch_misses = data->branch_misses;
	record->last.last_cache_misses = data->last_cache_misses;
	record->last.raw_pmu_event1 = data->raw_pmu_event1;
	record->last.raw_pmu_event2 = data->raw_pmu_event2;
}

static inline void handle_delta(unsigned long curr, unsigned long* prev,
		unsigned long *sum, char * prefix)
{
	signed long delta = curr - *prev;

	*prev = curr;
	if (likely(delta > 0)) {
		*sum += delta;
	}
}

static inline void pmu_acc_delta(struct pmu_percpu *record,
		const struct pmu_registers *data)
{
	handle_delta(data->instructions, &record->last.instructions,
			&record->sum.instructions, "instructions");
	handle_delta(data->cycles, &record->last.cycles,
			&record->sum.cycles, "cycles");
	handle_delta(data->ref_cycles, &record->last.ref_cycles,
			&record->sum.ref_cycles, "ref_cycles");
	handle_delta(data->branch_misses, &record->last.branch_misses,
			&record->sum.branch_misses, "branch_misses");
	handle_delta(data->last_cache_misses, &record->last.last_cache_misses,
			&record->sum.last_cache_misses, "last_chche_misses");
	handle_delta(data->raw_pmu_event1, &record->last.raw_pmu_event1,
			&record->sum.raw_pmu_event1, "raw_pmu_event1");
	handle_delta(data->raw_pmu_event2, &record->last.raw_pmu_event2,
			&record->sum.raw_pmu_event2, "raw_pmu_event2");
}

static inline unsigned long pmu_read_core_event(struct perf_event *event)
{
	unsigned long flags;

	if (!event)
		return 0;

#if defined (APROF_ARM64)
	if (!orig_armpmu_read)
		return 0;
#else
	if (!orig_x86_perf_event_update)
		return 0;
#endif

	if (event->state == PERF_EVENT_STATE_ACTIVE) {
		local_irq_save(flags);
#if defined (APROF_ARM64)
		orig_armpmu_read(event);
#else
		orig_x86_perf_event_update(event);
#endif
		local_irq_restore(flags);
	}

	return local64_read(&event->count);
}

static inline void pmu_read_core_registers(struct pmu_registers *data)
{
	struct diag_percpu_context *ctx = get_percpu_context();

	if (unlikely(!ctx))
		return;

	if (pmu_settings.conf_fixed_counters) {
		data->cycles = pmu_read_core_event(ctx->pmu.events[PMU_INDEX_CYCLES]);
		data->instructions = pmu_read_core_event(ctx->pmu.events[PMU_INDEX_INSTRUCTIONS]);
		data->ref_cycles = pmu_read_core_event(ctx->pmu.events[PMU_INDEX_REF_CYCLES]);
	}

	if (pmu_settings.conf_branch_misses)
		data->branch_misses = pmu_read_core_event(ctx->pmu.events[PMU_INDEX_BRANCH_MISSES]);

	if (pmu_settings.conf_last_cache_misses) {
		data->last_cache_misses = pmu_read_core_event(ctx->pmu.events[PMU_INDEX_LLC_MISSES]);
	}

	if (pmu_settings.conf_raw_pmu_event1)
		data->raw_pmu_event1 = pmu_read_core_event(ctx->pmu.events[PMU_INDEX_RAW_EVENT1]);

	if (pmu_settings.conf_raw_pmu_event2)
		data->raw_pmu_event2 = pmu_read_core_event(ctx->pmu.events[PMU_INDEX_RAW_EVENT2]);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,0)
#define ACCT_CGRP_ID cpuacct_cgrp_id
#else
#define ACCT_CGRP_ID cpuacct_subsys_id
#endif

struct radix_tree_root;
extern struct radix_tree_root pmu_cgroup_tree;

static inline struct pmu_cgroup *pmu_pick_cgroup_by_task(struct task_struct *task)
{
	struct cgroup *cgrp = NULL;
	struct pmu_cgroup *info = NULL;

	if (task && task->cgroups &&
			task->cgroups->subsys &&
			task->cgroups->subsys[ACCT_CGRP_ID] &&
			task->cgroups->subsys[ACCT_CGRP_ID]->cgroup)
		cgrp = task->cgroups->subsys[ACCT_CGRP_ID]->cgroup;
	else
		goto out;

	rcu_read_lock();
	info = radix_tree_lookup(&pmu_cgroup_tree, (unsigned long)cgrp);
	rcu_read_unlock();

out:
	return info;
}

static inline struct pmu_percpu *pmu_find_record(struct task_struct *task)
{
	struct pmu_cgroup *pmu_cgrp;

	pmu_cgrp = pmu_pick_cgroup_by_task(task);
	if (!pmu_cgrp)
		return NULL;

	return (struct pmu_percpu*)&(pmu_cgrp->percpu_data[smp_processor_id()]);
}

static inline struct pmu_cgroup *pmu_find_cgroup(struct cgroup *cgrp)
{
	struct pmu_cgroup *info = NULL;

	if (!cgrp)
		goto out;

	rcu_read_lock();
	info = radix_tree_lookup(&pmu_cgroup_tree, (unsigned long)cgrp);
	rcu_read_unlock();

out:
	return info;
}

#endif /* APROF_PMU_H */
