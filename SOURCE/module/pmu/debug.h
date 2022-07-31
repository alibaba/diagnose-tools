#ifndef APROF_PMU_DEBUG_H
#define APROF_PMU_DEBUG_H

#if defined(PMU_DEBUG) && PMU_DEBUG > 0


/**
 * 调试PMU相关模块的性能
 */
struct pmu_cost {
	unsigned long long nr_switch;
	unsigned long long nr_fork;
	unsigned long long nr_exit;
	unsigned long long nr_timer;
	unsigned long long cycles_switch;
	unsigned long long cycles_fork;
	unsigned long long cycles_exit;
	unsigned long long cycles_timer;
	unsigned long long cycles_find_record;
	unsigned long long cycles_init_record;
	unsigned long long cycles_update_record;
	unsigned long long cycles_dump_record;
	unsigned long long cycles_attach_record;
	unsigned long long cycles_detach_record;
};

DECLARE_PER_CPU(struct pmu_cost, diag_pmu_costs);

extern void pmu_debug_init(void);
extern void pmu_debug_context_switch(cycles_t cycles_begin,
			cycles_t cycles_mm_task_prev,
			cycles_t cycles_mm_task_next,
			cycles_t cycles_update_pmu_prev,
			cycles_t cycles_update_pmu_next,
			cycles_t cycles_end);
extern void pmu_debug_cgroup_rmdir(cycles_t cycles_begin,
	cycles_t cycles_dump,
	cycles_t cycles_detach);
extern void pmu_debug_cgroup_mkdir(cycles_t cycles_begin,
	cycles_t cycles_end);
extern void pmu_debug_in_timer(cycles_t cycles_begin,
	cycles_t cycles_find_record,
	cycles_t cycles_update_record,
	cycles_t cycles_end);
#define pmu_debug_get_cycles(v) \
	do {						\
		v = get_cycles();		\
	} while (0)

extern int pmu_debug_proc_create(void);
extern void pmu_debug_proc_destroy(void);

extern void pmu_debug_nr_cgroup_inc(void);
extern void pmu_debug_nr_cgroup_dec(void);

#else
static inline void pmu_debug_init(void)
{
	//
}

#define pmu_debug_get_cycles(v)	\
	do {						\
	} while (0)

static inline void pmu_debug_context_switch(cycles_t cycles_begin,
			cycles_t cycles_mm_task_prev,
			cycles_t cycles_mm_task_next,
			cycles_t cycles_update_pmu_prev,
			cycles_t cycles_update_pmu_next,
			cycles_t cycles_end)
{
	//
}

static inline void pmu_debug_cgroup_rmdir(cycles_t cycles_begin,
	cycles_t cycles_dump,
	cycles_t cycles_detach)
{
	//
}

static inline void pmu_debug_cgroup_mkdir(cycles_t cycles_begin,
	cycles_t cycles_end)
{
	//
}

static inline void pmu_debug_in_timer(cycles_t cycles_begin,
	cycles_t cycles_find_record,
	cycles_t cycles_update_record,
	cycles_t cycles_end)
{
	//
}

static inline int pmu_debug_proc_create(void)
{
	return 0;
}

static inline void pmu_debug_proc_destroy(void)
{
	//
}

static inline void pmu_debug_nr_cgroup_inc(void)
{
	//
}

static inline void pmu_debug_nr_cgroup_dec(void)
{
	//
}

#endif /* APROF_DEBUG */

#endif

