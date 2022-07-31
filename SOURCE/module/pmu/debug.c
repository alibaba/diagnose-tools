#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "uapi/pmu.h"

#if defined(PMU_DEBUG) && PMU_DEBUG > 0

#define PMU_DEBUG_FILE "ali-linux/diag/diag_pmu_costs"

DEFINE_PER_CPU(struct pmu_cost, diag_pmu_costs);

static int diag_pmu_nr_cgroup = 0;

void pmu_debug_init(void)
{
	struct pmu_cost *cost;
	unsigned int cpu;

	for_each_online_cpu(cpu) {
		cost = &per_cpu(diag_pmu_costs, cpu);
		memset(cost, 0, sizeof(struct pmu_cost));
	}
}

void pmu_debug_context_switch(cycles_t cycles_begin,
			cycles_t cycles_mm_task_prev,
			cycles_t cycles_mm_task_next,
			cycles_t cycles_update_pmu_prev,
			cycles_t cycles_update_pmu_next,
			cycles_t cycles_end)

{
    struct pmu_cost *cost;

    cost = this_cpu_ptr(&diag_pmu_costs);
	cost->nr_switch +=1;
	cost->cycles_switch += cycles_end - cycles_begin;
	cost->cycles_find_record += cycles_mm_task_prev ?
		cycles_mm_task_prev - cycles_begin : 0;
	cost->cycles_update_record += cycles_update_pmu_prev ?
		cycles_update_pmu_prev - cycles_mm_task_prev : 0;
	cost->cycles_find_record += cycles_mm_task_next ?
		(cycles_update_pmu_prev ? cycles_mm_task_next - cycles_update_pmu_prev : 0) : 0;
	cost->cycles_update_record += cycles_mm_task_next ?
		cycles_end - cycles_mm_task_next : 0;
}

void pmu_debug_cgroup_rmdir(cycles_t cycles_begin,
	cycles_t cycles_dump,
	cycles_t cycles_detach)
{
	struct pmu_cost *cost;

    cost = &per_cpu(diag_pmu_costs, smp_processor_id());
	cost->nr_exit += 1;
	cost->cycles_exit += cycles_detach - cycles_begin;
	cost->cycles_dump_record += cycles_dump - cycles_begin;
	cost->cycles_detach_record += cycles_detach - cycles_dump;
}

void pmu_debug_cgroup_mkdir(cycles_t cycles_begin,
	cycles_t cycles_end)
{
    struct pmu_cost *cost;

	cost = this_cpu_ptr(&diag_pmu_costs);
	cost->nr_fork += 1;
	cost->cycles_fork += cycles_end - cycles_begin;
	cost->cycles_attach_record += cycles_end - cycles_begin;
}

void pmu_debug_in_timer(cycles_t cycles_begin,
	cycles_t cycles_find_record,
	cycles_t cycles_update_record,
	cycles_t cycles_end)
{
    struct pmu_cost *cost;

    cost = this_cpu_ptr(&diag_pmu_costs);
    cost->nr_timer += 1;
    cost->cycles_timer += cycles_end - cycles_begin;
    cost->cycles_find_record += cycles_find_record - cycles_begin;
    cost->cycles_update_record += cycles_update_record - cycles_find_record;
}

void pmu_debug_nr_cgroup_inc(void)
{
	diag_pmu_nr_cgroup += 1;
}

void pmu_debug_nr_cgroup_dec(void)
{
	diag_pmu_nr_cgroup -= 1;
}


static int pmu_cost_show(struct seq_file *m, void *v)
{
	struct pmu_cost *cost;
	int cpu;

	for_each_online_cpu(cpu) {
		cost = &per_cpu(diag_pmu_costs, cpu);
		seq_printf(m, "cpu[%d] nr_switch %llu ->cycles_switch %llu "
				"nr_timer %llu ->cycles_timer %llu "
				"nr_fork %llu ->cycles_fork %llu "
				"nr_exit %llu ->cycles_exit %llu "
				"| cycles_find_record %llu cycles_update_record %llu "
				"cycles_attach_record %llu cycles_detach_record %llu\n",
				cpu, cost->nr_switch, cost->cycles_switch,
				cost->nr_timer, cost->cycles_timer,
				cost->nr_fork, cost->cycles_fork,
				cost->nr_exit, cost->cycles_exit,
				cost->cycles_find_record, cost->cycles_update_record,
				cost->cycles_attach_record, cost->cycles_detach_record);
	}

	seq_printf(m, "-----------------------------\n");
	seq_printf(m, "nr_cgroups: %d\n", diag_pmu_nr_cgroup);

	return 0;
}

static int pmu_cost_open(struct inode *inode, struct file *file)
{
	return single_open(file, pmu_cost_show, NULL);
}

static const struct file_operations pmu_cost_fops =
{
	.owner		= THIS_MODULE,
	.open		= pmu_cost_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

int pmu_debug_proc_create(void)
{
    struct proc_dir_entry *pe;
    int ret = 0;

    pe = proc_create(PMU_DEBUG_FILE, S_IFREG | 0444, NULL,
			&pmu_cost_fops);

	if (!pe) {
		ret = -ENOMEM;
	}

    return ret;
}

void pmu_debug_proc_destroy(void)
{
	remove_proc_entry(PMU_DEBUG_FILE, NULL);

}

#endif
