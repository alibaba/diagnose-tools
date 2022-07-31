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
#include <linux/delay.h>
#include <linux/kallsyms.h>
#include <linux/module.h>

#include "internal.h"
#include "pub/cgroup.h"
#include "pub/trace_point.h"
#include "pub/variant_buffer.h"

#include "uapi/pmu.h"
#include "pmu/pmu.h"
#include "pmu/debug.h"
#include "pub/mem_pool.h"
#include "pub/kprobe.h"

#if !defined(ALIOS_7U) && !defined(UBUNTU)
long diag_ioctl_pmu(unsigned int cmd, unsigned long arg)
{
	return -ENOSYS;
}

int activate_pmu(void)
{
	return 0;
}

int deactivate_pmu(void)
{
	return 0;
}

int diag_pmu_init(void)
{
	return 0;
}

int diag_pmu_exit(void)
{
	return 0;
}

#else

extern struct diag_variant_buffer pmu_variant_buffer;
extern struct diag_pmu_settings pmu_settings;
extern struct ali_mem_pool mem_pool;

#define CGROUP_BUFFER_MAX_COUNT 5000
#define CGROUP_BUFFER_INIT_COUNT 1000
static unsigned long diag_pmu_buffer_curr = 0;
static unsigned long diag_pmu_buffer_grow = 0;

enum {
	DIAG_PMU_NOT_LOAD = 0,
	DIAG_PMU_LOADING,
	DIAG_PMU_LOADED,
	DIAG_PMU_EXITING,
	DIAG_PMU_EXITED,
};

static int diag_pmu_module_state = DIAG_PMU_NOT_LOAD;
static DEFINE_SEMAPHORE(diag_pmu_sem);

__maybe_unused static struct kprobe kprobe_cgroup_destroy_locked;
__maybe_unused static struct kprobe kprobe_cgroup_populate_dir;

#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
static void trace_sched_switch_hit(void *__data, bool preempt,
		struct task_struct *prev, struct task_struct *next)
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
static void trace_sched_switch_hit(void *__data,
		struct task_struct *prev, struct task_struct *next)
#else
static void trace_sched_switch_hit(struct rq *rq, struct task_struct *prev,
		struct task_struct *next)
#endif
{
	struct pmu_percpu *record;
	struct pmu_registers data = {0};

	__maybe_unused cycles_t cycles_begin = 0;
	__maybe_unused cycles_t cycles_mm_task_prev = 0;
	__maybe_unused cycles_t cycles_mm_task_next = 0;
	__maybe_unused cycles_t cycles_update_pmu_prev= 0;
	__maybe_unused cycles_t cycles_update_pmu_next= 0;
	__maybe_unused cycles_t cycles_end;

	if (!pmu_settings.activated || !pmu_settings.sample)
		return;

	pmu_debug_get_cycles(cycles_begin);
	pmu_read_core_registers(&data);

	record = pmu_find_record(prev);
	if (record) {
		pmu_debug_get_cycles(cycles_mm_task_prev);
		if (record->flags == PMU_FLAG_SCHED_IN) {
			pmu_acc_delta(record, &data);
		}
		record->flags = PMU_FLAG_SCHED_OUT;
		pmu_debug_get_cycles(cycles_update_pmu_prev);
	}

	record = pmu_find_record(next);
	if (record) {
		pmu_debug_get_cycles(cycles_mm_task_next);
		pmu_refresh_counters(record, &data);
		record->flags = PMU_FLAG_SCHED_IN;
		pmu_debug_get_cycles(cycles_update_pmu_next);
	}

	pmu_debug_get_cycles(cycles_end);
	pmu_debug_context_switch(cycles_begin,
			cycles_mm_task_prev,
			cycles_mm_task_next,
			cycles_update_pmu_prev,
			cycles_update_pmu_next,
			cycles_end);
	return;
}

static void pmu_cgroup_rmdir(struct cgroup *cgrp)
{
	struct diag_pmu_detail *detail;
	struct pmu_cgroup *pmu_cgrp;
	struct pmu_registers data;
	struct pmu_percpu *record;
	unsigned long flags;
	int cpu;
	__maybe_unused cycles_t cycles_begin = 0;
	__maybe_unused cycles_t cycles_dump = 0;
	__maybe_unused cycles_t cycles_detach = 0;

	if (!cgrp)
		return;

	pmu_cgrp = pmu_find_cgroup(cgrp);
	if (unlikely(!pmu_cgrp))
		return;

	get_online_cpus();
	preempt_disable();

	pmu_debug_get_cycles(cycles_begin);

	pmu_cgrp = pmu_find_cgroup(cgrp);
	if (!pmu_cgrp) {
		put_online_cpus();
		return;
	}

	for_each_online_cpu(cpu) {
		record = (struct pmu_percpu*)&(pmu_cgrp->percpu_data[cpu]);
		if (record) {
			memset(&data, 0, sizeof(data));
			pmu_read_and_clear_record(&data, record);
			if (!data.instructions && !data.cycles && !data.ref_cycles)
				continue;

			detail = &get_percpu_context()->pmu.detail;
			pmu_fill_core_detail(detail, &data, cpu);

			diag_variant_buffer_spin_lock(&pmu_variant_buffer, flags);
			diag_variant_buffer_reserve(&pmu_variant_buffer, sizeof(*detail));
			diag_variant_buffer_write_nolock(&pmu_variant_buffer, detail,
					sizeof(*detail));
			diag_variant_buffer_seal(&pmu_variant_buffer);
			diag_variant_buffer_spin_unlock(&pmu_variant_buffer, flags);
		}
	}
	put_online_cpus();

	pmu_debug_get_cycles(cycles_dump);

	pmu_detach_cgroup(cgrp);

	pmu_debug_get_cycles(cycles_detach);

	pmu_debug_cgroup_rmdir(cycles_begin, cycles_dump, cycles_detach);

	preempt_enable();
}

#if KERNEL_VERSION(4, 19, 0) <= LINUX_VERSION_CODE
__maybe_unused static void trace_cgroup_rmdir_hit(void *__data,
		struct cgroup *cgrp, const char *path)
{
	pmu_cgroup_rmdir(cgrp);
}
#elif KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
__maybe_unused static void trace_cgroup_rmdir_hit(void *__data,
		struct cgroup *cgrp)
{
	pmu_cgroup_rmdir(cgrp);
}
#endif

static void pmu_cgroup_mkdir(struct cgroup *cgrp)
{
	__maybe_unused cycles_t cycles_begin = 0;
	__maybe_unused cycles_t cycles_end;

	if (unlikely(!cgrp))
		return;

#if KERNEL_VERSION(4, 8, 0) < LINUX_VERSION_CODE
	if (!(cgrp->subtree_ss_mask & (1 << cpuacct_cgrp_id)))
		return;
#else
	if (!cgrp->subsys[cpuacct_subsys_id])
		return;
#endif

	preempt_disable();

	pmu_debug_get_cycles(cycles_begin);
	pmu_attach_cgroup(cgrp);
	pmu_debug_get_cycles(cycles_end);

	preempt_enable();

	pmu_debug_cgroup_mkdir(cycles_begin, cycles_end);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
__maybe_unused static void trace_cgroup_mkdir_hit(void *__data,
		struct cgroup *cgrp, const char *path)
{
	pmu_cgroup_mkdir(cgrp);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
__maybe_unused static void trace_cgroup_mkdir_hit(void *__data,
		struct cgroup *cgrp)
{
	pmu_cgroup_mkdir(cgrp);
}
#else

__maybe_unused static int kprobe_cgroup_populate_dir_pre(struct kprobe *p,
		struct pt_regs *regs)
{
	struct cgroup * cgrp = (void *)ORIG_PARAM1(regs);

	pmu_cgroup_mkdir(cgrp);
	return 0;
}

__maybe_unused static int kprobe_cgroup_destroy_locked_pre(struct kprobe *p,
		struct pt_regs *regs)
{
	struct cgroup * cgrp = (void *)ORIG_PARAM1(regs);

	pmu_cgroup_rmdir(cgrp);
	return 0;
}

#endif

static void pmu_unhook_cgroup_create(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	unhook_kprobe(&kprobe_cgroup_populate_dir);
#else
	unhook_tracepoint("cgroup_mkdir", trace_cgroup_mkdir_hit, NULL);
#endif
}

static void pmu_unhook_cgroup_destroy(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	unhook_kprobe(&kprobe_cgroup_destroy_locked);
#else
	unhook_tracepoint("cgroup_rmdir", trace_cgroup_rmdir_hit, NULL);
#endif
}

static int pmu_hook_cgroup_create(void)
{
	int ret;

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
	ret = hook_tracepoint("cgroup_mkdir", trace_cgroup_mkdir_hit, NULL);
#else
	ret = hook_kprobe(&kprobe_cgroup_populate_dir, "cgroup_populate_dir",
			kprobe_cgroup_populate_dir_pre, NULL);
#endif

	if (ret)
		pr_err("pmu: failed to hook cgroup_mkdir, ret=%d\n", ret);

	return ret;
}

static int pmu_hook_cgroup_destroy(void)
{
	int ret;

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
	ret = hook_tracepoint("cgroup_rmdir", trace_cgroup_rmdir_hit, NULL);
#else
	ret = hook_kprobe(&kprobe_cgroup_destroy_locked, "cgroup_destroy_locked",
			kprobe_cgroup_destroy_locked_pre, NULL);
#endif

	if (ret)
		pr_err("pmu: failed to hook cgroup_rmdir, ret=%d\n", ret);

	return ret;
}

static int __activate_pmu(void)
{
	int ret = 0;

	pmu_clean_data();
	pmu_attach_all_cgroups();

	ret = pmu_create_all_events();
	if (ret) {
		pr_err("pmu: failed to activate pmu, ret=%d\n", ret);
		goto err_out;
	}

	ret = pmu_hook_cgroup_create();
	if (ret)
		goto err_detach;

	ret = pmu_hook_cgroup_destroy();
	if (ret) {
		goto err_unhook_cgroup_mkdir;
	}

	ret = hook_tracepoint("sched_switch", trace_sched_switch_hit, NULL);
	if (ret) {
		pr_err("pmu: failed to hook sched_switch, ret=%d\n", ret);
		goto err_unhook_cgroup_rmdir;
	}

	pmu_settings.activated = 1;
	return 1;

err_unhook_cgroup_rmdir:
	pmu_unhook_cgroup_destroy();

err_unhook_cgroup_mkdir:
	pmu_unhook_cgroup_create();

err_detach:
	synchronize_sched();

	pmu_detach_all_cgroups();
	pmu_destroy_all_events();

err_out:
	return 0;
}

int activate_pmu(void)
{
	int ret = 0;

	down(&diag_pmu_sem);
	if (!pmu_settings.activated)
		ret = __activate_pmu();
	up(&diag_pmu_sem);

	return ret;
}

static int __deactivate_pmu(void)
{
	int ret = 0;

	unhook_tracepoint("sched_switch", trace_sched_switch_hit, NULL);
	pmu_unhook_cgroup_create();
	pmu_unhook_cgroup_destroy();

	synchronize_sched();
	msleep(10);
	pmu_destroy_all_events();
	pmu_detach_all_cgroups();

	return ret;
}

int deactivate_pmu(void)
{
	int ret = 0;

	down(&diag_pmu_sem);
	if (pmu_settings.activated) {
		__deactivate_pmu();
	} else {
		ret = -EAGAIN;
	}
	pmu_settings.activated = 0;
	up(&diag_pmu_sem);

	return ret;
}

long diag_ioctl_pmu(unsigned int cmd, unsigned long arg)
{
	int ret = -EINVAL;
	int sample;
	static struct diag_pmu_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_PMU_SET:
		down(&diag_pmu_sem);
		if (pmu_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_pmu_settings));
			if (!ret) {
				pmu_settings = settings;
				pmu_settings.activated = 0;
			}
		}
		up(&diag_pmu_sem);

		break;
	case CMD_PMU_SETTINGS:
		settings = pmu_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_pmu_settings));

		break;
	case CMD_PMU_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));
		if (!ret) {
			pmu_do_dump();
			ret = copy_to_user_variant_buffer(&pmu_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
		}

		break;
	case CMD_PMU_SAMPLE:
		ret = copy_from_user(&sample, (void *)arg, sizeof(int));
		if (!ret) {
			pmu_settings.sample = sample;
		}

		break;
	default:
		break;
	}

	return ret;
}

static int diag_pmu_mem_pool_grow(unsigned int num)
{
	int ret;

	if (diag_pmu_buffer_curr + num > CGROUP_BUFFER_MAX_COUNT)
		return -EINVAL;

	ret = ali_mem_pool_putin(&mem_pool, num);
	if (ret) {
		pr_err("pmu: grow mem_pool failed, ret=%d, num=%u\n",
				ret, num);
		return ret;
	}

	diag_pmu_buffer_grow = num;
	diag_pmu_buffer_curr += num;

	return 0;
}

static int pmu_lookup_syms(void)
{
#if defined(DIAG_ARM64)
	LOOKUP_SYMS(armpmu_read);
#else
	LOOKUP_SYMS(x86_perf_event_update);
#endif

	return 0;
}

int diag_pmu_init(void)
{
	int ret;

	WRITE_ONCE(diag_pmu_module_state, DIAG_PMU_LOADING);
	diag_pmu_pool_init();
	diag_pmu_radix_init();
	ret = init_diag_variant_buffer(&pmu_variant_buffer, DIAG_PMU_VARIANT_BUF_LEN);
	if (ret) {
		pr_err("pmu: init variant_buffer failed, ret=%d\n", ret);
		return ret;
	}

	ret = alloc_diag_variant_buffer(&pmu_variant_buffer);
	if (ret) {
		pr_err("pmu: alloc variant_buffer failed, ret=%d\n", ret);
		goto out_destroy_variant_buffer;
	}

	ret = diag_pmu_mem_pool_grow(CGROUP_BUFFER_INIT_COUNT);
	if (ret) {
		goto out_destroy_variant_buffer;
	}

	if (pmu_lookup_syms()) {
		ret = -EINVAL;
		goto out_destroy_mem_pool;
	}

	diag_pmu_init_wq();

	ret = pmu_debug_proc_create();
	if (ret) {
		goto out_destroy_mem_pool;
	}

	WRITE_ONCE(diag_pmu_module_state, DIAG_PMU_LOADED);
	return 0;

out_destroy_mem_pool:
	ali_mem_pool_destroy(&mem_pool);
out_destroy_variant_buffer:
	destroy_diag_variant_buffer(&pmu_variant_buffer);
	return ret;
}

void diag_pmu_exit(void)
{
	down(&diag_pmu_sem);
	WRITE_ONCE(diag_pmu_module_state, DIAG_PMU_EXITING);
	pmu_debug_proc_destroy();

	if (pmu_settings.activated) {
		__deactivate_pmu();
	}

	destroy_diag_variant_buffer(&pmu_variant_buffer);

	ali_mem_pool_destroy(&mem_pool);
	WRITE_ONCE(diag_pmu_module_state, DIAG_PMU_EXITED);
	up(&diag_pmu_sem);
}

#endif
