/*
 * Linux内核诊断工具--内核态cgroup公共函数实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include "pub/cgroup.h"
#include "symbol.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0) || LINUX_VERSION_CODE > KERNEL_VERSION(4,10,0)
struct cgroup * cpuacct_to_cgroup(struct cpuacct *acct)
{
	return NULL;
}

struct cgroup *diag_cpuacct_cgroup_tsk(struct task_struct *tsk)
{
	return NULL;
}

struct cpuacct *diag_find_cpuacct_name(char *name)
{
	return NULL;
}

void diag_cpuacct_cgroup_name_tsk(struct task_struct *tsk, char *buf, unsigned int count)
{
}

#else

typedef struct cpuacct *(*match_cpuacct)(struct cpuacct *acct, void *data);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,0)

#define diag_css_for_each_descendant_pre(pos, css)				\
	for ((pos) = orig_css_next_descendant_pre(NULL, (css)); (pos);	\
	     (pos) = orig_css_next_descendant_pre((pos), (css)))

/*
 * CPU accounting code for task groups.
 *
 * Based on the work by Paul Menage (menage@google.com) and Balbir Singh
 * (balbir@in.ibm.com).
 */

/* Time spent by the tasks of the cpu accounting group executing in ... */
enum cpuacct_stat_index {
	CPUACCT_STAT_USER,	/* ... user mode */
	CPUACCT_STAT_SYSTEM,	/* ... kernel mode */

	CPUACCT_STAT_NSTATS,
};

static const char * const cpuacct_stat_desc[] = {
	[CPUACCT_STAT_USER] = "user",
	[CPUACCT_STAT_SYSTEM] = "system",
};

struct cpuacct_usage {
	u64	usages[CPUACCT_STAT_NSTATS];
};

/* track cpu usage of a group of tasks and its child groups */
struct cpuacct {
	struct cgroup_subsys_state css;
	/* cpuusage holds pointer to a u64-type object on every cpu */
	struct cpuacct_usage __percpu *cpuusage;
	struct kernel_cpustat __percpu *cpustat;
};

static inline int diag_cgroup_name(struct cgroup *cgrp, char *buf, size_t buflen)
{
	memset(buf, 0, buflen);

	if (orig_kernfs_name && cgrp) {
		return orig_kernfs_name(cgrp->kn, buf, buflen);
	} else {
		return 0;
	}
}

struct cgroup *diag_cpuacct_cgroup_tsk(struct task_struct *tsk)
{
	struct cgroup *ret = NULL;

	if (tsk && tsk->cgroups && tsk->cgroups->subsys
			&& tsk->cgroups->subsys[cpuacct_cgrp_id]
			&& tsk->cgroups->subsys[cpuacct_cgrp_id]->cgroup) {
		ret = tsk->cgroups->subsys[cpuacct_cgrp_id]->cgroup;
	}

	return ret;
}

static struct cpuacct * cpuacct_cgroup_walk_tree(match_cpuacct match_cpuacct, void *data)
{
	struct cpuacct *root = orig_root_cpuacct;
	struct cgroup_subsys_state *css;
	struct cpuacct *acct;
	struct cpuacct *ret = NULL;

	if (!orig_css_next_descendant_pre || !orig_root_cpuacct)
		return NULL;

	rcu_read_lock();
	diag_css_for_each_descendant_pre(css, &root->css) {
		acct = NULL;
		if (css && css_tryget(css))
			acct = container_of(css, struct cpuacct, css);
		if (acct) {
			ret = match_cpuacct(acct, data);
			css_put(&acct->css);
		}

		if (ret)
			break;

		if (!css)
			break;
	}
	rcu_read_unlock();

	return ret;
}
#else

#define MAX_SCHED_LAT 50
typedef u64 sched_lat_array[MAX_SCHED_LAT];

/* Time spent by the tasks of the cpu accounting group executing in ... */
enum cpuacct_stat_index {
	CPUACCT_STAT_USER,	/* ... user mode */
	CPUACCT_STAT_SYSTEM,	/* ... kernel mode */
	CPUACCT_STAT_MIGRATIONS,

	CPUACCT_STAT_NSTATS,
};

enum cpuacct_usage_index {
	CPUACCT_USAGE_USER,	/* ... user mode */
	CPUACCT_USAGE_SYSTEM,	/* ... kernel mode */

	CPUACCT_USAGE_NRUSAGE,
};

/* track cpu usage of a group of tasks and its child groups */
struct cpuacct {
	struct cgroup_subsys_state css;
	/* cpuusage holds pointer to a u64-type object on every cpu */
	u64 __percpu *cpuusage;
	struct kernel_cpustat __percpu *cpustat;
};

static inline int diag_cgroup_name(struct cgroup *cgrp, char *buf, size_t buflen)
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

static struct cpuacct * cpuacct_cgroup_walk_tree(match_cpuacct match_cpuacct, void *data)
{
	struct cpuacct *root = orig_root_cpuacct;
	struct cgroup_subsys_state *css;
	struct cpuacct *acct;
	int found, nextid;
	struct cpuacct *ret = NULL;

	if (!orig_root_cpuacct || !orig_css_get_next)
		return NULL;

	nextid = 1;
	do {
		ret = 0;
		acct = NULL;

		rcu_read_lock();
		css = orig_css_get_next(orig_cpuacct_subsys, nextid, &root->css,
						   &found);
		if (css && css_tryget(css)) {
			acct = container_of(css, struct cpuacct, css);
			ret = match_cpuacct(acct, data);
		}
		rcu_read_unlock();

		if (acct) {
			css_put(&acct->css);
		}
		nextid = found + 1;
	} while (!ret && css);

	return ret;
}

struct cgroup *diag_cpuacct_cgroup_tsk(struct task_struct *tsk)
{
	struct cgroup *ret = NULL;

	if (tsk && tsk->cgroups && tsk->cgroups->subsys
			&& tsk->cgroups->subsys[cpuacct_subsys_id]
			&& tsk->cgroups->subsys[cpuacct_subsys_id]->cgroup) {
		ret = tsk->cgroups->subsys[cpuacct_subsys_id]->cgroup;
	}

	return ret;
}

#endif

static struct cpuacct *match_cpuacct_name(struct cpuacct *acct, void *data)
{
	char buf[256];

	diag_cgroup_name(acct->css.cgroup, buf, 255);
	if (strncmp(buf, data, 255) == 0) {
		return acct;
	} else {
		return NULL;
	}
}

struct cpuacct *diag_find_cpuacct_name(char *name)
{
	struct cpuacct *ret;

	ret = cpuacct_cgroup_walk_tree(match_cpuacct_name, (void *)name);

	return ret;
}

void diag_cpuacct_cgroup_name_tsk(struct task_struct *tsk, char *buf, unsigned int count)
{
	struct cgroup *cgroup = NULL;

	memset(buf, 0, count);
	cgroup = diag_cpuacct_cgroup_tsk(tsk);

	if (cgroup) {
		diag_cgroup_name(cgroup, buf, count);
	}
}

struct cgroup * cpuacct_to_cgroup(struct cpuacct *acct)
{
	if (acct) {
		return acct->css.cgroup;
	} else {
		return NULL;
	}
}
#endif

