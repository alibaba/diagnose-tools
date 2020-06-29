/*
 * Linux内核诊断工具--内核态cgroup公共函数头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef __DIAG_PUB_CGROUP_H
#define __DIAG_PUB_CGROUP_H

#include <linux/cgroup.h>
#include <linux/version.h>

struct cpuacct;
struct cpuacct *diag_find_cpuacct_name(char *name);
struct cgroup *diag_cpuacct_cgroup_tsk(struct task_struct *tsk);
void diag_cpuacct_cgroup_name_tsk(struct task_struct *tsk, char *buf, unsigned int count);
struct cgroup * cpuacct_to_cgroup(struct cpuacct *acct);

#endif /* __DIAG_PUB_CGROUP_H */

