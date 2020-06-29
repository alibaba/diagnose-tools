/*
 * Alibaba 内核诊断模块
 * 
 * 访问非当前进程堆栈，特别是其用户态堆栈。
 * 由于本功能存在潜在风险，因此仅仅用于实验版本。
 *
 * Copyright (C) 2019 Alibaba Ltd.
 *
 * Author: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 */

#ifndef __DIAG_PUB_REMOTE_STACK_H
#define __DIAG_PUB_REMOTE_STACK_H

struct task_struct;
void diagnose_print_stack_trace_user_tsk(int pre, int orig, struct task_struct *tsk, unsigned long *backtrace);

#endif /* __DIAG_PUB_REMOTE_STACK_H */

