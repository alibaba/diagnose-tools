/*
 * Linux内核诊断工具--内核态堆栈公共函数头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef __DIAG_PUB_STACK_H
#define __DIAG_PUB_STACK_H

void diagnose_save_stack_trace(struct task_struct *tsk, unsigned long *backtrace);
void diagnose_save_stack_trace_user(unsigned long *backtrace);
void diagnose_print_stack_trace(int pre, struct task_struct *p, unsigned long *backtrace);
void diagnose_print_stack_trace_user(int pre, unsigned long *backtrace);
void diagnose_print_stack_trace_unfold(int pre, struct task_struct *p, unsigned long *backtrace);
void diagnose_print_stack_trace_unfold_user(int pre, unsigned long *backtrace);

int diagnose_stack_trace_equal(unsigned long *backtrace1, unsigned long *backtrace2);
int diagnose_stack_trace_cmp(unsigned long *backtrace1, unsigned long *backtrace2);
void dump_all_task_stack(int pre);

#endif /* __DIAG_PUB_STACK_H */

