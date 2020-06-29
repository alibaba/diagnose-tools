/*
 * Linux内核诊断工具--内核态tracepoint公共函数头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef __DIAG_PUB_TRACE_POINT_H
#define __DIAG_PUB_TRACE_POINT_H

struct pt_regs;
typedef void (*cb_sys_enter)(void *data, struct pt_regs *regs, long id);

int diag_register_cb_sys_enter(cb_sys_enter cb, void *data);
int diag_unregister_cb_sys_enter(cb_sys_enter cb, void *data);

int diag_call_sys_enter(struct pt_regs *regs, long id);

extern int hook_tracepoint(const char *name, void *probe, void *data);
extern int unhook_tracepoint(const char *name, void *probe, void *data);

#endif /* __DIAG_PUB_TRACE_POINT_H */
