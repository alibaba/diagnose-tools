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

#ifndef __DIAG_PUB_SYMBOL_H
#define __DIAG_PUB_SYMBOL_H

extern unsigned long (*diag_kallsyms_lookup_name)(const char *name);
extern int diag_get_symbol_count(char *symbol);
extern int diag_init_symbol(void);

#endif /* __DIAG_PUB_SYMBOL_H */

