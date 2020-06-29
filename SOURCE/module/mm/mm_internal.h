/*
 * Linux内核诊断工具--内核态内存功能头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

extern int diag_alloc_page_init(void);
extern void diag_alloc_page_exit(void);
extern int diag_memory_leak_init(void);
extern void diag_memory_leak_exit(void);
extern int diag_mm_page_fault_init(void);
extern void diag_mm_page_fault_exit(void);
extern int diag_alloc_top_init(void);
extern void diag_alloc_top_exit(void);
