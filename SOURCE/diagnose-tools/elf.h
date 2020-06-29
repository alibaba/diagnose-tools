/*
 * Linux内核诊断工具--elf相关函数头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef _PERF_ELF_H__
#define _PERF_ELF_H__

#include <set>
#include <string>

#include "symbol.h"

bool get_symbol_in_elf(std::set<symbol> &ss, const char *path);
bool search_symbol(const std::set<symbol> &ss, symbol &sym);
#endif
