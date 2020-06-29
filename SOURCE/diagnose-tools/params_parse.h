/*
 * Linux内核诊断工具--参数解析小函数头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef __PUB_PARAMS_PARSE_H__
#define __PUB_PARAMS_PARSE_H__

#include <iostream>
#include <map>
#include <vector>
#include <set>
#include <string>

struct params_parser {
	std::map<std::string, std::string> map;

    params_parser(std::string arg);
	std::string & string_value(std::string key);
	unsigned long int_value(std::string key);
	bool bool_value(std::string key);
};

#endif /* __PUB_PARAMS_PARSE_H__ */