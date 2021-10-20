/*
 * Linux内核诊断工具--参数解析小函数实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <iostream>
#include <map>
#include <vector>
#include <set>
#include <string>
#include <algorithm>

#include "params_parse.h"
using namespace std;

inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
        return std::isgraph(ch);
    }).base(), s.end());
}

inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) {
        return std::isgraph(ch);
    }));
}

inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
    return;
}

params_parser::params_parser(string str)
{
	string split = " ";
	string line;
	int index1, index2;
	string key;
	string value;

	while (str.length() > 0) {
		index1 = str.find(split);
		if (index1 >= 0) {
			line.assign(str.c_str(), index1);
			str = str.substr(index1 + 1);
		} else {
			line = str;
			str = "";
		}

		//cout << " line: " << line << endl;

		index2 = line.find("=");
		key.assign(line.c_str(), index2);
		value = line.substr(index2 + 1);
		//cout << " key: " << key << endl;
		//cout << " value: " << value << endl;

		trim(key);
		trim(value);
		map.insert(std::make_pair(key, value));
	}
}

string & params_parser::string_value(string key)
{
	return map[key];
}

unsigned long params_parser::int_value(std::string key, unsigned long def)
{
	string value = map[key];
	
	if (value.length() <= 0)
		return def;
	else {
		try {
			return std::stoul(value);
		} catch (...) {
			return def;
		}
	}
}

unsigned long params_parser::int_value(string key)
{
	return int_value(key, 0);
}

bool params_parser::bool_value(string key, bool def)
{
	string value = map[key];

	if (value.length() <= 0)
		return def;
	else {
		try {
			return std::stoul(value);
		} catch (...) {
			return def;
		}
	}
}

bool params_parser::bool_value(string key)
{
	return bool_value(key, false);
}

int xby_test(void)
{
	struct params_parser parse("sls=/tmp/diagnose-tools.log,syslog=1");

	cout << parse.string_value("sls") << endl;
	cout << parse.bool_value("syslog") << endl;

	return 0;
}
