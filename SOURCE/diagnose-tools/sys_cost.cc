/*
 * Linux内核诊断工具--用户态sys-cost功能实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

#include <sys/time.h>
#include <string.h>
#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */

#include <set>

#include "internal.h"
#include "symbol.h"
#include "json/json.h"
#include <iostream>
#include <fstream>
#include <fcntl.h>

#include "uapi/sys_cost.h"
#include "params_parse.h"
#include "unwind.h"

using namespace std;
static char sls_file[256];
static int syslog_enabled;

void usage_sys_cost(void)
{
	printf("    sys-cost usage:\n");
	printf("        --help sys-cost help info\n");
	printf("        --activate\n");
	printf("          verbose VERBOSE\n");
	printf("          tgid process group that monitored\n");
	printf("          pid thread id that monitored\n");
	printf("          comm comm that monitored\n");
	printf("        --deactivate\n");
	printf("        --settings dump settings\n");
	printf("        --report dump log with text.\n");
	printf("        --log\n");
	printf("          sls=/tmp/1.log store in file\n");
	printf("          syslog=1 store in syslog\n");
}

static void do_activate(const char *arg)
{
	int ret;
	struct params_parser parse(arg);
	struct diag_sys_cost_settings settings;
	string str;

	memset(&settings, 0, sizeof(struct diag_sys_cost_settings));
	
	settings.verbose = parse.int_value("verbose");
	settings.tgid = parse.int_value("tgid");
	settings.pid = parse.int_value("pid");
	
	str = parse.string_value("comm");
	if (str.length() > 0) {
		strncpy(settings.comm, str.c_str(), TASK_COMM_LEN);
		settings.comm[TASK_COMM_LEN - 1] = 0;
	}

	ret = -ENOSYS;
	syscall(DIAG_SYS_COST_SET, &ret, &settings, sizeof(struct diag_sys_cost_settings));
	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    进程ID：%d\n", settings.tgid);
	printf("    线程ID：%d\n", settings.pid);
	printf("    进程名称：%s\n", settings.comm);
	printf("    输出级别：%d\n", settings.verbose);
	ret = diag_activate("sys-cost");
	if (ret == 1) {
		printf("sys-cost activated\n");
	} else {
		printf("sys-cost is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;
	
	ret = diag_deactivate("sys-cost");
	if (ret == 0) {
		printf("sys-cost is not activated\n");
	} else {
		printf("deactivate sys-cost fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_sys_cost_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["tgid"] = Json::Value(settings->tgid);
		root["pid"] = Json::Value(settings->pid);
		root["comm"] = Json::Value(settings->comm);
		root["verbose"] = Json::Value(settings->verbose);
	} else {
		root["err"] = Json::Value("found sys-cost settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_sys_cost_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	memset(&settings, 0, sizeof(struct diag_sys_cost_settings));
	ret = -ENOSYS;
	syscall(DIAG_SYS_COST_SETTINGS, &ret, &settings, sizeof(struct diag_sys_cost_settings));

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    进程ID：%d\n", settings.tgid);
		printf("    线程ID：%d\n", settings.pid);
		printf("    进程名称：%s\n", settings.comm);
		printf("    输出级别：%d\n", settings.verbose);
	} else {
		printf("获取sys-cost设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int sys_cost_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct sys_cost_detail *detail;
	int i;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_sys_cost_detail:
		if (len < sizeof(struct sys_cost_detail))
			break;
		detail = (struct sys_cost_detail *)buf;

		printf("CPU：%lu，时间：[%lu:%lu]\n",
			detail->cpu,
			detail->tv.tv_sec, detail->tv.tv_usec);

		for (i = 0; i < USER_NR_syscalls_virt; i++) {
			printf("    SYSCALL：%d, COUNT：%lu, COST：%lu\n",
				i, detail->count[i], detail->cost[i]);
		}

		for (i = 0; i < USER_NR_syscalls_virt; i++) {
			if (detail->count[i])
				printf("**CPU %3lu;SYSCALL %3d; %lu\n", detail->cpu, i, detail->count[i]);
			if (detail->cost[i])
				printf("*#CPU %3lu;SYSCALL %3d; %lu\n", detail->cpu, i, detail->cost[i]);
		}
		break;
	default:
		break;
	}
	return 0;
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct sys_cost_detail *detail;
	int i;
	Json::Value root;
	Json::Value tsk;
	Json::Value sys_info;
	std::string str_log;
	stringstream ss;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_sys_cost_detail:
		if (len < sizeof(struct sys_cost_detail))
			break;
		detail = (struct sys_cost_detail *)buf;

		root["CPU"] = Json::Value(detail->cpu);
		root["tv_sec"] = Json::Value(detail->tv.tv_sec);
		root["tv_usec"] = Json::Value(detail->tv.tv_usec);

		for (i = 0; i < USER_NR_syscalls_virt; i++) {
			if ((0 == detail->count[i]) && (0 == detail->cost[i]))
			{
				continue;
			}

			sys_info["num"] = Json::Value(i);
			sys_info["count"] = Json::Value(detail->count[i]);
			sys_info["cost"] = Json::Value(detail->cost[i]);
			ss.str("");
			ss << "syscall_" << i;
			tsk[ss.str()] = Json::Value(sys_info);
		}
		root["msg"] = tsk;

		write_file(sls_file, "sys-cost", &detail->tv, 0, detail->cpu, root);
		write_syslog(syslog_enabled, "sys-cost", &detail->tv, 0, detail->cpu, root);

		break;
	default:
		break;
	}
	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, sys_cost_extract, NULL);
}

static void do_dump(void)
{
	static char variant_buf[40 * 1024 * 1024];
	int len;
	int ret = 0;

	memset(variant_buf, 0, 40* 1024 * 1024);
	ret = -ENOSYS;
	syscall(DIAG_SYS_COST_DUMP, &ret, &len, variant_buf, 1 * 1024 * 1024);
	if (ret == 0) {
		do_extract(variant_buf, len);
	}
}

static void do_sls(char *arg)
{
	int ret;
	static char variant_buf[1024 * 1024];

	int len;
	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	while (1) {
		syscall(DIAG_SYS_COST_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}	
}

int sys_cost_main(int argc, char **argv)
{
	static struct option long_options[] = {
			{"help",     no_argument, 0,  0 },
			{"activate",     optional_argument, 0,  0 },
			{"deactivate", no_argument,       0,  0 },
			{"settings",     optional_argument, 0,  0 },
			{"report",     no_argument, 0,  0 },
			{"log",     required_argument, 0,  0 },
			{0,         0,                 0,  0 }
		};
	int c;

	if (argc <= 1) {
		 usage_sys_cost();
		 return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_sys_cost();
			break;
	  case 1:
			do_activate(optarg ? optarg : "");
			break;
		case 2:
			do_deactivate();
			break;
		case 3:
			do_settings(optarg ? optarg : "");
			break;
		case 4:
			do_dump();
			break;
		case 5:
			do_sls(optarg);
			break;
		default:
			usage_sys_cost();
			break;
		}
	}

	return 0;
}
