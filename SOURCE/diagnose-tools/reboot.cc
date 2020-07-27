/*
 * Linux内核诊断工具--用户态reboot功能实现
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

#include "internal.h"
#include "symbol.h"
#include "uapi/reboot.h"
#include "params_parse.h"

void usage_reboot(void)
{
	printf("    reboot usage:\n");
	printf("        --help reboot help info\n");
	printf("        --activate\n");
	printf("        --deactivate\n");
	printf("        --verbose VERBOSE\n");
	printf("        --settings dump settings\n");
}

static void do_activate(void)
{
	int ret = 0;

	ret = diag_activate("reboot");
	if (ret == 1) {
		printf("reboot activated\n");
	} else {
		printf("reboot is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;
	
	ret = diag_deactivate("reboot");
	if (ret == 0) {
		printf("reboot is not activated\n");
	} else {
		printf("deactivate reboot fail, ret is %d\n", ret);
	}
}

static void do_verbose(char *arg)
{
	int ret;
	unsigned int verbose;

	ret = sscanf(arg, "%d", &verbose);
	if (ret != 1)
		return;

	ret = -ENOSYS;
	ret = diag_call_ioctl(DIAG_IOCTL_REBOOT_VERBOSE, verbose);
	printf("set verbose for reboot: %d, ret is %d\n", verbose, ret);
}

static void print_settings_in_json(struct diag_reboot_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["verbose"] = Json::Value(settings->verbose);
	} else {
		root["err"] = Json::Value("found reboot settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_reboot_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	memset(&settings, 0, sizeof(struct diag_reboot_settings));
	ret = -ENOSYS;
	ret = diag_call_ioctl(DIAG_IOCTL_REBOOT_SETTINGS, (long)&settings);

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    输出级别：%d\n", settings.verbose);
	} else {
		printf("获取reboot设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

int reboot_main(int argc, char **argv)
{
	static struct option long_options[] = {
			{"activate",     no_argument, 0,  0 },
			{"deactivate", no_argument,       0,  0 },
			{"verbose",     required_argument, 0,  0 },
			{"v",     required_argument, 0,  0 },
			{"settings",     optional_argument, 0,  0 },
			{"help",     no_argument, 0,  0 },
			{0,         0,                 0,  0 }
		};
	int c;

	if (argc <= 1) {
		 usage_reboot();
		 return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
	    case 0:
			do_activate();
			break;
		case 1:
			do_deactivate();
			break;
		case 2:
		case 3:
			do_verbose(optarg);
			break;
		case 4:
			do_settings(optarg ? optarg : "");
			break;
		case 5:
			usage_reboot();
			break;
		default:
			usage_reboot();
			break;
		}
	}

	return 0;
}
