/*
 * Linux内核诊断工具--用户态exec-monitor功能实现
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
#include "uapi/exec_monitor.h"
#include "params_parse.h"

static char sls_file[256];
static int syslog_enabled;

void usage_exec_monitor(void)
{
	printf("    exec-monitor usage:\n");
	printf("        --help exec-monitor help info\n");
	printf("        --activate\n");
	printf("            verbose VERBOSE\n");
	printf("        --deactivate\n");
	printf("        --report dump log with text.\n");
	printf("        --log\n");
	printf("          sls=/tmp/1.log store in file\n");
	printf("          syslog=1 store in syslog\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_exec_monitor_settings settings;

	memset(&settings, 0, sizeof(struct diag_exec_monitor_settings));
	
	settings.verbose = parse.int_value("verbose");

	ret = -ENOSYS;
	syscall(DIAG_EXEC_MONITOR_SET, &ret, &settings, sizeof(struct diag_exec_monitor_settings));
	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    输出级别：%d\n", settings.verbose);
	ret = diag_activate("exec-monitor");
	if (ret == 1) {
		printf("exec-monitor activated\n");
	} else {
		printf("exec-monitor is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("exec-monitor");
	if (ret == 0) {
		printf("exec-monitor is not activated\n");
	} else {
		printf("deactivate exec-monitor fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_exec_monitor_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["verbose"] = Json::Value(settings->verbose);
	} else {
		root["err"] = Json::Value("found exec-monitor settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_exec_monitor_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	ret = -ENOSYS;
	syscall(DIAG_EXEC_MONITOR_SETTINGS, &ret, &settings, sizeof(struct diag_exec_monitor_settings));

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    输出级别：%d\n", settings.verbose);
	} else {
		printf("获取exec-monitor设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int exec_monitor_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct exec_monitor_detail *detail;
    symbol sym;
    elf_file file;
	int i;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_exec_monitor_detail:
		if (len < sizeof(struct exec_monitor_detail))
			break;
		detail = (struct exec_monitor_detail *)buf;

		printf("创建进程： [%s]，CGROUP：[%s], 当前进程：%d[%s], tgid： %d，当前时间：[%lu:%lu]\n",
			detail->filename,
			detail->task.cgroup_buf, detail->task.pid, detail->task.comm, detail->task.tgid,
			detail->tv.tv_sec, detail->tv.tv_usec);

		printf("    进程链信息：\n");
		for (i = 0; i < PROCESS_CHAINS_COUNT; i++) {
			printf("        %s\n", detail->proc_chains.chains[i]);
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
	struct exec_monitor_detail *detail;
	symbol sym;
	elf_file file;
	Json::Value root;
	Json::Value proc_chains;
	Json::Value task;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_exec_monitor_detail:
		if (len < sizeof(struct exec_monitor_detail))
			break;
		detail = (struct exec_monitor_detail *)buf;

		root["filename"]=Json::Value(detail->filename);
		diag_sls_time(&detail->tv, root);
		diag_sls_task(&detail->task, task);
		diag_sls_proc_chains(&detail->proc_chains, task);
		root["task"] = task;

		write_file(sls_file, "exec-monitor", &detail->tv, 0, 0, root);
		write_syslog(syslog_enabled, "exec-monitor", &detail->tv, 0, 0, root);
		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, exec_monitor_extract, NULL);
}

static void do_dump(void)
{
	static char variant_buf[1024 * 1024];
	int len;
	int ret = 0;

	ret = -ENOSYS;
	syscall(DIAG_EXEC_MONITOR_DUMP, &ret, &len, variant_buf, 1024 * 1024);
	if (ret == 0) {
		do_extract(variant_buf, len);
	}
}

static void do_sls(char *arg)
{
	int ret;
	int len;
	static char variant_buf[1024 * 1024];

	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	while(1) {
		syscall(DIAG_EXEC_MONITOR_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}

}

int exec_monitor_main(int argc, char **argv)
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
		usage_exec_monitor();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_exec_monitor();
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
			usage_exec_monitor();
			break;
		}
	}

	return 0;
}
