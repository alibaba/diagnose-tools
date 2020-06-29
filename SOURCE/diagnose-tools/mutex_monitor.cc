/*
 * Linux内核诊断工具--用户态mutex-monitor功能实现
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
#include "uapi/mutex_monitor.h"
#include "params_parse.h"

static char sls_file[256];
static int syslog_enabled;

void usage_mutex_monitor(void)
{
	printf("    mutex-monitor usage:\n");
	printf("        --help mutex-monitor help info\n");
	printf("        --activate\n");
	printf("            verbose VERBOSE\n");
	printf("            threshold threshold(ms)\n");
	printf("            style dump style: 0 - common, 1 - process chains\n");
	printf("        --deactivate\n");
	printf("        --settings dump settings with text.\n");
	printf("        --report dump log with text.\n");
	printf("        --test testcase for mutex-monitor.\n");
	printf("        --log\n");
	printf("          sls=/tmp/1.log store in file\n");
	printf("          syslog=1 store in syslog\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_mutex_monitor_settings settings;

	memset(&settings, 0, sizeof(struct diag_mutex_monitor_settings));
	
	settings.verbose = parse.int_value("verbose");
	settings.style = parse.int_value("style");
	settings.threshold = parse.int_value("threshold");

	if (0 == settings.threshold)
	{
		settings.threshold = 1000;
	}

	ret = -ENOSYS;
	syscall(DIAG_MUTEX_MONITOR_SET, &ret, &settings, sizeof(struct diag_mutex_monitor_settings));
	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    阀值(ms)：\t%d\n", settings.threshold);
	printf("    输出级别：\t%d\n", settings.verbose);
	printf("    STYLE：\t%d\n", settings.style);

	ret = diag_activate("mutex-monitor");
	if (ret == 1) {
		printf("mutex-monitor activated\n");
	} else {
		printf("mutex-monitor is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("mutex-monitor");
	if (ret == 0) {
		printf("mutex-monitor is not activated\n");
	} else {
		printf("deactivate mutex-monitor fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_mutex_monitor_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["threshold_ms"] = Json::Value(settings->threshold);
		root["verbose"] = Json::Value(settings->verbose);
		root["STYLE"] = Json::Value(settings->style);
	} else {
		root["err"] = Json::Value("found mutex-monitor settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_mutex_monitor_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	ret = -ENOSYS;
	syscall(DIAG_MUTEX_MONITOR_SETTINGS, &ret, &settings, sizeof(struct diag_mutex_monitor_settings));

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：\t%s\n", settings.activated ? "√" : "×");
		printf("    阀值(ms)：\t%d\n", settings.threshold);
		printf("    输出级别：\t%d\n", settings.verbose);
		printf("    STYLE：\t%d\n", settings.style);
	} else {
		printf("获取mutex-monitor设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int mutex_monitor_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct mutex_monitor_detail *detail;
    symbol sym;
    elf_file file;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_mutex_monitor_detail:
		if (len < sizeof(struct mutex_monitor_detail))
			break;
		detail = (struct mutex_monitor_detail *)buf;
        
		printf("MUTEX延迟： %p，PID： %d[%s]， %lu ms, 时间：[%lu:%lu]\n",
			detail->lock,
			detail->task.pid, detail->task.comm,
			detail->delay_ns / 1000 / 1000,
			detail->tv.tv_sec, detail->tv.tv_usec);
		diag_printf_time(&detail->tv);
		diag_printf_task(&detail->task);
		diag_printf_kern_stack(&detail->kern_stack);
		diag_printf_user_stack(detail->task.tgid,
				detail->task.container_tgid,
				detail->task.comm,
				&detail->user_stack);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				detail->task.comm);
		diag_printf_proc_chains(&detail->proc_chains);
		printf("##\n");

		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, mutex_monitor_extract, NULL);
}

static void do_dump(void)
{
	static char variant_buf[1024 * 1024];
	int len;
	int ret = 0;

	ret = -ENOSYS;
	syscall(DIAG_MUTEX_MONITOR_DUMP, &ret, &len, variant_buf, 1024 * 1024);
	if (ret == 0 && len > 0) {
		do_extract(variant_buf, len);
	}
}

static void do_test(void)
{
	int ret;

	ret = -ENOSYS;
	syscall(DIAG_MUTEX_MONITOR_TEST, &ret, 1500);
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct mutex_monitor_detail *detail;
	symbol sym;
	elf_file file;
	Json::Value root;
	Json::Value task;
	Json::Value kern_stack;
	Json::Value user_stack;
	Json::Value proc_chains;
	char lock_buf[255];

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_mutex_monitor_detail:
		if (len < sizeof(struct mutex_monitor_detail))
			break;
		detail = (struct mutex_monitor_detail *)buf;

		snprintf(lock_buf, 255, "0x%016lx", (unsigned long)detail->lock);
		root["lock"] = Json::Value(lock_buf);
		root["delay_ms"] = Json::Value(detail->delay_ns / 1000 / 1000);

		diag_sls_time(&detail->tv, root);
		diag_sls_task(&detail->task, task);
		diag_sls_kern_stack(&detail->kern_stack, task);
		diag_sls_user_stack(detail->task.tgid,
			detail->task.container_tgid,
			detail->task.comm,
			&detail->user_stack, task);
		diag_sls_proc_chains(&detail->proc_chains, task);
		root["task"] = task;

		write_file(sls_file, "mutex-monitor", &detail->tv, 0, 0, root);
		write_syslog(syslog_enabled, "mutex-monitor", &detail->tv, 0, 0, root);

		break;
	default:
		break;
	}

	return 0;
}

static void do_sls(char *arg)
{
	int ret;
	int len;
	static char variant_buf[1024 * 1024];

	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	while (1) {
		syscall(DIAG_MUTEX_MONITOR_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}
}

int mutex_monitor_main(int argc, char **argv)
{
	static struct option long_options[] = {
			{"help",     no_argument, 0,  0 },
			{"activate",     optional_argument, 0,  0 },
			{"deactivate", no_argument,       0,  0 },
			{"settings",     optional_argument, 0,  0 },
			{"report",     no_argument, 0,  0 },
			{"test",     no_argument, 0,  0 },
			{"log",     required_argument, 0,  0 },
			{0,         0,                 0,  0 }
		};
	int c;
    
	if (argc <= 1) {
		usage_mutex_monitor();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_mutex_monitor();
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
			do_test();
			break;
		case 6:
			do_sls(optarg);
			break;
		default:
			usage_mutex_monitor();
			break;
		}
	}

	return 0;
}
