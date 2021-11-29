/*
 * Linux内核诊断工具--用户态rss-monitor功能实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Jiyun Fan <fanjiyun.fjy@alibaba-inc.com>
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
#include "unwind.h"
#include "json/json.h"
#include "uapi/rss_monitor.h"
#include "params_parse.h"

void usage_rss_monitor(void)
{
	printf("    rss-monitor usage:\n");
	printf("        --help rss-monitor help info\n");
	printf("        --activate\n");
	printf("          verbose VERBOSE\n");
	printf("          time-threshold default threshold(s)\n");
	printf("          tgid process group that monitored\n");
	printf("          pid thread id that monitored\n");
	printf("          raw-stack output raw stack\n");
	printf("        --deactivate\n");
	printf("        --settings print settings\n");
	printf("        --report dump log with text\n");
	printf("          follow output until the record is empty\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_rss_monitor_settings settings;

	memset(&settings, 0, sizeof(struct diag_rss_monitor_settings));

	settings.tgid = parse.int_value("tgid");
	settings.pid = parse.int_value("pid");
	settings.raw_stack = parse.int_value("raw-stack");
	settings.verbose = parse.int_value("verbose");
	settings.time_threshold = parse.int_value("time-threshold");

	if (!settings.tgid && !settings.pid) {
		printf("activate: please set tgid or pid!\n");
		return;
	}

	if(run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_RSS_MONITOR_SET, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_RSS_MONITOR_SET, &ret, &settings, sizeof(struct diag_rss_monitor_settings));
	}

	printf("功能设置%s, 返回值：%d\n", ret ? "失败":"成功", ret);
	printf("    进程ID：\t%d\n", settings.tgid);
	printf("    线程ID：\t%d\n", settings.pid);
	printf("    阈值(s)：\t%lu\n", settings.time_threshold);
	printf("    RAW-STACK：\t%lu\n", settings.raw_stack);
	printf("    输出级别：\t%d\n", settings.verbose);

	if(ret)
		return;

	ret = diag_activate("rss-monitor");
	if (1 == ret) {
		printf("rss-monitor activated\n");
	} else {
		printf("rss-monitor is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("rss-monitor");
	if (0 == ret) {
		printf("rss-monitor is not activated\n");
	} else {
		printf("deactivate rss-monitor fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_rss_monitor_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["tgid"] = Json::Value(settings->tgid);
		root["pid"] = Json::Value(settings->pid);
		root["raw"] = Json::Value(settings->raw_stack);
		root["verbose"] = Json::Value(settings->verbose);
		root["time_threshold"] = Json::Value(settings->time_threshold);
	} else {
		root["err"] = Json::Value("found rss-monitors settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_rss_monitor_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	memset(&settings, 0, sizeof(struct diag_rss_monitor_settings));

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_RSS_MONITOR_SETTINGS, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_RSS_MONITOR_SETTINGS, &ret, &settings, sizeof(struct diag_rss_monitor_settings));
	}

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (0 == ret) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    进程ID：%d\n", settings.tgid);
		printf("    线程ID：%d\n", settings.pid);
		printf("    阈值(s)：%lu\n", settings.time_threshold);
		printf("    RAW-STACK：%lu\n", settings.raw_stack);
		printf("    输出级别：%d\n", settings.verbose);
	} else {
		printf("获取rss-monitor设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int rss_monitor_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct rss_monitor_detail *detail;
	struct rss_monitor_raw_stack_detail *raw_detail;
	static int seq = 0;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_rss_monitor_detail:
		if (len < sizeof(struct rss_monitor_detail))
			break;
		detail = (struct rss_monitor_detail *)buf;

		printf("命中：PID： %d[%s]，时间：[%lu:%lu]\n",
			detail->task.pid, detail->task.comm,
			detail->tv.tv_sec, detail->tv.tv_usec);
		seq++;
		printf("##CGROUP:[%s]  %d      [%03d]  时间：[%lu:%lu]\n",
				detail->task.cgroup_buf,
				detail->task.pid,
				seq,
				detail->tv.tv_sec, detail->tv.tv_usec);
		printf("#*      0xffffffffffffff  %lu  %lu(s)  [0x%lx] (UNKNOWN)\n",
			detail->alloc_len, detail->delta_time, detail->addr);
		//diag_printf_kern_stack(&detail->kern_stack);
		diag_printf_user_stack(detail->task.tgid,
				detail->task.container_tgid,
				detail->task.comm,
				&detail->user_stack, 0);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				detail->task.comm);
		printf("##\n");
		break;
	case et_rss_monitor_raw_detail:
		if (len < sizeof(struct rss_monitor_raw_stack_detail))
			break;
		raw_detail = (struct rss_monitor_raw_stack_detail *)buf;

		printf("命中：PID： %d[%s]，时间：[%lu:%lu]\n",
			raw_detail->task.pid, raw_detail->task.comm,
			raw_detail->tv.tv_sec, raw_detail->tv.tv_usec);
		seq++;
		printf("##CGROUP:[%s]  %d      [%03d]  时间：[%lu:%lu]\n",
				raw_detail->task.cgroup_buf,
				raw_detail->task.pid,
				seq,
				raw_detail->tv.tv_usec, raw_detail->tv.tv_usec);
		printf("#*      0xffffffffffffff  %lu  %lu(s) [0x%lx] (UNKNOWN)\n",
			raw_detail->alloc_len, raw_detail->delta_time, raw_detail->addr);
		//diag_printf_kern_stack(&raw_detail->kern_stack);
		diag_printf_raw_stack(run_in_host ? raw_detail->task.tgid : raw_detail->task.container_tgid,
				raw_detail->task.container_tgid,
				raw_detail->task.comm,
				&raw_detail->raw_stack);
		printf("#*		0xffffffffffffff %s (UNKNOWN)\n",
			raw_detail->task.comm);
		printf("##\n");
		break;
	default:
		break;
	}
	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, rss_monitor_extract, NULL);
}

static void do_dump(const char *arg)
{
	static char variant_buf[40 * 1024 * 1024];
	int len;
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_ioctl_dump_param_cycle dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 40 * 1024 * 1024,
		.user_buf = variant_buf,
		.cycle = 1,
	};

	int user_symbol = 1;
	int follow = 0;

	//user_symbol = parse.int_value("user-symbol", 1);
	g_symbol_parser.user_symbol = user_symbol;

	follow = parse.int_value("follow");

	memset(variant_buf, 0, 40 * 1024 * 1024);

	do {
		if (run_in_host) {
			ret = diag_call_ioctl(DIAG_IOCTL_RSS_MONITOR_DUMP, (long)&dump_param);
		} else {
			ret = -ENOSYS;
			syscall(DIAG_RSS_MONITOR_DUMP, &ret, &len, variant_buf, 40 * 1024 * 1024);
		}
		if (ret == 0) {
			do_extract(variant_buf, len);
		}
		dump_param.cycle = 0;
	} while (follow && ret == 0 && len > 0);
}

int rss_monitor_main(int argc, char **argv)
{
	static struct option long_options[] = {
			{"help",    no_argument, 0,  0 },
			{"activate",     optional_argument, 0,  0 },
			{"deactivate",     no_argument,       0,  0 },
			{"settings",     optional_argument, 0,  0 },
			{"report",     optional_argument, 0,  0},
			{0,         0,                 0,  0}
		};
	int c;

	if (argc <= 1) {
		usage_rss_monitor();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_rss_monitor();
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
			do_dump(optarg ? optarg : "");
			break;
		default:
			usage_rss_monitor();
			break;
		}
	}

	return 0;
}

