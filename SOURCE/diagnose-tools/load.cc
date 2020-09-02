/*
 * Linux内核诊断工具--用户态load-monitor功能实现
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

#include <iostream>  
#include <fstream>  

#include <sys/time.h>
#include <string.h>
#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */

#include "internal.h"
#include "symbol.h"
#include "json/json.h"
#include "uapi/load_monitor.h"
#include "params_parse.h"

using namespace std;

static char sls_file[256];
static int syslog_enabled;
static int process_chains = 0;

void usage_load_monitor(void)
{
	printf("    load-monitor usage:\n");
	printf("        --help load-monitor help info\n");
	printf("        --activate\n");
	printf("            verbose VERBOSE\n");
	printf("            style dump style: 0 - common, 1 - process chains\n");
	printf("            load threshold for load(ms)\n");
	printf("            load.r threshold for load.r(ms)\n");
	printf("            load.d threshold for load.d(ms)\n");
	printf("            task.d threshold for task.d(ms)\n");
	printf("        --settings print settings.\n");
	printf("        --deactivate\n");
	printf("        --report dump log with text.\n");
	printf("        --sls save detail into sls files.\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_load_monitor_settings settings;

	memset(&settings, 0, sizeof(struct diag_load_monitor_settings));
	
	settings.threshold_load = parse.int_value("load");
	settings.threshold_load_r = parse.int_value("load-r");
	settings.threshold_load_d = parse.int_value("load-d");
	settings.threshold_task_d = parse.int_value("task-d");
	settings.verbose = parse.int_value("verbose");
	settings.style = parse.int_value("style");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_LOAD_MONITOR_SET, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_LOAD_MONITOR_SET, &ret, &settings, sizeof(struct diag_load_monitor_settings));
	}

	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    Load：\t%d\n", settings.threshold_load);
	printf("    Load.R：\t%d\n", settings.threshold_load_r);
	printf("    Load.D：\t%d\n", settings.threshold_load_d);
	printf("    Task.D：\t%d\n", settings.threshold_task_d);
	printf("    输出级别：\t%d\n", settings.verbose);
	printf("    STYLE：\t%d\n", settings.style);
	if (ret)
		return;

	ret = diag_activate("load-monitor");
	if (ret == 1) {
		printf("load-monitor activated\n");
	} else {
		printf("load-monitor is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("load-monitor");
	if (ret == 0) {
		printf("load-monitor is not activated\n");
	} else {
		printf("deactivate load-monitor fail, ret is %d\n", ret);
	}
}

static void do_settings(const char *arg)
{
	struct diag_load_monitor_settings settings;
	int ret;
	int enable_json = 0;
	Json::Value root;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_LOAD_MONITOR_SETTINGS, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_LOAD_MONITOR_SETTINGS, &ret, &settings, sizeof(struct diag_load_monitor_settings));
	}

	if (ret == 0) {
		if (1 != enable_json)
		{
			printf("功能设置：\n");
			printf("    是否激活：\t%s\n", settings.activated ? "√" : "×");
			printf("    Load：\t%d\n", settings.threshold_load);
			printf("    Load.R：\t%d\n", settings.threshold_load_r);
			printf("    Load.D：\t%d\n", settings.threshold_load_d);
			printf("    Task.D：\t%d\n", settings.threshold_task_d);
			printf("    输出级别：\t%d\n", settings.verbose);
			printf("    STYLE：\t%d\n", settings.style);
		}
		else
		{
			root["activated"] = Json::Value(settings.activated);
			root["Load"] = Json::Value(settings.threshold_load);
			root["Load.R"] = Json::Value(settings.threshold_load_r);
			root["Load.D"] = Json::Value(settings.threshold_load_d);
			root["Task.D"] = Json::Value(settings.threshold_task_d);
			root["verbose"] = Json::Value(settings.verbose);
			root["STYLE"] = Json::Value(settings.style);
		}
	} else {
		if ( 1 != enable_json)
		{
			printf("获取load-monitor设置失败，请确保正确安装了diagnose-tools工具\n");
		}

		else
		{
			root["err"]=Json::Value("found load-monitor settings failed, please check diagnose-tools installed or not\n");
		}
	}

	if (1 == enable_json)
	{
		std::string str_log;
		str_log.append(root.toStyledString());
		printf("%s", str_log.c_str());
	}

	return;

}

static int load_monitor_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct load_monitor_detail *detail;
	struct load_monitor_task *tsk_info;
	static int seq = 0;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_load_monitor_detail:
		if (len < sizeof(struct load_monitor_detail))
			break;
		detail = (struct load_monitor_detail *)buf;

		printf("Load飙高：[%lu:%lu]\n",
					detail->tv.tv_sec, detail->tv.tv_usec);
		printf("\tLoad: %d.%02d, %d.%02d, %d.%02d\n",
					detail->load_1_1, detail->load_1_2,
					detail->load_5_1, detail->load_5_2,
					detail->load_15_1, detail->load_15_2);
		printf("\tLoad.R: %d.%02d, %d.%02d, %d.%02d\n",
					detail->load_r_1_1, detail->load_r_1_2,
					detail->load_r_5_1, detail->load_r_5_2,
					detail->load_r_15_1, detail->load_r_15_2);
		printf("\tLoad.D: %d.%02d, %d.%02d, %d.%02d\n",
					detail->load_d_1_1, detail->load_d_1_2,
					detail->load_d_5_1, detail->load_d_5_2,
					detail->load_d_15_1, detail->load_d_15_2);

		break;
	case et_load_monitor_task:
		if (len < sizeof(struct load_monitor_task))
			break;
		tsk_info = (struct load_monitor_task *)buf;
		seq++;
		printf("##CGROUP:[%s]  %d      [%03d]  采样命中[%s]\n",
				tsk_info->task.cgroup_buf,
				tsk_info->task.pid,
				seq,
				tsk_info->task.state == 0 ? "R" : "D");

		diag_printf_kern_stack(&tsk_info->kern_stack);

		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				tsk_info->task.comm);
		diag_printf_proc_chains(&tsk_info->proc_chains, 0, process_chains);
		printf("##\n");

		tsk_info++;

		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, load_monitor_extract, NULL);
}

static void do_dump(const char *arg)
{
	static char variant_buf[1024 * 1024];
	struct params_parser parse(arg);
	int len;
	int ret = 0;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 1024 * 1024,
		.user_buf = variant_buf,
	};

	process_chains = parse.int_value("process-chains");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_LOAD_MONITOR_DUMP, (long)&dump_param);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_LOAD_MONITOR_DUMP, &ret, &len, variant_buf, 1024 * 1024);
	}

	if (ret == 0) {
		do_extract(variant_buf, len);
	}
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct load_monitor_detail *detail;
	struct load_monitor_task *tsk_info;
	Json::Value root;
	Json::Value tsk;
	stringstream ss;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_load_monitor_detail:
		if (len < sizeof(struct load_monitor_detail))
			break;
		detail = (struct load_monitor_detail *)buf;

		root["tv_sec"] = Json::Value(detail->tv.tv_sec);
		root["tv_usec"] = Json::Value(detail->tv.tv_usec);

		ss.str("");
		ss << detail->load_1_1 << "." << detail->load_1_2;
		root["load_1"] = Json::Value(ss.str());

		ss.str("");
		ss << detail->load_5_1 << "." << detail->load_5_2;
		root["load_5"] = Json::Value(ss.str());

		ss.str("");
		ss << detail->load_15_1 << "." << detail->load_15_2;
		root["load_15"] = Json::Value(ss.str());

		ss.str("");
		ss << detail->load_r_1_1 << "." << detail->load_r_1_2;
		root["load_r_1"] = Json::Value(ss.str());

		ss.str("");
		ss << detail->load_r_5_1 << "." << detail->load_r_5_2;
		root["load_r_5"] = Json::Value(ss.str());
	
		ss.str("");
		ss << detail->load_r_15_1 << "." << detail->load_r_15_2;
		root["load_r_15"] = Json::Value(ss.str());

		ss.str("");
		ss << detail->load_d_1_1 << "." << detail->load_d_1_2;
		root["load_d_1"] = Json::Value(ss.str());

		ss.str("");
		ss << detail->load_d_5_1 << "." << detail->load_d_5_2;
		root["load_d_5"] = Json::Value(ss.str());

		ss.str("");
		ss << detail->load_d_15_1 << "." << detail->load_d_15_2;
		root["load_d_15"] = Json::Value(ss.str());

		root["id"] = Json::Value(detail->id);

		write_file(sls_file, "load-monitor-summary", &detail->tv, detail->id, 0, root);
		write_syslog(syslog_enabled, "load-monitor-summary", &detail->tv, detail->id, 0, root);

		break;
	case et_load_monitor_task:
		if (len < sizeof(struct load_monitor_task))
			break;
		tsk_info = (struct load_monitor_task *)buf;

		tsk["id"] = Json::Value(tsk_info->id);
		diag_sls_task(&tsk_info->task, tsk);
		diag_sls_kern_stack(&tsk_info->kern_stack, tsk);
		diag_sls_proc_chains(&tsk_info->proc_chains, tsk);

		write_file(sls_file, "load-monitor-task", &tsk_info->tv, tsk_info->id, 0, tsk);
		//root["task"] = Json::Value(tsk);
		write_syslog(syslog_enabled, "load-monitor-task", &tsk_info->tv, tsk_info->id, 0, tsk);
		
		break;
	default:
		break;
	}

	return 0;
}

static void do_sls(char *arg)
{
	int ret;
	static char variant_buf[1024 * 1024];
	int len;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 1024 * 1024,
		.user_buf = variant_buf,
	};

	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	while (1) {
		if (run_in_host) {
			ret = diag_call_ioctl(DIAG_IOCTL_LOAD_MONITOR_DUMP, (long)&dump_param);
		} else {
			ret = -ENOSYS;
			syscall(DIAG_LOAD_MONITOR_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		}

		if (ret == 0) {
			pid_cmdline.clear();
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}
}

int load_monitor_main(int argc, char **argv)
{
	static struct option long_options[] = {
			{"help",     no_argument, 0,  0 },
			{"activate",     optional_argument, 0,  0 },
			{"deactivate", no_argument,       0,  0 },
			{"settings",     optional_argument, 0,  0 },
			{"report",     optional_argument, 0,  0 },
			{"log",     required_argument, 0,  0 },
			{0,         0,                 0,  0 }
		};
	int c;

	if (argc <= 1) {
		usage_load_monitor();
		return 0;
	}

	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 10:
			usage_load_monitor();
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
		case 5:
			do_sls(optarg);
			break;
		default:
			usage_load_monitor();
			break;
		}
	}

	return 0;
}

