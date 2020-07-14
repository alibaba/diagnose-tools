/*
 * Linux内核诊断工具--用户态utilization功能实现
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
#include "json/json.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include "uapi/utilization.h"
#include "params_parse.h"

using namespace std;

static char sls_file[256];
static int syslog_enabled;

static unsigned long exec_sum;
static stringstream ss_cpu;
static stringstream ss_pages;
static stringstream ss_wild;

void usage_utilization(void)
{
	printf("    utilization usage:\n");
	printf("        --activate\n");
	printf("            verbose VERBOSE\n");
	printf("            style dump style: 0 - common, 1 - process chains\n");
	printf("            sample stop sample if it is 0\n");
	printf("            cpu cpu-list that monitored\n");
	printf("        --deactivate\n");
	printf("        --settings print settings.\n");
	printf("        --report dump log with text.\n");
	printf("        --isolate CPU CGROUP set isolated cgroup name for cpu\n");
	printf("        --sample stop sample if it is 0\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_utilization_settings settings;
	string str;

	memset(&settings, 0, sizeof(struct diag_utilization_settings));
	
	settings.style = parse.int_value("style");
	settings.verbose = parse.int_value("verbose");
	settings.sample = parse.int_value("sample");

	str = parse.string_value("cpu");
	if (str.length() > 0) {
		strncpy(settings.cpus, str.c_str(), 512);
		settings.cpus[511] = 0;
	}

	ret = diag_call_ioctl(DIAG_IOCTL_UTILIZATION_SET, (long)&settings);	
	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    STYLE：\t%d\n", settings.style);
	printf("    SAMPLE：\t%d\n", settings.sample);
	printf("    输出级别：\t%d\n", settings.verbose);
	printf("    CPUS：\t%s\n", settings.cpus);

	if (ret)
		return;

	ret = diag_activate("utilization");
	if (ret == 1) {
		printf("utilization activated\n");
	} else {
		printf("utilization is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("utilization");
	if (ret == 0) {
		printf("utilization is not activated\n");
	} else {
		printf("deactivate utilization fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_utilization_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["verbose"] = Json::Value(settings->verbose);
		root["STYLE"] = Json::Value(settings->style);
		root["CPUS"] = Json::Value(settings->cpus);
	} else {
		root["err"] = Json::Value("found utilization settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_utilization_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	ret = diag_call_ioctl(DIAG_IOCTL_UTILIZATION_SETTINGS, (long)&settings);
	if (ret)
		return;

	if (1 == enable_json) {
		print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：\t%s\n", settings.activated ? "√" : "×");
		printf("    输出级别：\t%d\n", settings.verbose);
		printf("    STYLE：\t%d\n", settings.style);
		printf("    SAMPLE：\t%d\n", settings.sample);
		printf("    CPUS：\t%s\n", settings.cpus);
	} else {
		printf("获取utilization设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int utilization_extract(void *buf, unsigned int len, void *unused)
{
	int *et_type;
	struct utilization_detail *detail;
	int i;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_utilization_detail:
		if (len < sizeof(struct utilization_detail))
			break;
		detail = (struct utilization_detail *)buf;

		exec_sum += detail->exec;
		printf("资源利用监控：\n");
		printf("    执行时长：%lu, 分配页面数量：%lu\n",
					detail->exec, detail->pages);
		diag_printf_time(&detail->tv);
		diag_printf_task(&detail->task);
		diag_printf_proc_chains(&detail->proc_chains);

		ss_cpu << "**" << "CGROUP:[" << detail->task.cgroup_buf << "]" << ";";
		for (i = PROCESS_CHAINS_COUNT - 1; i >= 0 ; i--) {
			if (detail->proc_chains.chains[i][0] == 0)
				continue;
			if (detail->proc_chains.full_argv[i] == 0) {
				string cmdline = pid_cmdline.get_pid_cmdline(detail->proc_chains.tgid[i]);

				ss_cpu << " " << cmdline.c_str() << ";";
			} else {
				ss_cpu << " " << detail->proc_chains.chains[i] << ";";
			}
		}
		ss_cpu << detail->task.comm << ";";
		ss_cpu << " " << detail->exec << endl;

		if (detail->pages) {
			ss_pages << "*#" << "CGROUP:[" << detail->task.cgroup_buf << "]" << ";";
			for (i = PROCESS_CHAINS_COUNT - 1; i >= 0 ; i--) {
				if (detail->proc_chains.chains[i][0] == 0)
					continue;
				if (detail->proc_chains.full_argv[i] == 0) {
					string cmdline = pid_cmdline.get_pid_cmdline(detail->proc_chains.tgid[i]);

					ss_pages << " " << cmdline.c_str() << ";";
				} else {
					ss_pages << " " << detail->proc_chains.chains[i] << ";";
				}
			}
			ss_pages << detail->task.comm << ";";
			ss_pages << " " << detail->pages << endl;
		}
	
		if (detail->wild) {
			ss_wild << "*^" << "CGROUP:[" << detail->task.cgroup_buf << "]" << ";";
			for (i = PROCESS_CHAINS_COUNT - 1; i >= 0 ; i--) {
				if (detail->proc_chains.chains[i][0] == 0)
					continue;
				if (detail->proc_chains.full_argv[i] == 0) {
					string cmdline = pid_cmdline.get_pid_cmdline(detail->proc_chains.tgid[i]);

					ss_wild << " " << cmdline.c_str() << ";";
				} else {
					ss_wild << " " << detail->proc_chains.chains[i] << ";";
				}
			}
			ss_wild << detail->task.comm << ";";
			ss_wild << "wild: " << setw(10) << detail->wild << ";" << endl;
		}
	
		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	exec_sum = 0;
	ss_cpu.str("");
	ss_pages.str("");
	ss_wild.str("");
	extract_variant_buffer(buf, len, utilization_extract, NULL);
	printf("%s\n", ss_cpu.str().c_str());
	printf("%s\n", ss_pages.str().c_str());
	printf("%s\n", ss_wild.str().c_str());

	printf("Exec sum: %lu\n", exec_sum);
}

static void do_dump(void)
{
	static char variant_buf[1024 * 1024];
	int len;
	int ret = 0;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 1024 * 1024,
		.user_buf = variant_buf,
	};

	ret = diag_call_ioctl(DIAG_IOCTL_UTILIZATION_DUMP, (long)&dump_param);
	if (ret == 0) {
		do_extract(variant_buf, len);
	}
}

static void do_isolate(char *arg)
{
	int ret;
	char comm[256];
	struct diag_ioctl_utilization_isolate isolate = {
		.user_buf = comm,
		.user_buf_len = 256,
	};

	memset(comm, 0, 256);
	ret = sscanf(arg, "%d %255s", &isolate.cpu, comm);
	if (ret < 1)
		return;

	ret = diag_call_ioctl(DIAG_IOCTL_UTILIZATION_ISOLATE, (long)&isolate);
	printf("set isolate for utilization: %d, %s, ret is %d\n", isolate.cpu, comm, ret);
}

static void do_sample(char *arg)
{
	int ret;
	unsigned int sample;

	ret = sscanf(arg, "%d", &sample);
	if (ret < 1)
		return;

	ret = diag_call_ioctl(DIAG_IOCTL_UTILIZATION_SAMPLE, sample);
	printf("set sample for utilization: %d, ret is %d\n", sample, ret);
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct utilization_detail *detail;
	unsigned long *isolate;
	
	Json::Value root;
	Json::Value task;
	Json::Value wild;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_utilization_detail:
		if (len < sizeof(struct utilization_detail))
			break;
		detail = (struct utilization_detail *)buf;

		root["exec"] = Json::Value(detail->exec);
		root["pages"] = Json::Value(detail->pages);
		diag_sls_time(&detail->tv, root);
		diag_sls_task(&detail->task, task);
		diag_sls_proc_chains(&detail->proc_chains, task);
	
		isolate = (unsigned long *)(detail + 1);
		while (*isolate != ~0UL && (char *)(isolate + 2) < ((char *)buf + len)) {
			wild["cpu"] = Json::Value(*isolate);
			wild["ns"] = Json::Value(*(isolate + 1));
			task["wild"].append(wild);
			isolate += 2;
		}

		root["task"] = task;

		write_file(sls_file, "utilization", &detail->tv, 0, 0, root);
		write_syslog(syslog_enabled, "utilization", &detail->tv, 0, 0, root);
		break;
	default:
		break;
	}

	return 0;
}

static void do_sls(char *arg)
{
	int ret;
	static char variant_buf[10 * 1024 * 1024];
	int len;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 10 * 1024 * 1024,
		.user_buf = variant_buf,
	};

	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	while (1) {
		ret = diag_call_ioctl(DIAG_IOCTL_UTILIZATION_DUMP, (long)&dump_param);
		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}
}

int utilization_main(int argc, char **argv)
{
	static struct option long_options[] = {
			{"help",     no_argument, 0,  0 },
			{"activate",     optional_argument, 0,  0 },
			{"deactivate", no_argument,       0,  0 },
			{"settings",     optional_argument, 0,  0 },
			{"report",     no_argument, 0,  0 },
			{"isolate", required_argument, 0,  0 },
			{"sample", required_argument, 0,  0 },
			{"log",     required_argument, 0,  0 },
			{0,         0,                 0,  0 }
		};
	int c;

	if (argc <= 1) {
		usage_utilization();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_utilization();
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
			do_isolate(optarg);
			break;
		case 6:
			do_sample(optarg);
			break;
		case 7:
			do_sls(optarg);
			break;
		default:
			usage_utilization();
			break;
		}
	}

	return 0;
}
