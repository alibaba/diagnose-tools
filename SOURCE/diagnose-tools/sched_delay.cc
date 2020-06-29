/*
 * Linux内核诊断工具--用户态sched-delay功能实现
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

#include "uapi/sched_delay.h"
#include "params_parse.h"
#include <syslog.h>

using namespace std;

static char sls_file[256];
static int syslog_enabled;

void usage_sched_delay(void)
{
	printf("    sched-delay usage:\n");
	printf("        --help sched-delay help info\n");
	printf("        --activate\n");
	printf("          verbose VERBOSE\n");
	printf("          threshold THRESHOLD(MS)\n");
	printf("          tgid process group monitored\n");
	printf("          pid thread id that monitored\n");
	printf("          comm comm that monitored\n");
	printf("        --deactivate\n");
	printf("        --report dump log with text.\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_sched_delay_settings settings;
	string str;

	memset(&settings, 0, sizeof(struct diag_sched_delay_settings));
	
	settings.verbose = parse.int_value("verbose");
	settings.tgid = parse.int_value("tgid");
	settings.pid = parse.int_value("pid");
	settings.bvt = parse.int_value("bvt");
	settings.threshold_ms = parse.int_value("threshold");

	if (0 == settings.threshold_ms)
	{
		settings.threshold_ms = 50;
	}

	str = parse.string_value("comm");
	if (str.length() > 0) {
		strncpy(settings.comm, str.c_str(), TASK_COMM_LEN);
		settings.comm[TASK_COMM_LEN - 1] = 0;
	}

	ret = -ENOSYS;
	syscall(DIAG_SCHED_DELAY_SET, &ret, &settings, sizeof(struct diag_sched_delay_settings));
	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    进程ID：\t%d\n", settings.pid);
	printf("    线程ID：\t%d\n", settings.pid);
	printf("    进程名称：\t%s\n", settings.comm);
	printf("    监控阈值(ms)：\t%d\n", settings.threshold_ms);
	printf("    输出级别：\t%d\n", settings.verbose);

	ret = diag_activate("sched-delay");
	if (ret == 1) {
		printf("sched-delay activated\n");
	} else {
		printf("sched-delay is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("sched-delay");
	if (ret == 0) {
		printf("sched-delay is not activated\n");
	} else {
		printf("deactivate sched-delay fail, ret is %d\n", ret);
	}
}

static void do_settings(const char *arg)
{
	struct diag_sched_delay_settings settings;
	int ret;
	int enable_json = 0;
	Json::Value root;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	ret = -ENOSYS;
	syscall(DIAG_SCHED_DELAY_SETTINGS, &ret, &settings,
		sizeof(struct diag_sched_delay_settings));
	if (ret == 0) {
		if (1 != enable_json)
		{
			printf("功能设置：\n");
			printf("    是否激活：\t%s\n", settings.activated ? "√" : "×");
			printf("    进程ID：\t%d\n", settings.pid);
			printf("    线程ID：\t%d\n", settings.pid);
			printf("    进程名称：\t%s\n", settings.comm);
			printf("    监控阈值(ms)：\t%d\n", settings.threshold_ms);
			printf("    输出级别：\t%d\n", settings.verbose);
		}
		else
		{
			root["activated"] = Json::Value(settings.activated);
			root["pid"] = Json::Value(settings.pid);
			root["tid"] = Json::Value(settings.pid);
			root["comm"] = Json::Value(settings.comm);
			root["threshold"] = Json::Value(settings.threshold_ms);
			root["verbose"] = Json::Value(settings.verbose);
		}
	} else {
		if (1 != enable_json)
		{
			printf("获取sched-delay设置失败，请确保正确安装了diagnose-tools工具\n");
		}
		else
		{
			root["err"]=Json::Value("found sched-delay settings failed, please check diagnose-tools installed or not\n");
		}
	}

	if (1 == enable_json)
	{
		std::string str_log;
		str_log.append(root.toStyledString());
		printf("%s", str_log.c_str());
	}
}

static int sched_delay_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct sched_delay_dither *dither;
	struct sched_delay_rq *rq;
	static int seq = 0;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_sched_delay_dither:
		if (len < sizeof(struct sched_delay_dither))
			break;
		dither = (struct sched_delay_dither *)buf;

		printf("警告：调度被延迟 %lu ms，NOW: %lu, QUEUED: %lu, 当前时间：[%lu:%lu]\n",
			dither->delay_ms,
			dither->now,
			dither->queued,
			dither->tv.tv_sec,
			dither->tv.tv_usec);

		printf("##CGROUP:[%s]  %d      [%03d]  采样命中\n",
				dither->task.cgroup_buf,
				dither->task.pid,
				seq);
		seq++;

		diag_printf_kern_stack(&dither->kern_stack);
		diag_printf_user_stack(dither->task.tgid,
				dither->task.container_tgid,
				dither->task.comm,
				&dither->user_stack);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				dither->task.comm);
		diag_printf_proc_chains(&dither->proc_chains);
		printf("##\n");

		break;
	case et_sched_delay_rq:
		if (len < sizeof(struct sched_delay_rq))
			break;
		rq = (struct sched_delay_rq *)buf;

		printf("\tCPU %d，nr_running:%d\n",
			rq->cpu, rq->nr_running);

		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, sched_delay_extract, NULL);
}

static void do_dump(const char *arg)
{
	static char variant_buf[50 * 1024 * 1024];
	int len;
	int ret = 0;

	memset(variant_buf, 0, 4 * 1024 * 1024);
	ret = -ENOSYS;
	syscall(DIAG_SCHED_DELAY_DUMP, &ret, &len, variant_buf, 4 * 1024 * 1024);
	if (ret == 0 && len > 0) {
		do_extract(variant_buf, len);
	}
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct sched_delay_dither *dither;
	struct sched_delay_rq *rq;
    symbol sym;
	
	Json::Value root;
	Json::Value task;
	Json::Value kern_stack;
	Json::Value user_stack;
	Json::Value proc_chains;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_sched_delay_dither:
		if (len < sizeof(struct sched_delay_dither))
			break;
		dither = (struct sched_delay_dither *)buf;
		root["id"] = dither->id;
		root["seq"] = dither->seq;
		root["delay_ms"] = Json::Value(dither->delay_ms);
		root["now"] = Json::Value(dither->now);
		root["queued"] = Json::Value(dither->queued);
		diag_sls_time(&dither->tv, root);
		diag_sls_task(&dither->task, task);
		diag_sls_kern_stack(&dither->kern_stack, task);
		diag_sls_user_stack(dither->task.tgid,
			dither->task.container_tgid,
			dither->task.comm,
			&dither->user_stack, task, 0);
		diag_sls_proc_chains(&dither->proc_chains, task);
		root["task"] = task;

		write_file(sls_file, "sched-delay-dither", &dither->tv, dither->id, dither->seq, root);
		write_syslog(syslog_enabled, "sched-delay-dither", &dither->tv, dither->id, dither->seq, root);
		break;
	case et_sched_delay_rq:
		if (len < sizeof(struct sched_delay_rq))
			break;
		rq = (struct sched_delay_rq *)buf;
		root["id"] = rq->id;
		root["seq"] = rq->seq;
		diag_sls_time(&rq->tv, root);
		root["cpu"] = rq->cpu;
		root["nr_running"] = rq->nr_running;
		write_file(sls_file, "sched-delay-rq", &rq->tv, rq->id, rq->seq, root);
		write_syslog(syslog_enabled, "sched-delay-rq", &rq->tv, rq->id, rq->seq, root);
		break;
	default:
		break;
	}

	return 0;
}

static void do_sls(char *arg)
{
	int ret;
	static char variant_buf[4 * 1024 * 1024];
	int len;
	int jiffies_sls = 0;

	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	java_attach_once();
	while (1) {
		ret = -ENOSYS;
		syscall(DIAG_SCHED_DELAY_DUMP, &ret, &len, variant_buf, 4 * 1024 * 1024);
		if (ret == 0 && len > 0) {
			/**
			 * 10 min
			 */
			if (jiffies_sls >= 60) {
				jiffies_sls = 0;
				clear_symbol_info(pid_cmdline, g_symbol_parser.get_java_procs(), 1);
				java_attach_once();
			}

			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
		jiffies_sls++;
	}
}

int sched_delay_main(int argc, char **argv)
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
		usage_sched_delay();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_sched_delay();
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
			usage_sched_delay();
			break;
		}
	}

	return 0;
}
