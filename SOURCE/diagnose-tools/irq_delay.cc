/*
 * Linux内核诊断工具--用户态alloc-top功能实现
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
#include "json/json.h"
#include <iostream>
#include <fstream>

#include "params_parse.h"
#include "uapi/irq_delay.h"

using namespace std;

static char sls_file[256];
static int syslog_enabled;

void usage_irq_delay(void)
{
	printf("    irq-delay usage:\n");
	printf("        --help irq-delay help info\n");
	printf("        --activate\n");
	printf("            verbose VERBOSE\n");
	printf("            threshold threshold(ms)\n");
	printf("        --deactivate\n");
	printf("        --settings dump settings with text.\n");
	printf("        --report dump log with text.\n");
	printf("        --test testcase for irq-delay.\n");
}

static void do_activate(const char *arg)
{
	int ret  = 0;
	struct params_parser parse(arg);
	struct diag_irq_delay_settings settings;

	memset(&settings, 0, sizeof(struct diag_irq_delay_settings));
	
	settings.verbose = parse.int_value("verbose");
	settings.threshold = parse.int_value("threshold");
	if (settings.threshold <= 0)
		settings.threshold = 20;

	ret = -ENOSYS;
	syscall(DIAG_IRQ_DELAY_SET, &ret, &settings, sizeof(struct diag_irq_delay_settings));
	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    阀值(ms)：\t%d\n", settings.threshold);
	printf("    输出级别：\t%d\n", settings.verbose);

	ret = diag_activate("irq-delay");
	if (ret == 1) {
		printf("irq-delay activated\n");
	} else {
		printf("irq-delay is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret  = 0;

	ret = diag_deactivate("irq-delay");
	if (ret == 0) {
		printf("irq-delay is not activated\n");
	} else {
		printf("deactivate irq-delay fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_irq_delay_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["threshold_ms"] = Json::Value(settings->threshold);
		root["verbose"] = Json::Value(settings->verbose);
	} else {
		root["err"] = Json::Value("found irq-delay settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_irq_delay_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	ret = -ENOSYS;
	syscall(DIAG_IRQ_DELAY_SETTINGS, &ret, &settings, sizeof(struct diag_irq_delay_settings));

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    阀值(ms)：%d\n", settings.threshold);
		printf("    输出级别：%d\n", settings.verbose);
	} else {
		printf("获取irq-delay设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int irq_delay_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct irq_delay_detail *detail;
	static int seq;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_irq_delay_detail:
		if (len < sizeof(struct irq_delay_detail))
			break;
		detail = (struct irq_delay_detail *)buf;

		printf("中断延迟，PID： %d[%s]， CPU：%d, %lu ms, 时间：[%lu:%lu]\n",
			detail->task.pid, detail->task.comm,
			detail->cpu, detail->delay_ns / 1000 / 1000,
			detail->tv.tv_sec, detail->tv.tv_usec);

		diag_printf_time(&detail->tv);
		diag_printf_task(&detail->task);
		seq++;
		printf("##CGROUP:[%s]  %d      [%03d]  采样命中\n",
				detail->task.cgroup_buf,
				detail->task.pid,
				seq);
		diag_printf_kern_stack(&detail->kern_stack);
		diag_printf_user_stack(detail->task.tgid,
				detail->task.container_tgid,
				detail->task.comm,
				&detail->user_stack);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				detail->task.comm);
		printf("##\n");

		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, irq_delay_extract, NULL);
}

static void do_dump(void)
{
	static char variant_buf[1024 * 1024];
	int len;
	int ret = 0;

	ret = -ENOSYS;
	syscall(DIAG_IRQ_DELAY_DUMP, &ret, &len, variant_buf, 1024 * 1024);
	if (ret == 0 && len > 0) {
		do_extract(variant_buf, len);
	}
}

static void do_test(void)
{
	int ret;

	ret = -ENOSYS;
	syscall(DIAG_IRQ_DELAY_TEST, &ret, 100);
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct irq_delay_detail *detail;
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
	case et_irq_delay_detail:
		if (len < sizeof(struct irq_delay_detail))
			break;
		detail = (struct irq_delay_detail *)buf;
		root["cpu"] = Json::Value(detail->cpu);
		root["delay_ns"] = Json::Value(detail->delay_ns);
		diag_sls_time(&detail->tv, root);
		diag_sls_task(&detail->task, task);
		diag_sls_kern_stack(&detail->kern_stack, task);
		diag_sls_user_stack(detail->task.tgid,
			detail->task.container_tgid,
			detail->task.comm,
			&detail->user_stack, task);
		root["task"] = task;

		write_file(sls_file, "irq-delay", &detail->tv, 0, 0, root);
		write_syslog(syslog_enabled, "irq-delay", &detail->tv, 0, 0, root);

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
	int jiffies_sls = 0;

	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	while (1) {
		ret = -ENOSYS;
		syscall(DIAG_IRQ_DELAY_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		if (ret == 0 && len > 0) {
			/**
			 * 10 min
			 */
			if (jiffies_sls >= 60) {
				jiffies_sls = 0;
				clear_symbol_info(pid_cmdline, g_symbol_parser.get_java_procs(), 1);
			}

			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
		jiffies_sls++;
	}
}

int irq_delay_main(int argc, char **argv)
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
		usage_irq_delay();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_irq_delay();
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
			usage_irq_delay();
			break;
		}
	}

	return 0;
}
