/*
 * Linux内核诊断工具--用户态irq-trace功能实现
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

#include "uapi/irq_trace.h"
#include "params_parse.h"

using namespace std;

static char sls_file[256];
static int syslog_enabled;

void usage_irq_trace(void)
{
	printf("    irq-trace usage:\n");
	printf("        --help irq-trace help info\n");
	printf("        --activate\n");
	printf("            verbose VERBOSE\n");
	printf("            irq set irq threshold(ms)\n");
	printf("            sirq set soft-irq threshold(ms)\n");
	printf("            timer set timer threshold(ms)\n");
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
	struct diag_irq_trace_settings settings;

	memset(&settings, 0, sizeof(struct diag_irq_trace_settings));

	settings.verbose = parse.int_value("verbose");
	settings.threshold_irq = parse.int_value("irq");
	settings.threshold_sirq = parse.int_value("sirq");
	settings.threshold_timer = parse.int_value("timer");

	ret = -ENOSYS;
	syscall(DIAG_IRQ_TRACE_SET, &ret, &settings, sizeof(struct diag_irq_trace_settings));
	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    输出级别：%d\n", settings.verbose);
	printf("    IRQ：%lu(ms)\n", settings.threshold_irq);
	printf("    SIRQ：%lu(ms)\n", settings.threshold_sirq);
	printf("    TIMER：%lu(ms)\n", settings.threshold_timer);

	ret = diag_activate("irq-trace");
	if (ret == 1) {
		printf("irq-trace activated\n");
	} else {
		printf("irq-trace is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("irq-trace");
	if (ret == 0) {
		printf("irq-trace is not activated\n");
	} else {
		printf("deactivate irq-trace fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_irq_trace_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["verbose"] = Json::Value(settings->verbose);
		root["threshold_IRQ_ms"] = Json::Value(settings->threshold_irq);
		root["threshold_SIRQ_ms"] = Json::Value(settings->threshold_sirq);
		root["threshold_TIMER_ms"] = Json::Value(settings->threshold_timer);
	} else {
		root["err"] = Json::Value("found irq-trace settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_irq_trace_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	ret = -ENOSYS;
	syscall(DIAG_IRQ_TRACE_SETTINGS, &ret, &settings, sizeof(struct diag_irq_trace_settings));

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    输出级别：%d\n", settings.verbose);
		printf("    IRQ：%lu(ms)\n", settings.threshold_irq);
		printf("    SIRQ：%lu(ms)\n", settings.threshold_sirq);
		printf("    TIMER：%lu(ms)\n", settings.threshold_timer);
	} else {
		printf("获取irq-trace设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int irq_trace_extract(void *buf, unsigned int len, void *)
{
	int i;
	int *et_type;
	struct irq_trace_detail *detail;
	struct irq_trace_sum *sum;
    symbol sym;
    elf_file file;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_irq_trace_detail:
		if (len < sizeof(struct irq_trace_detail))
			break;
		detail = (struct irq_trace_detail *)buf;

		sym.reset((unsigned long)detail->func);
		printf("detail: core%-4d type: %s, %p, %s, time: %lu, [%lu,: %lu]\n",
				detail->cpu,
				detail->source == 0 ? "IRQ" : (detail->source == 1 ? "SIRQ" : "TIMER"),
				detail->func,
				g_symbol_parser.find_kernel_symbol(sym) ? sym.name.c_str() : "UNKNOWN",
				detail->time,
				detail->tv.tv_sec,
				detail->tv.tv_usec);

		break;
	case et_irq_trace_sum:
		if (len < sizeof(struct irq_trace_sum))
			break;
		sum = (struct irq_trace_sum *)buf;

		printf("SUM: \n");
		printf("       IRQ: %10lu / %20lu\n",
				sum->irq_count,
				sum->irq_runs);
		for (i = 0; i < DIAG_NR_SOFTIRQS; i++) {
			printf("   SIRQ %2d: %10lu / %20lu\n",
				i,
				sum->sirq_count[i],
				sum->sirq_runs[i]);
		}
		printf("     TIMER: %10lu / %20lu\n",
				sum->timer_count,
				sum->timer_runs);

		break;
	default:
		break;
	}

	return 0;
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int i;
	int *et_type;
	struct irq_trace_detail *detail;
	struct irq_trace_sum *sum;
	symbol sym;
	elf_file file;
	Json::Value root;
	Json::Value raw;
	Json::Value sirq;
	stringstream ss;
	struct timeval tv;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_irq_trace_detail:
		if (len < sizeof(struct irq_trace_detail))
			break;
		detail = (struct irq_trace_detail *)buf;

		root["cpu"] = Json::Value(detail->cpu);

		if (0 == detail->source) {
			root["type"] = Json::Value("IRQ");
		} else if (1 == detail->source) {
			root["type"] = Json::Value("SIRQ");
		} else {
			root["type"] = Json::Value("TIMER");
		}

		ss.str("");
		ss << std::hex << detail->func;
		root["func_pointer"] = Json::Value(ss.str());

		sym.reset((unsigned long)detail->func);
		if (1 == g_symbol_parser.find_kernel_symbol(sym)) {
			root["func"] = Json::Value(sym.name.c_str());
		} else {
			root["func"] = Json::Value("UNKNOWN");
		}

		root["time"] = Json::Value(detail->time);
		diag_sls_time(&detail->tv, root);

		write_file(sls_file, "irq-trace-detail", &detail->tv, 0, 0, root);
		write_syslog(syslog_enabled, "irq-trace-detail", &detail->tv, 0, 0, root);
		break;
	case et_irq_trace_sum:
		if (len < sizeof(struct irq_trace_sum))
			break;
		sum = (struct irq_trace_sum *)buf;

		raw["count"] = Json::Value(sum->irq_count);
		raw["runs"] = Json::Value(sum->irq_runs);
		root["irq"] = raw;

		raw["count"] = Json::Value(sum->timer_count);
		raw["runs"] = Json::Value(sum->timer_runs);
		root["timer"] = raw;

		for (i = 0; i < DIAG_NR_SOFTIRQS; i++) {
				raw["count"] = Json::Value(sum->sirq_count[i]);
				raw["runs"] = Json::Value(sum->sirq_runs[i]);
				raw["no"] = Json::Value(i);

				ss.str("");
				ss << "SIRQ_" << i;
				sirq[ss.str()] = raw;
		}
		root["sirq"] = sirq;

		gettimeofday(&tv, NULL);
		write_file(sls_file, "irq-trace-sum",  &tv, 0, 0, root);
		write_syslog(syslog_enabled, "irq-trace-sum",  &tv, 0, 0, root);

		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, irq_trace_extract, NULL);
}

static void do_dump(void)
{
	static char variant_buf[1024 * 1024];
	int len;
	int ret = 0;

	ret = -ENOSYS;
	syscall(DIAG_IRQ_TRACE_DUMP, &ret, &len, variant_buf, 1024 * 1024);
	if (ret == 0 && len > 0) {
		do_extract(variant_buf, len);
	}
}

static void do_sls(char *arg)
{
	static char variant_buf[1024 * 1024];
	int len;
	int ret = 0;

	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	while (1) {
		syscall(DIAG_IRQ_TRACE_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}

}

int irq_trace_main(int argc, char **argv)
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
		usage_irq_trace();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_irq_trace();
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
			usage_irq_trace();
			break;
		}
	}

	return 0;
}

