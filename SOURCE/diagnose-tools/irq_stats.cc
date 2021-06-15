/*
 * Linux内核诊断工具--用户态irq-stats功能实现
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
#include "uapi/irq_stats.h"
#include "params_parse.h"

using namespace std;

static unsigned long irq_count = 0;
static unsigned long irq_sum = 0;
static unsigned long sirq_count = 0;
static unsigned long sirq_sum = 0;
static unsigned long sirq_counts[DIAG_NR_SOFTIRQS];
static unsigned long sirq_sums[DIAG_NR_SOFTIRQS];

static unsigned long sls_irq_count = 0;
static unsigned long sls_irq_sum = 0;
static unsigned long sls_sirq_count = 0;
static unsigned long sls_sirq_sum = 0;
static unsigned long sls_sirq_counts[DIAG_NR_SOFTIRQS];
static unsigned long sls_sirq_sums[DIAG_NR_SOFTIRQS];
static struct diag_timespec sls_tv;
static unsigned long sls_id;
static char sls_file[256];
static int syslog_enabled;

void usage_irq_stats(void)
{
	printf("    irq-stats usage:\n");
	printf("        --help irq-stats help info\n");
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
	struct diag_irq_stats_settings settings;
	string str;

	memset(&settings, 0, sizeof(struct diag_irq_stats_settings));

	settings.verbose = parse.int_value("verbose");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_IRQ_STATS_SET, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_IRQ_STATS_SET, &ret, &settings, sizeof(struct diag_irq_stats_settings));
	}

	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    输出级别：%d\n", settings.verbose);
	if (ret)
		return;

	ret = diag_activate("irq-stats");
	if (ret == 1) {
		printf("irq-stats activated\n");
	} else {
		printf("irq-stats is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("irq-stats");
	if (ret == 0) {
		printf("irq-stats is not activated\n");
	} else {
		printf("deactivate irq-stats fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_irq_stats_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["verbose"] = Json::Value(settings->verbose);
	} else {
		root["err"] = Json::Value("found irq-stats settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_irq_stats_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_IRQ_STATS_SETTINGS, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_IRQ_STATS_SETTINGS, &ret, &settings, sizeof(struct diag_irq_stats_settings));
	}

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    输出级别：%d\n", settings.verbose);
	} else {
		printf("获取irq-stats设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int irq_stats_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct irq_stats_header *header;
	struct irq_stats_irq_summary *irq_summary;
	struct irq_stats_irq_detail *irq_detail;
	struct irq_stats_softirq_summary *softirq_summary;
    symbol sym;
    elf_file file;
	int i;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_irq_stats_header:
		if (len < sizeof(struct irq_stats_header))
			break;
		header = (struct irq_stats_header *)buf;

		printf("中断统计：[%lu:%lu]\n",
			header->tv.tv_sec, header->tv.tv_usec);
		break;
	case et_irq_stats_irq_summary:
		if (len < sizeof(struct irq_stats_irq_summary))
			break;
		irq_summary = (struct irq_stats_irq_summary *)buf;
		printf("    core%-4d %-10lu %-20lu %-10lu %-10lu\n",
			irq_summary->cpu,
			irq_summary->irq_cnt,
			irq_summary->irq_run_total,
			irq_summary->max_irq,
			irq_summary->max_irq_time);
		irq_count += irq_summary->irq_cnt;
		irq_sum += irq_summary->irq_run_total;
		break;
	case et_irq_stats_irq_detail:
		if (len < sizeof(struct irq_stats_irq_detail))
			break;
		irq_detail = (struct irq_stats_irq_detail *)buf;
		printf("    IRQ: core%-4d irq: %4d, handler: %p, runtime(ns): %8lu / %10lu\n",
			irq_detail->cpu,
			irq_detail->irq,
			irq_detail->handler,
			irq_detail->irq_cnt,
			irq_detail->irq_run_total);
		break;
	case et_irq_stats_softirq_summary:
		if (len < sizeof(struct irq_stats_softirq_summary))
			break;
		softirq_summary = (struct irq_stats_softirq_summary *)buf;

		for (i = 0; i < DIAG_NR_SOFTIRQS; i++) {
			printf("    SOFT-IRQ: core%-4d soft-irq: %4d, count: %8lu / %10lu, runtime(ns): %8lu / %10lu\n",
				softirq_summary->cpu,
				i,
				softirq_summary->softirq_cnt[i],
				softirq_summary->softirq_cnt_d[i],
				softirq_summary->sortirq_run_total[i],
				softirq_summary->sortirq_run_total_d[i]);
				sirq_count += softirq_summary->softirq_cnt[i] + softirq_summary->softirq_cnt_d[i];
				sirq_sum += softirq_summary->sortirq_run_total[i] + softirq_summary->sortirq_run_total_d[i];
				sirq_counts[i] += softirq_summary->softirq_cnt[i] + softirq_summary->softirq_cnt_d[i];
				sirq_sums[i] += softirq_summary->sortirq_run_total[i] + softirq_summary->sortirq_run_total_d[i];
		}
		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, irq_stats_extract, NULL);
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

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_IRQ_STATS_DUMP, (long)&dump_param);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_IRQ_STATS_DUMP, &ret, &len, variant_buf, 1024 * 1024);
	}

	if (ret == 0 && len > 0) {
		int i;

		do_extract(variant_buf, len);
		printf("SUM: %lu, %lu, %lu, %lu\n", irq_count, irq_sum, sirq_count, sirq_sum);
		irq_count = 0;
		irq_sum = 0;
		sirq_count = 0;
		sirq_sum = 0;
		for (i = 0; i < DIAG_NR_SOFTIRQS; i++) {
			printf("\tSOFTIRQ %3d: %lu, %lu\n", i, sirq_counts[i], sirq_sums[i]);
			sirq_counts[i] = 0;
			sirq_sums[i] = 0;
		}
	}
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct irq_stats_header *header;
	struct irq_stats_irq_summary *irq_summary;
	struct irq_stats_irq_detail *irq_detail;
	struct irq_stats_softirq_summary *softirq_summary;
	int i;
	Json::Value root;
	stringstream ss;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_irq_stats_header:
		if (len < sizeof(struct irq_stats_header))
			break;
		header = (struct irq_stats_header *)buf;

		sls_tv.tv_sec = header->tv.tv_sec;
		sls_tv.tv_usec = header->tv.tv_usec;

		sls_id = sls_tv.tv_sec;

		diag_sls_time(&header->tv, root);

		write_file(sls_file, "irq-stats-header", &sls_tv, sls_id, 0, root);
		write_syslog(syslog_enabled, "irq-stats-header", &sls_tv, sls_id, 0, root);
		break;
	case et_irq_stats_irq_summary:
		if (len < sizeof(struct irq_stats_irq_summary))
			break;
		irq_summary = (struct irq_stats_irq_summary *)buf;

		root["core"] = Json::Value(irq_summary->cpu);
		root["irq_cnt"] = Json::Value(irq_summary->irq_cnt);
		root["irq_run_total"] = Json::Value(irq_summary->irq_run_total);
		root["max_irq_no"] = Json::Value(irq_summary->max_irq);
		root["max_irq_runtime"] = Json::Value(irq_summary->max_irq_time);

		write_file(sls_file, "irq-stats-irq-summary", &sls_tv, sls_id, 0, root);
		write_syslog(syslog_enabled,"irq-stats-irq-summary", &sls_tv, sls_id, 0, root);

		sls_irq_count += irq_summary->irq_cnt;
		sls_irq_sum += irq_summary->irq_run_total;
		break;
	case et_irq_stats_irq_detail:
		if (len < sizeof(struct irq_stats_irq_detail))
			break;
		irq_detail = (struct irq_stats_irq_detail *)buf;

		root["core"] = Json::Value(irq_detail->cpu);
		root["irq-no"] = Json::Value(irq_detail->irq);

		ss.str("");
		ss << std::hex << irq_detail->handler;
		root["handler"] = Json::Value(ss.str());

		root["irq_cnt"] = Json::Value(irq_detail->irq_cnt);
		root["irq_run_total"] = Json::Value(irq_detail->irq_run_total);

		write_file(sls_file, "irq-stats-irq-detail", &sls_tv, sls_id, 0, root);
		write_syslog(syslog_enabled, "irq-stats-irq-detail", &sls_tv, sls_id, 0, root);

		break;
	case et_irq_stats_softirq_summary:
		if (len < sizeof(struct irq_stats_softirq_summary))
			break;
		softirq_summary = (struct irq_stats_softirq_summary *)buf;

		for (i = 0; i < DIAG_NR_SOFTIRQS; i++) {
			root["core"] = Json::Value(softirq_summary->cpu);
			root["sirq-no"] = Json::Value(i);
			root["sirq-cnt"] = Json::Value(softirq_summary->softirq_cnt[i]);
			root["sirq-cnt-d"] = Json::Value(softirq_summary->softirq_cnt_d[i]);
			root["sirq-run"] = Json::Value(softirq_summary->sortirq_run_total[i]);
			root["sirq-run-d"] = Json::Value(softirq_summary->sortirq_run_total_d[i]);
			write_file(sls_file, "irq-stats-softirq-summary", &sls_tv, sls_id, 0, root);
			write_syslog(syslog_enabled, "irq-stats-softirq-summary", &sls_tv, sls_id, 0, root);

			sls_sirq_count += softirq_summary->softirq_cnt[i] + softirq_summary->softirq_cnt_d[i];
			sls_sirq_sum += softirq_summary->sortirq_run_total[i] + softirq_summary->sortirq_run_total_d[i];
			sls_sirq_counts[i] += softirq_summary->softirq_cnt[i] + softirq_summary->softirq_cnt_d[i];
			sls_sirq_sums[i] += softirq_summary->sortirq_run_total[i] + softirq_summary->sortirq_run_total_d[i];
		}

		break;
	default:
		break;
	}

	return 0;
}

static void write_sls_summary(void)
{
	int i;
	Json::Value root;
	Json::Value detail;

	root["sum_irq_total_cnt"] = Json::Value(sls_irq_count);
	root["sum_irq_total_runs"] = Json::Value(sls_irq_sum);
	root["sum_sirq_total_cnt"] = Json::Value(sls_sirq_count);
	root["sum_sirq_total_runs"] = Json::Value(sls_sirq_sum);
	write_file(sls_file, "irq-stats-total", &sls_tv, sls_id, 0, root);
	write_syslog(syslog_enabled, "irq-stats-total", &sls_tv, sls_id, 0, root);

	sls_irq_count = 0;
	sls_irq_sum = 0;
	sls_sirq_count = 0;
	sls_sirq_sum = 0;

	for (i = 0; i < DIAG_NR_SOFTIRQS; i++) {
		detail["sirq_total_cnt"] = Json::Value(sls_sirq_counts[i]);
		detail["sirq_total_runs"] = Json::Value(sls_sirq_sums[i]);
		detail["sirq_no"] = Json::Value(i);
		write_file(sls_file, "irq-stats-total-softirq", &sls_tv, sls_id, 0, detail);
		write_syslog(syslog_enabled, "irq-stats-total-softirq", &sls_tv, sls_id, 0, detail);
		
		sls_sirq_counts[i] = 0;
		sls_sirq_sums[i] = 0;
	}

	return;
}

static void do_sls(char *arg)
{
	static char variant_buf[1024 * 1024];
	int len;
	int ret = 0;
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
			ret = diag_call_ioctl(DIAG_IOCTL_IRQ_STATS_DUMP, (long)&dump_param);
		} else {
			syscall(DIAG_IRQ_STATS_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		}

		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
			write_sls_summary();
		}

		sleep(10);
	}	

}

int irq_stats_main(int argc, char **argv)
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
		usage_irq_stats();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_irq_stats();
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
			usage_irq_stats();
			break;
		}
	}

	return 0;
}

