/*
 * Linux内核诊断工具--用户态ping-delay功能实现
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
#include "uapi/ping_delay.h"
#include "unwind.h"
#include "params_parse.h"

using namespace std;

static char sls_file[256];
static int syslog_enabled;

void usage_ping_delay(void)
{
	printf("    ping-delay usage:\n");
	printf("        --help ping_delay help info\n");
	printf("        --activate\n");
	printf("          verbose VERBOSE\n");
	printf("          addr filtered ip address.\n");
	printf("        --deactivate\n");
	printf("        --settings dump settings\n");
	printf("        --report dump log with text.\n");
	printf("        --log\n");
	printf("          sls=/tmp/1.log store in file\n");
	printf("          syslog=1 store in syslog\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_ping_delay_settings settings;
	string str;
	char ipstr[255];

	memset(&settings, 0, sizeof(struct diag_ping_delay_settings));
	
	settings.verbose = parse.int_value("verbose");

	str = parse.string_value("addr");
	if (str.length() > 0) {
		settings.addr = ipstr2int(str.c_str());
	}

	ret = -ENOSYS;
	syscall(DIAG_PING_DELAY_SET, &ret, &settings, sizeof(struct diag_ping_delay_settings));
	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
		printf("    输出级别：%d\n", settings.verbose);
		printf("    过滤地址：%s\n", int2ipstr(settings.addr, ipstr, 255));

	ret = diag_activate("ping-delay");
	if (ret == 1) {
		printf("ping-delay activated\n");
	} else {
		printf("ping-delay is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("ping-delay");
	if (ret == 0) {
		printf("ping-delay is not activated\n");
	} else {
		printf("deactivate ping-delay fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_ping_delay_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;
	char ipstr[255];

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["verbose"] = Json::Value(settings->verbose);
		root["ipaddr"] = Json::Value(int2ipstr(settings->addr, ipstr, 255));
	} else {
		root["err"] = Json::Value("found ping-delay settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_ping_delay_settings settings;
	int ret;
	char ipstr[255];
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	memset(&settings, 0, sizeof(struct diag_ping_delay_settings));
	ret = -ENOSYS;
	syscall(DIAG_PING_DELAY_SETTINGS, &ret, &settings, sizeof(struct diag_ping_delay_settings));

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    输出级别：%d\n", settings.verbose);
		printf("    过滤地址：%s\n", int2ipstr(settings.addr, ipstr, 255));
		
	} else {
		printf("获取ping-delay设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int ping_delay_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct ping_delay_summary *summary;
	struct ping_delay_detail *detail;
	struct ping_delay_event *event;
	unsigned char *saddr;
	unsigned char *daddr;
	int i;
	symbol sym;
	const char *func;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_ping_delay_summary:
		if (len < sizeof(struct ping_delay_summary))
			break;
		summary = (struct ping_delay_summary *)buf;
		saddr = (unsigned char *)&summary->saddr;
		daddr = (unsigned char *)&summary->daddr;

		printf("PING延时信息, 源IP：[%lu.%lu.%lu.%lu], 目的IP：[%lu.%lu.%lu.%lu], ID：%d, SEQ: %d, 时间：[%lu:%lu]\n",
			(unsigned long)saddr[0], (unsigned long)saddr[1], (unsigned long)saddr[2], (unsigned long)saddr[3],
			(unsigned long)daddr[0], (unsigned long)daddr[1], (unsigned long)daddr[2], (unsigned long)daddr[3],
			summary->echo_id, summary->echo_sequence,
			summary->tv.tv_sec, summary->tv.tv_usec);
		for (i = 0; i < PD_TRACK_COUNT; i++) {
			printf("    %30s: %20lu\n",
				ping_delay_packet_steps_str[i],
				summary->time_stamp[i]
			);
		}
		break;
	case et_ping_delay_detail:
		if (len < sizeof(struct ping_delay_detail))
			break;
		detail = (struct ping_delay_detail *)buf;

		saddr = (unsigned char *)&detail->saddr;
		daddr = (unsigned char *)&detail->daddr;

		printf("PING延时跟踪, 源IP：%lu.%lu.%lu.%lu, 目的IP：%lu.%lu.%lu.%lu, ID：%d, SEQ: %d, STEP: %s, 时间：[%lu:%lu]\n",
			(unsigned long)saddr[0], (unsigned long)saddr[1], (unsigned long)saddr[2], (unsigned long)saddr[3],
			(unsigned long)daddr[0], (unsigned long)daddr[1], (unsigned long)daddr[2], (unsigned long)daddr[3],
			detail->echo_id, detail->echo_sequence,
			detail->step < PD_TRACK_COUNT ? ping_delay_packet_steps_str[detail->step] : "?",
			detail->tv.tv_sec, detail->tv.tv_usec);

		break;
	case et_ping_delay_event:
		if (len < sizeof(struct ping_delay_event))
			break;
		event = (struct ping_delay_event *)buf;

		sym.reset(event->func);
		if (g_symbol_parser.find_kernel_symbol(sym)) {
			func = sym.name.c_str();
		} else {
			func = "UNKNOWN";
		}

		printf("PING延时事件, type：%d, func: 0x%lx[%s], 时间：[%lu:%lu]\n",
			event->action, 
			event->func, func,
			event->tv.tv_sec, event->tv.tv_usec);
		break;
	default:
		break;
	}
	return 0;
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct ping_delay_summary *summary;
	struct ping_delay_detail *detail;
	struct ping_delay_event *event;
	unsigned char *saddr;
	unsigned char *daddr;
	int i;
	symbol sym;
	const char *func;
	Json::Value root;
	Json::Value raw;
	Json::Value msg;
	stringstream ss;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_ping_delay_summary:
		if (len < sizeof(struct ping_delay_summary))
			break;
		summary = (struct ping_delay_summary *)buf;
		saddr = (unsigned char *)&summary->saddr;
		daddr = (unsigned char *)&summary->daddr;

		diag_ip_addr_to_str(saddr, "src_addr", root);
		diag_ip_addr_to_str(daddr, "dest_addr", root);

		root["echo_id"] = Json::Value(summary->echo_id);
		root["echo_sequence"] = Json::Value(summary->echo_sequence);
		diag_sls_time(&summary->tv, root);

		for (i = 0; i < PD_TRACK_COUNT; i++) {
			raw["time_stamp"] = Json::Value(summary->time_stamp[i]);
			msg[ping_delay_packet_steps_str[i]] = raw;
		}
		root["msg"] = msg;

		write_file(sls_file, "ping-delay-summary", &summary->tv, 0, 0, root);
		write_syslog(syslog_enabled, "ping-delay-summary", &summary->tv, 0, 0, root);
		break;
	case et_ping_delay_detail:
		if (len < sizeof(struct ping_delay_detail))
			break;
		detail = (struct ping_delay_detail *)buf;

		saddr = (unsigned char *)&detail->saddr;
		daddr = (unsigned char *)&detail->daddr;
		diag_ip_addr_to_str(saddr, "src_addr", root);
		diag_ip_addr_to_str(daddr, "dest_addr", root);

		root["echo_id"] = Json::Value(detail->echo_id);
		root["echo_sequence"] = Json::Value(detail->echo_sequence);
		diag_sls_time(&detail->tv, root);

		if (detail->step < PD_TRACK_COUNT) {
			root["STEP"] = Json::Value(ping_delay_packet_steps_str[detail->step]);
		} else {
			root["STEP"] = Json::Value("?");
		}

		write_file(sls_file, "ping-delay-detail", &detail->tv, 0, 0, root);
		write_syslog(syslog_enabled, "ping-delay-detail", &detail->tv, 0, 0, root);
		break;
	case et_ping_delay_event:
		if (len < sizeof(struct ping_delay_event))
			break;
		event = (struct ping_delay_event *)buf;

		sym.reset(event->func);
		if (g_symbol_parser.find_kernel_symbol(sym)) {
			func = sym.name.c_str();
		} else {
			func = "UNKNOWN";
		}

		root["type"] = Json::Value(event->action);

		ss << "0x";
		ss << std::hex << event->func;
		root["func_pointer"] = Json::Value(ss.str());
		root["func"] = Json::Value(func);
		diag_sls_time(&event->tv, root);

		write_file(sls_file, "ping-delay-event", &event->tv, 0, 0, root);
		write_syslog(syslog_enabled, "ping-delay-event", &event->tv, 0, 0, root);
		break;
	default:
		break;
	}
	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, ping_delay_extract, NULL);
}

static void do_dump(void)
{
	static char variant_buf[1 * 1024 * 1024];
	int len;
	int ret = 0;

	memset(variant_buf, 0, 1 * 1024 * 1024);
	ret = -ENOSYS;
	syscall(DIAG_PING_DELAY_DUMP, &ret, &len, variant_buf, 1 * 1024 * 1024);
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

	while (1) {
		syscall(DIAG_PING_DELAY_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}
}

int ping_delay_main(int argc, char **argv)
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
		 usage_ping_delay();
		 return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_ping_delay();
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
			usage_ping_delay();
			break;
		}
	}

	return 0;
}
