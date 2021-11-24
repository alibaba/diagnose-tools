/*
 * Linux内核诊断工具--用户态tcp-retrans功能实现
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

#include <iostream>
#include <fstream>

#include "internal.h"
#include "symbol.h"
#include "uapi/tcp_retrans.h"
#include "params_parse.h"
#include "params_parse.h"

using namespace std;

static int tcp_retrans_ignore = 0;
static char sls_file[256];
static int syslog_enabled;

void usage_tcp_retrans(void)
{
	printf("    tcp-retrans usage:\n");
	printf("        --help tcp-retrans help info\n");
	printf("        --activate\n");
	printf("          verbose VERBOSE\n");
	printf("          source-addr source addr you want monitor\n");
	printf("          source-port source port you want monitor\n");
	printf("          dest-addr dest addr you want monitor\n");
	printf("          dest-port dest port you want monitor\n");
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
	struct diag_tcp_retrans_settings settings;
	string str;

	memset(&settings, 0, sizeof(struct diag_tcp_retrans_settings));
	
	settings.verbose = parse.int_value("verbose");

#if 0
	str = parse.string_value("comm");
	if (str.length() > 0) {
		strncpy(settings.comm, str.c_str(), TASK_COMM_LEN);
		settings.comm[TASK_COMM_LEN - 1] = 0;
	}
#endif
	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_TCP_RETRANS_SET, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_TCP_RETRANS_SET, &ret, &settings, sizeof(struct diag_tcp_retrans_settings));
	}

	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    输出级别：%d\n", settings.verbose);

	if (ret)
		return;

	ret = diag_activate("tcp-retrans");
	if (ret == 1) {
		printf("tcp-retrans activated\n");
	} else {
		printf("tcp-retrans is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("tcp-retrans");
	if (ret == 0) {
		printf("tcp-retrans is not activated\n");
	} else {
		printf("deactivate tcp-retrans fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_tcp_retrans_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["verbose"] = Json::Value(settings->verbose);
	} else {
		root["err"] = Json::Value("found tcp-retrans settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_tcp_retrans_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	memset(&settings, 0, sizeof(struct diag_tcp_retrans_settings));
	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_TCP_RETRANS_SETTINGS, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_TCP_RETRANS_SETTINGS, &ret, &settings, sizeof(struct diag_tcp_retrans_settings));
	}

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    输出级别：%d\n", settings.verbose);
	} else {
		printf("获取tcp-retrans设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int tcp_retrans_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct tcp_retrans_summary *summary;
	struct tcp_retrans_detail *detail;
	struct tcp_retrans_trace *trace;
	unsigned char *src_addr;
	unsigned char *dest_addr;
	struct tm *tm;
	Json::Value root;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_tcp_retrans_summary:
		if (len < sizeof(struct tcp_retrans_summary))
			break;
		summary = (struct tcp_retrans_summary *)buf;
			printf("TCP重传调试统计：\n");
			printf("    分配次数：%lu\n", summary->alloc_count);
			printf("    tcp_retransmit_skb调用次数：%lu\n", summary->nr_tcp_retransmit_skb);
			printf("    tcp_rtx_synack调用次数：%lu\n", summary->nr_tcp_rtx_synack);
			printf("    tcp_dupack调用次数：%lu\n", summary->tcp_dupack);
			printf("    tcp_send_dupack调用次数：%lu\n", summary->tcp_send_dupack);	
		break;
	case et_tcp_retrans_detail:
		if (len < sizeof(struct tcp_retrans_detail))
			break;
		detail = (struct tcp_retrans_detail *)buf;
		src_addr = (unsigned char *)&detail->src_addr;
		dest_addr = (unsigned char *)&detail->dest_addr;
		if (detail->syncack_count >= tcp_retrans_ignore
			|| detail->skb_count >= tcp_retrans_ignore) {
			printf("    源地址： %u.%u.%u.%u[%d]， "
					"目的地址： %u.%u.%u.%u[%d]， SYNC重传次数: %d, 报文重传次数： %d\n",
				src_addr[0], src_addr[1], src_addr[2], src_addr[3], detail->src_port,
				dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3], detail->dest_port,
				detail->syncack_count,
				detail->skb_count);
		}
		break;
	case et_tcp_retrans_trace:
	if (len < sizeof(struct tcp_retrans_trace))
			break;
		trace = (struct tcp_retrans_trace *)buf;
		src_addr = (unsigned char *)&trace->src_addr;
		dest_addr = (unsigned char *)&trace->dest_addr;
		tm = localtime((time_t *)&trace->tv);
		printf("丢包记录[%04d-%02d-%02d %02d:%02d:%02d]， 源地址： %u.%u.%u.%u[%d]， "
					"目的地址： %u.%u.%u.%u[%d]， SYNC： %s\n",
				tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec,
				src_addr[0], src_addr[1], src_addr[2], src_addr[3], trace->src_port,
				dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3], trace->dest_port,
				trace->sync_or_skb ? "Y" : "N");
		break;
	default:
		break;
	}

	return 0;
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct tcp_retrans_summary *summary;
	struct tcp_retrans_detail *detail;
	struct tcp_retrans_trace *trace;
	unsigned char *src_addr;
	unsigned char *dest_addr;
	struct diag_timespec tv;
	Json::Value root;
	stringstream ss;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_tcp_retrans_summary:
		if (len < sizeof(struct tcp_retrans_summary))
			break;
		summary = (struct tcp_retrans_summary *)buf;

		root["alloc_count"] = Json::Value(summary->alloc_count);
		root["tcp_retransmit_skb"] = Json::Value(summary->nr_tcp_retransmit_skb);
		root["tcp_rtx_synack"] = Json::Value(summary->nr_tcp_rtx_synack);
		root["tcp_dupack"] = Json::Value(summary->tcp_dupack);
		root["tcp_send_dupack"] = Json::Value(summary->tcp_send_dupack);

		diag_gettimeofday(&tv, NULL);
		write_file(sls_file, "tcp-retrans-summary", &tv, 0, 0, root);
		write_syslog(syslog_enabled, "tcp-retrans-summary", &tv, 0, 0, root);

		break;
	case et_tcp_retrans_detail:
		if (len < sizeof(struct tcp_retrans_detail))
			break;
		detail = (struct tcp_retrans_detail *)buf;

		if (detail->syncack_count >= tcp_retrans_ignore
			|| detail->skb_count >= tcp_retrans_ignore) {

			src_addr = (unsigned char *)&detail->src_addr;
			ss.str("");
			ss << (unsigned int)(src_addr[0]) << "."; 
			ss << (unsigned int)(src_addr[1]) << ".";
			ss << (unsigned int)(src_addr[2]) << ".";
			ss << (unsigned int)(src_addr[3]);
			root["src_addr"] = Json::Value(ss.str());

			dest_addr = (unsigned char *)&detail->dest_addr;
			ss.str("");
			ss << (unsigned int)(dest_addr[0]) << "."; 
			ss << (unsigned int)(dest_addr[1]) << ".";
			ss << (unsigned int)(dest_addr[2]) << ".";
			ss << (unsigned int)(dest_addr[3]);
			root["dest_addr"] = Json::Value(ss.str());

			root["src_port"] = Json::Value(detail->src_port);
			root["dest_port"] = Json::Value(detail->dest_port);

			root["syncack_count"] = Json::Value(detail->syncack_count);
			root["skb_count"] = Json::Value(detail->skb_count);

			diag_gettimeofday(&tv, NULL);
			write_file(sls_file, "tcp-retrans-detail", &tv, 0, 0, root);
			write_syslog(syslog_enabled, "tcp-retrans-detail", &tv, 0, 0, root);
		}
		break;
	case et_tcp_retrans_trace:
	if (len < sizeof(struct tcp_retrans_trace))
			break;
		trace = (struct tcp_retrans_trace *)buf;
		src_addr = (unsigned char *)&trace->src_addr;
		ss.str("");
		ss << (unsigned int)(src_addr[0]) << "."; 
		ss << (unsigned int)(src_addr[1]) << ".";
		ss << (unsigned int)(src_addr[2]) << ".";
		ss << (unsigned int)(src_addr[3]);
		root["src_addr"] = Json::Value(ss.str());

		dest_addr = (unsigned char *)&trace->dest_addr;
		ss.str("");
		ss << (unsigned int)(dest_addr[0]) << "."; 
		ss << (unsigned int)(dest_addr[1]) << ".";
		ss << (unsigned int)(dest_addr[2]) << ".";
		ss << (unsigned int)(dest_addr[3]);
		root["dest_addr"] = Json::Value(ss.str());

		root["src_port"] = Json::Value(trace->src_port);
		root["dest_port"] = Json::Value(trace->dest_port);

		if (1 == trace->sync_or_skb) {
			root["sync_or_skb"] = Json::Value("Y");
		} else if (0 == trace->sync_or_skb) {
			root["sync_or_skb"] = Json::Value("N");
		}

		write_file(sls_file, "tcp-retrans-trace", &trace->tv, 0, 0, root);
		write_syslog(syslog_enabled, "tcp-retrans-trace", &trace->tv, 0, 0, root);
		break;
	default:
		break;
	}

	return 0;
}
static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, tcp_retrans_extract, NULL);
}

static void do_dump(const char *arg)
{
	static char variant_buf[1024 * 1024];
	int len;
	int ret = 0;
	struct params_parser parse(arg);
	tcp_retrans_ignore = parse.int_value("ignore");
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 1024 * 1024,
		.user_buf = variant_buf,
	};

	memset(variant_buf, 0, 1024 * 1024);
	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_TCP_RETRANS_SET_DUMP, (long)&dump_param);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_TCP_RETRANS_DUMP, &ret, &len, variant_buf, 1024 * 1024);
	}

	if (ret == 0) {
		do_extract(variant_buf, len);
	}

	tcp_retrans_ignore = 0;
}

static void do_sls(char *arg)
{
	int ret;
	int len;
	static char variant_buf[1024 * 1024];
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
			ret = diag_call_ioctl(DIAG_IOCTL_TCP_RETRANS_SET_DUMP, (long)&dump_param);
		} else {
			syscall(DIAG_TCP_RETRANS_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		}

		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}
}

int tcp_retrans_main(int argc, char **argv)
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
		usage_tcp_retrans();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_tcp_retrans();
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
			usage_tcp_retrans();
			break;
		}
	}

	return 0;
}
