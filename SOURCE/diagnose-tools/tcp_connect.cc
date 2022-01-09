/*
 * Linux内核诊断工具--用户态tcp-connect功能实现
 *
 * Copyright (C) 2022 Alibaba Ltd.
 *
 * 作者: Yang Wei <albin.yangwei@linux.alibaba.com>
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <iostream>
#include <fstream>

#include "internal.h"
#include "symbol.h"
#include "uapi/tcp_connect.h"
#include "params_parse.h"
#include "params_parse.h"

using namespace std;

static int tcp_connect_ignore = 0;
static char sls_file[256];
static int syslog_enabled;

void usage_tcp_connect(void)
{
	printf("    tcp-connect usage:\n");
	printf("        --help tcp-connect help info\n");
	printf("        --activate\n");
	printf("          verbose VERBOSE\n");
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
	struct diag_tcp_connect_settings settings;
	string str;

	memset(&settings, 0, sizeof(struct diag_tcp_connect_settings));
	
	settings.verbose = parse.int_value("verbose");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_TCP_CONNECT_SET, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_TCP_CONNECT_SET, &ret, &settings, sizeof(struct diag_tcp_connect_settings));
	}

	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    输出级别：%d\n", settings.verbose);

	if (ret)
		return;

	ret = diag_activate("tcp-connect");
	if (ret == 1) {
		printf("tcp-connect activated\n");
	} else {
		printf("tcp-connect is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("tcp-connect");
	if (ret == 0) {
		printf("tcp-connect is not activated\n");
	} else {
		printf("deactivate tcp-connect fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_tcp_connect_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["verbose"] = Json::Value(settings->verbose);
	} else {
		root["err"] = Json::Value("found tcp-connect settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_tcp_connect_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	memset(&settings, 0, sizeof(struct diag_tcp_connect_settings));
	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_TCP_CONNECT_SETTINGS, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_TCP_CONNECT_SETTINGS, &ret, &settings, sizeof(struct diag_tcp_connect_settings));
	}

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    输出级别：%d\n", settings.verbose);
	} else {
		printf("获取tcp-connect设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int tcp_connect_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct tcp_connect_detail *detail;
	struct in_addr addr;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_tcp_connect_detail:
		if (len < sizeof(struct tcp_connect_detail))
			break;
		detail = (struct tcp_connect_detail *)buf;
		printf("CGROUP:[%s] comm:%s 时间:[%lu:%lu]\n", detail->cgroup, detail->comm,
			detail->tv.tv_sec, detail->tv.tv_usec);
  		printf("type:%d\n", detail->con_type);
		addr.s_addr = detail->laddr;
 		printf("laddr:%s lport:%d\n", inet_ntoa(addr), detail->lport);
		addr.s_addr = detail->raddr;
		printf("raddr:%s rport:%d\n", inet_ntoa(addr), detail->rport);
		printf("\n");
		break;
	default:
		break;
	}

	return 0;
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct tcp_connect_detail *detail;
	struct in_addr addr;
	struct diag_timespec tv;
	Json::Value root;
	stringstream ss;

	if (len == 0)
		return 0;

	diag_gettimeofday(&tv, NULL);
	et_type = (int *)buf;
	switch (*et_type) {
	case et_tcp_connect_detail:
		if (len < sizeof(struct tcp_connect_detail))
			break;
		detail = (struct tcp_connect_detail *)buf;
		root["type"] = Json::Value(detail->con_type);
		root["time"] = Json::Value(detail->tv.tv_sec);
		addr.s_addr = detail->laddr;
		root["laddr"] = Json::Value(inet_ntoa(addr));
		root["lport"] = Json::Value(detail->lport);
		addr.s_addr = detail->raddr;
		root["raddr"] = Json::Value(inet_ntoa(addr));
		root["rport"] = Json::Value(detail->rport);
		root["comm"] = Json::Value(detail->comm);
		root["cgroup"] = Json::Value(detail->cgroup);

		write_file(sls_file, "tcp-connect", &tv, 0, 0, root);
		write_syslog(syslog_enabled, "tcp-connect", &tv, 0, 0, root);
		break;
	default:
		break;
	}

	return 0;
}
static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, tcp_connect_extract, NULL);
}

static void do_dump(const char *arg)
{
	static char variant_buf[1024 * 1024];
	int len;
	int ret = 0;
	struct params_parser parse(arg);
	tcp_connect_ignore = parse.int_value("ignore");
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 1024 * 1024,
		.user_buf = variant_buf,
	};

	memset(variant_buf, 0, 1024 * 1024);
	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_TCP_CONNECT_SET_DUMP, (long)&dump_param);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_TCP_CONNECT_DUMP, &ret, &len, variant_buf, 1024 * 1024);
	}

	if (ret == 0) {
		do_extract(variant_buf, len);
	}

	tcp_connect_ignore = 0;
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
			ret = diag_call_ioctl(DIAG_IOCTL_TCP_CONNECT_SET_DUMP, (long)&dump_param);
		} else {
			syscall(DIAG_TCP_CONNECT_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		}

		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}
}

int tcp_connect_main(int argc, char **argv)
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
		usage_tcp_connect();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_tcp_connect();
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
			usage_tcp_connect();
			break;
		}
	}

	return 0;
}
