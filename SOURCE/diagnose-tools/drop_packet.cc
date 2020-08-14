/*
 * Linux内核诊断工具--用户态drop-packet功能实现
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
#include "uapi/drop_packet.h"
#include "params_parse.h"

using namespace std;
static char sls_file[256];
static int syslog_enabled;

void usage_drop_packet(void)
{
	printf("    drop-packet usage:\n");
	printf("        --help drop-packet help info\n");
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
	struct diag_drop_packet_settings settings;
	string str;

	memset(&settings, 0, sizeof(struct diag_drop_packet_settings));

	settings.verbose = parse.int_value("verbose");

#if 0
	str = parse.string_value("comm");
	if (str.length() > 0) {
		strncpy(settings.comm, str.c_str(), TASK_COMM_LEN);
		settings.comm[TASK_COMM_LEN - 1] = 0;
	}
#endif

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_DROP_PACKET_SET, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_DROP_PACKET_SET, &ret, &settings, sizeof(struct diag_drop_packet_settings));
	}

	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    输出级别：%d\n", settings.verbose);

	if (ret)
		return;

	ret = diag_activate("drop-packet");
	if (ret == 1) {
		printf("drop-packet activated\n");
	} else {
		printf("drop-packet is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("drop-packet");
	if (ret == 0) {
		printf("drop-packet is not activated\n");
	} else {
		printf("deactivate drop-packet fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_drop_packet_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["verbose"] = Json::Value(settings->verbose);
	} else {
		root["err"] = Json::Value("found drop-packet settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_drop_packet_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_DROP_PACKET_SETTINGS, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_DROP_PACKET_SETTINGS, &ret, &settings, sizeof(struct diag_drop_packet_settings));
	}

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    输出级别：%d\n", settings.verbose);
	} else {
		printf("获取drop-packet设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int drop_packet_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct drop_packet_detail *detail;
    symbol sym;
    elf_file file;
	int i;
	unsigned char *saddr;
	unsigned char *daddr;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_drop_packet_detail:
		if (len < sizeof(struct drop_packet_detail))
			break;
		detail = (struct drop_packet_detail *)buf;
		saddr = (unsigned char *)&detail->saddr;
		daddr = (unsigned char *)&detail->daddr;
		printf("协议类型：%s, 源IP：%u.%u.%u.%u, 源端口：%d, "
				"目的IP：%u.%u.%u.%u, 目的端口：%d\n",
				detail->protocol == DIAG_IPPROTO_UDP ? "UDP" : "TCP",
				saddr[0], saddr[1], saddr[2], saddr[3], detail->sport,
				daddr[0], daddr[1], daddr[2], daddr[3], detail->dport);
		for (i = 0; i < TRACK_COUNT; i++) {
			printf("    %20s: pkg-count: %12lu, true-size: %12lu, len: %12lu, datalen: %12lu\n",
				packet_steps_str[i],
				detail->packages[i],
				detail->sum_truesize[i],
				detail->sum_len[i],
				detail->sum_datalen[i]
			);
		}

		break;
	default:
		break;
	}

	return 0;
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct drop_packet_detail *detail;
	int i;
	unsigned char *saddr;
	unsigned char *daddr;
	struct timeval tv;
	Json::Value root;
	Json::Value raw;
	stringstream ss;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_drop_packet_detail:
		if (len < sizeof(struct drop_packet_detail))
			break;
		detail = (struct drop_packet_detail *)buf;
		saddr = (unsigned char *)&detail->saddr;
		daddr = (unsigned char *)&detail->daddr;

		if (DIAG_IPPROTO_UDP == detail->protocol) {
			root["protocol"] = Json::Value("UDP");
		} else {
			root["protocol"] = Json::Value("TCP");
		}

		ss.str("");
		ss << (unsigned int)(saddr[0]) << "."; 
		ss << (unsigned int)(saddr[1]) << ".";
		ss << (unsigned int)(saddr[2]) << ".";
		ss << (unsigned int)(saddr[3]);
		root["src_addr"] = Json::Value(ss.str());

		ss.str("");
		ss << (unsigned int)(daddr[0]) << "."; 
		ss << (unsigned int)(daddr[1]) << ".";
		ss << (unsigned int)(daddr[2]) << ".";
		ss << (unsigned int)(daddr[3]);
		root["dest_addr"] = Json::Value(ss.str());

		root["src_port"] = Json::Value(detail->sport);
		root["dest_port"] = Json::Value(detail->dport);

		for (i = 0; i < TRACK_COUNT; i++) {
			raw["pkg-count"] = Json::Value(detail->packages[i]);
			raw["true-size"] = Json::Value(detail->sum_truesize[i]);
			raw["len"] = Json::Value(detail->sum_len[i]);
			raw["datalen"] = Json::Value(detail->sum_datalen[i]);

			root[packet_steps_str[i]] = raw;
		}

		gettimeofday(&tv, NULL);
		write_file(sls_file, "drop-packet", &tv, 0, 0, root);
		write_syslog(syslog_enabled, "drop-packet", &tv, 0, 0, root);
		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, drop_packet_extract, NULL);
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

	memset(variant_buf, 0, 1024 * 1024);
	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_DROP_PACKET_DUMP, (long)&dump_param);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_DROP_PACKET_DUMP, &ret, &len, variant_buf, 1024 * 1024);
	}

	if (ret == 0) {
		do_extract(variant_buf, len);
	}
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
			ret = diag_call_ioctl(DIAG_IOCTL_DROP_PACKET_DUMP, (long)&dump_param);
		} else {
			syscall(DIAG_DROP_PACKET_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		}

		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}
}

int drop_packet_main(int argc, char **argv)
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
		usage_drop_packet();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_drop_packet();
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
			usage_drop_packet();
			break;
		}
	}

	return 0;
}

