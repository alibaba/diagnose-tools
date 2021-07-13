/*
 * Linux内核诊断工具--用户态drop-packet功能实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 * 作者: Wllabs <wllabs@163.com>
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
#include <map>
#include <sys/time.h>

#include "internal.h"
#include "symbol.h"
#include "uapi/net_bandwidth.h"
#include "params_parse.h"

using namespace std;
static volatile unsigned cached_lines = 0;

class bandwidth_info
{
public:
	int et_type;
	int protocol;
	int saddr;
	int sport;
	int daddr;
	int dport;
	unsigned long packages[NET_COUNT];
	unsigned long sum_truesize[NET_COUNT];
};
typedef std::map<string, bandwidth_info> BANDWIDTH_MAP;
BANDWIDTH_MAP bandwidth_map;

int fd_lines(int fd) {
	struct winsize ws = {};

	if (ioctl(fd, TIOCGWINSZ, &ws) < 0)
		return -errno;

	if (ws.ws_row <= 0)
		return -EIO;

	return ws.ws_row;
}

unsigned lines(void) {
	const char *e;
	int l;

	if (cached_lines > 0)
		return cached_lines;

	l = 0;
	e = getenv("LINES");
	if (e)
		l = atoi(e);

	if (l <= 0)
		l = fd_lines(STDOUT_FILENO);

	if (l <= 0)
		l = 24;

	cached_lines = l;
	return cached_lines;
}

void usage_net_bandwidth(void)
{
	printf("    net-bandwidth usage:\n");
	printf("        --help net-bandwidth help info\n");
	printf("        --activate\n");
	printf("          verbose VERBOSE\n");
	printf("        --deactivate\n");
	printf("        --report dump log with text.\n");
	printf("          sort SORT\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_net_bandwidth_settings settings;
	string str;

	memset(&settings, 0, sizeof(struct diag_net_bandwidth_settings));

	settings.verbose = parse.int_value("verbose");

#if 0
	str = parse.string_value("comm");
	if (str.length() > 0) {
		strncpy(settings.comm, str.c_str(), TASK_COMM_LEN);
		settings.comm[TASK_COMM_LEN - 1] = 0;
	}
#endif

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_NET_BANDWIDTH_SET, (long)&settings);
	} else {
		syscall(DIAG_NET_BANDWIDTH_SET, &ret, &settings, sizeof(struct diag_net_bandwidth_settings));
	}

	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    输出级别：%d\n", settings.verbose);

	if (ret)
		return;

	ret = diag_activate("net-bandwidth");
	if (ret == 1) {
		printf("net-bandwidth activated\n");
	} else {
		printf("net-bandwidth is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("net-bandwidth");
	if (ret == 0) {
		printf("net-bandwidth is not activated\n");
	} else {
		printf("deactivate net-bandwidth fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_net_bandwidth_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["verbose"] = Json::Value(settings->verbose);
	} else {
		root["err"] = Json::Value("found net-bandwidth settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_net_bandwidth_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_NET_BANDWIDTH_SETTINGS, (long)&settings);
	} else {
		syscall(DIAG_NET_BANDWIDTH_SETTINGS, &ret, &settings, sizeof(struct diag_net_bandwidth_settings));
	}

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    输出级别：%d\n", settings.verbose);
	} else {
		printf("获取net-bandwidth设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int is_activated()
{
	struct diag_net_bandwidth_settings settings;
	int ret;

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_NET_BANDWIDTH_SETTINGS, (long)&settings);
	} else {
		syscall(DIAG_NET_BANDWIDTH_SETTINGS, &ret, &settings, sizeof(struct diag_net_bandwidth_settings));
	}

	if (ret == 0) {
		if (settings.activated)
			return 1;
	} else {
		printf("获取net-bandwidth失败，请确保正确安装了diagnose-tools工具\n");
	}
	return 0;
}

static void get_hash_key(void *buf, char *key)
{
	struct net_bandwidth_detail *detail;
	unsigned char *saddr;
	unsigned char *daddr;

	detail = (struct net_bandwidth_detail *)buf;
	saddr = (unsigned char *)&detail->saddr;
	daddr = (unsigned char *)&detail->daddr;
	snprintf(key, 49, "%u.%u.%u.%u:%d-%u.%u.%u.%u:%d",
			saddr[0], saddr[1], saddr[2], saddr[3], detail->sport,
			daddr[0], daddr[1], daddr[2], daddr[3], detail->dport);
}

static int packet_net_info(void *buf, bandwidth_info *info)
{
	struct net_bandwidth_detail *detail;
	int i;

	detail = (struct net_bandwidth_detail *)buf;

	info->et_type = detail->protocol;
	info->saddr = detail->saddr;
	info->sport = detail->sport;
	info->daddr = detail->daddr;
	info->dport = detail->dport;
	for (i = 0; i < NET_COUNT; i++) {
		info->packages[i] = detail->packages[i];
		info->sum_truesize[i] = detail->sum_truesize[i];
	}

	return 0;
}

static void put_net_hash(void *buf)
{
	char key[50];

	get_hash_key(buf, key);

	struct bandwidth_info info;
	packet_net_info(buf, &info);

	bandwidth_map.insert(make_pair(key, info));
}

static int process_net_bandwidth(void *buf)
{
	put_net_hash(buf);
	return 0;
}

static int bandwidth_map_compare(const void *a, const void *b)
{
	bandwidth_info *info1 = *(bandwidth_info **)a;
	bandwidth_info *info2 = *(bandwidth_info **)b;

	return info2->sum_truesize[NET_RECV_SKB] + info2->sum_truesize[NET_SEND_SKB]
		- info1->sum_truesize[NET_RECV_SKB] - info1->sum_truesize[NET_SEND_SKB];
}

static int display()
{
	struct bandwidth_info **array;
	struct bandwidth_info *info;
	unsigned n = 0, j;
	unsigned char *saddr;
	unsigned char *daddr;
	char path[50];

	array = (struct bandwidth_info **)malloc(sizeof(struct bandwidth_info *) * bandwidth_map.size());

	BANDWIDTH_MAP::iterator it;
	for (it = bandwidth_map.begin(); it != bandwidth_map.end(); it++) {
		array[n++] = &it->second;
	}
	qsort(array, n, sizeof(struct bandwidth_info *), bandwidth_map_compare);

	printf("%s %46s %20s %20s\n\n", "协议", "路径", "入向带宽", "出向带宽");

	for (j = 0; j < n; j++) {
		info = array[j];

		saddr = (unsigned char *)&info->saddr;
		daddr = (unsigned char *)&info->daddr;
		snprintf(path, 50, "%u.%u.%u.%u:%d --> %u.%u.%u.%u:%d",
				 saddr[0], saddr[1], saddr[2], saddr[3], info->sport,
				 daddr[0], daddr[1], daddr[2], daddr[3], info->dport);

		printf("%s %45s",
			    info->protocol == DIAG_IPPROTO_UDP ? "UDP" : "TCP",
				path);

		printf(" %10lu / %10lu", info->packages[NET_RECV_SKB], info->sum_truesize[NET_RECV_SKB]);
		printf(" %10lu / %10lu", info->packages[NET_SEND_SKB], info->sum_truesize[NET_SEND_SKB]);

		printf("\n");
	}
	free(array);
	bandwidth_map.erase(bandwidth_map.begin(), bandwidth_map.end());
	return 0;
}

static int net_bandwidth_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	symbol sym;
	elf_file file;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_net_bandwidth_detail:
		if (len < sizeof(struct net_bandwidth_detail))
			break;
		process_net_bandwidth(buf);
		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, net_bandwidth_extract, NULL);
}

static void do_dump(const char *arg)
{
	static char variant_buf[10 * 1024 * 1024];
	int len;
	int ret = 0;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 10 * 1024 * 1024,
		.user_buf = variant_buf,
	};

	ret = is_activated();
	if (ret <=0 ) {
		printf("请先激活net-bandwidth工具\n");
		return;
	}

	memset(variant_buf, 0, 10 * 1024 * 1024);
	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_NET_BANDWIDTH_DUMP, (long)&dump_param);
	} else {
		syscall(DIAG_NET_BANDWIDTH_DUMP, &ret, &len, variant_buf, 10 * 1024 * 1024);
	}
	if (ret == 0) {
		do_extract(variant_buf, len);
		display();
	}
}

int net_bandwidth_main(int argc, char **argv)
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
		usage_net_bandwidth();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_net_bandwidth();
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
		default:
			usage_net_bandwidth();
			break;
		}
	}

	return 0;
}
