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
static int cached_on_tty = -1;

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
	uint64_t fraction[NET_COUNT];
	uint64_t total_fraction;
	struct timespec net_timestamp;
};
typedef std::map<string, bandwidth_info> BANDWIDTH_MAP;
BANDWIDTH_MAP bandwidth_map;

struct timespec last_ts = {0, 0}, now_ts = {0, 0};

static enum {
        ORDER_TOTAL,
        ORDER_IN,
        ORDER_OUT,
} arg_order = ORDER_TOTAL;

bool on_tty(void) {
	if (cached_on_tty < 0)
		cached_on_tty = isatty(STDOUT_FILENO) > 0;

	return cached_on_tty;
}

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

char *format_bytes(char *buf, size_t l, off_t t) {
        unsigned i, length;

        static const struct {
                const char *suffix;
                off_t factor;
        } table[] = {
                { "E", 1024ULL*1024ULL*1024ULL*1024ULL*1024ULL*1024ULL },
                { "P", 1024ULL*1024ULL*1024ULL*1024ULL*1024ULL },
                { "T", 1024ULL*1024ULL*1024ULL*1024ULL },
                { "G", 1024ULL*1024ULL*1024ULL },
                { "M", 1024ULL*1024ULL },
                { "K", 1024ULL },
        };

        if (t == (off_t) -1)
                return NULL;

        length = sizeof(table)/sizeof((table))[0];
        for (i = 0; i < length; i++) {

                if (t >= table[i].factor) {
                        snprintf(buf, l,
                                 "%llu.%llu%s",
                                 (unsigned long long) (t / table[i].factor),
                                 (unsigned long long) (((t*10ULL) / table[i].factor) % 10ULL),
                                 table[i].suffix);

                        goto finish;
                }
        }

        snprintf(buf, l, "%lluB", (unsigned long long) t);

finish:
        buf[l-1] = 0;
        return buf;

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

static int packet_net_info(void *buf, bandwidth_info *info, struct timespec ts)
{
	struct net_bandwidth_detail *detail;
	int i;
	uint64_t x;
	uint64_t total_fraction = 0.0;

	detail = (struct net_bandwidth_detail *)buf;

	info->et_type = detail->protocol;
	info->saddr = detail->saddr;
	info->sport = detail->sport;
	info->daddr = detail->daddr;
	info->dport = detail->dport;
	for (i = 0; i < NET_COUNT; i++) {
		info->packages[i] = detail->packages[i];
		info->sum_truesize[i] = detail->sum_truesize[i];
		info->fraction[i] = 0;
		if (last_ts.tv_sec > 0) {
			x = ((uint64_t) now_ts.tv_sec * 1000000000ULL + (uint64_t) now_ts.tv_nsec) -
					((uint64_t) last_ts.tv_sec * 1000000000ULL + (uint64_t) last_ts.tv_nsec);
			info->fraction[i] =  info->sum_truesize[i] * 1000000000ULL / x;
			total_fraction += info->fraction[i];
		}
	}
	info->total_fraction = total_fraction;

	info->net_timestamp = ts;
	return 0;
}

static void put_net_hash(void *buf, struct timespec ts)
{
	char key[50];

	get_hash_key(buf, key);

	struct bandwidth_info info;
	packet_net_info(buf, &info, ts);

	bandwidth_map.insert(make_pair(key, info));
}

static int process_net_bandwidth(void *buf)
{
	put_net_hash(buf, now_ts);
	return 0;

	/*
	struct net_bandwidth_detail *detail;
	unsigned char *saddr;
	unsigned char *daddr;

	saddr = (unsigned char *)&detail->saddr;
	daddr = (unsigned char *)&detail->daddr;
	printf("协议类型：%s, 源IP：%u.%u.%u.%u, 源端口：%d, "
			"目的IP：%u.%u.%u.%u, 目的端口：%d\n",
			detail->protocol == DIAG_IPPROTO_UDP ? "UDP" : "TCP",
			saddr[0], saddr[1], saddr[2], saddr[3], detail->sport,
			daddr[0], daddr[1], daddr[2], daddr[3], detail->dport);

	if (last_ts.tv_sec > 0) {
		printf("    %10s 入向带宽(KB/s): %12f \n", "", fraction0);
		printf("    %10s 出向带宽(KB/s): %12f \n", "", fraction1);
	} else {
		printf("    %10s 入向带宽(KB/s): %12s \n", "", "-");
		printf("    %10s 出向带宽(KB/s): %12s \n", "", "-");
	}

	return 0;
	*/
}

static int bandwidth_map_compare(const void *a, const void *b)
{
	bandwidth_info *info1 = (bandwidth_info *)a;
	bandwidth_info *info2 = (bandwidth_info *)b;

	if (arg_order == ORDER_TOTAL) {
		return info2->total_fraction - info1->total_fraction;
	} else if (arg_order == ORDER_IN) {
		return info2->fraction[0] - info1->fraction[0];
	} else if (arg_order == ORDER_OUT) {
		return info2->fraction[1] - info1->fraction[1];
	} else {
		return info2->total_fraction - info1->total_fraction;
	}
}

static int display()
{
	struct bandwidth_info **array;
	struct bandwidth_info *info;
	unsigned rows, n = 0, j;
	unsigned char *saddr;
	unsigned char *daddr;
	char path[50];
	char buffer[10];

	array = (struct bandwidth_info **)malloc(sizeof(struct bandwidth_info) * bandwidth_map.size());

	BANDWIDTH_MAP::iterator it;
	for (it = bandwidth_map.begin(); it != bandwidth_map.end(); it++) {
		array[n++] = &it->second;
	}

	qsort(array, n, sizeof(struct bandwidth_info), bandwidth_map_compare);

	rows = lines();
	if (rows <= 10)
		rows = 10;

	printf("%s %46s %16s %16s\n\n", "协议", "路径", "入向带宽", "出向带宽");

	for (j = 0; j < n; j++) {
		if (on_tty() && j + 3 > rows)
			break;

		info = array[j];

		saddr = (unsigned char *)&info->saddr;
		daddr = (unsigned char *)&info->daddr;
		snprintf(path, 50, "%u.%u.%u.%u:%d --> %u.%u.%u.%u:%d",
				 saddr[0], saddr[1], saddr[2], saddr[3], info->sport,
				 daddr[0], daddr[1], daddr[2], daddr[3], info->dport);

		printf("%s %45s",
			    info->protocol == DIAG_IPPROTO_UDP ? "UDP" : "TCP",
				path);

		if (last_ts.tv_sec > 0) {
			printf(" %10s/S",
					format_bytes(buffer, sizeof(buffer), info->fraction[0]));
			printf(" %10s/S",
					format_bytes(buffer, sizeof(buffer), info->fraction[1]));
		} else {
			printf("           -             -");
		}
		printf("\n");
	}

	last_ts = now_ts;
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
	if (on_tty())
		fputs("\033[H"
				"\033[2J", stdout);
	clock_gettime(CLOCK_MONOTONIC, &now_ts);

	extract_variant_buffer(buf, len, net_bandwidth_extract, NULL);
}

static void do_dump(const char *arg)
{
	static char variant_buf[1024 * 1024];
	int len, testcount, i = 0;
	int ret = 0;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 1024 * 1024,
		.user_buf = variant_buf,
	};

	struct params_parser parse(arg);
	string str = parse.string_value("sort");
	if (str.length() > 0) {
		if ( strcmp(str.c_str(), "in") == 0) {
			arg_order = ORDER_IN;
		} else if ( strcmp(str.c_str(), "out") == 0) {
			arg_order = ORDER_OUT;
		}
	}
	testcount = parse.int_value("testcount");
	if (testcount > 0) {
		cached_on_tty = 0;
	}

	ret = is_activated();
	if (ret <=0 ) {
		printf("请先激活net-bandwidth工具\n");
		return;
	}

	while(true) {
		memset(variant_buf, 0, 1024 * 1024);
		if (run_in_host) {
			ret = diag_call_ioctl(DIAG_IOCTL_NET_BANDWIDTH_DUMP, (long)&dump_param);
		} else {
			syscall(DIAG_NET_BANDWIDTH_DUMP, &ret, &len, variant_buf, 10 * 1024 * 1024);
		}
		if (ret == 0) {
			do_extract(variant_buf, len);
			display();
		}
		sleep(1);
		if ( testcount > 0 && ++i >= testcount)
			break;
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
