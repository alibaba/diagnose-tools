/*
 * Linux内核诊断工具--用户态memcg-stats功能实现
 *
 * Copyright (C) 2021 Alibaba Ltd.
 *
 * 作者: Wen Yang <simon.wy@alibaba-inc.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <errno.h>
#include <getopt.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "internal.h"
#include "params_parse.h"
#include "symbol.h"
#include "uapi/memcg_stats.h"

using namespace std;

static char sls_file[256];
static int syslog_enabled;

#define VAR_BUF_LEN (5 * 1024 *1024)

void usage_memcg_stats(void)
{
	printf("    memcg-stats usage:\n");
	printf("        --help memcg-stats help info\n");
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
	struct diag_memcg_stats_settings settings;
	string str;

	memset(&settings, 0, sizeof(struct diag_memcg_stats_settings));

	settings.verbose = parse.int_value("verbose");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_MEMCG_STATS_SET, (long)&settings);
	} else
		ret = -ENOSYS;

	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    输出级别：%d\n", settings.verbose);
	if (ret)
		return;

	ret = diag_activate("memcg-stats");
	if (ret == 1) {
		printf("memcg-stats activated\n");
	} else {
		printf("memcg-stats is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("memcg-stats");
	if (ret == 0) {
		printf("memcg-stats is not activated\n");
	} else {
		printf("deactivate memcg-stats fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_memcg_stats_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["verbose"] = Json::Value(settings->verbose);
	} else {
		root["err"] = Json::Value("found memcg-stats settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_memcg_stats_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_MEMCG_STATS_SETTINGS, (long)&settings);
	} else {
		ret = -ENOSYS;
	}

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    输出级别：%d\n", settings.verbose);
	} else {
		printf("获取memcg-stats设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

#define MINORBITS   20
#define MINORMASK   ((1U << MINORBITS) - 1)

#define MAJOR(dev)  ((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)  ((unsigned int) ((dev) & MINORMASK))

static int memcg_stats_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct diag_memcg_stats_summary *summary;
	struct diag_memcg_stats_detail *detail;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_memcg_stats_summary:
		if (len < sizeof(struct diag_memcg_stats_summary))
			break;
		summary = (struct diag_memcg_stats_summary *)buf;
		if (debug_mode) {
			printf("\nMEMCG:\nmemcg: %p flag: %lu dying: %u pages: %u name: %s\n",
					(void *)summary->addr,
					summary->flags,
					summary->dying,
					summary->pages,
					summary->name);
		} else {
			printf("\nMEMCG: \nflag: %lu dying: %u pages: %u name: %s\n",
					summary->flags,
					summary->dying,
					summary->pages,
					summary->name);
		}
		break;

	case et_memcg_stats_detail:
		if (len < sizeof(struct diag_memcg_stats_detail))
			break;
		detail = (struct diag_memcg_stats_detail *)buf;
		if (debug_mode) {
			printf("memcg: %p inode: %p major: %u minor: %u ino: %lu pages: %u mnt: %s name: %s\n",
					(void *)detail->cg_addr,
					(void *)detail->key,
					MAJOR(detail->dev),
					MINOR(detail->dev),
					detail->ino,
					detail->pages,
					detail->mnt_dir,
					detail->name);
		} else {
			printf("major: %u minor: %u ino: %lu pages: %u mnt: %s name: %s\n",
					MAJOR(detail->dev),
					MINOR(detail->dev),
					detail->ino,
					detail->pages,
					detail->mnt_dir,
					detail->name);
		}
		break;

	default:
		break;
	}

	return 0;
}

static void do_dump(void)
{
	static char variant_buf[VAR_BUF_LEN];
	int len;
	int ret = 0;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = VAR_BUF_LEN,
		.user_buf = variant_buf,
	};

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_MEMCG_STATS_DUMP, (long)&dump_param);
	} else {
		ret = -ENOSYS;
	}

	if (ret == 0 && len > 0) {
		extract_variant_buffer(variant_buf, len, memcg_stats_extract, NULL);
	}
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct diag_memcg_stats_summary *summary;
	struct diag_memcg_stats_detail *detail;
	struct diag_timespec tv;
	Json::Value root;
	stringstream ss;

	if (len == 0)
		return 0;

	diag_gettimeofday(&tv, NULL);
	et_type = (int *)buf;
	switch (*et_type) {
	case et_memcg_stats_summary:
		if (len < sizeof(*summary))
			break;
		summary = (struct diag_memcg_stats_summary *)buf;
		root["flags"] = Json::Value(summary->flags);
		root["dying"] = Json::Value(summary->dying);
		root["pages"] = Json::Value(summary->pages);
		root["name"] = Json::Value(summary->name);

		write_file(sls_file, "memcg-stats-summary", &tv, 0, 0, root);
		write_syslog(syslog_enabled,"memcg-stats-summary", &tv, 0, 0, root);
		break;
	case et_memcg_stats_detail:
		if (len < sizeof(*detail))
			break;
		detail = (struct diag_memcg_stats_detail *)buf;
		root["major"] = Json::Value(MAJOR(detail->dev));
		root["minor"] = Json::Value(MINOR(detail->dev));
		root["ino"] = Json::Value(detail->ino);
		root["pages"] = Json::Value(detail->pages);
		root["name"] = Json::Value(detail->name);

		write_file(sls_file, "memcg-stats-detail", &tv, 0, 0, root);
		write_syslog(syslog_enabled,"memcg-stats-detail", &tv, 0, 0, root);
		break;

	default:
		break;
	}

	return 0;
}

static void do_sls(char *arg)
{
	static char variant_buf[VAR_BUF_LEN];
	int len;
	int ret = 0;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = VAR_BUF_LEN,
		.user_buf = variant_buf,
	};

	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	while (1) {
		if (run_in_host) {
			ret = diag_call_ioctl(DIAG_IOCTL_MEMCG_STATS_DUMP, (long)&dump_param);
		} else {
			ret = -ENOSYS;
		}

		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}
}

int memcg_stats_main(int argc, char **argv)
{
	static struct option long_options[] = {
			{"help",       no_argument,       0,  0 },
			{"activate",   optional_argument, 0,  0 },
			{"deactivate", no_argument,       0,  0 },
			{"settings",   optional_argument, 0,  0 },
			{"report",     no_argument,       0,  0 },
			{"log",        required_argument, 0,  0 },
			{0,            0,                 0,  0 }
		};
	int c;

	if (argc <= 1) {
		usage_memcg_stats();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_memcg_stats();
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
			usage_memcg_stats();
			break;
		}
	}

	return 0;
}

