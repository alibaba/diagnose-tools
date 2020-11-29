/*
 * Linux内核诊断工具--用户态fs-cache功能实现
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
#include "uapi/fs_cache.h"
#include "params_parse.h"

using namespace std;

static char sls_file[256];
static int syslog_enabled;

void usage_fs_cache(void)
{
	printf("    fs-cache usage:\n");
	printf("        --help fs-cache help info\n");
	printf("        --activate\n");
	printf("          verbose VERBOSE\n");
	printf("          top how many items to dump\n");
	printf("          size filter size\n");
	printf("        --deactivate\n");
	printf("        --report dump log with text.\n");
	printf("        --drop invalid file cache\n");
	printf("        --log\n");
	printf("          sls=/tmp/1.log store in file\n");
	printf("          syslog=1 store in syslog\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_fs_cache_settings settings;

	memset(&settings, 0, sizeof(struct diag_fs_cache_settings));
	
	settings.verbose = parse.int_value("verbose");
	settings.top = parse.int_value("top");
	settings.size = parse.int_value("size");
	if (settings.top <= 0)
		settings.top = 100;

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_FS_CACHE_SET, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_FS_CACHE_SET, &ret, &settings, sizeof(struct diag_fs_cache_settings));
	}

	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    TOP：%d\n", settings.top);
	printf("    输出级别：%d\n", settings.verbose);
	if (ret)
		return;

	ret = diag_activate("fs-cache");
	if (ret == 1) {
		printf("fs-cache activated\n");
	} else {
		printf("fs-cache is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("fs-cache");
	if (ret == 0) {
		printf("fs-cache is not activated\n");
	} else {
		printf("deactivate fs-cache fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_fs_cache_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["TOP"] = Json::Value(settings->top);
		root["verbose"] = Json::Value(settings->verbose);
	} else {
		root["err"] = Json::Value("found fs-cache settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_fs_cache_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_FS_CACHE_SETTINGS, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_FS_CACHE_SETTINGS, &ret, &settings, sizeof(struct diag_fs_cache_settings));
	}

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    TOP：%d\n", settings.top);
		printf("    输出级别：%d\n", settings.verbose);
	} else {
		printf("获取fs-cache设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int fs_cache_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct fs_cache_detail *detail;

	if (len == 0)
		return 0;
       
	et_type = (int *)buf;
	switch (*et_type) {
	case et_fs_cache_detail:
		if (len < sizeof(struct fs_cache_detail))
			break;
		detail = (struct fs_cache_detail *)buf;
		printf("%5d%18lu%18lu        %-20p[%lu]%-50s\n",
			detail->seq,
			detail->f_size,
			detail->cache_nr_pages,
			detail->f_inode,
			(unsigned long)detail->f_inode,
			detail->path_name);

		break;
	default:
		break;
	}

	return 0;
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct fs_cache_detail *detail;
	Json::Value root;
	struct timeval tv;
	char inode_buf[255];

	if (len == 0)
		return 0;
       
	et_type = (int *)buf;
	switch (*et_type) {
	case et_fs_cache_detail:
		if (len < sizeof(struct fs_cache_detail))
			break;
		detail = (struct fs_cache_detail *)buf;

		root["seq"] = Json::Value(detail->seq);
		root["f_size"] = Json::Value(detail->f_size);
		root["cache_nr_pages"] = Json::Value(detail->cache_nr_pages);
		snprintf(inode_buf, 255, "0x%016lx", (unsigned long)detail->f_inode);
		root["f_inode"] = Json::Value(inode_buf);
		root["path_name"] = Json::Value(detail->path_name);

		gettimeofday(&tv, NULL);
		write_file(sls_file, "fs-cache", &tv, detail->id, detail->seq, root);
		write_syslog(syslog_enabled, "fs-cache", &tv, detail->id, detail->seq, root);

		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, fs_cache_extract, NULL);
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
		ret = diag_call_ioctl(DIAG_IOCTL_FS_CACHE_DUMP, (long)&dump_param);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_FS_CACHE_DUMP, &ret, &len, variant_buf, 1024 * 1024);
	}

	if (ret == 0 && len > 0) {
		printf("文件缓存统计：\n");
		printf("  序号        FILE-SIZE        CACHE-PAGES       OBJECT                                    文件名\n");
		do_extract(variant_buf, len);
	}
}

static void do_drop(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	unsigned long inode;
	
	inode = parse.int_value("inode");
	if (inode <= 0) {
		printf("inode param missed\n");
		return;
	}

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_FS_CACHE_DROP, (long)&inode);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_FS_CACHE_DROP, &ret, inode);
	}

	if (ret)
		return;
	printf("fs-cache drop inode %lx, ret %d\n", inode, ret);
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
			ret = diag_call_ioctl(DIAG_IOCTL_FS_CACHE_DUMP, (long)&dump_param);
		} else {
			syscall(DIAG_FS_CACHE_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		}

		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}	

}

int fs_cache_main(int argc, char **argv)
{
	static struct option long_options[] = {
			{"help",     no_argument, 0,  0 },
			{"activate",     optional_argument, 0,  0 },
			{"deactivate", no_argument,       0,  0 },
			{"settings",     optional_argument, 0,  0 },
			{"report",     no_argument, 0,  0 },
			{"drop",     required_argument, 0,  0 },
			{"log",     required_argument, 0,  0 },
			{0,         0,                 0,  0 }
		};
	int c;
    
	if (argc <= 1) {
		usage_fs_cache();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_fs_cache();
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
			do_drop(optarg ? optarg : "");
			break;
		case 6:
			do_sls(optarg);
			break;
		default:
			usage_fs_cache();
			break;
		}
	}

	return 0;
}
