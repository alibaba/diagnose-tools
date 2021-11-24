/*
 * Linux内核诊断工具--用户态fs-orphan功能实现
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
#include "uapi/fs_orphan.h"
#include "params_parse.h"

using namespace std;

static char sls_file[256];
static int syslog_enabled;
static struct diag_timespec sls_tv;
static unsigned long sls_id;

void usage_fs_orphan(void)
{
	printf("    fs-orphan usage:\n");
	printf("        --help fs-orphan help info\n");
	printf("        --activate\n");
	printf("          verbose VERBOSE\n");
	printf("          dev devname that monitored, for instance dba\n");
	printf("        --deactivate\n");
	printf("        --settings print settings.\n");
	printf("        --report dump log with text.\n");
	printf("        --log\n");
	printf("          sls=/tmp/1.log store in file\n");
	printf("          syslog=1 store in syslog\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_fs_orphan_settings settings;
	string str;

	memset(&settings, 0, sizeof(struct diag_fs_orphan_settings));
	
	settings.verbose = parse.int_value("verbose");

	str = parse.string_value("dev");
	if (str.length() > 0) {
		strncpy(settings.devname, str.c_str(), 255);
		settings.devname[254] = 0;
	}

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_FS_ORPHAN_SET, (long)&settings);
	} else {
		syscall(DIAG_FS_ORPHAN_SET, &ret, &settings, sizeof(struct diag_fs_orphan_settings));
	}

	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    输出级别：%d\n", settings.verbose);
	printf("    DEV：%s\n", settings.devname);
	if (ret)
		return;

	ret = diag_activate("fs-orphan");
	if (ret == 1) {
		printf("fs-orphan activated\n");
	} else {
		printf("fs-orphan is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	printf("deactivate fs-orphan\n");
	diag_deactivate("fs-orphan");
}

static void print_settings_in_json(struct diag_fs_orphan_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["verbose"] = Json::Value(settings->verbose);
		root["DEV"] = Json::Value(settings->devname);
	} else {
		root["err"] = Json::Value("found fs-orphan settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_fs_orphan_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_FS_ORPHAN_SETTINGS, (long)&settings);
	} else {
		syscall(DIAG_FS_ORPHAN_SETTINGS, &ret, &settings, sizeof(struct diag_fs_orphan_settings));
	}

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    输出级别：%d\n", settings.verbose);
		printf("    DEV：%s\n", settings.devname);
	} else {
		printf("获取fs-orphan设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int fs_orphan_extract(void *buf, unsigned int len, void *unused)
{
	int *et_type;
	struct fs_orphan_detail *detail;
	struct fs_orphan_summary *summary;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_fs_orphan_summary:
		if (len < sizeof(struct fs_orphan_summary))
			break;
		summary = (struct fs_orphan_summary *)buf;

		printf("孤儿节点：\n");
		diag_printf_inode(&summary->inode);
		break;
	case et_fs_orphan_detail:
		if (len < sizeof(struct fs_orphan_detail))
			break;
		detail = (struct fs_orphan_detail *)buf;

		printf("进程孤儿节点：[%s]\n", detail->path_name);
		diag_printf_inode(&detail->inode);
		diag_printf_task(&detail->task);
		diag_printf_proc_chains(&detail->proc_chains);
		break;
	default:
		break;
	}

	return 0;
}

static int sls_extract(void *buf, unsigned int len, void *unused)
{
	int *et_type;
	struct fs_orphan_detail *detail;
	struct fs_orphan_summary *summary;
	Json::Value root;
	Json::Value inode;
	Json::Value tsk;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_fs_orphan_summary:
		if (len < sizeof(struct fs_orphan_summary))
			break;
		summary = (struct fs_orphan_summary *)buf;
		diag_sls_inode(&summary->inode, inode);
		root["inode"] = inode;

		write_file(sls_file, "fs-orphan-summary", &sls_tv, sls_id, 0, root);
		write_syslog(syslog_enabled,"fs-orphan-summary", &sls_tv, sls_id, 0, root);
		break;
	case et_fs_orphan_detail:
		if (len < sizeof(struct fs_orphan_detail))
			break;
		detail = (struct fs_orphan_detail *)buf;

		root["filename"] = Json::Value(detail->path_name);

		diag_sls_inode(&detail->inode, inode);
		root["inode"] = inode;

		diag_sls_task(&detail->task, tsk);
		diag_sls_proc_chains(&detail->proc_chains, tsk);
		root["task"] = tsk;

		write_file(sls_file, "fs-orphan-detail", &sls_tv, sls_id, 0, root);
		write_syslog(syslog_enabled,"fs-orphan-detail", &sls_tv, sls_id, 0, root);
		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, fs_orphan_extract, NULL);
}

static void do_dump(void)
{
	static char variant_buf[10 * 1024 * 1024];
	int len;
	int ret = 0;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 10 * 1024 * 1024,
		.user_buf = variant_buf,
	};

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_FS_ORPHAN_DUMP, (long)&dump_param);
	} else {
		syscall(DIAG_FS_ORPHAN_DUMP, &ret, &len, variant_buf, 10 * 1024 * 1024);
	}

	if (ret == 0) {
		do_extract(variant_buf, len);
	}
}

static void do_sls(char *arg)
{
	static char variant_buf[10 * 1024 * 1024];
	int len;
	int ret = 0;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 10 * 1024 * 1024,
		.user_buf = variant_buf,
	};

	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_FS_ORPHAN_DUMP, (long)&dump_param);
	} else {
		syscall(DIAG_FS_ORPHAN_DUMP, &ret, &len, variant_buf, 10 * 1024 * 1024);
	}

	if (ret == 0 && len > 0) {
		diag_gettimeofday(&sls_tv, NULL);
		sls_id = sls_tv.tv_sec;
		extract_variant_buffer(variant_buf, len, sls_extract, NULL);
	}
}

int fs_orphan_main(int argc, char **argv)
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
		usage_fs_orphan();
		return 0;
	}

	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_fs_orphan();
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
			usage_fs_orphan();
			break;
		}
	}

	return 0;
}

