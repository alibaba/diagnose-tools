/*
 * Linux内核诊断工具--用户态rw-top功能实现
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
#include "uapi/rw_top.h"
#include "params_parse.h"

using namespace std;

static char sls_file[256];
static int syslog_enabled;

void usage_rw_top(void)
{
	printf("    rw-top usage:\n");
	printf("        --help rw-top help info\n");
	printf("        --activate\n");
	printf("          verbose VERBOSE\n");
	printf("          top how many items to dump\n");
	printf("          shm set 1 if want dump shm\n");
	printf("          perf set 1 if want perf detail\n");
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
	struct diag_rw_top_settings settings;

	memset(&settings, 0, sizeof(struct diag_rw_top_settings));
	
	settings.verbose = parse.int_value("verbose");
	settings.shm = parse.int_value("shm");
	settings.top = parse.int_value("top");
	settings.perf = parse.int_value("perf");

	ret = diag_call_ioctl(DIAG_IOCTL_RW_TOP_SET, (long)&settings);
	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    TOP：%d\n", settings.top);
	printf("    SHM：%d\n", settings.shm);
	printf("    PERF：%d\n", settings.perf);
	printf("    输出级别：%d\n", settings.verbose);

	if (ret)
		return;

	ret = diag_activate("rw-top");
	if (ret == 1) {
		printf("rw-top activated\n");
	} else {
		printf("rw-top is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("rw-top");
	if (ret == 0) {
		printf("rw-top is not activated\n");
	} else {
		printf("deactivate rw-top fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_rw_top_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["TOP"] = Json::Value(settings->top);
		root["SHM"] = Json::Value(settings->shm);
		root["PERF"] = Json::Value(settings->perf);
		root["verbose"] = Json::Value(settings->verbose);
	} else {
		root["err"] = Json::Value("found rw-top settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_rw_top_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	ret = diag_call_ioctl(DIAG_IOCTL_RW_TOP_SETTINGS, (long)&settings);

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    TOP：%d\n", settings.top);
		printf("    SHM：%d\n", settings.shm);
		printf("    PERF：%d\n", settings.perf);
		printf("    输出级别：%d\n", settings.verbose);
	} else {
		printf("获取rw-top设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int rw_top_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct rw_top_detail *detail;
	struct rw_top_perf *perf;

	if (len == 0)
		return 0;

	printf("  序号           R-SIZE            W-SIZE          MAP-SIZE           RW-SIZE        文件名\n");
	
	et_type = (int *)buf;
	switch (*et_type) {
	case et_rw_top_detail:
		if (len < sizeof(struct rw_top_detail))
			break;
		detail = (struct rw_top_detail *)buf;

		printf("%5d%18lu%18lu%18lu%18lu        %-100s\n",
			detail->seq,
			detail->r_size,
			detail->w_size,
			detail->map_size,
			detail->rw_size,
			detail->path_name);

		break;
	case et_rw_top_perf:
		if (len < sizeof(struct rw_top_perf))
			break;
		perf = (struct rw_top_perf *)buf;

		printf("##CGROUP:[%s]  %d      [%03d]  采样命中\n",
				perf->task.cgroup_buf,
				perf->task.pid,
				0);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				perf->path_name);
		diag_printf_kern_stack(&perf->kern_stack);
		diag_printf_user_stack(perf->task.tgid,
				perf->task.container_tgid,
				perf->task.comm,
				&perf->user_stack, 0);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				perf->task.comm);
		diag_printf_proc_chains(&perf->proc_chains);
		printf("##\n");
	default:
		break;
	}

	return 0;
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct rw_top_detail *detail;
	Json::Value root;
	struct timeval tv;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_rw_top_detail:
		if (len < sizeof(struct rw_top_detail))
			break;
		detail = (struct rw_top_detail *)buf;
		root["seq"] = Json::Value(detail->seq);
		root["r_size"] = Json::Value(detail->r_size);
		root["w_size"] = Json::Value(detail->w_size);
		root["map_size"] = Json::Value(detail->map_size);
		root["rw_size"] = Json::Value(detail->rw_size);
		root["path_name"] = Json::Value(detail->path_name);

		gettimeofday(&tv, NULL);
		write_file(sls_file, "rw-top", &tv, detail->id, detail->seq, root);
		write_syslog(syslog_enabled, "rw-top", &tv, detail->id, detail->seq, root);

		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, rw_top_extract, NULL);
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

	ret = diag_call_ioctl(DIAG_IOCTL_RW_TOP_DUMP, (long)&dump_param);
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
		ret = diag_call_ioctl(DIAG_IOCTL_RW_TOP_DUMP, (long)&dump_param);
		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}	

}

int rw_top_main(int argc, char **argv)
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
		usage_rw_top();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_rw_top();
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
			usage_rw_top();
			break;
		}
	}

	return 0;
}
