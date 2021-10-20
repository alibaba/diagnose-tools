/*
 * Linux内核诊断工具--用户态sig-info功能实现
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

#include "internal.h"
#include "symbol.h"
#include "uapi/sig_info.h"
#include "params_parse.h"

using namespace std;
static char sls_file[256];
static int syslog_enabled;

void usage_sig_info(void)
{
	printf("    sig-info usage:\n");
	printf("        --help sig-info help info\n");
	printf("        --activate\n");
	printf("            tgid set pid of receive process if you want monitor specify pid\n");
	printf("            comm comm that monitored\n");
	printf("            signum set signal num you want to monitor(eg:9,15/9-18),or monitor all sig if signum is not set \n");
	printf("        --deactivate\n");
	printf("        --report dump log with text.\n");
	printf("          interval=1 loop second\n");
	printf("        --log\n");
	printf("          sls=/tmp/1.log store in file\n");
	printf("          syslog=1 store in syslog\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_sig_info_settings settings;
	string str;

	memset(&settings, 0, sizeof(struct diag_sig_info_settings));

	str = parse.string_value("comm");
	if (str.length() > 0) {
		strncpy(settings.comm, str.c_str(), TASK_COMM_LEN);
		settings.comm[TASK_COMM_LEN - 1] = 0;
	}

	settings.tgid = parse.int_value("tgid");
	str = parse.string_value("signum");
	if (str.length() > 0) {
		strncpy(settings.signum, str.c_str(), 255);
		settings.signum[255] = 0;
	}

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_SIG_INFO_SET, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_SIG_INFO_SET, &ret, &settings, sizeof(struct diag_sig_info_settings));
	}

	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    接收信号进程PID：\t%ld\n", settings.tgid);
	printf("    进程名称：\t%s\n", settings.comm);
	printf("    监控信号编号：\t%s\n", settings.signum);

	if (ret)
		return;

	ret = diag_activate("sig-info");
	if (ret == 1) {
		printf("sig-info activated\n");
	} else {
		printf("sig-info is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("sig-info");
	if (ret == 0) {
		printf("sig-info is not activated\n");
	} else {
		printf("deactivate sig-info fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_sig_info_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["tgid"] = Json::Value(settings->tgid);
		root["comm"] = Json::Value(settings->comm);
		root["signum"] = Json::Value(settings->signum);
	} else {
		root["err"] = Json::Value("found sig-info settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_sig_info_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_SIG_INFO_SETTINGS, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_SIG_INFO_SETTINGS, &ret, &settings, sizeof(struct diag_sig_info_settings));
	}

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    接收信号进程PID：%ld\n", settings.tgid);
		printf("    进程名称：\t%s\n", settings.comm);
		printf("    监控信号编号：\t%s\n", settings.signum);
	} else {
		printf("获取sig-info设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int sig_info_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct sig_info_detail *detail;
	int signum;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_sig_info_detail:
		if (len < sizeof(struct sig_info_detail))
			break;
		detail = (struct sig_info_detail *)buf;
		signum = detail->sig;
		
		printf("##CGROUP:[%s]  %d      [%03d]  采样命中\n",
				detail->task.cgroup_buf,
				detail->task.pid,
				0);
		diag_printf_kern_stack(&detail->kern_stack);
		diag_printf_user_stack(detail->task.tgid,
				detail->task.container_tgid,
				detail->task.comm,
				&detail->user_stack, 0);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				detail->task.comm);
		diag_printf_proc_chains(&detail->proc_chains);
		printf("#*        0xffffffffffffff SIG:%d (UNKNOWN)\n",
				signum);
				printf("#*        0xffffffffffffff TASK:[%s / %d / %d] (UNKNOWN)\n",
				detail->receive_task.comm,
				detail->task.tgid,
				detail->task.container_tgid
				);
		printf("#*        0xffffffffffffff CGROUP:[%s] (UNKNOWN)\n",
				detail->receive_task.cgroup_buf);
		printf("##\n");
		break;
	default:
		break;
	}

	return 0;
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct sig_info_detail *detail;
	struct diag_timespec tv;
	Json::Value root;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_sig_info_detail:
		if (len < sizeof(struct sig_info_detail))
			break;
		detail = (struct sig_info_detail *)buf;

		root["signum"] = Json::Value(detail->sig);

		/* to-do */
		diag_gettimeofday(&tv, NULL);
		write_file(sls_file, "sig-info", &tv, 0, 0, root);
		write_syslog(syslog_enabled, "sig-info", &tv, 0, 0, root);
		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, sig_info_extract, NULL);
}

static void do_dump(const char *arg)
{
	static char variant_buf[20 * 1024 * 1024];
	int len;
	int ret = 0;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 20 * 1024 * 1024,
		.user_buf = variant_buf,
	};

	memset(variant_buf, 0, 20 * 1024 * 1024);
	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_SIG_INFO_DUMP, (long)&dump_param);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_SIG_INFO_DUMP, &ret, &len, variant_buf, 20 * 1024 * 1024);
	}

	if (ret == 0) {
		do_extract(variant_buf, len);
	}
}

static void do_sls(char *arg)
{
	int ret;
	int len;
	static char variant_buf[20 * 1024 * 1024];
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 20 * 1024 * 1024,
		.user_buf = variant_buf,
	};

	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	while (1) {
		if (run_in_host) {
			ret = diag_call_ioctl(DIAG_IOCTL_SIG_INFO_DUMP, (long)&dump_param);
		} else {
			syscall(DIAG_SIG_INFO_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		}

		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}
}

int sig_info_main(int argc, char **argv)
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
		usage_sig_info();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_sig_info();
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
			usage_sig_info();
			break;
		}
	}

	return 0;
}
