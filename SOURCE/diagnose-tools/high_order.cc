/*
 * Linux内核诊断工具--用户态high-order功能实现
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
#include "uapi/high_order.h"
#include "params_parse.h"

static char sls_file[256];
static int syslog_enabled;

void usage_high_order(void)
{
	printf("    high-order usage:\n");
	printf("        --help high-order help info\n");
	printf("        --activate\n");
	printf("          verbose VERBOSE\n");
	printf("          order threshold value\n");
	printf("        --deactivate\n");
	printf("        --settins dump settings with text.\n");
	printf("        --report dump log with text.\n");
	printf("        --test testcase for high-order.\n");
	printf("        --log\n");
	printf("          sls=/tmp/1.log store in file\n");
	printf("          syslog=1 store in syslog\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_high_order_settings settings;

	memset(&settings, 0, sizeof(struct diag_high_order_settings));
	
	settings.order = parse.int_value("order");
	if (settings.order <= 0)
		settings.order = 3;
	settings.verbose = parse.int_value("verbose");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_HIGH_ORDER_SET, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_HIGH_ORDER_SET, &ret, &settings, sizeof(struct diag_high_order_settings));
	}

	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    ORDER：%d\n", settings.order);
	printf("    输出级别：%d\n", settings.verbose);

	if (ret)
		return;

	ret = diag_activate("high-order");
	if (ret == 1) {
		printf("high-order activated\n");
	} else {
		printf("high-order is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("high-order");
	if (ret == 0) {
		printf("high-order is not activated\n");
	} else {
		printf("deactivate high-order fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_high_order_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["ORDER"] = Json::Value(settings->order);
		root["verbose"] = Json::Value(settings->verbose);
	} else {
		root["err"] = Json::Value("found high-order settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_high_order_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_HIGH_ORDER_SETTINGS, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_HIGH_ORDER_SETTINGS, &ret, &settings, sizeof(struct diag_high_order_settings));
	}

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    ORDER：%d\n", settings.order);
		printf("    输出级别：%d\n", settings.verbose);
	} else {
		printf("获取high-order设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int high_order_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct high_order_detail *detail;
	symbol sym;
	elf_file file;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_high_order_detail:
		if (len < sizeof(struct high_order_detail))
			break;
		detail = (struct high_order_detail *)buf;
		printf("##CGROUP:[%s]  %d      [%03lu]  采样命中[%u]\n",
				detail->task.cgroup_buf,
				detail->task.pid,
				detail->seq,
				detail->order);
		diag_printf_kern_stack(&detail->kern_stack);
		diag_printf_user_stack(detail->task.tgid,
				detail->task.container_tgid,
				detail->task.comm,
				&detail->user_stack, 0);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				detail->task.comm);
		diag_printf_proc_chains(&detail->proc_chains);
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
	struct high_order_detail *detail;
	Json::Value root;
	Json::Value task;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_high_order_detail:
		if (len < sizeof(struct high_order_detail))
			break;
		detail = (struct high_order_detail *)buf;

		root["order"] = Json::Value(detail->order); 
		root["seq"] = Json::Value(detail->seq); 
		diag_sls_time(&detail->tv, root);
		diag_sls_task(&detail->task, task);
		diag_sls_kern_stack(&detail->kern_stack, task);
		diag_sls_user_stack(detail->task.tgid,
			detail->task.container_tgid,
			detail->task.comm,
			&detail->user_stack, task, 0);
		diag_sls_proc_chains(&detail->proc_chains, task);
		root["task"] = task;
		write_file(sls_file, "high-order", &detail->tv, detail->id, detail->seq, root);
		write_syslog(syslog_enabled, "high-order", &detail->tv, detail->id, detail->seq, root);
		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, high_order_extract, NULL);
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
		ret = diag_call_ioctl(DIAG_IOCTL_HIGH_ORDER_DUMP, (long)&dump_param);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_HIGH_ORDER_DUMP, &ret, &len, variant_buf, 10 * 1024 * 1024);
	}

	if (ret == 0 ) {
		do_extract(variant_buf, len);
	}
}

static void do_test(void)
{
	int ret = 0;

	if (run_in_host) {
		diag_call_ioctl(DIAG_IOCTL_HIGH_ORDER_TEST, (long)&ret);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_HIGH_ORDER_TEST, &ret);
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
			ret = diag_call_ioctl(DIAG_IOCTL_HIGH_ORDER_DUMP, (long)&dump_param);
		} else {
			syscall(DIAG_HIGH_ORDER_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		}

		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}	

}

int high_order_main(int argc, char **argv)
{
	static struct option long_options[] = {
			{"help",     no_argument, 0,  0 },
			{"activate",     optional_argument, 0,  0 },
			{"deactivate", no_argument,       0,  0 },
			{"settings",     optional_argument, 0,  0 },
			{"report",     no_argument, 0,  0 },
			{"test",     no_argument, 0,  0 },
			{"log",     required_argument, 0,  0 },
			{0,         0,                 0,  0 }
		};
	int c;

	if (argc <= 1) {
		usage_high_order();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_high_order();
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
			do_test();
			break;
		case 6:
			do_sls(optarg);
			break;
		default:
			usage_high_order();
			break;
		}
	}

	return 0;
}
