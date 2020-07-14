/*
 * Linux内核诊断工具--用户态sys-delay功能实现
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
#include "json/json.h"
#include <iostream>
#include <fstream>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "params_parse.h"
#include "uapi/sys_delay.h"
#include "unwind.h"

using namespace std;

static char sls_file[256];
static int syslog_enabled;

void usage_sys_delay(void)
{
	printf("    sys-delay usage:\n");
	printf("        --help sys-delay help info\n");
	printf("        --activate\n");
	printf("            verbose VERBOSE\n");
	printf("            threshold THRESHOLD(MS)\n");
	printf("            style dump style: 0 - common, 1 - process chains\n");
	printf("        --deactivate\n");
	printf("        --settings print settings.\n");
	printf("        --report dump log with text.\n");
	printf("        --test loop in sys for 100ms, so triger this monitor.\n");
	printf("        --log  format:\"sls=1.log[,syslog=1]\" to store in file or syslog.\n");
}

static void do_activate(const char *arg)
{
	int fd;
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_sys_delay_settings settings;

	memset(&settings, 0, sizeof(struct diag_sys_delay_settings));
	
	settings.verbose = parse.int_value("verbose");
	settings.style = parse.int_value("style");
	settings.threshold_ms = parse.int_value("threshold");
	if (settings.threshold_ms <= 0)
		settings.threshold_ms = 50;

	fd = open("/dev/diagnose-tools", O_RDWR, 0);
	if (fd < 0) {
		printf("open /dev/diagnose-tools error!\n");
		return;
	}

	ret = ioctl(fd, DIAG_IOCTL_SYS_DELAY_SET, &settings);
	if (ret < 0) {
		printf("call cmd DIAG_IOCTL_SYS_DELAY_SET fail\n");
		goto err;
	}
	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    阀值(ms)：\t%d\n", settings.threshold_ms);
	printf("    输出级别：\t%d\n", settings.verbose);
	printf("    STYLE：\t%d\n", settings.style);

	ret = diag_activate("sys-delay");
	if (ret == 1) {
		printf("sys-delay activated\n");
	} else {
		printf("sys-delay is not activated, ret %d\n", ret);
	}

err:
	close(fd);
}

static void do_deactivate(void)
{
	int ret = 0;
	
	ret = diag_deactivate("sys-delay");
	if (ret == 0) {
		printf("sys-delay is not activated\n");
	} else {
		printf("deactivate sys-delay fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_sys_delay_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;
	stringstream ss;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["threshold_ms"] = Json::Value(settings->threshold_ms);
		root["verbose"] = Json::Value(settings->verbose);
		root["STYLE"] = Json::Value(settings->style);
	} else {
		ss << "found sys-delay settings failed, errcode[";
		ss << ret;
		ss << "], please check if diagnose-tools is installed correctly or not.";
		root["err"] = Json::Value(ss.str());
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	int fd;
	struct diag_sys_delay_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	fd = open("/dev/diagnose-tools", O_RDWR, 0);
	if (fd < 0) {
		printf("open /dev/diagnose-tools error!\n");
		return;
	}

	ret = ioctl(fd, DIAG_IOCTL_SYS_DELAY_SETTINGS, &settings);
	if (ret < 0) {
		printf("call cmd DIAG_IOCTL_SYS_DELAY_SETTINGS fail\n");
		goto err;
	}

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：\t%s\n", settings.activated ? "√" : "×");
		printf("    阀值(ms)：\t%d\n", settings.threshold_ms);
		printf("    输出级别：\t%d\n", settings.verbose);
		printf("    STYLE：\t%d\n", settings.style);
	} else {
		printf("获取sys-delay设置失败[%d]，请确保正确安装了diagnose-tools工具\n", ret);
	}

err:
	close(fd);
}

static int sys_delay_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct sys_delay_detail *detail;
    symbol sym;
    elf_file file;
	static int seq;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_sys_delay_detail:
		if (len < sizeof(struct sys_delay_detail))
			break;
		detail = (struct sys_delay_detail *)buf;
		printf("抢占关闭, 时长： %lu(ms).\n",
			detail->delay_ns / 1000 / 1000);

		diag_printf_time(&detail->tv);
		diag_printf_task(&detail->task);
		seq++;
		printf("##CGROUP:[%s]  %d      [%03d]  采样命中\n",
				detail->task.cgroup_buf,
				detail->task.pid,
				seq);
		diag_printf_kern_stack(&detail->kern_stack);
#if 0
		diag_printf_user_stack(detail->task.tgid,
				detail->task.container_tgid,
				detail->task.comm,
				&detail->user_stack);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				detail->task.comm);
#else
		diag_printf_raw_stack(detail->task.tgid,
				detail->task.container_tgid,
				detail->task.comm,
				&detail->raw_stack);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				detail->task.comm);
#endif
		diag_printf_proc_chains(&detail->proc_chains);
		printf("##\n");

		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, sys_delay_extract, NULL);
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
	int fd;

	fd = open("/dev/diagnose-tools", O_RDWR, 0);
	if (fd < 0) {
		printf("open /dev/diagnose-tools error!\n");
		return;
	}

	ret = ioctl(fd, DIAG_IOCTL_SYS_DELAY_DUMP, &dump_param);
	if (ret < 0) {
		printf("call cmd DIAG_IOCTL_SYS_DELAY_DUMP fail\n");
		goto err;
	}

	if (ret == 0 && len > 0) {
		do_extract(variant_buf, len);
	}

err:
	close(fd);
}

static void do_test(void)
{
	int ret = 0;
	int fd;
	int ms = 100;

	fd = open("/dev/diagnose-tools", O_RDWR, 0);
	if (fd < 0) {
		printf("open /dev/diagnose-tools error!\n");
		return;
	}

	ret = ioctl(fd, DIAG_IOCTL_SYS_DELAY_TEST, &ms);
	if (ret < 0) {
		printf("call cmd DIAG_IOCTL_SYS_DELAY_TEST fail\n");
		goto err;
	}

err:
	close(fd);
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct sys_delay_detail *detail;
    symbol sym;
	
	Json::Value root;
	Json::Value task;
	Json::Value kern_stack;
	Json::Value user_stack;
	Json::Value proc_chains;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_sys_delay_detail:
		if (len < sizeof(struct sys_delay_detail))
			break;
		detail = (struct sys_delay_detail *)buf;
		root["delay_ns"] = Json::Value(detail->delay_ns);
		diag_sls_time(&detail->tv, root);
		diag_sls_task(&detail->task, task);
		diag_sls_kern_stack(&detail->kern_stack, task);
		diag_sls_user_stack(detail->task.tgid,
			detail->task.container_tgid,
			detail->task.comm,
			&detail->user_stack, task);
		diag_sls_proc_chains(&detail->proc_chains, task);
		root["task"] = task;

		write_file(sls_file, "sys-delay", &detail->tv, 0, 0, root);
		write_syslog(syslog_enabled, "sys-delay", &detail->tv, 0, 0, root);

		break;
	default:
		break;
	}

	return 0;
}

static void do_sls(char *arg)
{
	int ret;
	static char variant_buf[1024 * 1024];
	int len;
	int jiffies_sls = 0;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &ret,
		.user_buf_len = 1024 * 1024,
		.user_buf = variant_buf,
	};
	int fd;

	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	java_attach_once();
	while (1) {
		fd = open("/dev/diagnose-tools", O_RDWR, 0);
		if (fd < 0) {
			printf("open /dev/diagnose-tools error!\n");
			goto cont;
		}

		ret = ioctl(fd, DIAG_IOCTL_SYS_DELAY_DUMP, &dump_param);
		if (ret < 0) {
			printf("call cmd DIAG_IOCTL_SYS_DELAY_DUMP fail\n");
			goto err;
		}

		if (ret == 0 && len > 0) {
			/**
			 * 10 min
			 */
			if (jiffies_sls >= 60) {
				jiffies_sls = 0;
				clear_symbol_info(pid_cmdline, g_symbol_parser.get_java_procs(), 1);
				java_attach_once();
			}

			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

err:
		close(fd);
cont:
		sleep(10);
		jiffies_sls++;
	}
}

int sys_delay_main(int argc, char **argv)
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
		usage_sys_delay();
		return 0;
	}

	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_sys_delay();
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
			usage_sys_delay();
			break;
		}
	}

	return 0;
}

