/*
 * Linux内核诊断工具--用户态uprobe功能实现
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

#include <set>

#include "internal.h"
#include "symbol.h"
#include "json/json.h"
#include <iostream>
#include <fstream>
#include <fcntl.h>

#include "uapi/uprobe.h"
#include "params_parse.h"
#include "unwind.h"

using namespace std;

static char sls_file[256];
static int syslog_enabled;

void usage_uprobe(void)
{
	printf("    uprobe usage:\n");
	printf("        --help uprobe help info\n");
	printf("        --activate launch file and offset\n");
	printf("          verbose VERBOSE\n");
	printf("          tgid process group that monitored\n");
	printf("          pid thread id that monitored\n");
	printf("          comm comm that monitored\n");
	printf("          cpu cpu-list that monitored\n");
	printf("        --deactivate\n");
	printf("        --settings dump settings\n");
	printf("        --report dump log with text.\n");
	printf("        --log\n");
	printf("          sls=/tmp/1.log store in file\n");
	printf("          syslog=1 store in syslog\n");
	printf("        --params set params info.\n");
}

static void do_activate(const char *arg)
{
	struct params_parser parse(arg);
	int offset;
	int fd;
	int ret;
	struct diag_uprobe_settings settings;
	string str;
	string param_name;

	memset(&settings, 0, sizeof(struct diag_uprobe_settings));

	str = parse.string_value("file");
	offset = parse.int_value("offset");
	if (str.length() <= 0 || offset <= 0) {
		printf("file or offset param missed\n");
		return;
	}

	fd = open(str.c_str(), O_RDONLY, 0);

	if(fd < 0) {
		printf("can not open %s\n", str.c_str());
		return;
	}

	settings.fd = fd;
	settings.offset = offset;
	settings.verbose = parse.int_value("verbose");
	settings.tgid = parse.int_value("tgid");
	settings.verbose = parse.int_value("verbose");
	settings.sample_step = parse.int_value("sample-step");
	
	str = parse.string_value("comm");
	if (str.length() > 0) {
		strncpy(settings.comm, str.c_str(), TASK_COMM_LEN);
		settings.comm[TASK_COMM_LEN - 1] = 0;
	}
	str = parse.string_value("cpu");
	if (str.length() > 0) {
		strncpy(settings.cpus, str.c_str(), 255);
		settings.cpus[254] = 0;
	}

	param_name = parse.string_value("param1-name");
	memcpy(settings.params[0].param_name, param_name.c_str(), 255);
	settings.params[0].param_idx = parse.int_value("param1-index");
	settings.params[0].type = parse.int_value("param1-type");
	settings.params[0].size = parse.int_value("param1-size");

	param_name = parse.string_value("param2-name");
	memcpy(settings.params[1].param_name, param_name.c_str(), 255);
	settings.params[1].param_idx = parse.int_value("param2-index");
	settings.params[1].type = parse.int_value("param2-type");
	settings.params[1].size = parse.int_value("param3-size");

	param_name = parse.string_value("param3-name");
	memcpy(settings.params[2].param_name, param_name.c_str(), 255);
	settings.params[2].param_idx = parse.int_value("param3-index");
	settings.params[2].type = parse.int_value("param3-type");
	settings.params[2].size = parse.int_value("param3-size");

	param_name = parse.string_value("param4-name");
	memcpy(settings.params[3].param_name, param_name.c_str(), 255);
	settings.params[3].param_idx = parse.int_value("param4-index");
	settings.params[3].type = parse.int_value("param4-type");
	settings.params[3].size = parse.int_value("param4-size");

	param_name = parse.string_value("param5-name");
	memcpy(settings.params[4].param_name, param_name.c_str(), 255);
	settings.params[4].param_idx = parse.int_value("param5-index");
	settings.params[4].type = parse.int_value("param5-type");
	settings.params[4].size = parse.int_value("param5-size");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_UPROBE_SET,(long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_UPROBE_SET, &ret, &settings, sizeof(struct diag_uprobe_settings));
	}

	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    进程ID：%d\n", settings.tgid);
	printf("    线程ID：%d\n", settings.pid);
	printf("    进程名称：%s\n", settings.comm);
	printf("    CPUS：%s\n", settings.cpus);
	printf("    输出级别：%d\n", settings.verbose);
	printf("    文件名：%s\n", settings.file_name);
	printf("    偏移：%d\n", settings.offset);
	printf("    参数1：%s\n", settings.params[0].param_name);
	printf("    参数2：%s\n", settings.params[1].param_name);
	printf("    参数3：%s\n", settings.params[2].param_name);
	printf("    参数4：%s\n", settings.params[3].param_name);
	printf("    参数5：%s\n", settings.params[4].param_name);
	if (ret)
		return;

	ret = diag_activate("uprobe");
	if (ret == 1) {
		printf("uprobe activated\n");
	} else {
		printf("uprobe is not activated, ret %d\n", ret);
	}

	close(fd);
}

static void do_deactivate(void)
{
	int ret = 0;
	
	ret = diag_deactivate("uprobe");
	if (ret == 0) {
		printf("uprobe is not activated\n");
	} else {
		printf("deactivate uprobe fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_uprobe_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["tgid"] = Json::Value(settings->tgid);
		root["pid"] = Json::Value(settings->pid);
		root["comm"] = Json::Value(settings->comm);
		root["CPUS"] = Json::Value(settings->cpus);
		root["verbose"] = Json::Value(settings->verbose);
		root["file_name"] = Json::Value(settings->file_name);
		root["offset"] = Json::Value(settings->offset);
	} else {
		root["err"] = Json::Value("found uprobe settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_uprobe_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	memset(&settings, 0, sizeof(struct diag_uprobe_settings));
	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_UPROBE_SETTINGS, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_UPROBE_SETTINGS, &ret, &settings, sizeof(struct diag_uprobe_settings));
	}

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    进程ID：%d\n", settings.tgid);
		printf("    线程ID：%d\n", settings.pid);
		printf("    进程名称：%s\n", settings.comm);
		printf("    CPUS：%s\n", settings.cpus);
		printf("    输出级别：%d\n", settings.verbose);
		printf("    文件名：%s\n", settings.file_name);
		printf("    偏移：%d\n", settings.offset);
		printf("    参数1：%s\n", settings.params[0].param_name);
		printf("    参数2：%s\n", settings.params[1].param_name);
		printf("    参数3：%s\n", settings.params[2].param_name);
		printf("    参数4：%s\n", settings.params[3].param_name);
		printf("    参数5：%s\n", settings.params[4].param_name);
	} else {
		printf("获取uprobe设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static void printf_params(struct diag_uprobe_param_value *values)
{
	int i;

	for (i = 0; i < DIAG_UPROBE_MAX_PARAMS; i++) {
		switch (values[i].type) {
		case 1:
			printf("    Params %d, value: %lu\n", i + 1, values[i].int_value);
			break;
		case 2:
			printf("    Params %d, value: %s[%lu]\n", i + 1, values[i].buf.data, values[i].buf.len);
			break;
		case 3:
			printf("    Params %d, value: %s[%lu]\n", i + 1, values[i].buf.data, values[i].buf.len);
			break;
		default:
			break;
		}
	}
}

static int uprobe_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct uprobe_detail *detail;
	struct uprobe_raw_stack_detail *raw_detail;
    symbol sym;
    elf_file file;
	static int seq = 0;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_uprobe_detail:
		if (len < sizeof(struct uprobe_detail))
			break;
		detail = (struct uprobe_detail *)buf;

		printf("UPROBE命中：PID： %d[%s]，时间：[%lu:%lu]\n",
			detail->task.pid, detail->task.comm,
			detail->tv.tv_sec, detail->tv.tv_usec);

		seq++;
		printf("##CGROUP:[%s]  %d      [%03d]  UPROBE命中，时间：[%lu:%lu]\n",
				detail->task.cgroup_buf,
				detail->task.pid,
				seq,
				detail->tv.tv_sec, detail->tv.tv_usec);
#if 1
		diag_printf_user_stack(detail->task.tgid,
				detail->task.container_tgid,
				detail->task.comm,
				&detail->user_stack, 0);
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

		printf_params(detail->values);

		break;
	case et_uprobe_raw_detail:
		if (len < sizeof(struct uprobe_raw_stack_detail))
			break;
		raw_detail = (struct uprobe_raw_stack_detail *)buf;

		printf("UPROBE命中：PID： %d[%s]，时间：[%lu:%lu]\n",
			raw_detail->task.pid, raw_detail->task.comm,
			raw_detail->tv.tv_sec, raw_detail->tv.tv_usec);

		seq++;
		printf("##CGROUP:[%s]  %d      [%03d]  UPROBE命中，时间：[%lu:%lu]\n",
				raw_detail->task.cgroup_buf,
				raw_detail->task.pid,
				seq,
				raw_detail->tv.tv_usec, raw_detail->tv.tv_usec);
#if 0
		diag_printf_user_stack(raw_detail->task.tgid,
				raw_detail->task.container_tgid,
				raw_detail->task.comm,
				&raw_detail->user_stack, 0);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				raw_detail->task.comm);
#else
		diag_printf_raw_stack(raw_detail->task.tgid,
				raw_detail->task.container_tgid,
				raw_detail->task.comm,
				&raw_detail->raw_stack);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				raw_detail->task.comm);
#endif
		diag_printf_proc_chains(&raw_detail->proc_chains);
		printf("##\n");

		printf_params(raw_detail->values);

		break;
	default:
		break;
	}
	return 0;
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct uprobe_detail *detail;
	struct uprobe_raw_stack_detail *raw_detail;
	Json::Value root;
	Json::Value task;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_uprobe_detail:
		if (len < sizeof(struct uprobe_detail))
			break;
		detail = (struct uprobe_detail *)buf;
		diag_sls_time(&detail->tv, root);
		diag_sls_task(&detail->task, task);
		diag_sls_user_stack(detail->task.tgid,
			detail->task.container_tgid,
			detail->task.comm,
			&detail->user_stack, task);
		diag_sls_proc_chains(&detail->proc_chains, task);
		root["task"] = task;

		write_file(sls_file, "uprobe-detail", &detail->tv, 0, 0, root);
		write_syslog(syslog_enabled, "uprobe-detail", &detail->tv, 0, 0, root);
		break;
	case et_uprobe_raw_detail:
		if (len < sizeof(struct uprobe_raw_stack_detail))
			break;
		raw_detail = (struct uprobe_raw_stack_detail *)buf;
		diag_sls_time(&raw_detail->tv, root);
		diag_sls_task(&raw_detail->task, task);
#if 0
		diag_sls_user_stack(raw_detail->task.tgid,
			raw_detail->task.container_tgid,
			raw_detail->task.comm,
			&raw_detail->user_stack, task);
#endif
		diag_sls_proc_chains(&raw_detail->proc_chains, task);
		root["task"] = task;

		write_file(sls_file, "uprobe-raw-detail", &raw_detail->tv, 0, 0, root);
		write_syslog(syslog_enabled, "uprobe-raw-detail", &raw_detail->tv, 0, 0, root);
		break;
	default:
		break;
	}
	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, uprobe_extract, NULL);
}

static void do_dump(void)
{
	static char variant_buf[40 * 1024 * 1024];
	int len;
	int ret = 0;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 40 * 1024 * 1024,
		.user_buf = variant_buf,
	};

	memset(variant_buf, 0, 40* 1024 * 1024);
	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_UPROBE_DUMP,(long)&dump_param);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_UPROBE_DUMP, &ret, &len, variant_buf, 40 * 1024 * 1024);
	}

	if (ret == 0 && len > 0) {
		do_extract(variant_buf, len);
	}
}

static void do_sls(char *arg)
{
	int ret;
	int len;
	static char variant_buf[40 * 1024 * 1024];
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 40 * 1024 * 1024,
		.user_buf = variant_buf,
	};

	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	while (1) {
		if (run_in_host) {
			ret = diag_call_ioctl(DIAG_IOCTL_UPROBE_DUMP,(long)&dump_param);
		} else {
			syscall(DIAG_UPROBE_DUMP, &ret, &len, variant_buf, 40 * 1024 * 1024);
		}

		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}

}

extern "C" {
	static __attribute__ ((noinline)) unsigned long diag_uprobe_test_4(int param1,
		char param2, const char *str, const char *buf, int len)
	{
		printf("xby-debug in diag_uprobe_test, params is %d, %c, %s, %s, %d\n",
			param1, param2, str, buf, len);

		sleep(2);
		return 0;
	}

	static __attribute__ ((noinline))  void diag_uprobe_test_3(int param1,
		char param2, const char *str, const char *buf, int len)
	{
		diag_uprobe_test_4(param1, param2, str, buf, len);
		printf("xby-debug in diag_uprobe_test_3\n");
	}

	static __attribute__ ((noinline))  void diag_uprobe_test_2(int param1,
		char param2, const char *str, const char *buf, int len)
	{
		diag_uprobe_test_3(param1, param2, str, buf, len);
		printf("xby-debug in diag_uprobe_test_2\n");
	}

	static __attribute__ ((noinline))  void diag_uprobe_test_1(int param1,
		char param2, const char *str, const char *buf, int len)
	{
		printf("xby-debug in diag_uprobe_test_1\n");
		diag_uprobe_test_2(param1, param2, str, buf, len);
		sleep(1);
	}
}

static void do_test(const char *arg)
{
	struct params_parser parse(arg);
	string str;
	string buf;
	unsigned long param1;
	unsigned long param2;
	unsigned long len;

	str = parse.string_value("str");
	buf = parse.string_value("buf");
	len = buf.length();
	param1 = parse.int_value("param1");
	param2 = parse.int_value("param2");
	diag_uprobe_test_1(param1, param2, str.c_str(), buf.c_str(), len);
}

int uprobe_main(int argc, char **argv)
{
	static struct option long_options[] = {
			{"help",     no_argument, 0,  0 },
			{"activate",     optional_argument, 0,  0 },
			{"deactivate", no_argument,       0,  0 },
			{"settings",     optional_argument, 0,  0 },
			{"report",     no_argument, 0,  0 },
			{"log",     required_argument, 0,  0 },
			{"test",     required_argument, 0,  0 },
			{0,         0,                 0,  0 }
		};
	int c;

	if (argc <= 1) {
		 usage_uprobe();
		 return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_uprobe();
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
		case 6:
			do_test(optarg);
			break;
		default:
			usage_uprobe();
			break;
		}
	}

	return 0;
}
