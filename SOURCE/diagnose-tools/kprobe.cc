/*
 * Linux内核诊断工具--用户态kprobe功能实现
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
#include "uapi/kprobe.h"
#include "unwind.h"
#include "params_parse.h"

using namespace std;

static char sls_file[256];
static int syslog_enabled;

void usage_kprobe(void)
{
	printf("    kprobe usage:\n");
	printf("        --help kprobe help info\n");
	printf("        --activate\n");
	printf("            verbose VERBOSE\n");
	printf("            tgid process group that monitored\n");
	printf("            pid thread id that monitored\n");
	printf("            comm comm that monitored\n");
	printf("            cpu cpu-list that monitored\n");
	printf("            raw-stack output raw stack\n");
	printf("            probe function that monitored\n");
	printf("        --deactivate\n");
	printf("        --report dump log with text.\n");
	printf("        --settings dump settings\n");
	printf("        --log\n");
	printf("          sls=/tmp/1.log store in file\n");
	printf("          syslog=1 store in syslog\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_kprobe_settings settings;
	string str;

	memset(&settings, 0, sizeof(struct diag_kprobe_settings));
	
	settings.verbose = parse.int_value("verbose");
	settings.tgid = parse.int_value("tgid");
	settings.pid = parse.int_value("pid");
	settings.dump_style = parse.int_value("dump-style");
	settings.raw_stack = parse.int_value("raw-stack");
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

	str = parse.string_value("probe");
	if (str.length() > 0) {
		strncpy(settings.func, str.c_str(), 255);
		settings.func[254] = 0;
	}

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_KPROBE_SET, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_KPROBE_SET, &ret, &settings, sizeof(struct diag_kprobe_settings));
	}

	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    进程ID：%d\n", settings.pid);
	printf("    线程ID：%d\n", settings.pid);
	printf("    进程名称：%s\n", settings.comm);
	printf("    函数名称：%s\n", settings.func);
	printf("    CPUS：%s\n", settings.cpus);
	printf("    RAW-STACK：%lu\n", settings.raw_stack);
	printf("    输出级别：%d\n", settings.verbose);

	if (ret)
		return;

	ret = diag_activate("kprobe");
	if (ret == 1) {
		printf("kprobe activated\n");
	} else {
		printf("kprobe is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;
	
	ret = diag_deactivate("kprobe");
	if (ret == 0) {
		printf("kprobe is not activated\n");
	} else {
		printf("deactivate kprobe fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_kprobe_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["tgid"] = Json::Value(settings->pid);
		root["pid"] = Json::Value(settings->pid);
		root["comm"] = Json::Value(settings->comm);
		root["func"] = Json::Value(settings->func);
		root["CPUS"] = Json::Value(settings->cpus);
		root["verbose"] = Json::Value(settings->verbose);
	} else {
		root["err"] = Json::Value("found kprobe settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_kprobe_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	memset(&settings, 0, sizeof(struct diag_kprobe_settings));
	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_KPROBE_SETTINGS, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_KPROBE_SETTINGS, &ret, &settings, sizeof(struct diag_kprobe_settings));
	}

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    进程ID：%d\n", settings.pid);
		printf("    线程ID：%d\n", settings.pid);
		printf("    进程名称：%s\n", settings.comm);
		printf("    函数名称：%s\n", settings.func);
		printf("    CPUS：%s\n", settings.cpus);
		printf("    RAW-STACK：%lu\n", settings.raw_stack);
		printf("    输出级别：%d\n", settings.verbose);
	} else {
		printf("获取kprobe设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int kprobe_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct kprobe_detail *detail;
	struct kprobe_raw_stack_detail *raw_detail;
    symbol sym;
    elf_file file;
	static int seq = 0;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_kprobe_detail:
		if (len < sizeof(struct kprobe_detail))
			break;
		detail = (struct kprobe_detail *)buf;

		printf("KPROBE命中：PID： %d[%s]，时间：[%lu:%lu]\n",
			detail->task.pid, detail->task.comm,
			detail->tv.tv_sec, detail->tv.tv_usec);

		seq++;
		printf("##CGROUP:[%s]  %d      [%03d]  KPROBE命中，时间：[%lu:%lu]\n",
				detail->task.cgroup_buf,
				detail->task.pid,
				seq,
				detail->tv.tv_sec, detail->tv.tv_usec);
		diag_printf_kern_stack(&detail->kern_stack);
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

		break;
	case et_kprobe_raw_detail:
		if (len < sizeof(struct kprobe_raw_stack_detail))
			break;
		raw_detail = (struct kprobe_raw_stack_detail *)buf;

		printf("KPROBE命中：PID： %d[%s]，时间：[%lu:%lu]\n",
			raw_detail->task.pid, raw_detail->task.comm,
			raw_detail->tv.tv_sec, raw_detail->tv.tv_usec);

		seq++;
		printf("##CGROUP:[%s]  %d      [%03d]  KPROBE命中，时间：[%lu:%lu]\n",
				raw_detail->task.cgroup_buf,
				raw_detail->task.pid,
				seq,
				raw_detail->tv.tv_usec, raw_detail->tv.tv_usec);
		diag_printf_kern_stack(&raw_detail->kern_stack);
#if 0
		diag_printf_user_stack(raw_detail->task.tgid,
				raw_detail->task.container_tgid,
				raw_detail->task.comm,
				&raw_detail->user_stack, 0);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				raw_detail->task.comm);
#else
		diag_printf_raw_stack(run_in_host ? raw_detail->task.tgid : raw_detail->task.container_tgid,
				raw_detail->task.container_tgid,
				raw_detail->task.comm,
				&raw_detail->raw_stack);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				raw_detail->task.comm);
#endif
		diag_printf_proc_chains(&raw_detail->proc_chains);
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
	struct kprobe_detail *detail;
	struct kprobe_raw_stack_detail *raw_detail;
	Json::Value root;
	Json::Value task;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_kprobe_detail:
		if (len < sizeof(struct kprobe_detail))
			break;
		detail = (struct kprobe_detail *)buf;

		diag_sls_time(&detail->tv, root);
		diag_sls_task(&detail->task, task);
		diag_sls_kern_stack(&detail->kern_stack, task);
		diag_sls_user_stack(detail->task.tgid,
			detail->task.container_tgid,
			detail->task.comm,
			&detail->user_stack, task);
		diag_sls_proc_chains(&detail->proc_chains, task);
		root["task"] = task;

		write_file(sls_file, "kprobe-detail", &detail->tv, 0, 0, root);
		write_syslog(syslog_enabled, "kprobe-detail", &detail->tv, 0, 0, root);
		break;
	case et_kprobe_raw_detail:
		if (len < sizeof(struct kprobe_raw_stack_detail))
			break;
		raw_detail = (struct kprobe_raw_stack_detail *)buf;

		diag_sls_time(&raw_detail->tv, root);
		diag_sls_task(&raw_detail->task, task);
		diag_sls_kern_stack(&raw_detail->kern_stack, task);
#if 0
		diag_sls_user_stack(raw_detail->task.tgid,
			raw_detail->task.container_tgid,
			raw_detail->task.comm,
			&raw_detail->user_stack, task);
#endif
		diag_sls_proc_chains(&raw_detail->proc_chains, task);
		root["task"] = task;

		write_file(sls_file, "kprobe-raw-detail", &raw_detail->tv, 0, 0, root);
		write_syslog(syslog_enabled, "kprobe-raw-detail", &raw_detail->tv, 0, 0, root);
		break;
	default:
		break;
	}
	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, kprobe_extract, NULL);
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
		ret = diag_call_ioctl(DIAG_IOCTL_KPROBE_DUMP, (long)&dump_param);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_KPROBE_DUMP, &ret, &len, variant_buf, 40 * 1024 * 1024);
	}

	if (ret == 0) {
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
			ret = diag_call_ioctl(DIAG_IOCTL_KPROBE_DUMP, (long)&dump_param);
		} else {
			syscall(DIAG_KPROBE_DUMP, &ret, &len, variant_buf, 40 * 1024 * 1024);
		}

		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}	

}

int kprobe_main(int argc, char **argv)
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
		 usage_kprobe();
		 return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_kprobe();
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
			usage_kprobe();
			break;
		}
	}

	return 0;
}
