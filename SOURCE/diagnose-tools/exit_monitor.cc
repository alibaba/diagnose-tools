/*
 * Linux内核诊断工具--用户态exit-monitor功能实现
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

#include <linux/kdev_t.h>

#include "internal.h"
#include "symbol.h"
#include "unwind.h"
#include "uapi/exit_monitor.h"
#include "params_parse.h"

using namespace std;

static char sls_file[256];
static int syslog_enabled;

void usage_exit_monitor(void)
{
	printf("    exit-monitor usage:\n");
	printf("        --help exit-monitor help info\n");
	printf("        --activate\n");
	printf("          verbose VERBOSE\n");
	printf("          tgid process group that monitored\n");
	printf("          comm comm that monitored\n");
	printf("        --deactivate\n");
	printf("        --report dump log with text.\n");
	printf("        --test testcase for exit-monitor.\n");
	printf("        --log\n");
	printf("          sls=/tmp/1.log store in file\n");
	printf("          syslog=1 store in syslog\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_exit_monitor_settings settings;
	string str;

	memset(&settings, 0, sizeof(struct diag_exit_monitor_settings));
	
	settings.tgid = parse.int_value("tgid");
	settings.verbose = parse.int_value("verbose");

	str = parse.string_value("comm");
	if (str.length() > 0) {
		strncpy(settings.comm, str.c_str(), TASK_COMM_LEN);
		settings.comm[TASK_COMM_LEN - 1] = 0;
	}

	ret = -ENOSYS;
	syscall(DIAG_EXIT_MONITOR_SET, &ret, &settings, sizeof(struct diag_exit_monitor_settings));
	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    进程ID：%d\n", settings.tgid);
	printf("    进程名称：%s\n", settings.comm);
	printf("    输出级别：%d\n", settings.verbose);
	ret = diag_activate("exit-monitor");
	if (ret == 1) {
		printf("exit-monitor activated\n");
	} else {
		printf("exit-monitor is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("exit-monitor");
	if (ret == 0) {
		printf("exit-monitor is not activated\n");
	} else {
		printf("deactivate exit-monitor fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_exit_monitor_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["tgid"] = Json::Value(settings->tgid);
		root["comm"] = Json::Value(settings->comm);
		root["verbose"] = Json::Value(settings->verbose);
	} else {
		root["err"] = Json::Value("found exit-monitor settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_exit_monitor_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	ret = -ENOSYS;
	syscall(DIAG_EXIT_MONITOR_SETTINGS, &ret, &settings, sizeof(struct diag_exit_monitor_settings));

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    进程ID：%d\n", settings.tgid);
		printf("    进程名称：%s\n", settings.comm);
		printf("    输出级别：%d\n", settings.verbose);
	} else {
		printf("获取exit-monitor设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int exit_monitor_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct exit_monitor_detail *detail;
	struct exit_monitor_map *map;
    symbol sym;
    elf_file file;
	int i;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_exit_monitor_detail:
		if (len < sizeof(struct exit_monitor_detail))
			break;
		detail = (struct exit_monitor_detail *)buf;

		printf("线程退出，PID： %d[%s]，退出时间：[%lu:%lu]\n",
			detail->task.pid, detail->task.comm,
			detail->tv.tv_sec, detail->tv.tv_usec);

		for (i = 0; i < BACKTRACE_DEPTH; i++) {
            if (detail->kern_stack.stack[i] == (size_t)-1 || detail->kern_stack.stack[i] == 0) {
                continue;
            }
            sym.reset(detail->kern_stack.stack[i]);
			printf("        0x%lx,", detail->kern_stack.stack[i]);
            if (g_symbol_parser.find_kernel_symbol(sym)) {
                printf("        %s\n", sym.name.c_str());
            } else {
                printf("        %s\n", "(unknown)");
            }
		}

		diag_printf_raw_stack(detail->task.tgid,
				detail->task.container_tgid,
				detail->task.comm,
				&detail->raw_stack);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				detail->task.comm);

		break;
    case et_exit_monitor_map:
		if (len < sizeof(struct exit_monitor_map))
			break;
		map = (struct exit_monitor_map *)buf;

        g_symbol_parser.add_pid_maps(map->task.tgid, map->start, map->end, map->pgoff, map->file_name);

#if 0
		printf("线程MAPS，PID： %d[%s], %08lx-%08lx %lx %08llx %02x:%02x %lu %s\n",
			map->task.pid, map->task.comm,
			map->start,
			map->end,
			map->flags,
			map->pgoff,
			MAJOR(map->dev),
			MINOR(map->dev),
			map->ino,
			map->file_name);
#endif
		break;
	default:
		break;
	}

	return 0;
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct exit_monitor_detail *detail;
	symbol sym;
	elf_file file;
	Json::Value root;
	Json::Value task;
	Json::Value kern_stack;
	Json::Value user_stack;
	Json::Value proc_chains;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_exit_monitor_detail:
		if (len < sizeof(struct exit_monitor_detail))
			break;
		detail = (struct exit_monitor_detail *)buf;

		diag_sls_time(&detail->tv, root);
		diag_sls_task(&detail->task, task);
		diag_sls_kern_stack(&detail->kern_stack, task);
		diag_sls_user_stack(detail->task.tgid,
			detail->task.container_tgid,
			detail->task.comm,
			&detail->user_stack, task);
		root["task"] = task;

		write_file(sls_file, "exit-monitor", &detail->tv, 0, 0, root);
		write_syslog(syslog_enabled, "exit-monitor", &detail->tv, 0, 0, root);
		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, exit_monitor_extract, NULL);
}

static void do_dump(void)
{
	static char variant_buf[1024 * 1024];
	int len;
	int ret = 0;

	ret = -ENOSYS;
	syscall(DIAG_EXIT_MONITOR_DUMP, &ret, &len, variant_buf, 1024 * 1024);

	if (ret == 0 && len > 0) {
		do_extract(variant_buf, len);
	}
}

static void do_sls(char *arg)
{
	int ret;
	int len;
	static char variant_buf[1024 * 1024];

	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	while(1) {
		syscall(DIAG_EXIT_MONITOR_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}

}

int exit_monitor_main(int argc, char **argv)
{
	static struct option long_options[] = {
			{"help",     no_argument, 0,  0 },
			{"activate",     optional_argument, 0,  0 },
			{"deactivate", no_argument,       0,  0 },
			{"settings",     optional_argument, 0,  0 },
			{"report",     no_argument, 0,  0 },
			{"log",     required_argument, 0,  0 },
			{"test",     no_argument, 0,  0 },
			{0,         0,                 0,  0 }
		};
	int c;
    
	if (argc <= 1) {
		usage_exit_monitor();
		return 0;
	}

	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_exit_monitor();
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
			exit(1);
			break;
		default:
			usage_exit_monitor();
			break;
		}
	}

	return 0;
}
