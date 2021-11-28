/*
 * Linux内核诊断工具--用户态mm-leak功能实现
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
#include "uapi/mm_leak.h"
#include "params_parse.h"

void usage_mm_leak(void)
{
	printf("    mm-leak usage:\n");
	printf("	--help mm-leak help info\n");
	printf("	--activate\n");
	printf("	    time-threshold default threshold(s)\n");
	printf("	    max-bytes max bytes recorded\n");
	printf("	    min-bytes min bytes recorded \n");
	printf("	--deactivate\n");
	printf("	--report dump log with text\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;

	struct diag_mm_leak_settings settings;
	struct params_parser parse(arg);

	memset(&settings, 0, sizeof(struct diag_mm_leak_settings));

	settings.time_threshold = parse.int_value("time-threshold");
	settings.max_bytes =  parse.int_value("max-bytes");
	settings.min_bytes = parse.int_value("min-bytes");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_MM_LEAK_SET, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_MM_LEAK_SET, &ret, &settings, sizeof(struct diag_mm_leak_settings));
	}

	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    阈值(s)：%lu\n", settings.time_threshold);
	printf("    输出级别：%d\n", settings.verbose);
	printf("    MAX-BYTES：%d\n", settings.max_bytes);
	printf("    MIN-BYTES：%d\n", settings.min_bytes);
	if (ret)
		return;
	
	ret = diag_activate("mm-leak");
	if (ret == 1) {
		printf("mm-leak activated\n");
	} else {
		printf("mm-leak is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;
	
	ret = diag_deactivate("mm-leak");
	if (ret == 0) {
		printf("mm-leak is not activated\n");
	} else {
		printf("deactivate mm-leak fail, ret is %d\n", ret);
	}
}

static int mm_leak_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct mm_leak_detail *detail;
	symbol sym;
	elf_file file;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_mm_leak_detail:
		if (len < sizeof(struct mm_leak_detail))
			break;
		detail = (struct mm_leak_detail *)buf;

		printf("内存泄漏\n");
		printf("##CGROUP:[%s]  %d      [%03d]  采样命中\n",
				detail->task.cgroup_buf,
				detail->task.pid,
				0);
		printf("#*        0xffffffffffffff %lu / %lu  %lu(s)  [%lx] (UNKNOWN)\n",
				detail->bytes_req,
				detail->bytes_alloc,
				detail->delta_time,
				(unsigned long)detail->addr);
		diag_printf_kern_stack(&detail->kern_stack);
		printf("##\n");
		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, mm_leak_extract, NULL);
}

static void do_dump(void)
{
	static char variant_buf[5 * 1024 * 1024];
	int len;
	int ret = 0;

	struct diag_ioctl_dump_param_cycle dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 5 * 1024 * 1024,
		.user_buf = variant_buf,
		.cycle = 1,
	};

	memset(variant_buf, 0, 5 * 1024 * 1024);
	do {
		if (run_in_host) {
			ret = diag_call_ioctl(DIAG_IOCTL_MM_LEAK_DUMP, (long)&dump_param);
		} else {
			ret = -ENOSYS;
			syscall(DIAG_MM_LEAK_DUMP, &ret, &len, variant_buf, 5 * 1024 * 1024, dump_param.cycle);
		}

		if (ret == 0 && len > 0) {
			do_extract(variant_buf, len);
		}

		dump_param.cycle = 0;
	} while (ret == 0 && len > 0);
}

static void do_settings(void)
{
	struct diag_mm_leak_settings settings;
	int ret;

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_MM_LEAK_SETTINGS, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_MM_LEAK_SETTINGS, &ret, &settings, sizeof(struct diag_mm_leak_settings));
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    输出级别：%d\n", settings.verbose);
		printf("    阈值(s)：%lu\n", settings.time_threshold);
		printf("    MAX-BYTES：%d\n", settings.max_bytes);
		printf("    MIN-BYTES：%d\n", settings.min_bytes);
	} else {
		printf("获取mm-leak设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

int mm_leak_main(int argc, char **argv)
{
	static struct option long_options[] = {
			{"help",     no_argument, 0,  0 },
			{"activate",     optional_argument, 0,  0 },
			{"deactivate", no_argument,       0,  0 },
			{"settings",     no_argument, 0,  0 },
			{"report",     no_argument, 0,  0 },
			{0,         0,                 0,  0 }
		};
	int c;

	if (argc <= 1) {
		usage_mm_leak();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_mm_leak();
			break;
		case 1:
			do_activate(optarg ? optarg : "");
			break;
		case 2:
			do_deactivate();
			break;
		case 3:
			do_settings();
			break;
		case 4:
			do_dump();
			break;
		default:
			usage_mm_leak();
			break;
		}
	}

	return 0;
}

