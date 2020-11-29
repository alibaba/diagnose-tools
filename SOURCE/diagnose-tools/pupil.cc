/*
 * Linux内核诊断工具--用户态杂项功能实现
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
#include "uapi/pupil.h"
#include "params_parse.h"
#include <syslog.h>

static int report_reverse;

void usage_pupil(void)
{
	printf("    task-info dump task-info\n");
	printf("        --help task-info help info\n");
	printf("        --pid thread id intend to dump\n");
}

static void do_pid(char *arg)
{
	int pid = 0;
	int ret;

	sscanf(optarg, "%d", &pid);
	if (pid <= 0) {
		usage_pupil();
		return;
	}

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_PUPIL_TASK_PID, (long)&pid);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_PUPIL_TASK_PID, &ret, pid);
	}

	if (ret) {
		printf("	获取线程信息错误： %d\n", ret);
	}
}

static int task_info_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct pupil_task_detail *detail;
	static int seq;
	int pid;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_pupil_task:
		if (len < sizeof(struct pupil_task_detail))
			break;
		detail = (struct pupil_task_detail *)buf;
		pid = detail->task.pid;

		printf("线程详细信息： %d\n", pid);

		diag_printf_time(&detail->tv);
		diag_printf_task(&detail->task);
		seq++;
		printf("##CGROUP:[%s]  %d      [%03d]  采样命中\n",
				detail->task.cgroup_buf,
				detail->task.pid,
				seq);
		diag_printf_kern_stack(&detail->kern_stack);
		diag_printf_raw_stack(detail->task.tgid,
				detail->task.container_tgid,
				detail->task.comm,
				&detail->raw_stack);
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

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, task_info_extract, NULL);
}

static void do_dump(const char *arg)
{
	static char variant_buf[5 * 1024 * 1024];
	int len;
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 5 * 1024 * 1024,
		.user_buf = variant_buf,
	};

	report_reverse = parse.int_value("reverse");

	memset(variant_buf, 0, 5 * 1024 * 1024);
	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_PUPIL_TASK_DUMP, (long)&dump_param);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_PUPIL_TASK_DUMP, &ret, &len, variant_buf, 5 * 1024 * 1024);
	}

	if (ret == 0) {
		do_extract(variant_buf, len);
	}
}

int pupil_task_info(int argc, char *argv[])
{
	static const struct option long_options[] = {
			{"help",     no_argument, 0,  0 },
			{"report",     optional_argument, 0,  0 },
			{"pid",     required_argument, 0,  0 },
			{0,         0,                 0,  0 }
		};
	int c;

	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1) {
			break;
		}

		switch (option_index) {
		case 0:
			usage_pupil();
			break;
		case 1:
			do_dump(optarg ? optarg : "");
			break;
		case 2:
			do_pid(optarg);
			break;
		default:
			usage_pupil();
			break;
		}
	}

	return 0;
}
