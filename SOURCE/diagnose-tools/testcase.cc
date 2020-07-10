/*
 * Linux内核诊断工具--用户态测试功能实现
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
#include <fcntl.h>

#include "internal.h"
#include "uapi/ali_diagnose.h"
#include <sys/ioctl.h>

void usage_testcase(void)
{
	printf("    testcase usage:\n");
	printf("        --help testcase help info\n");
	printf("        --ioctl test char dev ioctl.\n");
}

static void do_ioctl(void)
{
	struct diag_ioctl_test val = {
		.in = 10,
	};
	int fd;

	fd = open("/dev/diagnose-tools", O_RDWR, 0);
	if (fd < 0) {
		printf("open /dev/diagnose-tools error!\n");
		return;
	}

	if (ioctl(fd, DIAG_IOCTL_TEST_IOCTL, &val) < 0) {
		printf("call cmd DIAG_IOCTL_TEST_IOCTL fail\n");
		goto err;
	}

	printf("xby-debug, in: %d, out: %d\n", val.in, val.out);
err:
	close(fd);
}

int testcase_main(int argc, char **argv)
{
	static struct option long_options[] = {
			{"help",     no_argument, 0,  0 },
			{"ioctl",     no_argument, 0,  0 },
			{0,         0,                 0,  0 }
		};
	int c;

	if (argc <= 1) {
		usage_testcase();
		return 0;
	}

	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_testcase();
			break;
	  	case 1:
			do_ioctl();
			break;
		default:
			usage_testcase();
			break;
		}
	}

	return 0;
}