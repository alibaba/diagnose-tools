/*
 * Linux诊断工具--用户态工具主入口
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

#include "uapi/pupil.h"

typedef int (*diagnose_fp)(int argc, char **argv);

struct diagnose_func {
	const char* name;
	diagnose_fp func;
};

static int report_version(int argc, char **argv)
{
	printf("diagnose-tools tools version 2.0-rc2\n");
	exit(0);
}

static int usage_flame(void)
{
	printf("    flame generate flame graph\n");
	printf("        --input source file\n");
	printf("        --output target file\n");

	return 0;
}
static int usage(int argc, char **argv)
{
	printf("diagnose-tools usage:\n");
	printf("    -v, -V, --version: report version\n");
	printf("    --help: print this text\n");
	printf("    install: install module into system\n");
	printf("    uninstall: remove module from system\n");
	printf("    task-info $pid dump task-info\n");
    printf("    jmaps\n");
	usage_flame();
	usage_run_trace();
	usage_load_monitor();
	usage_perf();
	usage_exit_monitor();
	usage_sys_delay();
	usage_utilization();
 	usage_tcp_retrans();
	usage_rw_top();
	usage_fs_cache();
	usage_irq_delay();
	usage_mutex_monitor();
	usage_alloc_top();
	usage_high_order();
	usage_drop_packet();
	usage_fs_orphan();
	usage_exec_monitor();
	usage_fs_shm();
	usage_irq_stats();
	usage_irq_trace();
	usage_kprobe();
	usage_mm_leak();
	usage_sched_delay();
	usage_ping_delay();
	usage_reboot();
	usage_uprobe();
	usage_sys_cost();
	usage_testcase();
	usage_test_memcpy();
	usage_test_pi();
	usage_test_md5();
	usage_test_run_trace();
	usage_pupil();

	printf("\n");
	printf("/***************************************************************************/\n");
	printf("/*                                                                         */\n");
	printf("/*       More help documents are in /usr/diagnose-tools/usage.docx          */\n");
	printf("/*                                                                         */\n");
	printf("/***************************************************************************/\n");
	printf("\n");

	exit(0);
}

static int do_install(int argc, char **argv)
{
	int ret;

	ret = system("\\cp -f /usr/diagnose-tools/libperfmap.so /tmp");
	ret = system("/usr/diagnose-tools/diagnose-tools.sh install");

	return ret;
}

static int do_uninstall(int argc, char **argv)
{
	return	system("/usr/diagnose-tools/diagnose-tools.sh uninstall");
}

int do_flame(int argc, char *argv[])
{
	static const struct option long_options[] = {
			{"input",     required_argument, 0,  0 },
			{"output",     required_argument, 0,  0 },
			{0,         0,                 0,  0 }
		};
	int c;
	char *input = NULL;
	char *output = NULL;
	char cmd[1024];
	int __attribute__ ((unused)) ret;

	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1) {
			break;
		}

		switch (option_index) {
		case 0:
			input = optarg;
			break;
		case 1:
			output = optarg;
			break;
		default:
			usage_flame();
			return 0;
		}
	}

	if (!input || !output) {
		usage_flame();
		return 0;
	}

	sprintf(cmd, "cat %s | awk \'{if (substr($1,1,1) == \"#\") {print substr($0, 3)}}\' " \
		"| c++filt | /usr/diagnose-tools/flame-graph/stackcollapse.pl " \
		"| /usr/diagnose-tools/flame-graph/flamegraph.pl > %s", input, output);
	ret = system(cmd);

	return 0;
}

static struct diagnose_func all_funcs[] {
	{"usage", usage},
	{"run-trace", run_trace_main},
	{"jmaps", jmaps_main},
	{"load-monitor", load_monitor_main},
	{"perf", perf_main},
	{"exit-monitor", exit_monitor_main},
	{"sys-delay", sys_delay_main},
	{"sched-delay", sched_delay_main},
	{"utilization", utilization_main},
	{"tcp-retrans", tcp_retrans_main},
	{"rw-top", rw_top_main},
	{"fs-cache", fs_cache_main},
	{"irq-delay", irq_delay_main},
	{"mutex-monitor", mutex_monitor_main},
	{"alloc-top", alloc_top_main},
	{"high-order", high_order_main},
	{"drop-packet", drop_packet_main},
	{"fs-orphan", fs_orphan_main},
	{"exec-monitor", exec_monitor_main},
	{"fs-shm", fs_shm_main},
	{"irq-stats", irq_stats_main},
	{"irq-trace", irq_trace_main},
	{"kprobe", kprobe_main},
	{"mm-leak",mm_leak_main},
	{"ping-delay", ping_delay_main},
	{"uprobe", uprobe_main},
	{"-V", report_version},
	{"-v", report_version},
	{"--version", report_version},
	{"install", do_install},
	{"uninstall", do_uninstall},
	{"flame", do_flame},
	{"task-info", pupil_task_info},
	{"reboot", reboot_main},
	{"test-pi", pi_main},
	{"test-memcpy", memcpy_main},
	{"test-md5", md5_main},
	{"test-run-trace", test_run_trace_main},
	{"sys-cost", sys_cost_main},
	{"test", testcase_main},
};

int main(int argc, char* argv[])
{
	unsigned int i;
	diagnose_fp func = usage;
	unsigned int version = -1;
	int fd;

	fd = open("/dev/diagnose-tools", O_RDWR, 0);
	if (fd > 0) {
		version = ioctl(fd, DIAG_IOCTL_VERSION_ALL, 0);
		close(fd);
		if (version != DIAG_VERSION && version != -1UL && version != 0xffffffffU) {
			printf("严重警告，diagnose-tools工具与内核模块版本不匹配。\n");
			printf("期望的版本号：%lx, 运行的模块版本号：%x\n",
				(unsigned long)DIAG_VERSION,
				version);
			return -1;
		}
	}

	if (argc <= 1) {
		usage(argc, argv);
		return -1;
	}

    linux_2_6_x = is_linux_2_6_x();
	tzset();

	for (i = 0; i < sizeof(all_funcs) / sizeof(struct diagnose_func); i++) {
		if (strcmp(argv[1], all_funcs[i].name) == 0) {
			func = all_funcs[i].func;
			break;
		}
	}

	return func(argc - 1, argv + 1);
}
