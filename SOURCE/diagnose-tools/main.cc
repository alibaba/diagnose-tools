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

#include <assert.h>
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
#include <stdio_ext.h>

#include <set>

#include "internal.h"
#include "symbol.h"

#include "uapi/pupil.h"

typedef int (*diagnose_fp)(int argc, char **argv);

struct diagnose_func {
	const char* name;
	diagnose_fp func;
};

unsigned long run_in_host = 0;

static int report_version(int argc, char **argv)
{
	printf("diagnose-tools tools version 2.1-release\n");
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
	usage_net_bandwidth();
	usage_sig_info();

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
	{"net-bandwidth", net_bandwidth_main},
	{"sig-info", sig_info_main},
	{"test", testcase_main},
};

#define BUF_LEN 4096
#define WHITESPACE        " \t\n\r"
#define strneq(a, b, n) (strncmp((a), (b), (n)) == 0)
#define streq(a,b) (strcmp((a),(b)) == 0)

int is_pid_1_has_environ(const char *field) {
	bool done = false;
	FILE *f = NULL;
	int r = 0;
	size_t l;

	assert(field);

	f = fopen("/proc/1/environ", "re");
	if (!f)
		return 0;

	(void) __fsetlocking(f, FSETLOCKING_BYCALLER);

	l = strlen(field);

	do {
		char line[BUF_LEN];
		size_t i;

		for (i = 0; i < sizeof(line)-1; i++) {
			int c;

			c = getc(f);
			if ((c == EOF)) {
				done = true;
				break;
			} else if (c == 0)
				break;

			line[i] = c;
		}
		line[i] = 0;

		if (strneq(line, field, l) && line[l] == '=') {
			r = 1;
			goto out;
		}

	} while (!done);

out:
	fclose(f);
	return r;
}

enum {
	RUN_IN_HOST = 0,
	RUN_IN_CONTAINER
};

/**
 * Retrieve one field from a file like /proc/self/status.  pattern
 * should not include whitespace or the delimiter (':'). pattern matches only
 * the beginning of a line. Whitespace before ':' is skipped. Whitespace and
 * zeros after the ':' will be skipped. field must be freed afterwards.
 * terminator specifies the terminating characters of the field value (not
 * included in the value).
 */
int get_proc_field(const char *filename, const char *pattern, const char *terminator, char **field) {
	char status[BUF_LEN] = {0};
	char *t, *f;
	size_t len;
	int r;

	assert(terminator);
	assert(filename);
	assert(pattern);
	assert(field);

	int fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -errno;

	r = read(fd, &status, BUF_LEN - 1);
	if (r < 0)
		return r;

	t = status;

	do {
		bool pattern_ok;

		do {
			t = strstr(t, pattern);
			if (!t)
				return -ENOENT;

			/* Check that pattern occurs in beginning of line. */
			pattern_ok = (t == status || t[-1] == '\n');

			t += strlen(pattern);

		} while (!pattern_ok);

		t += strspn(t, " \t");
		if (!*t)
			return -ENOENT;

	} while (*t != ':');

	t++;


	if (*t) {
		t += strspn(t, " \t");

		/* Also skip zeros, because when this is used for
		 * capabilities, we don't want the zeros. This way the
		 * same capability set always maps to the same string,
		 * irrespective of the total capability set size. For
		 * other numbers it shouldn't matter. */
		t += strspn(t, "0");
		/* Back off one char if there's nothing but whitespace
		   and zeros */
		if (!*t || isspace(*t))
			t--;
	}

	len = strcspn(t, terminator);

	f = strndup(t, len);
	if (!f)
		return -ENOMEM;

	*field = f;
	return 0;
}

static int detect_container_by_pid_2(void) {
	char *s = NULL;
	int r;

	r = get_proc_field("/proc/2/status", "PPid", WHITESPACE, &s);
	if (r >= 0) {
		if (streq(s, "0"))
			r = RUN_IN_HOST;
		else
			r = RUN_IN_CONTAINER;
	} else if (r == -ENOENT)
		r = RUN_IN_CONTAINER;
	else {
		printf("Failed to read /proc/2/status: %d\n", r);
		r = RUN_IN_HOST;
	}

	free(s);
	return r;
}

static int check_in_host(void)
{
	int r;

	if (is_pid_1_has_environ("container"))
		r = RUN_IN_CONTAINER;
	else 
		r = detect_container_by_pid_2();
	printf("diagnose-tool is running in %s\n", r == RUN_IN_HOST ? 
			"HOST" : "CONTAINER");

	return r == RUN_IN_HOST;
}

int main(int argc, char* argv[])
{
	unsigned int i;
	diagnose_fp func = usage;
	unsigned int version = -1;
	int fd;

	run_in_host = check_in_host();
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
