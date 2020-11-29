#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

#include "uapi/ali_diagnose.h"
#include "uapi/run_trace.h"

void usage_test_run_trace(void)
{
	printf("    test-run-trace usage:\n");
	printf("        --help test-run-trace help info\n");
	printf("        --type 0-->syscall 1-->proc 2-->uprobe\n");
	printf("        --threshold threshold(ms)\n");
	printf("        --count loop count\n");
}

extern "C" {
	static __attribute__ ((noinline))  void mytest3(void)
	{
			sleep(1);
	}

	static __attribute__ ((noinline))  void mytest2(void)
	{
			mytest3();
	}

	static __attribute__ ((noinline))  void mytest1(void)
	{
			mytest2();
	}

	static __attribute__ ((noinline))  void mytest(void)
	{
		mytest1();
		sleep(1);
	}
}

int test_run_trace_main(int argc, char *argv[])
{
	int i, count = 2, type = 0, threshold = 1234;
	int fp = 0;
	int c;
	ssize_t __attribute__ ((unused)) size;
	static struct option long_options[] = {
			{"help",     no_argument, 0,  0 },
			{"type",     required_argument, 0,  0 },
			{"threshold", required_argument, 0,  0 },
			{"count", required_argument, 0,  0 },
			{0,         0,                 0,  0 }
	};

	while (1) {
		//int this_option_optind = optind ? optind : 1;
		int option_index = 0;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (option_index) {
		case 0:
			usage_test_run_trace();
			return 0;
	    case 1:
			type = atoi(optarg);
			break;
		case 2:
			threshold = atoi(optarg);
			break;
		case 3:
			count = atoi(optarg);
			break;
		default:
			break;
		}
	}

	for (i = 0; i < count; i++) {
		if (type == 0) {
			diag_call_ioctl(DIAG_IOCTL_RUN_TRACE_START, (long)&threshold);
		} else if (type == 1) {
			fp = open("/proc/ali-linux/diagnose/kern/run-trace-settings", O_WRONLY);
			if (fp != -1) {
				size = write(fp, "start 1234", 11);
				close(fp);
			}
		} else if (type == 2) {
			//
		}

		mytest();
		sleep(1);
		sleep(1);

		if (type == 0) {
			diag_call_ioctl(DIAG_IOCTL_RUN_TRACE_STOP, 0);
		} else if (type == 1) {
			fp = open("/proc/ali-linux/diagnose/kern/run-trace-settings", O_WRONLY);
			if (fp != -1) {
				size = write(fp, "stop", 5);
				close(fp);
			}
		} else if (type == 2) {
			//
		}
	}

	return 0;
}
