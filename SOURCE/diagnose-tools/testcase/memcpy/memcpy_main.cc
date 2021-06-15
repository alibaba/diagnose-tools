#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

#include <iostream>
#include <sys/time.h>
#include <string.h>
#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */

#include "../../internal.h"

using namespace std;

void usage_test_memcpy(void)
{
	printf("    test-memcpy usage:\n");
	printf("        --help test-pi help info\n");
	printf("        --cpu bind testcase on cpu\n");
	printf("        --verbose VERBOSE\n");
}

int memcpy_main(int argc, char* argv[])
{
	int c;
	static struct option long_options[] = {
            {"cpu",     required_argument, 0,  'c' },
            {"verbose", no_argument,       0,  0 },
            {0,         0,                 0,  0 }
        };

	int cpus = 0;
	int cpu = -1;
	cpu_set_t mask;
	cpu_set_t get;
	int i;
	int verbose = 0;

	long len = 1024 * 1024;
	int  loop = 20000;
	char* p = new char[len];
	char* q = p;
	struct diag_timespec start, end;
	double total_us = 0;
	double total_size;

	while (1) {
		//int this_option_optind = optind ? optind : 1;
		int option_index = 0;

		c = getopt_long(argc, argv, "c:v", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
	        case 0:
			printf("option %s", long_options[option_index].name);
			if (optarg)
				printf(" with arg %s", optarg);
			printf("\n");
			break;
		case 'c':
			printf("cpu is %s\n", optarg);
			cpu = atoi(optarg);
			break;
		case 'v':
			printf("verbose is true\n");
			verbose = 1;
			break;
		default:
			break;
		}
	}

	cpus = sysconf(_SC_NPROCESSORS_CONF);
	printf("cpus: %d\n", cpus);

	if (cpu >= 0) {
		CPU_ZERO(&mask);
		CPU_SET(cpu, &mask);
		if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
			printf("Set CPU affinity failue, ERROR:%s\n", strerror(errno));
			return -1; 
		}
	}

	CPU_ZERO(&get);
	if (sched_getaffinity(0, sizeof(get), &get) == -1) {
		printf("get CPU affinity failue, ERROR:%s\n", strerror(errno));
		return -1;
	}
	for(i = 0; i < cpus; i++) {
		if (CPU_ISSET(i, &get)) { /*查看cpu i 是否在get 集合当中*/
			if (verbose)
				printf("this process %d of running processor: %d\n", getpid(), i); 
		}
	}

	diag_gettimeofday(&start, NULL);
	for (int i =0; i < loop; ++i) {
		char* p = new char[len];
		*p = char(i);

		memcpy(p, q, len);
		delete [] p;
	}
	diag_gettimeofday(&end, NULL);

	total_us = (end.tv_sec - start.tv_sec) * 1000 * 1000 * 1000 + double(end.tv_usec - start.tv_usec);
	total_size = len * loop;

	cout <<"total_size: " << total_size << " \n";
	cout <<"total_us: " << total_us << " \n";

	return 0;
}
