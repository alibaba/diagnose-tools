#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

void usage_test_pi(void)
{
	printf("    test-pi usage:\n");
	printf("        --help test-pi help info\n");
	printf("        --cpu bind testcase on cpu\n");
	printf("        --verbose VERBOSE\n");
}

int pi_main(int argc, char *argv[])
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
	int verbose = 0;

	double x = 2, z = 2;
	int a = 1, b = 3;
	int i = 0;
	double result = 0;

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

	for (i = 0; i < 10000000; i++) {
		x = 2;
		z = 2;
		a = 1;
		b = 3;
		while(z > 1e-20){
			z = z * a / b;
			x += z;
			a++;
			b += 2;
		}
		result = x;
	}

	printf("∏ = %.20f\n", result);

	return 0;
}
