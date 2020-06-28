#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "md5.h"

void usage_test_md5(void)
{
	printf("    test-md5 usage:\n");
	printf("        --help test-md5 help info\n");
	printf("        --count loop count\n");
}

int md5_main(int argc, char *argv[])
{
	int c;
	static struct option long_options[] = {
		{"count",     required_argument, 0,  'c' },
		{0,         0,                 0,  0 }
	};
	MD5_CTX md5;
	int i;
	int count = 10000000;
	unsigned char encrypt[] ="admin";//21232f297a57a5a743894a0e4a801fc3
	unsigned char decrypt[16];    

	while (1) {
		//int this_option_optind = optind ? optind : 1;
		int option_index = 0;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
	    case 0:
			count = atoi(optarg);
			break;
		default:
			break;
		}
	}       

	for (i = 0; i < count; i++) {
		MD5Init(&md5);         
		MD5Update(&md5, encrypt, strlen((char *)encrypt));
		MD5Final(&md5, decrypt);        
	}

	printf("加密前:%s\n加密后:", encrypt);
	for(i = 0; i < 16; i++)
	{
		printf("%02x", decrypt[i]);
	}
	printf("\n");

	return 0;
}
