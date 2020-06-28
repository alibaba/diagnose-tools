#!/bin/bash

rm -rf get_sys_call.out

cat > get_sys_call.c <<EOF
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

#include <sys/time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	printf("%d\n", __NR_$1);
	return 0;
}
EOF

gcc get_sys_call.c -o get_sys_call.out

nr_syscall=`./get_sys_call.out`
if [ $? -ne 0 ]; then
	echo -1
else
	echo $nr_syscall
fi
