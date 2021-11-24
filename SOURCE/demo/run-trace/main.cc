#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>

#include "uapi/ali_diagnose.h"
#include "uapi/run_trace.h"

__attribute__((unused)) static void demo_host(void)
{
	int i;
	struct timeval delay;
	int __attribute__ ((unused)) ret;
	int ms = 100;

	ret = diag_call_ioctl(DIAG_IOCTL_RUN_TRACE_START, (long)&ms);

	for (i = 0; i < 3000000; i++) {
		static int tmp = 0;
		tmp = tmp + 2 * i;
	}
	delay.tv_sec = 0;
	delay.tv_usec = 60 * 1000; // 20 ms
	select(0, NULL, NULL, NULL, &delay);
	for (i = 0; i < 3000000; i++) {
		static int tmp = 0;
		tmp = tmp + i;
	}
	delay.tv_sec = 0;
	delay.tv_usec = 100 * 1000; // 20 ms
	select(0, NULL, NULL, NULL, &delay);

	ret = diag_call_ioctl(DIAG_IOCTL_RUN_TRACE_STOP, 0);
}

__attribute__((unused)) static void demo_container(void)
{
	int i;
	struct timeval delay;
	int __attribute__ ((unused)) ret;
	int ms = 100;

	ret = -ENOSYS;
	syscall(DIAG_RUN_TRACE_START, &ret, ms);

	for (i = 0; i < 3000000; i++) {
		static int tmp = 0;
		tmp = tmp + 2 * i;
	}
	delay.tv_sec = 0;
	delay.tv_usec = 60 * 1000; // 20 ms
	select(0, NULL, NULL, NULL, &delay);
	for (i = 0; i < 3000000; i++) {
		static int tmp = 0;
		tmp = tmp + i;
	}
	delay.tv_sec = 0;
	delay.tv_usec = 100 * 1000; // 20 ms
	select(0, NULL, NULL, NULL, &delay);

	ret = -ENOSYS;
	syscall(DIAG_RUN_TRACE_STOP, &ret);
}

int main(int argc, char **argv)
{
    demo_container();
    demo_host();

    return 0;
}