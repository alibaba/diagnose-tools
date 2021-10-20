#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libaio.h>

int main()
{
        io_context_t ctx;
        unsigned nr_events = 10;
        memset(&ctx, 0, sizeof(ctx));  // It's necessary，这里一定要的
        int errcode = io_setup(nr_events, &ctx);
        if (errcode == 0)
                printf("io_setup success\n");
        else
                printf("io_setup error: :%d:%s\n", errcode, strerror(-errcode));

        // 如果不指定O_DIRECT，则io_submit操作和普通的read/write操作没有什么区别了，将来的LINUX可能
        // 可以支持不指定O_DIRECT标志
        int fd = open("./direct.txt", O_CREAT|O_DIRECT|O_WRONLY, S_IRWXU|S_IRWXG|S_IROTH);
        printf("open: %s\n", strerror(errno));

        char* buf;
        errcode = posix_memalign((void**)&buf, sysconf(_SC_PAGESIZE), sysconf(_SC_PAGESIZE) * 100);
        printf("posix_memalign: %s\n", strerror(errcode));

        strcpy(buf, "hello xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

	struct iocb *iocbpp = (struct iocb *)malloc(sizeof(struct iocb));
	while (1) {
		int i;

		for (i = 0; i <  100; i++) {
	        	memset(iocbpp, 0, sizeof(struct iocb));

		        iocbpp[0].data           = buf;
	        	iocbpp[0].aio_lio_opcode = IO_CMD_PWRITE;
	        	iocbpp[0].aio_reqprio    = 0;
		        iocbpp[0].aio_fildes     = fd;

        		iocbpp[0].u.c.buf    = buf;
		        iocbpp[0].u.c.nbytes = sysconf(_SC_PAGESIZE) * 100;//strlen(buf); // 这个值必须按512字节对齐
        		iocbpp[0].u.c.offset = 0; // 这个值必须按512字节对齐

		        // 提交异步操作，异步写磁盘
        		int n = io_submit(ctx, 1, &iocbpp);
	        	printf("==io_submit==: %d:%s\n", n, strerror(-n));

	        	struct io_event events[10];
		        struct diag_timespec timeout = {1, 100};
        		// 检查写磁盘情况，类似于epoll_wait或select
		        n = io_getevents(ctx, 1, 10, events, &timeout);
        		printf("io_getevents: %d:%s\n", n, strerror(-n));
		}
		usleep(200000);
	}

	close(fd);
        io_destroy(ctx);
	free(iocbpp);

        return 0;
}

