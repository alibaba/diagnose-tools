#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

extern "C" {
	static __attribute__ ((noinline))  int mytest10(void)
	{
		int i = 10;

		return i * i;
	}

        static __attribute__ ((noinline))  void mytest9(void)
        {
                        mytest10();
        }

        static __attribute__ ((noinline))  void mytest8(void)
        {
                        mytest9();
        }

        static __attribute__ ((noinline))  void mytest7(void)
        {
                        mytest8();
        }

        static __attribute__ ((noinline))  void mytest6(void)
        {
                        mytest7();
        }

        static __attribute__ ((noinline))  void mytest5(void)
        {
                        mytest6();
        }

        static __attribute__ ((noinline))  void mytest4(void)
        {
                        mytest5();
        }

        static __attribute__ ((noinline))  void mytest3(void)
        {
                        mytest4();
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
	}
}

int main(int argc, char *argv[])
{
	while (1) {
		mytest();
		//printf("xby-debug in main\n");
	}

	return 0;
}
