#include <stddef.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

#include "debug.h"

size_t get_current_rss(void)
{
    long rss = 0L;
    FILE* fp = NULL;

    if ((fp = fopen("/proc/self/statm", "r" )) == NULL)
        return (size_t)0L;      /* Can't open? */

    if (fscanf( fp, "%*s%ld", &rss ) != 1) {
        fclose(fp);
        return (size_t)0L;      /* Can't read? */
    }
    fclose(fp);

    return (size_t)rss * (size_t)sysconf(_SC_PAGESIZE);
}

size_t get_peak_rss(void)
{
    struct rusage rusage;

    getrusage(RUSAGE_SELF, &rusage);

    return (size_t)(rusage.ru_maxrss * 1024L);
}

#ifdef XBY_DEBUG

static size_t last_rss = 0;
#define TRACE_COUNT 100
static size_t memory_track[TRACE_COUNT];

void diag_track_memory(unsigned int step)
{
	size_t cur = get_current_rss();
	size_t diff;

	if (cur > last_rss)
		diff = cur - last_rss;
	else
		diff = 0;
	last_rss = cur;
	if (step >= 1 && step <= TRACE_COUNT) {
		memory_track[step - 1] += diff;
	}

	printf("xby-debug in diag_track_memory, step %d, diff: %lu\n", step, diff);
}

void diag_report_memory(void)
{
	int i;

	for (i = 0; i < TRACE_COUNT; i++) {
		printf("xby-debug in diag_report_memory, step %d, total: %lu\n", i, memory_track[i]);
	}
}

#endif
