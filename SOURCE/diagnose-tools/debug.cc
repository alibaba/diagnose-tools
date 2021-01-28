#include <stddef.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <set>

#include "debug.h"
#include "internal.h"
#include "symbol.h"
#include "elf.h"

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

static size_t last_rss = 0;
#define TRACE_COUNT 100
static size_t memory_track[TRACE_COUNT];

void diag_track_memory(unsigned int step)
{
	size_t cur = get_current_rss();
	size_t diff;

	if (!debug_mode)
		return;

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
	size_t cur, peak;

	if (!debug_mode)
		return;

	for (i = 0; i < TRACE_COUNT; i++) {
		printf("xby-debug in diag_report_memory, step %d, total: %lu\n", i, memory_track[i]);
	}

	cur = get_current_rss();
	peak = get_peak_rss();
	printf("xby-debug in diag_report_memory, PEAK: %lu, CURRENT: %lu\n", cur, peak);
}

void debug_get_symbol_from_elf(void)
{
	std::set<symbol> syms;

    if (get_symbol_from_elf(syms, "/home/xiebaoyou/git/diagnose-tools/SOURCE/test/loop/a.out")) {
		std::set<symbol>::iterator iter = syms.begin();

		for(; iter != syms.end(); ++iter) {
			symbol sym = *iter;
			printf("xby-debug in debug_get_symbol_from_elf, %lu, %lu, %lu, %s\n",
				sym.start,
				sym.end,
    			sym.ip,
    			sym.name.c_str());
		}
    }

	symbol sym;
	sym.reset(0x55917fe7b1cd);
	std::set<symbol>::const_iterator it = syms.find(sym);

    if (it != syms.end()) {
        sym.end = it->end;
        sym.start = it->start;
        sym.name = it->name;

        printf("xby-debug in debug_get_symbol_from_elf, step 2: 0x55917fe7b1cd, %lu, %lu, %lu, %s\n",
				sym.start,
				sym.end,
    			sym.ip,
    			sym.name.c_str());
    }

}