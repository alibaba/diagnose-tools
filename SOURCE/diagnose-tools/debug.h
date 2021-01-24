#ifndef __DIAG_DEBUG_H
#define __DIAG_DEBUG_H

#define XBY_DEBUG

extern size_t get_current_rss(void);
extern size_t get_peak_rss(void);

#ifdef XBY_DEBUG
extern void diag_track_memory(unsigned int step);
extern void diag_report_memory(void);
#else
static inline void diag_track_memory(unsigned int step)
{
	 __sync_synchronize();
}

static inline void diag_report_memory(void)
{
	__sync_synchronize();
}

#endif

#endif /* __DIAG_DEBUG_H */
