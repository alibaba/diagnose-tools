#ifndef __DIAG_DEBUG_H
#define __DIAG_DEBUG_H

extern size_t get_current_rss(void);
extern size_t get_peak_rss(void);

extern void diag_track_memory(unsigned int step);
extern void diag_report_memory(void);

#endif /* __DIAG_DEBUG_H */
