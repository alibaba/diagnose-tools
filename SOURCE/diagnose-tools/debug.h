#ifndef __DIAG_DEBUG_H
#define __DIAG_DEBUG_H

extern size_t get_current_rss(void);
extern size_t get_peak_rss(void);

extern void diag_track_memory(unsigned int step);
extern void diag_report_memory(void);
void debug_get_symbol_from_elf(void);

#endif /* __DIAG_DEBUG_H */
