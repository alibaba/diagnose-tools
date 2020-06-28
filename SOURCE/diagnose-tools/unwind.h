#ifndef __UNWIND_H
#define __UNWIND_H

#include <libunwind.h>
#include "symbol.h"

typedef unsigned long u64;
typedef unsigned char u8;
typedef unsigned int u32;
typedef long s64;
typedef char s8;
typedef int s32;


struct regs_dump {
    u64 *regs;
};

struct ip_callchain {
    u64 nr;
    u64 ips[0];
};

struct branch_flags {
    u64 mispred:1;
    u64 predicted:1;
    u64 reserved:62;
};

struct branch_entry {
    u64             from;
    u64             to;
    struct branch_flags flags;
};

struct branch_stack {
    u64             nr;
    struct branch_entry entries[0];
};

struct stack_dump {
    unsigned short offset;
    u64 size;
    char *data;
};

struct perf_sample {
    u64 ip;
    u32 pid, tid;
    u64 time;
    u64 addr;
    u64 id;
    u64 stream_id;
    u64 period;
    u32 cpu;
    u32 raw_size;
    void *raw_data;
    struct ip_callchain *callchain;
    struct branch_stack *branch_stack;
    struct regs_dump  user_regs;
    struct stack_dump user_stack;
};

#define PERF_REG_IP 0
#define PERF_REG_SP 1
#define PERF_REG_BP 2

struct unwind_entry {
    int pid;
    int pid_ns;
	u64	ip;
    struct vma *map;
};

typedef struct {
	struct perf_sample *stack_sample;
	void   *arg;
} entry_cb_arg_t;

typedef int (*unwind_entry_cb_t)(struct unwind_entry *entry, void *arg);

int unwind__get_entries(unwind_entry_cb_t cb, void *arg,
            symbol_parser *sp,
            int pid, int pid_ns,
			struct perf_sample *data);
int unwind__arch_reg_id(int regnum);

extern int stack_offset;
static inline void clear_stack_offset(void)
{
	stack_offset = 0;
}

static inline int get_stack_offset(void)
{
	return stack_offset;
}

extern void unwind__get_rbp(void *arg);

#endif /* __UNWIND_H */
