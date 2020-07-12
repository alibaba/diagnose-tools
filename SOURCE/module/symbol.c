/*
 * Linux内核诊断工具--内核态符号表相关函数实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/kallsyms.h>

#include "internal.h"

struct mutex *orig_text_mutex;
rwlock_t *orig_tasklist_lock;

#if defined(DIAG_ARM64)
void (*orig___flush_dcache_area)(void *addr, size_t len);
int (*orig_aarch64_insn_patch_text)(void *addrs[], u32 insns[], int cnt);
#else
void *(*orig_text_poke_smp)(void *, const void *, size_t);
void *(*orig_text_poke_bp)(void *addr, const void *opcode,
		size_t len, void *handler);
#endif

struct list_head *orig_ptype_all;

void (*orig___show_regs)(struct pt_regs *regs, int all);
#if !defined(DIAG_ARM64)
void (*orig_save_stack_trace_user)(struct stack_trace *trace);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
void (*orig___do_page_fault)(struct pt_regs *regs,
        unsigned long address, unsigned long error_code);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
void __kprobes (*orig___do_page_fault)(struct pt_regs *regs, unsigned long error_code);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
void (*orig___do_page_fault)(struct pt_regs *regs, unsigned long error_code,
                unsigned long address);
#else
void (*orig___do_page_fault)(struct pt_regs *regs, unsigned long error_code,
                unsigned long address);
#endif

struct class *orig_block_class; 
struct device_type *orig_disk_type;
char *(*orig_disk_name)(struct gendisk *hd, int partno, char *buf);
struct task_struct *(*orig_find_task_by_vpid)(pid_t nr);
struct task_struct *(*orig_find_task_by_pid_ns)(pid_t nr, struct pid_namespace *ns);

int (*orig_access_remote_vm)(struct mm_struct *mm, unsigned long addr,
		void *buf, int len, unsigned int gup_flags);
struct task_struct *(*orig_idle_task)(int cpu);
struct rq *orig_runqueues;
int (*orig_get_task_type)(struct sched_entity *se);
int (*orig_kernfs_name)(struct kernfs_node *kn, char *buf, size_t buflen);

struct cpuacct *orig_root_cpuacct;
struct cgroup_subsys_state *
(*orig_css_next_descendant_pre)(struct cgroup_subsys_state *pos,
			struct cgroup_subsys_state *root);

struct cgroup_subsys *orig_cpuacct_subsys;
struct cgroup_subsys_state *
(*orig_css_get_next)(struct cgroup_subsys *ss, int id,
		 struct cgroup_subsys_state *root, int *foundid);

struct files_struct *(*orig_get_files_struct)(struct task_struct *task);
void (*orig_put_files_struct)(struct files_struct *files);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 33)
struct page *(*orig_follow_page_mask)(struct vm_area_struct *vma,
			      unsigned long address, unsigned int foll_flags,
			      unsigned int *page_mask);
#else
struct page *(*orig_follow_page)(struct vm_area_struct *vma, unsigned long address,
			unsigned int flags);
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 0, 0)
unsigned int (*orig_stack_trace_save_tsk)(struct task_struct *task,
				  unsigned long *store, unsigned int size,
				  unsigned int skipnr);
unsigned int (*orig_stack_trace_save_user)(unsigned long *store, unsigned int size);
#endif

struct dentry * (*orig_d_find_any_alias)(struct inode *inode);

int (*orig_task_statm)(struct mm_struct *mm,
			 unsigned long *shared, unsigned long *text,
			 unsigned long *data, unsigned long *resident);

atomic64_t xby_debug_counter1;
atomic64_t xby_debug_counter2;
atomic64_t xby_debug_counter3;
atomic64_t xby_debug_counter4;
atomic64_t xby_debug_counter5;

static int lookup_syms(void)
{
	LOOKUP_SYMS(text_mutex);
	LOOKUP_SYMS(tasklist_lock);
#if defined(DIAG_ARM64)
	LOOKUP_SYMS(__flush_dcache_area);
	LOOKUP_SYMS(aarch64_insn_patch_text);
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
	LOOKUP_SYMS(text_poke_smp);
#else
	LOOKUP_SYMS(text_poke_bp);
#endif /* LINUX_VERSION_CODE */
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 0, 0)
	LOOKUP_SYMS(stack_trace_save_tsk);
	LOOKUP_SYMS(stack_trace_save_user);
#else
	LOOKUP_SYMS(save_stack_trace_user);
#endif
#endif /* DIAG_ARM64 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	orig_runqueues = (void *)__kallsyms_lookup_name("per_cpu__runqueues");
	if (orig_runqueues == NULL) {
		return -EINVAL;
	}
#else
	LOOKUP_SYMS(runqueues);
#endif
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,15,18)
	orig___do_page_fault = (void *)0xffffffff9e6757d0;
#endif
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,9,93)
        orig___do_page_fault = (void *)0xffffffff8106e940;
#endif
	//LOOKUP_SYMS(__do_page_fault);
	LOOKUP_SYMS(block_class);
	LOOKUP_SYMS(disk_type);
	LOOKUP_SYMS(disk_name);
	LOOKUP_SYMS(access_remote_vm);
	LOOKUP_SYMS(idle_task);
	LOOKUP_SYMS(get_files_struct);
	LOOKUP_SYMS(put_files_struct);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
	LOOKUP_SYMS(follow_page);
#else
	LOOKUP_SYMS(follow_page_mask);
#endif
	LOOKUP_SYMS(task_statm);

	orig_d_find_any_alias = (void *)__kallsyms_lookup_name("d_find_any_alias");

	orig_find_task_by_vpid = (void *)__kallsyms_lookup_name("find_task_by_vpid");
	orig_find_task_by_pid_ns = (void *)__kallsyms_lookup_name("find_task_by_pid_ns");
	orig_get_task_type = (void *)__kallsyms_lookup_name("get_task_type");
	orig_kernfs_name = (void *)__kallsyms_lookup_name("kernfs_name");
	orig_root_cpuacct = (void *)__kallsyms_lookup_name("root_cpuacct");
	orig_css_next_descendant_pre = (void *)__kallsyms_lookup_name("css_next_descendant_pre");
	orig_cpuacct_subsys = (void *)__kallsyms_lookup_name("cpuacct_subsys");
	orig_css_get_next = (void *)__kallsyms_lookup_name("css_get_next");

	return 0;
}

struct diag_symbol_info {
    char *symbol;
    int count;
};

static inline int get_symbol_count_callback(void *data, const char *name,
            struct module *mod, unsigned long addr)
{
    struct diag_symbol_info *info = data;

    if (strcmp(name, info->symbol) == 0) {
        info->count++;
        return 0;
    }

    return 0;
}

int diag_get_symbol_count(char *symbol)
{
	struct diag_symbol_info info;

	info.symbol = symbol;
	info.count = 0;  
	kallsyms_on_each_symbol(get_symbol_count_callback, &info);

	return info.count;
}

int alidiagnose_symbols_init(void)
{
	int ret;

	ret = lookup_syms();
	if (ret)
		return ret;

	ret = -EINVAL;

	orig___show_regs = (void *)__kallsyms_lookup_name("__show_regs");
	if (!orig___show_regs)
		return ret;

	orig_ptype_all = (void *)__kallsyms_lookup_name("ptype_all");
	if (!orig_ptype_all)
                return ret;

	return 0;
}

void alidiagnose_symbols_exit(void)
{
	//TO DO
}
