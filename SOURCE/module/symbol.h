/*
 * Linux内核诊断工具--内核态符号表头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef __DIAG_SYMBOL_H
#define __DIAG_SYMBOL_H

struct mutex;
struct stack_trace;
struct pid_namespace;
extern struct mutex *orig_text_mutex;
extern rwlock_t *orig_tasklist_lock;

extern unsigned long (*__kallsyms_lookup_name)(const char *name);

#if defined(DIAG_ARM64)
extern void (*orig___flush_dcache_area)(void *addr, size_t len);
extern int (*orig_aarch64_insn_patch_text)(void *addrs[], u32 insns[], int cnt);
extern void (*orig_save_stack_trace_tsk)(struct task_struct *tsk, struct stack_trace *trace);
#else
extern void *(*orig_text_poke_smp)(void *, const void *, size_t);
extern void *(*orig_text_poke_bp)(void *addr, const void *opcode, size_t len, void *handler);
#endif

#if defined(CENTOS_8U) || KERNEL_VERSION(5, 0, 0) > LINUX_VERSION_CODE
extern void (*orig_save_stack_trace_tsk)(struct task_struct *tsk, struct stack_trace *trace);
#endif
extern void (*orig___show_regs)(struct pt_regs *regs, int all);
extern struct list_head *orig_ptype_all;

#if !defined(DIAG_ARM64)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0) || defined(CENTOS_4_18_193)
extern unsigned int (*orig_stack_trace_save_tsk)(struct task_struct *task,
				  unsigned long *store, unsigned int size,
				  unsigned int skipnr);
extern unsigned int (*orig_stack_trace_save_user)(unsigned long *store, unsigned int size);
#else
extern void (*orig_save_stack_trace_user)(struct stack_trace *trace);
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
extern void (*orig___do_page_fault)(struct pt_regs *regs,
	unsigned long address, unsigned long error_code);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
extern void __kprobes
(*orig___do_page_fault)(struct pt_regs *regs, unsigned long error_code);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
extern void
(*orig___do_page_fault)(struct pt_regs *regs, unsigned long error_code,
		unsigned long address);
#else
extern void
(*orig___do_page_fault)(struct pt_regs *regs, unsigned long error_code,
		unsigned long address);
#endif
extern struct task_struct *(*orig_find_task_by_vpid)(pid_t nr);
extern struct task_struct *(*orig_find_task_by_pid_ns)(pid_t nr, struct pid_namespace *ns);
extern struct task_struct *(*orig_idle_task)(int cpu);
struct class;
struct device_type;
extern struct class *orig_block_class;
extern struct device_type *orig_disk_type;
struct gendisk;
extern char *(*orig_disk_name)(struct gendisk *hd, int partno, char *buf);
extern int (*orig_access_remote_vm)(struct mm_struct *mm, unsigned long addr,
		void *buf, int len, unsigned int gup_flags);
struct rq;
extern struct rq *orig_runqueues;
struct sched_entity;
extern int (*orig_get_task_type)(struct sched_entity *se);
struct kernfs_node;
extern int (*orig_kernfs_name)(struct kernfs_node *kn, char *buf, size_t buflen);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 33)
extern struct page *(*orig_follow_page_mask)(struct vm_area_struct *vma,
			      unsigned long address, unsigned int foll_flags,
			      unsigned int *page_mask);
#else
extern struct page *(*orig_follow_page)(struct vm_area_struct *vma, unsigned long address,
			unsigned int flags);
#endif

struct cpuacct;
extern struct cpuacct *orig_root_cpuacct;
struct cgroup_subsys_state;
extern struct cgroup_subsys_state *
(*orig_css_next_descendant_pre)(struct cgroup_subsys_state *pos,
			struct cgroup_subsys_state *root);

struct cgroup_subsys;
extern struct cgroup_subsys *orig_cpuacct_subsys;
extern struct cgroup_subsys_state *
(*orig_css_get_next)(struct cgroup_subsys *ss, int id,
		 struct cgroup_subsys_state *root, int *foundid);

struct files_struct;
extern struct files_struct *(*orig_get_files_struct)(struct task_struct *task);
extern void (*orig_put_files_struct)(struct files_struct *files);

struct dentry;
struct inode;
extern struct dentry * (*orig_d_find_any_alias)(struct inode *inode);
extern int (*orig_task_statm)(struct mm_struct *mm,
			 unsigned long *shared, unsigned long *text,
			 unsigned long *data, unsigned long *resident);

extern unsigned int (*orig_stack_trace_save_tsk)(struct task_struct *task,
				  unsigned long *store, unsigned int size,
				  unsigned int skipnr);
extern unsigned int (*orig_stack_trace_save_user)(unsigned long *store, unsigned int size);

int alidiagnose_symbols_init(void);
void alidiagnose_symbols_exit(void);

#endif /* __DIAG_SYMBOL_H */

