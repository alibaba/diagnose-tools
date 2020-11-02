/*
 * Linux内核诊断工具--内核态杂项函数实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/module.h>
#include <linux/stacktrace.h>
#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/timex.h>
#include <linux/tracepoint.h>
#include <trace/events/irq.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <trace/events/napi.h>
#include <linux/rtc.h>
#include <linux/time.h>
#include <linux/version.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/file.h>
#include <linux/pid_namespace.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
#include <linux/blk-mq.h>
#endif
#include <linux/bitmap.h>
#include <linux/cpumask.h>
#include "mm_tree.h"
#include "internal.h"
#include "pub/trace_file.h"

unsigned int sysctl_debug_trace_printk;
u64 timer_sampling_period_ms = 10;
int sysctl_force_printk = 0;


#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
static inline int __ktime_compare(const ktime_t cmp1, const ktime_t cmp2)
{
	if (cmp1.tv64 < cmp2.tv64)
		return -1;
	if (cmp1.tv64 > cmp2.tv64)
		return 1;
	return 0;
}
#else
static inline int __ktime_compare(const ktime_t cmp1, const ktime_t cmp2)
{
	if (cmp1 < cmp2)
		return -1;
	if (cmp1 > cmp2)
		return 1;
	return 0;
}
#endif


int need_dump(int delay_threshold_ms, u64 *max_delay_ms, u64 base)
{
	u64 now = sched_clock();
	u64 delay_ms = (now - base) / 1000 / 1000;
	int ret = 0;

	if (now <= base)
		return ret;

	if (0 == delay_threshold_ms) {
		if ((delay_ms >= timer_sampling_period_ms / 5) &&
				(delay_ms > *max_delay_ms * 3 / 2)) {
			*max_delay_ms = delay_ms;
			ret = 1;
		}
	} else if (delay_ms > delay_threshold_ms)
		ret = 1;

	return ret;
}

static char *bdevt_str(dev_t devt, char *buf)
{
	if (MAJOR(devt) <= 0xff && MINOR(devt) <= 0xff) {
		char tbuf[BDEVT_SIZE];
		snprintf(tbuf, BDEVT_SIZE, "%02x%02x", MAJOR(devt), MINOR(devt));
		snprintf(buf, BDEVT_SIZE, "%-9s", tbuf);
	} else
		snprintf(buf, BDEVT_SIZE, "%03x:%05x", MAJOR(devt), MINOR(devt));

	return buf;
}

/*
 * print a full list of all partitions - intended for places where the root
 * filesystem can't be mounted and thus to give the victim some idea of what
 * went wrong
 */
void diag_printk_all_partitions(void)
{
	struct class_dev_iter iter;
	struct device *dev;

	class_dev_iter_init(&iter, orig_block_class, NULL, orig_disk_type);
	while ((dev = class_dev_iter_next(&iter))) {
		struct gendisk *disk = dev_to_disk(dev);
		struct disk_part_iter piter;
		struct hd_struct *part;
		char name_buf[BDEVNAME_SIZE];
		char devt_buf[BDEVT_SIZE];

		/*
		 * Don't show empty devices or things that have been
		 * suppressed
		 */
		if (get_capacity(disk) == 0 ||
		    (disk->flags & GENHD_FL_SUPPRESS_PARTITION_INFO))
			continue;

		if (disk->queue && disk->queue->make_request_fn)
			diag_trace_printk("make_request_fn: %pS\n", disk->queue->make_request_fn);
		/*
		 * Note, unlike /proc/partitions, I am showing the
		 * numbers in hex - the same format as the root=
		 * option takes.
		 */
		disk_part_iter_init(&piter, disk, DISK_PITER_INCL_PART0);
		while ((part = disk_part_iter_next(&piter))) {
			bool is_part0 = part == &disk->part0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
                        diag_trace_printk("%s%s %10llu %s", is_part0 ? "" : "  ",
                               bdevt_str(part_devt(part), devt_buf),
                                (unsigned long long)part->nr_sects >> 1,
                               orig_disk_name(disk, part->partno, name_buf));
#else
			diag_trace_printk("%s%s %10llu %s %s", is_part0 ? "" : "  ",
			       bdevt_str(part_devt(part), devt_buf),
				(unsigned long long)part_nr_sects_read(part) >> 1,
			       orig_disk_name(disk, part->partno, name_buf),
			       part->info ? part->info->uuid : "");
#endif
			if (is_part0) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)
				if (disk->driverfs_dev != NULL &&
				    disk->driverfs_dev->driver != NULL)
					diag_trace_printk(" driver: %s\n",
					      disk->driverfs_dev->driver->name);
				else
					diag_trace_printk(" (driver?)\n");
#else
				if (dev->parent && dev->parent->driver)
					printk(" driver: %s\n",
					      dev->parent->driver->name);
				else
					printk(" (driver?)\n");
#endif
			} else
				diag_trace_printk("\n");
		}
		disk_part_iter_exit(&piter);
	}
	class_dev_iter_exit(&iter);
}

struct proc_dir_entry *diag_proc_mkdir(const char *name,
                struct proc_dir_entry *parent)
{
	struct proc_dir_entry *ret = NULL;
	struct file *file;
	char full_name[255];

	snprintf(full_name, 255, "/proc/%s", name);
	file = filp_open(full_name, O_RDONLY, 0);
	if (IS_ERR(file)) {
		ret = proc_mkdir(name, parent);
	} else {
		fput(file);
	}

	return ret;
}

void diag_comm_name(struct task_struct *tsk, char *buf, unsigned int count)
{
	if (count > TASK_COMM_LEN)
		count = TASK_COMM_LEN;

	strncpy(buf, tsk->comm, count);
	buf[count - 1] = 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
void __diag_cgroup_name(struct task_struct *tsk, char *buf, unsigned int count, int cgroup)
{
	memset(buf, 0, count);
}

static void inline __dump_cgroups_tsk(int pre, enum diag_printk_type type, void *obj,
		struct task_struct *tsk)
{
}

void dump_cgroups_tsk(int pre, struct task_struct *tsk)
{
	__dump_cgroups_tsk(pre, TRACE_PRINTK, NULL, tsk);
}

void trace_buffer_cgroups_tsk(int pre, struct diag_trace_buffer *buffer, struct task_struct *tsk)
{
	__dump_cgroups_tsk(pre, TRACE_BUFFER_PRINTK, buffer, tsk);
}

void trace_buffer_nolock_cgroups_tsk(int pre, struct diag_trace_buffer *buffer, struct task_struct *tsk)
{
	__dump_cgroups_tsk(pre, TRACE_BUFFER_PRINTK_NOLOCK, buffer, tsk);
}

void trace_file_cgroups_tsk(int pre, struct diag_trace_file *file, struct task_struct *tsk)
{
	__dump_cgroups_tsk(pre, TRACE_FILE_PRINTK, file, tsk);
}

void trace_file_nolock_cgroups_tsk(int pre, struct diag_trace_file *file, struct task_struct *tsk)
{
	__dump_cgroups_tsk(pre, TRACE_FILE_PRINTK_NOLOCK, file, tsk);
}

void dump_cgroups(int pre)
{
	dump_cgroups_tsk(pre, current);
}

void trace_buffer_cgroups(int pre, struct diag_trace_buffer *buffer)
{
	trace_buffer_cgroups_tsk(pre, buffer, current);
}

void trace_buffer_nolock_cgroups(int pre, struct diag_trace_buffer *buffer)
{
	trace_buffer_nolock_cgroups_tsk(pre, buffer, current);
}

void trace_file_cgroups(int pre, struct diag_trace_file *file)
{
	trace_file_cgroups_tsk(pre, file, current);
}

void trace_file_nolock_cgroups(int pre, struct diag_trace_file *file)
{
	trace_file_nolock_cgroups_tsk(pre, file, current);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,12,0)
static inline int orig_diag_cgroup_name(struct cgroup *cgrp, char *buf, size_t buflen)
{
	if (orig_kernfs_name) {
		return orig_kernfs_name(cgrp->kn, buf, buflen);
	} else {
		return 0;
	}
}

void __diag_cgroup_name(struct task_struct *tsk, char *buf, unsigned int count, int cgroup)
{
	int cgroup_id = cpuacct_cgrp_id;

	memset(buf, 0, count);

	if (cgroup == 1) {
		cgroup_id = cpuset_cgrp_id;
	}

	if (tsk && tsk->cgroups && tsk->cgroups->subsys
			&& tsk->cgroups->subsys[cgroup_id]
			&& tsk->cgroups->subsys[cgroup_id]->cgroup) {
		orig_diag_cgroup_name(tsk->cgroups->subsys[cgroup_id]->cgroup, buf, count);
	}
}

static void inline __dump_cgroups_tsk(int pre, enum diag_printk_type type, void *obj,
		struct task_struct *tsk)
{
	int i;
	char buf[255];

	memset(buf, 0, 255);
	DIAG_TRACE_PRINTK(pre, type, obj, "pid: %d[%s]\n", tsk->pid, tsk->comm);
	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		if (tsk->cgroups && tsk->cgroups->subsys
				&& tsk->cgroups->subsys[i]
				&& tsk->cgroups->subsys[i]->cgroup) {
			orig_diag_cgroup_name(tsk->cgroups->subsys[i]->cgroup, buf, 255);
			DIAG_TRACE_PRINTK(pre, type, obj, "\t[%s]\n", buf);
		}
	}
}

void dump_cgroups_tsk(int pre, struct task_struct *tsk)
{
	__dump_cgroups_tsk(pre, TRACE_PRINTK, NULL, tsk);
}

void trace_buffer_cgroups_tsk(int pre, struct diag_trace_buffer *buffer, struct task_struct *tsk)
{
	__dump_cgroups_tsk(pre, TRACE_BUFFER_PRINTK, buffer, tsk);
}

void trace_buffer_nolock_cgroups_tsk(int pre, struct diag_trace_buffer *buffer, struct task_struct *tsk)
{
	__dump_cgroups_tsk(pre, TRACE_BUFFER_PRINTK_NOLOCK, buffer, tsk);
}

void trace_file_cgroups_tsk(int pre, struct diag_trace_file *file, struct task_struct *tsk)
{
	__dump_cgroups_tsk(pre, TRACE_FILE_PRINTK, file, tsk);
}

void trace_file_nolock_cgroups_tsk(int pre, struct diag_trace_file *file, struct task_struct *tsk)
{
	__dump_cgroups_tsk(pre, TRACE_FILE_PRINTK_NOLOCK, file, tsk);
}

void dump_cgroups(int pre)
{
	dump_cgroups_tsk(pre, current);
}

void trace_buffer_cgroups(int pre, struct diag_trace_buffer *buffer)
{
	trace_buffer_cgroups_tsk(pre, buffer, current);
}

void trace_buffer_nolock_cgroups(int pre, struct diag_trace_buffer *buffer)
{
	trace_buffer_nolock_cgroups_tsk(pre, buffer, current);
}

void trace_file_cgroups(int pre, struct diag_trace_file *file)
{
	trace_file_cgroups_tsk(pre, file, current);
}

void trace_file_nolock_cgroups(int pre, struct diag_trace_file *file)
{
	trace_file_nolock_cgroups_tsk(pre, file, current);
}
#else
void __diag_cgroup_name(struct task_struct *tsk, char *buf, unsigned int count, int cgroup)
{
    int cgroup_id = cpuacct_subsys_id;
    const char *name;
    memset(buf, 0, count);

    if (cgroup == 1) {
        cgroup_id = cpuset_subsys_id;
    }

    if (tsk && tsk->cgroups && tsk->cgroups->subsys
            && tsk->cgroups->subsys[cgroup_id]
            && tsk->cgroups->subsys[cgroup_id]->cgroup) {
        rcu_read_lock();
        name = cgroup_name(tsk->cgroups->subsys[cgroup_id]->cgroup);
        strncpy(buf, name, count);
        rcu_read_unlock();
    }
}

static void inline __dump_cgroups_tsk(int pre, enum diag_printk_type type, void *obj,
	struct task_struct *tsk)
{
	int i;

	DIAG_TRACE_PRINTK(pre, type, obj, "pid: %d[%s]\n", tsk->pid, tsk->comm);
	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		if (tsk->cgroups && tsk->cgroups->subsys
				&& tsk->cgroups->subsys[i]
				&& tsk->cgroups->subsys[i]->cgroup){
			rcu_read_lock();
			DIAG_TRACE_PRINTK(pre, type, obj, "\t[%s]\n", cgroup_name(tsk->cgroups->subsys[i]->cgroup));
			rcu_read_unlock();
		}
	}
}

void dump_cgroups_tsk(int pre, struct task_struct *tsk)
{
	__dump_cgroups_tsk(pre, TRACE_PRINTK, NULL, tsk);
}

void trace_buffer_cgroups_tsk(int pre, struct diag_trace_buffer *buffer, struct task_struct *tsk)
{
	__dump_cgroups_tsk(pre, TRACE_BUFFER_PRINTK, buffer, tsk);
}

void trace_buffer_nolock_cgroups_tsk(int pre, struct diag_trace_buffer *buffer, struct task_struct *tsk)
{
	__dump_cgroups_tsk(pre, TRACE_BUFFER_PRINTK_NOLOCK, buffer, tsk);
}

void trace_file_cgroups_tsk(int pre, struct diag_trace_file *file, struct task_struct *tsk)
{
	__dump_cgroups_tsk(pre, TRACE_FILE_PRINTK, file, tsk);
}

void trace_file_nolock_cgroups_tsk(int pre, struct diag_trace_file *file, struct task_struct *tsk)
{
	__dump_cgroups_tsk(pre, TRACE_FILE_PRINTK_NOLOCK, file, tsk);
}

void dump_cgroups(int pre)
{
	dump_cgroups_tsk(pre, current);
}

void trace_buffer_cgroups(int pre, struct diag_trace_buffer *buffer)
{
	trace_buffer_cgroups_tsk(pre, buffer, current);
}

void trace_buffer_nolock_cgroups(int pre, struct diag_trace_buffer *buffer)
{
	trace_buffer_nolock_cgroups_tsk(pre, buffer, current);
}

void trace_file_cgroups(int pre, struct diag_trace_file *file)
{
	trace_file_cgroups_tsk(pre, file, current);
}

void trace_file_nolock_cgroups(int pre, struct diag_trace_file *file)
{
	trace_file_nolock_cgroups_tsk(pre, file, current);
}

#endif

void diag_cgroup_name(struct task_struct *tsk, char *buf, unsigned int count, int cgroup)
{
	__diag_cgroup_name(tsk, buf, count, cgroup);
}

int diag_get_task_type(struct task_struct *tsk)
{
	if (orig_get_task_type)
        return orig_get_task_type(&tsk->se);

	return 0;
}

#define IP_STR_LEN 18
#define MAC_STR_LEN 18
#define MAC_BIT_LEN 6
#define LITTLE_ENDIAN 0
#define BIG_ENDIAN 1

int big_little_endian(void)
{
	int data = 0x1;

	if (*((char *)&data) == 0x1)
		return LITTLE_ENDIAN;

	return BIG_ENDIAN;
}

unsigned int ipstr2int(const char *ipstr)
{
	unsigned int a, b, c, d;
	unsigned int ip = 0;
	int count;
	
	count = sscanf(ipstr, "%u.%u.%u.%u", &a, &b, &c, &d);
	if (count == 4) {
		a = (a << 24);
		b = (b << 16);
		c = (c << 8);
		d = (d << 0);
		ip = a | b | c | d;

		return ip;
	} else {
		return 0;
	}
}

char *int2ipstr(const unsigned int ip, char *ipstr, const unsigned int ip_str_len)
{
	int len;

	if (big_little_endian() == LITTLE_ENDIAN)
		len = snprintf(ipstr, ip_str_len, "%u.%u.%u.%u",
				(unsigned char) * ((char *)(&ip) + 3),
				(unsigned char) * ((char *)(&ip) + 2),
				(unsigned char) * ((char *)(&ip) + 1),
				(unsigned char) * ((char *)(&ip) + 0));
	else
		len = snprintf(ipstr, ip_str_len, "%u.%u.%u.%u",
				(unsigned char) * ((char *)(&ip) + 0),
				(unsigned char) * ((char *)(&ip) + 1),
				(unsigned char) * ((char *)(&ip) + 2),
				(unsigned char) * ((char *)(&ip) + 3));

	if (len < ip_str_len)
		return ipstr;
	else
		return NULL;
}

char *mac2str(const unsigned char *mac, char *mac_str, const unsigned int mac_str_len)
{
	int len;

	len = snprintf(mac_str, mac_str_len, "%02X-%02X-%02X-%02X-%02X-%02X",
			mac[0], mac[1], mac[2],
			mac[3], mac[4], mac[5]);
	if (len < mac_str_len)
		return mac_str;
	else
		return NULL;
}

void diag_task_brief(struct task_struct *tsk, struct diag_task_detail *detail)
{
	struct pid_namespace *ns;
	
	if (detail)
		memset(detail, 0, sizeof(struct diag_task_detail));
	if (!detail || !tsk)
		return;

	detail->pid = tsk->pid;
	detail->tgid = tsk->tgid;
	detail->state = tsk->state;
	ns =  task_active_pid_ns(tsk);
	if (ns) {
		detail->container_pid = task_pid_nr_ns(tsk, ns);
		detail->container_tgid = task_tgid_nr_ns(tsk, ns);
	} else {
		detail->container_pid = tsk->pid;
		detail->container_tgid = tsk->tgid;
	}
	strncpy(detail->comm, tsk->comm, TASK_COMM_LEN);
	detail->comm[TASK_COMM_LEN - 1] = 0;
	diag_cgroup_name(tsk, detail->cgroup_buf, CGROUP_NAME_LEN, 0);
	diag_cgroup_name(tsk, detail->cgroup_cpuset, CGROUP_NAME_LEN, 1);

	detail->cgroup_buf[CGROUP_NAME_LEN - 1] = 0;
}

void printk_task_brief(struct diag_task_detail *detail)
{
	printk("    进程信息： [%s / %s]， PID： %d / %d\n",
		detail->cgroup_buf, detail->comm,
		detail->tgid, detail->pid);
}

int str_to_cpumask(char *cpus, struct cpumask *cpumask)
{
	return cpulist_parse(cpus, cpumask);
}

void cpumask_to_str(struct cpumask *cpumask, char *buf, int len)
{
#if KERNEL_VERSION(4, 4, 0) <= LINUX_VERSION_CODE
	snprintf(buf, len, "%*pbl", cpumask_pr_args(cpumask));
#else
	bitmap_scnlistprintf(buf, len,
		cpumask_bits(cpumask), nr_cpu_ids);
	buf[len - 1] = 0;
#endif
}

int str_to_bitmaps(char *bits, unsigned long *bitmap, int nr)
{
	return bitmap_parselist(bits, bitmap, nr);
}

void bitmap_to_str(unsigned long *bitmap, int nr, char *buf, int len)
{
#if KERNEL_VERSION(4, 4, 0) <= LINUX_VERSION_CODE
	snprintf(buf, len, "%*pbl", nr, bitmap);
#else
	bitmap_scnlistprintf(buf, len,
		bitmap, nr);
	buf[len - 1] = 0;
#endif
}

void record_dump_cmd(char *func)
{
	printk_ratelimited(KERN_INFO "diagnose-tools: dump %s\n", func);
	return;
}
