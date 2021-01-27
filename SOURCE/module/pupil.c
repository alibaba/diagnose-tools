/*
 * Linux内核诊断工具--内核态杂项功能实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

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
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/random.h>
//#include <linux/printk.h>
#include <linux/cgroup.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/sort.h>
#include <linux/net.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <net/sock.h>
#include <linux/connector.h>
#ifdef CENTOS_7U
#include <linux/rhashtable.h>
#endif

#include <asm/kdebug.h>

#include "internal.h"
#include "mm_tree.h"
#include "pub/trace_file.h"
#include "pub/kprobe.h"
#include "pub/cgroup.h"

#include "uapi/pupil.h"

extern struct pid_namespace *task_active_pid_ns(struct task_struct *tsk);

static struct diag_trace_file pupil_settings_file;
static struct diag_trace_file pupil_log_file;

static struct diag_variant_buffer pupil_variant_buffer;
static int pupil_alloced;

#if defined(EXPERIENTIAL)
static char kprobe_func[255];
static struct kprobe kprobe_pupil;
static atomic64_t diag_kprobe_count = ATOMIC64_INIT(0);
static int kprobe_verbose;

static struct kprobe kprobe_mlx5_eq_int;

static char kretprobe_func[NAME_MAX];
struct kretprobe_data {
	struct pt_regs regs;
	ktime_t entry_stamp;
};
static int kretprobe_enabled;
static atomic64_t diag_kretprobe_count = ATOMIC64_INIT(0);
static atomic64_t diag_kretprobe_time = ATOMIC64_INIT(0);
enum {
	distribution_100ns,
	distribution_1000ns,
	distribution_10us,
	distribution_100us,
	distribution_1ms,
	distribution_10ms,
	distribution_100ms,
	distribution_other,
	nr_distribution,
};

static atomic64_t diag_pretprobe_time_distribution[nr_distribution];
static int kretprobe_verbose;

static int kretprobe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kretprobe_data *data;

	data = (struct kretprobe_data *)ri->data;
	data->regs = *regs;
	data->entry_stamp = ktime_get();

	return 0;
}

static int kretprobe_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct kretprobe_data *data = (struct kretprobe_data *)ri->data;
	s64 delta;
	ktime_t now;

	now = ktime_get();
	delta = ktime_to_ns(ktime_sub(now, data->entry_stamp));
	atomic64_inc_return(&diag_kretprobe_count);
	atomic64_add_return(delta, &diag_kretprobe_time);

	if (delta <= 100) {
		atomic64_add_return(1, &diag_pretprobe_time_distribution[distribution_100ns]);
	} else if (delta <= 1000) {
		atomic64_add_return(1, &diag_pretprobe_time_distribution[distribution_1000ns]);
	} else if (delta <= 10000) {
		atomic64_add_return(1, &diag_pretprobe_time_distribution[distribution_10us]);
	} else if (delta <= 100000) {
		atomic64_add_return(1, &diag_pretprobe_time_distribution[distribution_100us]);
	} else if (delta <= 1000000) {
		atomic64_add_return(1, &diag_pretprobe_time_distribution[distribution_1ms]);
	} else if (delta <= 10000000) {
		atomic64_add_return(1, &diag_pretprobe_time_distribution[distribution_10ms]);
	} else if (delta <= 100000000) {
		atomic64_add_return(1, &diag_pretprobe_time_distribution[distribution_100ms]);
	} else {
		atomic64_add_return(1, &diag_pretprobe_time_distribution[distribution_other]);
	}

	if (kretprobe_verbose & 1) {
		diag_trace_file_printk(&pupil_log_file,
				"%s 返回值： %d，消耗时间： %lld ns\n",
				kretprobe_func, retval, (long long)delta);
		if (delta > 100000) {
			diag_trace_file_printk(&pupil_log_file,
				"param[0] %lu, %lx, %pS.\n", ORIG_PARAM1(&data->regs), ORIG_PARAM1(&data->regs), (void *)ORIG_PARAM1(&data->regs));
			diag_trace_file_printk(&pupil_log_file,
				"param[1] %lu, %lx, %pS.\n", ORIG_PARAM2(&data->regs), ORIG_PARAM2(&data->regs), (void *)ORIG_PARAM2(&data->regs));
			diag_trace_file_printk(&pupil_log_file,
				"param[2] %lu, %lx, %pS.\n", ORIG_PARAM3(&data->regs), ORIG_PARAM3(&data->regs), (void *)ORIG_PARAM3(&data->regs));
			diag_trace_file_printk(&pupil_log_file,
				"param[3] %lu, %lx, %pS.\n", ORIG_PARAM4(&data->regs), ORIG_PARAM4(&data->regs), (void *)ORIG_PARAM4(&data->regs));
			diag_trace_file_printk(&pupil_log_file,
				"param[4] %lu, %lx, %pS.\n", ORIG_PARAM5(&data->regs), ORIG_PARAM5(&data->regs), (void *)ORIG_PARAM5(&data->regs));
			diag_trace_file_printk(&pupil_log_file,
				"param[5] %lu, %lx, %pS.\n", ORIG_PARAM6(&data->regs), ORIG_PARAM6(&data->regs), (void *)ORIG_PARAM6(&data->regs));
		}
	}

	return 0;
}

static struct kretprobe my_kretprobe = {
	.handler		= kretprobe_ret_handler,
	.entry_handler		= kretprobe_entry_handler,
	.data_size		= sizeof(struct kretprobe_data),
	.maxactive		= 200,
};

static struct kretprobe *ptr_kretprobe;

__maybe_unused static int kretprobe_init(void)
{
	int ret;
	int i;

	ptr_kretprobe = kmalloc(sizeof(struct kretprobe), GFP_KERNEL | __GFP_ZERO);
	if (ptr_kretprobe == NULL)
		return -1;

	atomic64_set(&diag_kretprobe_count, 0);
	atomic64_set(&diag_kretprobe_time, 0);
	for (i = 0; i < nr_distribution; i++) {
		atomic64_set(&diag_pretprobe_time_distribution[i], 0);
	}
	my_kretprobe.kp.symbol_name = kretprobe_func;
	*ptr_kretprobe = my_kretprobe;
	ret = register_kretprobe(ptr_kretprobe);
	if (ret < 0) {
		printk(KERN_INFO "register_kretprobe failed, returned %d\n",
				ret);
		return -1;
	}
	printk(KERN_INFO "Planted return probe at %s: %p\n",
			my_kretprobe.kp.symbol_name, my_kretprobe.kp.addr);
	kretprobe_enabled = 1;

	return 0;
}

static void kretprobe_exit(void)
{
	if (!kretprobe_enabled)
		return;

	unregister_kretprobe(ptr_kretprobe);
	printk(KERN_INFO "kretprobe at %p unregistered\n",
			my_kretprobe.kp.addr);

	/* nmissed > 0 suggests that maxactive was set too low. */
	printk(KERN_INFO "Missed probing %d instances of %s\n",
			my_kretprobe.nmissed, my_kretprobe.kp.symbol_name);
	kfree(ptr_kretprobe);
	ptr_kretprobe = NULL;
	kretprobe_enabled = 0;
}

__maybe_unused static int kprobe_mlx5_eq_int_pre(struct kprobe *p, struct pt_regs *regs)
{
	int i, ms;
	unsigned long flags;

	ms = 2000;

	local_irq_save(flags);
	for (i = 0; i < ms; i++)
		mdelay(1);
	local_irq_restore(flags);

	return 0;
}

__maybe_unused static int kprobe_pupil_pre(struct kprobe *p, struct pt_regs *regs)
{
	unsigned long trace_buf[BACKTRACE_DEPTH];

	atomic64_inc_return(&diag_kprobe_count);

	if (kprobe_verbose & 1) {
		diag_trace_file_printk(&pupil_log_file,
			"----------------- pid: %d, comm: %s\n", current->pid, current->comm);
		diag_trace_file_printk(&pupil_log_file,
			"param[0] %lu, %lx, %pS.\n", ORIG_PARAM1(regs), ORIG_PARAM1(regs), (void *)ORIG_PARAM1(regs));
		diag_trace_file_printk(&pupil_log_file,
			"param[1] %lu, %lx, %pS.\n", ORIG_PARAM2(regs), ORIG_PARAM2(regs), (void *)ORIG_PARAM2(regs));
		diag_trace_file_printk(&pupil_log_file,
			"param[2] %lu, %lx, %pS.\n", ORIG_PARAM3(regs), ORIG_PARAM3(regs), (void *)ORIG_PARAM3(regs));
		diag_trace_file_printk(&pupil_log_file,
			"param[3] %lu, %lx, %pS.\n", ORIG_PARAM4(regs), ORIG_PARAM4(regs), (void *)ORIG_PARAM4(regs));
		diag_trace_file_printk(&pupil_log_file,
			"param[4] %lu, %lx, %pS.\n", ORIG_PARAM5(regs), ORIG_PARAM5(regs), (void *)ORIG_PARAM5(regs));
		diag_trace_file_printk(&pupil_log_file,
			"param[5] %lu, %lx, %pS.\n", ORIG_PARAM6(regs), ORIG_PARAM6(regs), (void *)ORIG_PARAM6(regs));
		diag_trace_file_printk(&pupil_log_file,
			"--------- kernel stack:\n");
		diagnose_trace_file_stack_trace(0, &pupil_log_file, current, trace_buf);
		diag_trace_file_printk(&pupil_log_file,
			"--------- user stack:\n");
		diagnose_trace_file_stack_trace_user(0, &pupil_log_file, trace_buf);
	}

	return 0;
}

__maybe_unused static int test_thread(void* arg)
{
	set_current_state(TASK_INTERRUPTIBLE);
	schedule();
	printk("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	BUG();

	return 0;
}

static __used noinline void test_mutex(void)
{
	static DEFINE_MUTEX(lock);

	mutex_lock(&lock);
	msleep(2000);
	mutex_unlock(&lock);
        mutex_lock(&lock);
	msleep(4000);
	mutex_unlock(&lock);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
__maybe_unused static void timer_handler(unsigned long data)
{
	printk(KERN_EMERG "xby_debug in reqsk_timer_handler\n");
}
#else
__maybe_unused static void timer_handler(struct timer_list *data)
{
	printk(KERN_EMERG "xby_debug in reqsk_timer_handler\n");
}
#endif

static int xby_test_sort_compare(const void *one, const void *two) {
    unsigned long __one = *(const unsigned long *)one;
    unsigned long __two = *(const unsigned long *)two;

    if (__one < __two) return -1;
    if (__one > __two) return 1;

    return 0;
}

__maybe_unused static void xby_test_sort(void)
{
	static unsigned long rand;
	int i;
	int count = 100000;
	unsigned long *ptr;

	ptr = vmalloc(sizeof(unsigned long) * count);
	if (!ptr)
		return;

	rand = jiffies;
	for (i = 0; i < count; i++) {
		rand = rand * 1664525L + 1013904223L;
		ptr[i] = rand >> 24;
	}

	sort(ptr, count, sizeof(unsigned long), xby_test_sort_compare, NULL);
	vfree(ptr);
}

#ifdef CENTOS_7U
struct listeners {
	struct rcu_head         rcu;
	unsigned long           masks[0];
};

struct netlink_table {
	struct rhashtable       hash;
	struct hlist_head       mc_list;
	struct listeners __rcu  *listeners;
	unsigned int            flags;
	unsigned int            groups;
	struct mutex            *cb_mutex;
	struct module           *module;
	void                    (*bind)(int group);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
	void                    (*unbind)(struct net *net, int group);
#endif
	bool                    (*compare)(struct net *net, struct sock *sock);
	int                     registered;
};

extern rwlock_t nl_table_lock;
extern struct netlink_table *nl_table;

static u64 get_timestamp(void)
{
	return local_clock() >> 30LL;  /* 2^30 ~= 10^9 */
}

/*avoid long loop in kernel*/
static bool check_timeout(unsigned long start)
{
#define TIMEOUT 2
	if (start && (get_timestamp() > (start + TIMEOUT)))
		return true;
	return false;
}

static bool my_read_lock(rwlock_t *lock)
{
	int max_times = 1000;

	while(max_times-- > 0) {
		if (read_trylock(lock))
			return true;
		udelay(1);
	}
	return false;
}

static int count_open_files(struct fdtable *fdt)
{
	int size = fdt->max_fds;
	int i;

	/* Find the last open fd */
	for (i = size / BITS_PER_LONG; i > 0; ) {
		if (fdt->open_fds[--i])
			break;
	}
	i = (i + 1) * BITS_PER_LONG;
	return i;
}

static bool sock_owned_by_task(struct sock *sk, struct task_struct *tsk)
{
	struct file *file;
	struct files_struct *files;
	struct fdtable *fdt;
	struct socket *sock;
	int i, max, err;

	if (!sk || !tsk)
		return false;

	task_lock(tsk);
	files = tsk->files;
	if (!files) {
		task_unlock(tsk);
		return false;
	}

	fdt = files_fdtable(files);
	max = count_open_files(fdt);

	for (i = 3; i < max; i++) {
		rcu_read_lock();
		file = fcheck_files(files, i);
		if (file) {
			/* File object ref couldn't be taken */
			if (file->f_mode & FMODE_PATH ||
			    !atomic_long_inc_not_zero(&file->f_count))
				file = NULL;
        }
		rcu_read_unlock();

		if (file) {
			sock = sock_from_file(file, &err);
			if (sock && sock->sk == sk) {
				fput(file);
				task_unlock(tsk);
				return true;
			}
			fput(file);
		}
	}

	task_unlock(tsk);
	return false;
}

static int show_sk_task(struct sock *sk, unsigned long start, bool *timeout)
{
	struct task_struct *tsk;
	int ret = 0;

	if (!my_read_lock(orig_tasklist_lock)) {
		printk(KERN_DEBUG "lock tasklist failed\n");
		return -EBUSY;
	}

	for_each_process(tsk) {
		if (check_timeout(start)) {
			*timeout = true;
			ret = -E2BIG;
			break;
		}

		if (sock_owned_by_task(sk, tsk)) {
			diag_trace_file_printk(&pupil_log_file,
				"sock %p owned by task %s[%d]\n",
				sk, tsk->comm, tsk->pid);
			break;
		}
	}
	read_unlock(orig_tasklist_lock);
	return ret;
}

static void show_netlink(int protocol, unsigned long start, bool *timeout)
{
	struct sock *sk;
	int list_len = 0;

	if (!my_read_lock(&nl_table_lock)) {
		printk(KERN_DEBUG "lock nl_table failed\n");
		return;
	}

	sk_for_each_bound(sk, &nl_table[protocol].mc_list) {
		list_len++;
		if (check_timeout(start)) {
			*timeout = true;
			break;
		}
		if (show_sk_task(sk, start, timeout))
			break;
	}
	read_unlock(&nl_table_lock);

	if (list_len > 0)
		diag_trace_file_printk(&pupil_log_file,
			"protocol %d mc_list: len %d\n\n",
			protocol, list_len);
}

static void show_netlinks(void)
{
	unsigned long start;
	bool timeout = false;
	int protocol;

	start = get_timestamp();

	for (protocol = 0; protocol < MAX_LINKS; protocol++) {
		show_netlink(protocol, start, &timeout);
		if (timeout)
			break;
	}

	if (timeout)
		diag_trace_file_printk(&pupil_log_file,
			"print netlink mc_list timeout %d\n");
}
#endif
#endif

static ssize_t pupil_settings_file_read(struct diag_trace_file *trace_file,
		struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	__maybe_unused int i;

	diag_trace_file_mutex_lock(trace_file);

	diag_trace_file_printk(trace_file, "[%s]\n", XBY_VERSION);
	diag_trace_file_printk(trace_file, "  xby-debug:\n");
	diag_trace_file_printk(trace_file,
		"    xby-debug1:%ld\n", atomic64_read(&xby_debug_counter1));
	diag_trace_file_printk(trace_file, 
		"    xby-debug2:%ld\n", atomic64_read(&xby_debug_counter2));
	diag_trace_file_printk(trace_file,
		"    xby-debug3:%ld\n", atomic64_read(&xby_debug_counter3));
	diag_trace_file_printk(trace_file,
		"    xby-debug4:%ld\n", atomic64_read(&xby_debug_counter4));
	diag_trace_file_printk(trace_file,
		"    xby-debug5:%ld\n", atomic64_read(&xby_debug_counter5));
#if defined(EXPERIENTIAL)
	diag_trace_file_printk(trace_file,
		"  kprobe:%s\n", kprobe_func[0] ? kprobe_func : "none");
	diag_trace_file_printk(trace_file,
		"    count:%ld\n", atomic64_read(&diag_kprobe_count));
	diag_trace_file_printk(trace_file,
		"  kretprobe:%s\n", kretprobe_func[0] ? kretprobe_func : "none");
	diag_trace_file_printk(trace_file,
		"    count:%ld\n", atomic64_read(&diag_kretprobe_count));
	diag_trace_file_printk(trace_file,
		"    time:%ld\n", atomic64_read(&diag_kretprobe_time));
	for (i = 0; i < nr_distribution; i++) {
		diag_trace_file_printk(trace_file,
			"      %ld\n", atomic64_read(&diag_pretprobe_time_distribution[i]));
	}
#endif

	diag_trace_file_mutex_unlock(trace_file);

	return 0;
}

static ssize_t pupil_settings_file_write(struct diag_trace_file *trace_file,
		struct file *file, const char __user *buf, size_t count,
		loff_t *offs)
{
	int ret;
	char cmd[255];
	char chr[256];

	if (count < 1 || count >= 255 || *offs)
		return -EINVAL;

	if (copy_from_user(chr, buf, 256))
		return -EFAULT;
	chr[255] = 0;

	ret = sscanf(chr, "%s", cmd);
	if (ret != 1) {
		return -EINVAL;
	}

	if (strcmp(cmd, "pid") == 0) {
		unsigned int id;
		struct task_struct *tsk = NULL;

		ret = sscanf(chr, "%s %d", cmd, &id);
		if (ret == 2) {
			dump_cgroups(0);
			rcu_read_lock();
			if (orig_find_task_by_vpid)
				tsk = orig_find_task_by_vpid(id);
			if (tsk) {
				diag_trace_file_printk(&pupil_log_file,
					"------------------------------------------\n");
				diag_trace_file_printk(&pupil_log_file,
					"容器内ＩＤ：%d，主机ＰＩＤ：%d，进程名称：%s, type: %d\n",
					id, tsk->pid, tsk->comm, diag_get_task_type(tsk));
			}

			rcu_read_unlock();
		}
	} else if (strcmp(cmd, "vpid") == 0) {
		int id;
		pid_t vpid;
		struct task_struct *tsk = NULL;

		ret = sscanf(chr, "%s %d", cmd, &id);
		if (ret == 2) {
			rcu_read_lock();

			if (orig_find_task_by_pid_ns)
				tsk = orig_find_task_by_pid_ns(id, &init_pid_ns);
			if (tsk) {
				vpid = task_tgid_nr_ns(tsk, task_active_pid_ns(tsk));
				diag_trace_file_printk(&pupil_log_file,
					"容器内ＩＤ：%d，主机ＰＩＤ：%d，进程名称：%s, type: %d\n",
					vpid, id, tsk->comm, diag_get_task_type(tsk));
			}

			rcu_read_unlock();
		}
	}
	else if (strcmp(cmd, "debug_trace_printk") == 0) {
		ret = sscanf(chr, "%s %d", cmd, &sysctl_debug_trace_printk);
	}
	else if (strcmp(cmd, "force-printk") == 0) {
		ret = sscanf(chr, "%s %d", cmd, &sysctl_force_printk);
#if defined(EXPERIENTIAL)
	} else if (strcmp(cmd, "stack") == 0) {
		unsigned int id;
		struct task_struct *tsk = NULL;

		ret = sscanf(chr, "%s %d", cmd, &id);
		if (ret == 2) {
			rcu_read_lock();
			if (orig_find_task_by_vpid)
				tsk = orig_find_task_by_vpid(id);
			if (tsk) {
				char cgroup_buf[255];
				unsigned long backtrace[BACKTRACE_DEPTH];
				unsigned long flags;

				get_task_struct(tsk);
				diag_cgroup_name(tsk, cgroup_buf, 255, 0);
				diag_trace_file_spin_lock(&pupil_log_file, flags);
				diag_trace_file_printk_nolock(&pupil_log_file,
					"%s/%s	%d	[%03d]	采样命中\n",
					cgroup_buf, tsk->comm, tsk->pid, 0);
				diagnose_trace_file_nolock_stack_trace_unfold(8, &pupil_log_file, tsk, backtrace);
				diagnose_trace_file_nolock_stack_trace_unfold_user_tsk(8, 0, &pupil_log_file, tsk, backtrace);
				diag_trace_file_printk_nolock(&pupil_log_file, "\n");
				diag_trace_file_spin_unlock(&pupil_log_file, flags);
				put_task_struct(tsk);
			} else
				rcu_read_unlock();
		}
#endif
	} else if (strcmp(cmd, "process-chain") == 0) {
		unsigned int id;
		struct task_struct *tsk = NULL;

		ret = sscanf(chr, "%s %d", cmd, &id);
		if (ret == 2) {
			rcu_read_lock();
			if (orig_find_task_by_vpid)
				tsk = orig_find_task_by_vpid(id);
			if (tsk) {
				get_task_struct(tsk);
				diag_trace_file_printk(&pupil_log_file,
					"------------------------------------------\n");
				diag_trace_file_printk(&pupil_log_file,
					"ＩＤ：%d，主机ＰＩＤ：%d，进程名称：%s\n",
					id, tsk->pid, tsk->comm);
				diag_trace_file_printk(&pupil_log_file,
					"------------------------------------------\n");
				trace_file_cgroups_tsk(0, &pupil_log_file, tsk);
				rcu_read_unlock();
				diag_trace_file_printk(&pupil_log_file,
					"------------------------------------------\n");
				diag_trace_file_process_chain_cmdline(0, &pupil_log_file, tsk);
				put_task_struct(tsk);
			} else
				rcu_read_unlock();
		}
	}
	else if (strcmp(cmd, "irq-loop") == 0) {
		int i, ms;
		u64 now;
		u64 last;

		ret = sscanf(chr, "%s %d", cmd, &ms);
		if (ret != 2)
			return -EINVAL;

		local_irq_disable();
		last = sched_clock() / 1000 / 1000;
		for (i = 0; i < ms; i++) {
			mdelay(1);
			now = sched_clock() / 1000 / 1000;
			if (now - last > 5)
				diag_trace_file_printk(&pupil_log_file,
					"xby-debug in irq-loop, now is %llu, last is %llu\n", now, last);

			last = now;
		}
		local_irq_enable();
	}
#if defined(EXPERIENTIAL) && !defined(XBY_UBUNTU_1604)
	else if (strcmp(cmd, "mdelay") == 0) {
		int i, ms;

		ret = sscanf(chr, "%s %d", cmd, &ms);
		if (ret != 2)
			return -EINVAL;

		for (i = 0; i < ms; i++)
			mdelay(1);
	}
	else if (strcmp(cmd, "print") == 0) {
		char sub_cmd[255];

		ret = sscanf(chr, "%s %s", cmd, sub_cmd);
		if (ret == 2) {
			if (strcmp(sub_cmd, "process-chain") == 0) {
				diag_print_process_chain(0, current);
			} else if (strcmp(sub_cmd, "partitions") == 0) {
				diag_printk_all_partitions();
			} else if (strcmp(sub_cmd, "cgroups") == 0) {
				dump_cgroups(0);
			}
#ifdef CENTOS_7U
			else if (strcmp(sub_cmd, "netlink") == 0) {
				show_netlinks();
			}
#endif
		}
	} else if (strcmp(cmd, "hook-mlx") == 0) {
		hook_kprobe(&kprobe_mlx5_eq_int, "mlx5_eq_int",
					kprobe_mlx5_eq_int_pre, NULL);
	} else if (strcmp(cmd, "unhook-mlx") == 0) {
		unhook_kprobe(&kprobe_mlx5_eq_int);
	} else if (strcmp(cmd, "kprobe") == 0) {
		ret = sscanf(chr, "%s %s", cmd, kprobe_func);
		unhook_kprobe(&kprobe_pupil);
		atomic64_set(&diag_kprobe_count, 0);
		if ((ret == 2) && (strcmp(kprobe_func, "none") != 0))
			hook_kprobe(&kprobe_pupil, kprobe_func,
					kprobe_pupil_pre, NULL);
	} else if (strcmp(cmd, "kprobe-verbose") == 0) {
		ret = sscanf(chr, "%s %d", cmd, &kprobe_verbose);
		
		if (ret != 2)
			return -EINVAL;
	} else if (strcmp(cmd, "kretprobe") == 0) {
		if (kretprobe_enabled)
			kretprobe_exit();
		ret = sscanf(chr, "%s %s", cmd, kretprobe_func);
		if ((ret == 2) && (strcmp(kretprobe_func, "none") != 0))
			kretprobe_init();
	} else if (strcmp(cmd, "kretprobe-verbose") == 0) {
		ret = sscanf(chr, "%s %d", cmd, &kretprobe_verbose);
		
		if (ret != 2)
			return -EINVAL;
	} else if (strcmp(cmd, "xby-debug") == 0) {
		char sub_cmd[255];

		ret = sscanf(chr, "%s %s", cmd, sub_cmd);
        if (ret == 2) {
			if (strcmp(sub_cmd, "wait") == 0) {
				struct task_struct *tsk;

				tsk = kthread_run(test_thread, NULL, "xby_test");
			} else if (strcmp(sub_cmd, "cgroups") == 0) {
				dump_cgroups(0);
			} else if (strcmp(sub_cmd, "mutex") == 0) {
				test_mutex();
			} else if (strcmp(sub_cmd, "cond_resched") == 0) {
				int i;
				for (i = 0; i < 60 * 1000; i++) {
					cond_resched();
					mdelay(1);
				}
			} else if (strcmp(sub_cmd, "call-rcu") == 0) {
#if 0
				int i;
				
				for (i = 0; i < 100000; i++) {
					xby_debug_rcu.seq = 0;
					call_rcu(&xby_debug_rcu.rcu, xby_debug_rcu_free);
					//printk("call_rcu step 1\n");
					xby_debug_rcu.seq = 1;
					xby_debug_rcu2.seq = 10;
					//call_rcu(&xby_debug_rcu2.rcu, xby_debug_rcu_free);
					printk("call_rcu step 2\n");
					call_rcu(&xby_debug_rcu.rcu, xby_debug_rcu_free);
					//printk("call_rcu step 3\n");
				}
				printk("call_rcu step 1\n");
				xby_debug_rcu2.seq = 9999;
				call_rcu(&xby_debug_rcu2.rcu, xby_debug_rcu_free);
				printk("call_rcu step 2\n");
#else
				//xby_debug_rcu.seq = 0;
				//call_rcu(&xby_debug_rcu.rcu, xby_debug_rcu_free);
#endif

			} else if (strcmp(sub_cmd, "rcu-barrier") == 0) {
				rcu_barrier();
				printk("rcu_barrier step 1\n");
			} else if (strcmp(sub_cmd, "dfree") == 0) {
				void *p;

				p = kmalloc(100, GFP_KERNEL);

				kfree(p);
				kfree(p);
				printk("dfree ok\n");
			} else if (strcmp(sub_cmd, "timer") == 0) {
				static struct timer_list timer;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
				timer_setup(&timer, timer_handler, 0);
#else
				setup_timer(&timer, timer_handler, 0);
#endif
				mod_timer(&timer, jiffies + 100);
				msleep(10);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
				timer_setup(&timer, timer_handler, 0);
#else
				setup_timer(&timer, timer_handler, 0);
#endif
				mod_timer(&timer, jiffies + 100);
			} else if (strcmp(sub_cmd, "kmalloc") == 0) {
				static unsigned long ptrs[1024 * 1024];
				int i;
				
				for (i = 0; i < 1024 * 1024; i++)
					ptrs[i] = __get_free_page(GFP_ATOMIC);
				mdelay(10 * 1000);
				for (i = 0; i < 1024 * 1024; i++)
					free_page(ptrs[i]);
			} else if (strcmp(sub_cmd, "sort") == 0) {
				diag_trace_file_printk(&pupil_log_file, "sort start\n");
				xby_test_sort();
				diag_trace_file_printk(&pupil_log_file, "sort end\n");
			} else if (strcmp(sub_cmd, "kfree") == 0) {
				static void *ptrs[100 * 1024];
				int i;

				diag_trace_file_printk(&pupil_log_file, "kmalloc start(100 * 1024 times)\n");
				for (i = 0; i < 100 * 1024; i++)
					ptrs[i] = kmalloc(6400, GFP_ATOMIC);
				diag_trace_file_printk(&pupil_log_file, "kmalloc stop\n");
				diag_trace_file_printk(&pupil_log_file, "kfree start\n");
				for (i = 0; i < 100 * 1024; i++)
					kfree(ptrs[i]);
				diag_trace_file_printk(&pupil_log_file, "kfree stop\n");
			} else if (strcmp(sub_cmd, "memcpy") == 0) {
				void *mem_src = vmalloc(10 * 1024 * 1024);
				void *mem_dst = vmalloc(10 * 1024 * 1024);

				if (mem_src && mem_dst) {
					diag_trace_file_printk(&pupil_log_file, "memcpy 10M start\n");
					memcpy(mem_dst, mem_src, 10* 1024 * 1024);
					diag_trace_file_printk(&pupil_log_file, "memcpy end\n");
					vfree(mem_src);
					vfree(mem_dst);
				}
			} else if (strcmp(sub_cmd, "trace-buffer") == 0) {
				struct diag_trace_buffer buffer;
				int i;

				init_diag_trace_buffer(&buffer, 20 * 1024);
				for (i = 0; i < 10000; i++) {
					diag_trace_buffer_printk(&buffer, "xby-debug, i is %d\n", i);
					diag_trace_file_printk(&pupil_log_file, "xby-debug, %d\n", i);
				}
				backup_diag_trace_buffer(&buffer);
				for (i = 0; i < buffer.product.len; i++)
					diag_trace_file_printk(&pupil_log_file, "%c\n", buffer.product.data[i]);
				diag_trace_file_printk(&pupil_log_file, "\n");
				destroy_diag_trace_buffer(&buffer);
			} else if (strcmp(sub_cmd, "page-fault") == 0) {
				unsigned long flags;
				unsigned long trace_buf[BACKTRACE_DEPTH];

				if (!down_read_trylock(&current->mm->mmap_sem)) {
					return count;
				}

				diag_trace_file_spin_lock(&pupil_log_file, flags);
				diag_trace_file_printk_nolock(&pupil_log_file, "\n");
				diag_trace_file_printk_nolock(&pupil_log_file,
					"%s	%d	[%03d]	缺页命中\n",
					current->comm, current->pid, 0);
				diagnose_trace_file_nolock_stack_trace_unfold(8, &pupil_log_file, current, trace_buf);
				diagnose_trace_file_nolock_stack_trace_unfold_user(8, &pupil_log_file, trace_buf);
				diag_trace_file_spin_unlock(&pupil_log_file, flags);

				up_read(&current->mm->mmap_sem);
			} else if (strcmp(sub_cmd, "cpuacct") == 0) {
#if KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE
				char buf[256];
				struct cpuacct *acct;
				struct cgroup *cgroup;
				struct cgroup *tsk_cgroup;

				tsk_cgroup = diag_cpuacct_cgroup_tsk(current);
				acct = diag_find_cpuacct_name("staragent");
				cgroup = cpuacct_to_cgroup(acct);
				diag_cpuacct_cgroup_name_tsk(current, buf, 255);
#endif
			}
		}
	}
#endif

	return count;
}

static ssize_t pupil_log_file_read(struct diag_trace_file *trace_file,
		struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	return 0;
}

static ssize_t pupil_log_file_write(struct diag_trace_file *trace_file,
		struct file *file, const char __user *buf, size_t count,
		loff_t *offs)
{
	return 0;
}

static void save_task_info(struct task_struct *tsk, struct pupil_task_detail *detail)
{
	detail->et_type = et_pupil_task;
	do_gettimeofday(&detail->tv);
	detail->pid = tsk->pid;
	detail->proc_chains.chains[0][0] = 0;
	dump_proc_chains_simple(tsk, &detail->proc_chains);
	diag_task_brief(tsk, &detail->task);
	diag_task_kern_stack(tsk, &detail->kern_stack);
	diag_task_user_stack(tsk, &detail->user_stack);
	diag_task_raw_stack(tsk, &detail->raw_stack);
}

static int get_task_info(int nid)
{
	static struct pupil_task_detail detail;
	struct task_struct *tsk;
	struct task_struct *leader;
	int ret;
	unsigned long flags;
	pid_t id = (pid_t)nid;

	ret = alloc_diag_variant_buffer(&pupil_variant_buffer);
	if (ret)
		return -ENOMEM;
	pupil_alloced = 1;

	rcu_read_lock();
	tsk = NULL;
	if (orig_find_task_by_vpid)
		tsk = orig_find_task_by_vpid(id);
	if (!tsk) {
		ret = -EINVAL;
		rcu_read_unlock();
		return ret;
	}

	leader = tsk->group_leader;
	if (leader == NULL || leader->exit_state == EXIT_ZOMBIE){
		ret = -EINVAL;
		rcu_read_unlock();
		return ret;
	}

	get_task_struct(tsk);
	rcu_read_unlock();
	save_task_info(tsk, &detail);
	put_task_struct(tsk);

	diag_variant_buffer_spin_lock(&pupil_variant_buffer, flags);
	diag_variant_buffer_reserve(&pupil_variant_buffer,
			sizeof(struct pupil_task_detail));
	diag_variant_buffer_write_nolock(&pupil_variant_buffer,
			&detail, sizeof(struct pupil_task_detail));
	diag_variant_buffer_seal(&pupil_variant_buffer);
	diag_variant_buffer_spin_unlock(&pupil_variant_buffer, flags);

	return ret;
}

int pupil_syscall(struct pt_regs *regs, long id)
{
	int ret = 0;
	int __user *ptr_len;
	void __user *buf;
	size_t size;
	unsigned int pid;

	switch (id) {
	case DIAG_PUPIL_TASK_DUMP:
		ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		buf = (void __user *)SYSCALL_PARAM2(regs);
		size = (size_t)SYSCALL_PARAM3(regs);

		if (!pupil_alloced) {
			ret = -EINVAL;
		} else {
			ret = copy_to_user_variant_buffer(&pupil_variant_buffer, ptr_len, buf, size);
			record_dump_cmd("task-info");
		}
		break;
	case DIAG_PUPIL_TASK_PID:
		pid = (unsigned int)SYSCALL_PARAM1(regs);
		ret = get_task_info(pid);
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_pupil_task(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_ioctl_dump_param dump_param;
	int id = 0;

	switch (cmd) {
	case CMD_PUPIL_TASK_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));

		if (!pupil_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			ret = copy_to_user_variant_buffer(&pupil_variant_buffer, dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len); 
			record_dump_cmd("task-info");
		}
		break;
	case CMD_PUPIL_TASK_PID:
		ret = copy_from_user(&id, (void *)arg, sizeof(int));

		if (!ret) {
			ret = get_task_info(id);
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_pupil_init(void)
{
	int ret;

	init_diag_variant_buffer(&pupil_variant_buffer, 5 * 1024 * 1024);

	ret = init_diag_trace_file(&pupil_settings_file,
		"ali-linux/diagnose/pupil-settings",
		20 * 1024,
		pupil_settings_file_read,
		pupil_settings_file_write);

	if (ret)
		goto out_settings_file;

	ret = init_diag_trace_file(&pupil_log_file,
		"ali-linux/diagnose/pupil-log",
		4 * 1024 * 1024,
		pupil_log_file_read,
		pupil_log_file_write);
	if (ret)
		goto out_trace_file;

	return 0;

out_trace_file:
	destroy_diag_trace_file(&pupil_settings_file);
out_settings_file:
	return ret;
}

void diag_pupil_exit(void)
{
	destroy_diag_trace_file(&pupil_settings_file);

#if defined(EXPERIENTIAL)
	if (kprobe_func[0] && (strcmp(kprobe_func, "none") != 0))
		unhook_kprobe(&kprobe_pupil);
	if (kretprobe_enabled)
		kretprobe_exit();
#endif

	destroy_diag_trace_file(&pupil_log_file);
	destroy_diag_variant_buffer(&pupil_variant_buffer);
}
