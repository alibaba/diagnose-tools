/*
 * Linux内核诊断工具--内核态fs-cache功能实现
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
#include <linux/rbtree.h>
#include <linux/cpu.h>
#include <linux/syscalls.h>
#include <linux/percpu_counter.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#include <linux/context_tracking.h>
#endif
#include <linux/sort.h>
#include <linux/fsnotify.h>
#include <linux/backing-dev.h>
#include <linux/aio.h>
#include <linux/fdtable.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0) && LINUX_VERSION_CODE <= KERNEL_VERSION(4, 10, 0)
#include <linux/iomap.h>
#endif

#include <asm/irq_regs.h>
#include <asm/unistd.h>

#if !defined(DIAG_ARM64)
#include <asm/asm-offsets.h>
#endif

#include "internal.h"
#include "pub/trace_file.h"
#include "pub/fs_utils.h"
#include "uapi/fs_cache.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0) && LINUX_VERSION_CODE <= KERNEL_VERSION(4, 10, 0) \
	&& !defined(CENTOS_3_10_514)
static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_fs_cache_settings fs_cache_settings = {
	.top = 100,
};

static unsigned long fs_cache_alloced = 0;
static struct diag_variant_buffer fs_cache_variant_buffer;

struct inode_info {
	struct list_head list;
	struct inode *f_inode;
	u64 f_size;
	u64 cache_nr_pages;
	char path_name[DIAG_PATH_LEN];
};

#define MAX_FILE_COUNT 300000
static struct inode_info *inode_buf[MAX_FILE_COUNT];
static int inode_count = 0;
static DEFINE_MUTEX(inode_mutex);

static void (*orig___iget)(struct inode *inode);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
static void (*orig_iterate_supers)(void (*f)(struct super_block *, void *), void *arg);
#else
static void (*orig_iterate_supers)(void (*f)(struct super_block *, void *), void *arg);
#if !defined(CENTOS_3_10_862) && !defined(CENTOS_3_10_957) && !defined(CENTOS_3_10_1062) \
	&& !defined(CENTOS_3_10_1127)
static spinlock_t *orig_inode_sb_list_lock;
#endif
#endif

static int need_trace(struct inode *inode)
{
	int pages = fs_cache_settings.size >> PAGE_SHIFT;

	if (!fs_cache_settings.activated)
		return 0;

	if (!inode)
		return 0;

	if (pages == 0)
		pages = 1024;
	if (inode->i_mapping && inode->i_mapping->nrpages < pages)
		return 0;

	return 1;
}

static struct inode_info *alloc_inode_info(struct inode *inode)
{
	struct inode_info *info;

	if (inode == NULL)
		return NULL;

	info = kmalloc(sizeof(struct inode_info), GFP_NOFS | __GFP_ZERO);
	if (info) {
		info->f_inode = inode;
		info->f_size = inode->i_size;
		if (inode->i_mapping)
			info->cache_nr_pages = inode->i_mapping->nrpages;
		else
			info->cache_nr_pages = 0;
	}

	return info;
}

static int trace_inode(struct inode *inode)
{
	struct inode_info *info;

	if (!need_trace(inode))
		return 0;

	if (inode_count >= MAX_FILE_COUNT)
		return 0;

	info = alloc_inode_info(inode);
	if (info) {
		inode_buf[inode_count] = info;
		inode_count++;
		diag_inode_short_name(inode, info->path_name, DIAG_PATH_LEN);
	}

	return 0;
}

static int diag_compare_inode(const void *one, const void *two)
{
	struct inode_info *__one = *(struct inode_info **)one;
	struct inode_info *__two = *(struct inode_info **)two;

	if (__one->cache_nr_pages > __two->cache_nr_pages)
		return -1;
	if (__one->cache_nr_pages < __two->cache_nr_pages)
		return 1;

	return 0;
}

static void dump_sb(struct super_block *sb, void *arg)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	struct inode *inode, *toput_inode = NULL;

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);
		if ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) ||
		    (inode->i_mapping->nrpages == 0)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		orig___iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(&sb->s_inode_list_lock);

		trace_inode(inode);

		iput(toput_inode);
		toput_inode = inode;

		spin_lock(&sb->s_inode_list_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	iput(toput_inode);
#else
	struct inode *inode, *toput_inode = NULL;

#if !defined(CENTOS_3_10_862) && !defined(CENTOS_3_10_957) && !defined(CENTOS_3_10_1062) \
	&& !defined(CENTOS_3_10_1127)
	spin_lock(orig_inode_sb_list_lock);
#else
	spin_lock(&sb->s_inode_list_lock);
#endif
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);
		if ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) ||
		    (inode->i_mapping->nrpages == 0)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		orig___iget(inode);
		spin_unlock(&inode->i_lock);
#if !defined(CENTOS_3_10_862) && !defined(CENTOS_3_10_957) && !defined(CENTOS_3_10_1062) \
	&& !defined(CENTOS_3_10_1127)
		spin_unlock(orig_inode_sb_list_lock);
#else
		spin_unlock(&sb->s_inode_list_lock);
#endif

		trace_inode(inode);

		iput(toput_inode);
		toput_inode = inode;
#if !defined(CENTOS_3_10_862) && !defined(CENTOS_3_10_957) && !defined(CENTOS_3_10_1062) \
	&& !defined(CENTOS_3_10_1127)
		spin_lock(orig_inode_sb_list_lock);
#else
		spin_lock(&sb->s_inode_list_lock);
#endif
	}
#if !defined(CENTOS_3_10_862) && !defined(CENTOS_3_10_957) && !defined(CENTOS_3_10_1062) \
	&& !defined(CENTOS_3_10_1127)
		spin_unlock(orig_inode_sb_list_lock);
#else
		spin_unlock(&sb->s_inode_list_lock);
#endif
	iput(toput_inode);
#endif
}

static void do_dump(void)
{
	struct inode_info *inode_info;
	int i;
	unsigned long flags;
	static struct fs_cache_detail detail;

	mutex_lock(&inode_mutex);
	inode_count = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	orig_iterate_supers(dump_sb, &fs_cache_variant_buffer);
#else
	orig_iterate_supers(dump_sb, &fs_cache_variant_buffer);
#endif

	sort(&inode_buf[0], (size_t)inode_count, (size_t)sizeof(struct inode_info *),
		&diag_compare_inode, NULL);

	detail.id = get_cycles();
	for (i = 0; i < min_t(int, inode_count, fs_cache_settings.top); i++) {
		inode_info = inode_buf[i];

		detail.et_type = et_fs_cache_detail;
		detail.seq = i;
		detail.f_inode = inode_info->f_inode;
		detail.f_size = inode_info->f_size;
		detail.cache_nr_pages = inode_info->cache_nr_pages;
		diag_inode_full_name(inode_info->f_inode, detail.path_name, DIAG_PATH_LEN);
		if (detail.path_name[0] == 0) {
			strncpy(detail.path_name, inode_info->path_name, DIAG_PATH_LEN);
		}
		diag_variant_buffer_spin_lock(&fs_cache_variant_buffer, flags);
		diag_variant_buffer_reserve(&fs_cache_variant_buffer, sizeof(struct fs_cache_detail));
		diag_variant_buffer_write_nolock(&fs_cache_variant_buffer, &detail, sizeof(struct fs_cache_detail));
		diag_variant_buffer_seal(&fs_cache_variant_buffer);
		diag_variant_buffer_spin_unlock(&fs_cache_variant_buffer, flags);
	}

	for (i = 0; i < inode_count; i++)
	{
		inode_info = inode_buf[i];
		kfree(inode_info);
	}

	mutex_unlock(&inode_mutex);
}

static void drop_sb(struct super_block *sb, void *arg)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	struct inode *inode, *toput_inode = NULL;

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);
		if ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) ||
		    (inode->i_mapping->nrpages == 0)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		orig___iget(inode);
		spin_unlock(&inode->i_lock);
		spin_unlock(&sb->s_inode_list_lock);

		if (inode == arg) {
			if (inode->i_mapping)
				invalidate_mapping_pages(inode->i_mapping, 0, -1);			
		}

		iput(toput_inode);
		toput_inode = inode;

		spin_lock(&sb->s_inode_list_lock);

		if (inode == arg)
			break;
	}
	spin_unlock(&sb->s_inode_list_lock);
	iput(toput_inode);
#else
	struct inode *inode, *toput_inode = NULL;

#if !defined(CENTOS_3_10_862) && !defined(CENTOS_3_10_957) && !defined(CENTOS_3_10_1062) \
	&& !defined(CENTOS_3_10_1127)
	spin_lock(orig_inode_sb_list_lock);
#else
	spin_lock(&sb->s_inode_list_lock);
#endif
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		spin_lock(&inode->i_lock);
		if ((inode->i_state & (I_FREEING|I_WILL_FREE|I_NEW)) ||
		    (inode->i_mapping->nrpages == 0)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		orig___iget(inode);
		spin_unlock(&inode->i_lock);
#if !defined(CENTOS_3_10_862) && !defined(CENTOS_3_10_957) && !defined(CENTOS_3_10_1062) \
	&& !defined(CENTOS_3_10_1127)
		spin_unlock(orig_inode_sb_list_lock);
#else
		spin_unlock(&sb->s_inode_list_lock);
#endif
		if (inode == arg) {
			if (inode->i_mapping)
				invalidate_mapping_pages(inode->i_mapping, 0, -1);			
		}

		iput(toput_inode);
		toput_inode = inode;
#if !defined(CENTOS_3_10_862) && !defined(CENTOS_3_10_957) && !defined(CENTOS_3_10_1062) \
	&& !defined(CENTOS_3_10_1127)
		spin_lock(orig_inode_sb_list_lock);
#else
		spin_lock(&sb->s_inode_list_lock);
#endif

		if (inode == arg)
			break;
	}
#if !defined(CENTOS_3_10_862) && !defined(CENTOS_3_10_957) && !defined(CENTOS_3_10_1062) \
	&& !defined(CENTOS_3_10_1127)
	spin_unlock(orig_inode_sb_list_lock);
#else
	spin_unlock(&sb->s_inode_list_lock);
#endif
	iput(toput_inode);
#endif
}

static void do_drop(void *inode)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	orig_iterate_supers(drop_sb, inode);
#else
	orig_iterate_supers(drop_sb, inode);
#endif
}

static int __activate_fs_cache(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&fs_cache_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	fs_cache_alloced = 1;

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_fs_cache(void)
{
	u64 nr_running;

	synchronize_sched();
	msleep(10);
	nr_running = atomic64_read(&diag_nr_running);
	while (nr_running > 0)
	{
		msleep(10);
		nr_running = atomic64_read(&diag_nr_running);
	}
}

int activate_fs_cache(void)
{
	if (!fs_cache_settings.activated)
		fs_cache_settings.activated = __activate_fs_cache();

	return fs_cache_settings.activated;
}

int deactivate_fs_cache(void)
{
	if (fs_cache_settings.activated)
		__deactivate_fs_cache();
	fs_cache_settings.activated = 0;

	return 0;
}

long diag_ioctl_fs_cache(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_fs_cache_settings settings;
	struct diag_ioctl_dump_param dump_param;
	void *inode_addr;

	switch (cmd) {
	case CMD_FS_CACHE_SET:
		if (fs_cache_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_fs_cache_settings));
			if (!ret) {
				fs_cache_settings = settings;
			}
		}
		break;
	case CMD_FS_CACHE_SETTINGS:
		settings = fs_cache_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_fs_cache_settings));
		break;
	case CMD_FS_CACHE_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));
		if (!fs_cache_alloced) {
			ret = -EINVAL;
		} if (!ret) {
			do_dump();
			ret = copy_to_user_variant_buffer(&fs_cache_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("fs-cache");
		}
		break;
	case CMD_FS_CACHE_DROP:
		ret = copy_from_user(&inode_addr, (void *)arg, sizeof(unsigned long));
		if (!ret) {
			do_drop(inode_addr);
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

static int lookup_syms(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	LOOKUP_SYMS(iterate_supers);
#else
	LOOKUP_SYMS(iterate_supers);

#if !defined(CENTOS_3_10_862) && !defined(CENTOS_3_10_957) && !defined(CENTOS_3_10_1062) \
	&& !defined(CENTOS_3_10_1127)
	LOOKUP_SYMS(inode_sb_list_lock);
#endif

#endif
	LOOKUP_SYMS(__iget);

	return 0;
}

int diag_fs_cache_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&fs_cache_variant_buffer, 2 * 1024 * 1024);
	if (fs_cache_settings.activated)
		fs_cache_settings.activated = __activate_fs_cache();

	return 0;
}

void diag_fs_cache_exit(void)
{
	if (fs_cache_settings.activated)
		deactivate_fs_cache();
	fs_cache_settings.activated = 0;

	destroy_diag_variant_buffer(&fs_cache_variant_buffer);
}
#else
int diag_fs_cache_init(void)
{
	return 0;
}

void diag_fs_cache_exit(void)
{
	//
}
#endif

