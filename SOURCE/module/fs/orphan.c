/*
 * Linux内核诊断工具--内核态fs-orphan功能
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/delay.h>

#include "pub/fs_utils.h"
#include "internal.h"
#include "mm_tree.h"

#include "uapi/fs_orphan.h"

/**
 * 注意：这里暂时不支持5U/6U，版本过多，可能有坑。
 */
#if KERNEL_VERSION(2, 6, 32) <= LINUX_VERSION_CODE \
	&& KERNEL_VERSION(2, 6, 32) > LINUX_VERSION_CODE \
	|| (KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE \
		&& KERNEL_VERSION(3, 11, 0) > LINUX_VERSION_CODE) \
	|| (KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE\
		&& KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE) \
	|| (KERNEL_VERSION(4, 19, 0) <= LINUX_VERSION_CODE\
		&& KERNEL_VERSION(4, 20, 0) > LINUX_VERSION_CODE)

#include "ext4.h"

#if !defined(EXT4_SUPER_MAGIC)
#define EXT4_SUPER_MAGIC	0xEF53
#endif

/* Block device name. The length of super block informational name is 32. */
#define DEV_NAME_SIZE	32

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_fs_orphan_settings fs_orphan_settings;

static unsigned long fs_orphan_alloced;
static struct diag_variant_buffer fs_orphan_variant_buffer;

struct cb_info {
	struct radix_tree_root orphan_tree;
};

static void *cb_file(struct task_struct *tsk, struct file *file, void *data)
{
	struct inode *inode;
	struct inode *found;
	struct cb_info *cb_info = (struct cb_info *)data;

	if (file && file->f_path.dentry && file->f_path.dentry->d_inode) {
		inode = file->f_path.dentry->d_inode;

		found = radix_tree_lookup(&cb_info->orphan_tree, (unsigned long)inode);
		if (inode == found) {
			static struct fs_orphan_detail detail;
			unsigned long flags;

			detail.et_type = et_fs_orphan_detail;
			diag_inode_brief(inode, &detail.inode);
			diag_task_brief(tsk, &detail.task);
			dump_proc_chains_simple(tsk, &detail.proc_chains);
			diag_get_file_path(file, detail.path_name, 255);

			diag_variant_buffer_spin_lock(&fs_orphan_variant_buffer, flags);
			diag_variant_buffer_reserve(&fs_orphan_variant_buffer, sizeof(struct fs_orphan_detail));
			diag_variant_buffer_write_nolock(&fs_orphan_variant_buffer, &detail, sizeof(struct fs_orphan_detail));
			diag_variant_buffer_seal(&fs_orphan_variant_buffer);
			diag_variant_buffer_spin_unlock(&fs_orphan_variant_buffer, flags);

			return tsk;
		}
	}

	return NULL;
}

static void fs_orphan_task(struct cb_info *cb_info)
{
	struct task_struct *tsk;
	struct radix_tree_root proc_tree;
	struct task_struct *batch[NR_BATCH];
	int nr_found;
	unsigned long pos;
	int i;

	INIT_RADIX_TREE(&proc_tree, GFP_ATOMIC);
	for_each_process(tsk) {
		radix_tree_insert(&proc_tree, (unsigned long)tsk, tsk);
		get_task_struct(tsk);
	}

	pos = 0;
	do {
		nr_found = radix_tree_gang_lookup(&proc_tree, (void **)batch, pos, NR_BATCH);
		for (i = 0; i < nr_found; i++) {
			tsk = batch[i];
			radix_tree_delete(&proc_tree, (unsigned long)tsk);
			pos = (unsigned long)tsk + 1;
			for_each_files_task(tsk, cb_file, cb_info);
			put_task_struct(tsk);
		}
	} while (nr_found > 0);
}

static inline struct inode *orphan_list_entry(struct list_head *list)
{
	return &list_entry(list, struct ext4_inode_info, i_orphan)->vfs_inode;
}

static void fs_orphan_list(struct ext4_sb_info *sbi, struct super_block *sb)
{
	struct list_head *list = NULL;
	struct cb_info cb_info;
	struct inode *batch[NR_BATCH];
	int nr_found;
	unsigned long pos;
	struct inode *inode;
	int i;

	INIT_RADIX_TREE(&cb_info.orphan_tree, GFP_ATOMIC);
	list_for_each(list, &sbi->s_orphan) {
		struct inode *inode = orphan_list_entry(list);
		static struct fs_orphan_summary summary;
		unsigned long flags;

		summary.et_type = et_fs_orphan_summary;
		diag_inode_brief(inode, &summary.inode);

		diag_variant_buffer_spin_lock(&fs_orphan_variant_buffer, flags);
		diag_variant_buffer_reserve(&fs_orphan_variant_buffer, sizeof(struct fs_orphan_summary));
		diag_variant_buffer_write_nolock(&fs_orphan_variant_buffer, &summary, sizeof(struct fs_orphan_summary));
		diag_variant_buffer_seal(&fs_orphan_variant_buffer);
		diag_variant_buffer_spin_unlock(&fs_orphan_variant_buffer, flags);

		radix_tree_insert(&cb_info.orphan_tree, (unsigned long)inode, inode);
	}

	fs_orphan_task(&cb_info);

	pos = 0;
	do {
		nr_found = radix_tree_gang_lookup(&cb_info.orphan_tree, (void **)batch, pos, NR_BATCH);
		for (i = 0; i < nr_found; i++) {
			inode = batch[i];
			radix_tree_delete(&cb_info.orphan_tree, (unsigned long)inode);
			pos = (unsigned long)inode + 1;
		}
	} while (nr_found > 0);
}

static int fs_orphan_show(void)
{
	struct list_head *sym_super_blocks = NULL;
	spinlock_t *sym_sb_lock = NULL;
	struct super_block *sb = NULL;
	struct ext4_sb_info *sbi = NULL;
	int retval = 0;
	struct super_block *super = NULL;

	sym_super_blocks = (struct list_head *)diag_kallsyms_lookup_name("super_blocks");
	if (sym_super_blocks == NULL) {
		printk(KERN_WARNING "Failed to lookup super_blocks,"
			        " check configuration CONFIG_KALLSYMS_ALL\n");
		retval = -ENOENT;
		goto out;
	}

	sym_sb_lock = (spinlock_t *)diag_kallsyms_lookup_name("sb_lock");
	if (sym_sb_lock == NULL) {
		printk(KERN_WARNING "Failed to lookup sb_lock.\n");
		retval = -ENOENT;
		goto out;
	}

	spin_lock(sym_sb_lock);
	list_for_each_entry(sb, sym_super_blocks, s_list) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
		if (hlist_unhashed(&sb->s_instances))
			continue;
#endif
		if (sb->s_magic != EXT4_SUPER_MAGIC)
			continue;
		if (strcmp(sb->s_id, fs_orphan_settings.devname))
			continue;

		sbi = (struct ext4_sb_info *)sb->s_fs_info;
		super = sb;
		break;
	}
	spin_unlock(sym_sb_lock);

	if (sbi == NULL || super == NULL) {
		retval = -EINVAL;
		goto out;
	}

	fs_orphan_list(sbi, super);

out:
	return retval;
}

int fs_orphan_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_fs_orphan_settings settings;

	switch (id) {
	case DIAG_FS_ORPHAN_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_fs_orphan_settings)) {
			ret = -EINVAL;
		} else if (fs_orphan_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				fs_orphan_settings = settings;
			}
		}
		break;
	case DIAG_FS_ORPHAN_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_fs_orphan_settings)) {
			ret = -EINVAL;
		} else {
			settings = fs_orphan_settings;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_FS_ORPHAN_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!fs_orphan_alloced) {
			ret = -EINVAL;
		} else {
			fs_orphan_show();
			ret = copy_to_user_variant_buffer(&fs_orphan_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("fs-orphan");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_fs_orphan(unsigned int cmd, unsigned long arg)
{
	int ret = -EINVAL;
	struct diag_fs_orphan_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_FS_ORPHAN_SET:
		if (fs_orphan_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_fs_orphan_settings));
			if (!ret) {
				fs_orphan_settings = settings;
			}
		}
		break;
	case CMD_FS_ORPHAN_SETTINGS:
		settings = fs_orphan_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_fs_orphan_settings));
		break;
	case CMD_FS_ORPHAN_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));
		if (!fs_orphan_alloced) {
			ret = -EINVAL;
		} else if (!ret) {
			fs_orphan_show();
			ret = copy_to_user_variant_buffer(&fs_orphan_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("fs-orphan");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}


static void clean_data(void)
{
	//
}

static int __activate_fs_orphan(void)
{
	int ret = 0;

	clean_data();

	ret = alloc_diag_variant_buffer(&fs_orphan_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	fs_orphan_alloced = 1;

	return 1;
out_variant_buffer:
	return 0;
}

int activate_fs_orphan(void)
{
	if (!fs_orphan_settings.activated)
		fs_orphan_settings.activated = __activate_fs_orphan();

	return fs_orphan_settings.activated;
}

static void __deactivate_fs_orphan(void)
{
	synchronize_sched();
	msleep(10);
	while (atomic64_read(&diag_nr_running) > 0) {
		msleep(10);
	}

	clean_data();
}

int deactivate_fs_orphan(void)
{
	if (fs_orphan_settings.activated)
		__deactivate_fs_orphan();
	fs_orphan_settings.activated = 0;

	return 0;
}

static int lookup_syms(void)
{
	//

	return 0;
}

static void jump_init(void)
{
	//
}

int diag_fs_orphan_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&fs_orphan_variant_buffer, 10 * 1024 * 1024);
	jump_init();

	if (fs_orphan_settings.activated)
		__activate_fs_orphan();

	return 0;
}

void diag_fs_orphan_exit(void)
{
	if (fs_orphan_settings.activated)
		deactivate_fs_orphan();
	fs_orphan_settings.activated = 0;
	destroy_diag_variant_buffer(&fs_orphan_variant_buffer);
}

#endif /* LINUX_VERSION */
