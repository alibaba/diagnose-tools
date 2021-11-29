#include <linux/module.h>
#include <linux/compiler.h>
#include <linux/mmzone.h>
#include <linux/memcontrol.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/mount.h>
#if KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE
#include <linux/kernfs.h>
#endif
#include <asm/delay.h>
#include "uapi/ali_diagnose.h"
#include "uapi/memcg_stats.h"
#include "pub/variant_buffer.h"
#include "internal.h"

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 9, 0)

static struct mem_cgroup * (*orig_mem_cgroup_iter)(struct mem_cgroup *,
		struct mem_cgroup *,
		struct mem_cgroup_reclaim_cookie *) = NULL;

static struct dentry * (*orig_d_find_alias)(struct inode *inode) = NULL;

static struct address_space * (*orig_page_mapping)(struct page *page) = NULL;

static struct pglist_data * (*orig_first_online_pgdat)(void) = NULL;

static struct pglist_data * (*orig_next_online_pgdat)(struct pglist_data *pgdat) = NULL;

seqlock_t * orig_mount_lock = NULL;

static struct diag_variant_buffer memcg_stats_variant_buffer;

static int memcg_stats_alloced = 0;

static atomic64_t diag_nr_running = ATOMIC64_INIT(0);

struct diag_memcg_stats_settings memcg_stats_settings = {
	.activated = 0,
	.verbose = 0,
};

static char * prepend(char **buffer, int *buflen, const char *str, int namelen)
{
    *buflen -= namelen;
    if (*buflen < 0)
        return ERR_PTR(-ENAMETOOLONG);
    *buffer -= namelen;
    memcpy(*buffer, str, namelen);
    return *buffer;
}

static void memcg_name(struct kernfs_node *kn, char *buf, unsigned int len)
{
	struct kernfs_node *parent;
	char *end, *pos;

	if (!kn || !buf)
		return;

	kernfs_get(kn);
	end = buf + len - 1;
	prepend(&end, &len, "\0", 1);
	parent = kn;
	while (parent) {
		pos = prepend(&end, &len, parent->name, strlen(parent->name));
		if (IS_ERR(pos))
			break;
		pos = prepend(&end, &len, "/", 1);
		if (IS_ERR(pos))
			break;
		if (parent == parent->parent)
			break;
		parent = parent->parent;
	}

	kernfs_put(kn);
	memmove(buf, end, strlen(end) + 1);
}

static char *__dentry_name(struct dentry *dentry, char *name)
{
    char *p = dentry_path_raw(dentry, name, PATH_MAX);
    memmove(name, p, strlen(p) + 1);

    return name;
}

static void inode_name(struct inode *ino, char *buf, unsigned int len)
{
    struct dentry *dentry;
    char *name;

    if (!ino || !buf || !len)
	    return;

    buf[0] = '\0';
    dentry = orig_d_find_alias(ino);
    if (!dentry)
        return;

    name = __getname();
    if (!name)
        return;

    __dentry_name(dentry, name);
    dput(dentry);

    strncpy(buf, name, len - 1);
    kfree(name);
}

struct mount_diag {
	struct hlist_node mnt_hash;
	struct mount_diag *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	union {
		struct rcu_head mnt_rcu;
		struct llist_node mnt_llist;
	};
#ifdef CONFIG_SMP
	struct mnt_pcp __percpu *mnt_pcp;
#else
	int mnt_count;
	int mnt_writers;
#endif
	struct list_head mnt_mounts;    /* list of children, anchored here */
	struct list_head mnt_child; /* and going through their mnt_child */
	struct list_head mnt_instance;  /* mount instance on sb->s_mounts */
};

static void mnt_dir(struct inode *ino, char *buf, unsigned int len)
{
	struct mount_diag *mnt = NULL;
	struct super_block *sb;
	struct dentry *dentry;
	char *name;

	buf[0] = '\0';
	if (!ino || !buf || !len)
		goto out;
	sb = ino->i_sb;
	if (!sb)
		goto out;

	write_seqlock(orig_mount_lock);
	if (!list_empty(&sb->s_mounts))
		mnt = list_first_entry(&sb->s_mounts, struct mount_diag,
				mnt_instance);
	write_sequnlock(orig_mount_lock);

	if (!mnt)
		goto out;
	dentry = mnt->mnt_mountpoint;
	if (!dentry)
		goto out;

	name = __getname();
	if (!name)
		goto out;

	__dentry_name(dentry, name);
	strncpy(buf, name, len - 1);
	kfree(name);

out:
	return;
}

static void diag_memcg_dump_variant_buffer(void * data, unsigned int len)
{
	unsigned long flags;

	diag_variant_buffer_spin_lock(&memcg_stats_variant_buffer, flags);
	diag_variant_buffer_reserve(&memcg_stats_variant_buffer, len);
	diag_variant_buffer_write_nolock(&memcg_stats_variant_buffer, data, len);
	diag_variant_buffer_seal(&memcg_stats_variant_buffer);
	diag_variant_buffer_spin_unlock(&memcg_stats_variant_buffer, flags);
}

static void diag_memcg_destroy_inode_stats(
		struct radix_tree_root *inode_stats_tree)
{
	struct diag_memcg_stats_detail *stats_array[NR_BATCH];
	struct diag_memcg_stats_detail *stats;
	unsigned long pos = 0;
	int nr_found;
	int i;

	do {
		nr_found = radix_tree_gang_lookup(inode_stats_tree,
				(void **)stats_array, pos, NR_BATCH);

		for (i = 0; i < nr_found; i++) {
			stats = stats_array[i];
			radix_tree_delete(inode_stats_tree, (unsigned long)stats->key);
			pos = (unsigned long)stats->key + 1;
			kfree(stats);
		}
	} while (nr_found > 0);
}

static void diag_memcg_dump_inode_stats(struct radix_tree_root *inode_stats_tree)
{
	struct radix_tree_iter iter;
	void __rcu **slot;
	struct diag_memcg_stats_detail *detail;

	radix_tree_for_each_slot(slot, inode_stats_tree, &iter, 0) {
		detail = radix_tree_deref_slot(slot);
		if (!detail || radix_tree_exception(detail)) {
			if (radix_tree_deref_retry(detail)) {
				slot = radix_tree_iter_retry(&iter);
				continue;
			}
		}

		diag_memcg_dump_variant_buffer(detail, sizeof(*detail));
		if (need_resched()) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0)
			slot = radix_tree_iter_resume(slot, &iter);
#else
			slot = radix_tree_iter_next(&iter);
#endif
			cond_resched();
		}
	}
}

static void diag_memcg_build_inode_stats(struct mem_cgroup *memcg,
		struct radix_tree_root *inode_stats_tree)
{
	pg_data_t *pgdat;

	for (pgdat = orig_first_online_pgdat(); pgdat;
	     pgdat = orig_next_online_pgdat(pgdat)) {
		struct mem_cgroup_per_node *mz;
		struct page *page, *n;
		struct lruvec *lruvec;
		enum lru_list lru;

		mz = mem_cgroup_nodeinfo(memcg, pgdat->node_id);
		if (!mz)
			continue;

		lruvec = &mz->lruvec;
		for_each_lru(lru) {
			struct list_head *list = &lruvec->lists[lru];

			if (!BIT(lru))
				continue;

			list_for_each_entry_safe(page, n, list, lru) {
				struct address_space *mapping;
				struct diag_memcg_stats_detail *stats;
				struct inode *inode;

				rcu_read_lock();
				get_page(page);
				if (PageAnon(page))
					goto put_unlock_continue;

				mapping = orig_page_mapping(page);
				if (!mapping)
					goto put_unlock_continue;

				inode = READ_ONCE(mapping->host);
				if (!inode)
					goto put_unlock_continue;

				stats = radix_tree_lookup(inode_stats_tree, (unsigned long)inode);
				if (!stats) {
					stats = kmalloc(sizeof(struct diag_memcg_stats_detail),
							GFP_ATOMIC | __GFP_ZERO);
					stats->et_type = et_memcg_stats_detail;
					stats->key = (unsigned long)inode;
					stats->ino = inode->i_ino;
					stats->cg_addr = (unsigned long)memcg;
					stats->dev = inode->i_sb->s_dev;
					inode_name(inode, stats->name, MEMCG_NAME_LEN);
					mnt_dir(inode, stats->mnt_dir, MEMCG_NAME_LEN);
					stats->pages = 1;
					radix_tree_insert(inode_stats_tree, (unsigned long)inode, stats);
				} else
					stats->pages++;

put_unlock_continue:
				put_page(page);
				rcu_read_unlock();
				cond_resched();
			}
		}
	}
}


static void dump_memcg_detail(struct mem_cgroup *memcg)
{
	struct radix_tree_root inode_stats_tree;

	INIT_RADIX_TREE(&inode_stats_tree, GFP_KERNEL);
	diag_memcg_build_inode_stats(memcg, &inode_stats_tree);
	diag_memcg_dump_inode_stats(&inode_stats_tree);
	diag_memcg_destroy_inode_stats(&inode_stats_tree);
}

static int do_dump(void)
{
	struct mem_cgroup *iter;

	atomic64_inc(&diag_nr_running);
	for (iter = orig_mem_cgroup_iter(NULL, NULL, NULL);
			iter != NULL;
			iter = orig_mem_cgroup_iter(NULL, iter, NULL)) {
		struct diag_memcg_stats_summary summary = {0};
		struct kernfs_node * kn;

		if (mem_cgroup_online(iter)) {
			if (!memcg_stats_settings.verbose)
				continue;
		}

		kn = iter->css.cgroup->kn;
		if (!kn)
			continue;

		summary.et_type = et_memcg_stats_summary;
		memcg_name(kn, summary.name, MEMCG_NAME_LEN);
		summary.addr = (unsigned long)iter;
		summary.flags = iter->css.flags;
		summary.dying = percpu_ref_is_dying(&iter->css.refcnt);
		summary.timestamp = kn->iattr ?
			((struct iattr *)kn->iattr)->ia_atime.tv_sec : 0;
		summary.pages = page_counter_read(&iter->memory);

		diag_memcg_dump_variant_buffer(&summary, sizeof(summary));
		dump_memcg_detail(iter);

		cond_resched();
	}

	atomic64_dec(&diag_nr_running);
	return 0;
}

int diag_memcg_stats_syscall(struct pt_regs *regs, long id)
{
	return  -ENOSYS;
}

static int __activate_memcg_stats(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&memcg_stats_variant_buffer);
	if (ret)
		goto out_variant_buffer;

	memcg_stats_alloced = 1;

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_memcg_stats(void)
{
	synchronize_sched();
	msleep(10);
	while (atomic64_read(&diag_nr_running) > 0) {
		msleep(10);
	}
}

int activate_memcg_stats(void)
{
        if (!memcg_stats_settings.activated)
		memcg_stats_settings.activated = __activate_memcg_stats();

	return memcg_stats_settings.activated;
}

int deactivate_memcg_stats(void)
{
        if (memcg_stats_settings.activated)
                __deactivate_memcg_stats();
        memcg_stats_settings.activated = 0;

        return 0;
}

long diag_ioctl_memcg_stats(unsigned int cmd, unsigned long arg)
{
	struct diag_memcg_stats_settings settings = {0};
	struct diag_ioctl_dump_param dump_param = {0};
	int ret = 0;

	switch (cmd) {
	case CMD_MEMCG_STATS_SET:
		if (memcg_stats_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg,
					sizeof(settings));
			if (!ret) {
				memcg_stats_settings = settings;
			}
		}
		break;

	case CMD_MEMCG_STATS_SETTINGS:
		settings = memcg_stats_settings;
		ret = copy_to_user((void *)arg, &settings, sizeof(settings));
		break;

	case CMD_MEMCG_STATS_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg,
				sizeof(struct diag_ioctl_dump_param));
		if (memcg_stats_alloced && !ret) {
			do_dump();
			ret = copy_to_user_variant_buffer(
					&memcg_stats_variant_buffer,
					dump_param.user_ptr_len,
					dump_param.user_buf,
					dump_param.user_buf_len);
		} else {
			ret = -EINVAL;
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
	LOOKUP_SYMS(mem_cgroup_iter);
	LOOKUP_SYMS(d_find_alias);
	LOOKUP_SYMS(page_mapping);
	LOOKUP_SYMS(first_online_pgdat);
	LOOKUP_SYMS(next_online_pgdat);
	LOOKUP_SYMS(mount_lock);

	return 0;
}

int diag_memcg_stats_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	return init_diag_variant_buffer(
			&memcg_stats_variant_buffer,
			4 * 1024 * 1024);
}

void diag_memcg_stats_exit(void)
{
	if (memcg_stats_settings.activated)
		__deactivate_memcg_stats();
	memcg_stats_settings.activated = 0;
	destroy_diag_variant_buffer(&memcg_stats_variant_buffer);
}

#endif
