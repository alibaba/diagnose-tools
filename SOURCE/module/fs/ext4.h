/*
 * Linux内核诊断工具--ext4相关头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Ling Nan <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef __DIAG_EXT4_H
#define __DIAG_EXT4_H

#include <linux/version.h>
#include <linux/kobject.h>
#include <linux/ratelimit.h>
#include <linux/journal-head.h>
#include <linux/rbtree.h>

typedef int ext4_grpblk_t;

typedef unsigned long long ext4_fsblk_t;

typedef __u32 ext4_lblk_t;

typedef unsigned int ext4_group_t;

struct ext4_es_tree {
	struct rb_root root;
	struct extent_status *cache_es;
};

#if KERNEL_VERSION(2, 6, 32) <= LINUX_VERSION_CODE \
	&& KERNEL_VERSION(2, 6, 33) > LINUX_VERSION_CODE

#include <linux/jbd2.h>

/*
 * storage for cached extent
 */
struct ext4_ext_cache {
	ext4_fsblk_t	ec_start;
	ext4_lblk_t	ec_block;
	__u32		ec_len; /* must be 32bit to return holes */
	__u32		ec_type;
};

typedef struct ext4_io_end {
	struct list_head	list;		/* per-file finished IO list */
	struct inode		*inode;		/* file being written to */
	unsigned int		flag;		/* unwritten or not */
	int			error;		/* I/O error code */
	loff_t			offset;		/* offset in the file */
	ssize_t			size;		/* size of the extent */
	struct work_struct	work;		/* data work queue */
	struct kiocb		*iocb;		/* iocb struct for AIO */
	int			result;		/* error value for AIO */
} ext4_io_end_t;

/*
 * fourth extended file system inode data in memory
 */
struct ext4_inode_info {
	__le32	i_data[15];	/* unconverted */
	__u32	i_dtime;
	ext4_fsblk_t	i_file_acl;

	/*
	 * i_block_group is the number of the block group which contains
	 * this file's inode.  Constant across the lifetime of the inode,
	 * it is ued for making block allocation decisions - we try to
	 * place a file's data blocks near its inode block, and new inodes
	 * near to their parent directory's inode.
	 */
	ext4_group_t	i_block_group;
	unsigned long	i_state_flags;		/* Dynamic state flags */
	unsigned long	i_flags;

	ext4_lblk_t		i_dir_start_lookup;
#ifdef CONFIG_EXT4_FS_XATTR
	/*
	 * Extended attributes can be read independently of the main file
	 * data. Taking i_mutex even when reading would cause contention
	 * between readers of EAs and writers of regular file data, so
	 * instead we synchronize on xattr_sem when reading or changing
	 * EAs.
	 */
	struct rw_semaphore xattr_sem;
#endif

	struct list_head i_orphan;	/* unlinked but open inodes */

	/*
	 * i_disksize keeps track of what the inode size is ON DISK, not
	 * in memory.  During truncate, i_size is set to the new size by
	 * the VFS prior to calling ext4_truncate(), but the filesystem won't
	 * set i_disksize to 0 until the truncate is actually under way.
	 *
	 * The intent is that i_disksize always represents the blocks which
	 * are used by this file.  This allows recovery to restart truncate
	 * on orphans if we crash during truncate.  We actually write i_disksize
	 * into the on-disk inode when writing inodes out, instead of i_size.
	 *
	 * The only time when i_disksize and i_size may be different is when
	 * a truncate is in progress.  The only things which change i_disksize
	 * are ext4_get_block (growth) and ext4_truncate (shrinkth).
	 */
	loff_t	i_disksize;

	/*
	 * i_data_sem is for serialising ext4_truncate() against
	 * ext4_getblock().  In the 2.4 ext2 design, great chunks of inode's
	 * data tree are chopped off during truncate. We can't do that in
	 * ext4 because whenever we perform intermediate commits during
	 * truncate, the inode and all the metadata blocks *must* be in a
	 * consistent state which allows truncation of the orphans to restart
	 * during recovery.  Hence we must fix the get_block-vs-truncate race
	 * by other means, so we have i_data_sem.
	 */
	struct rw_semaphore i_data_sem;
	struct inode vfs_inode;
	struct jbd2_inode jinode;

	struct ext4_ext_cache i_cached_extent;
	/*
	 * File creation time. Its function is same as that of
	 * struct diag_timespec i_{a,c,m}time in the generic inode.
	 */
	struct diag_timespec i_crtime;

	/* mballoc */
	struct list_head i_prealloc_list;
	spinlock_t i_prealloc_lock;

	/* ialloc */
	ext4_group_t	i_last_alloc_group;

	/* allocation reservation info for delalloc */
	unsigned int i_reserved_data_blocks;
	unsigned int i_reserved_meta_blocks;
	unsigned int i_allocated_meta_blocks;
	unsigned short i_delalloc_reserved_flag;
	sector_t i_da_metadata_calc_last_lblock;
	int i_da_metadata_calc_len;

	/* on-disk additional length */
	__u16 i_extra_isize;

	spinlock_t i_block_reservation_lock;
#ifdef CONFIG_QUOTA
	/* quota space reservation, managed internally by quota code */
	qsize_t i_reserved_quota;
#endif

	/* completed async DIOs that might need unwritten extents handling */
	struct list_head i_aio_dio_complete_list;
	spinlock_t i_completed_io_lock;
	/* current io_end structure for async DIO write*/
	ext4_io_end_t *cur_aio_dio;
	atomic_t i_aiodio_unwritten; /* Number of inflight conversions pending */
	struct mutex i_aio_mutex; /* big hammer for unaligned AIO */

	/*
	 * Transactions that contain inode's metadata needed to complete
	 * fsync and fdatasync, respectively.
	 */
	tid_t i_sync_tid;
	tid_t i_datasync_tid;
};

/*
 * fourth extended-fs super-block data in memory
 */
struct ext4_sb_info {
	unsigned long s_desc_size;	/* Size of a group descriptor in bytes */
	unsigned long s_inodes_per_block;/* Number of inodes per block */
	unsigned long s_blocks_per_group;/* Number of blocks in a group */
	unsigned long s_inodes_per_group;/* Number of inodes in a group */
	unsigned long s_itb_per_group;	/* Number of inode table blocks per group */
	unsigned long s_gdb_count;	/* Number of group descriptor blocks */
	unsigned long s_desc_per_block;	/* Number of group descriptors per block */
	ext4_group_t s_groups_count;	/* Number of groups in the fs */
	ext4_group_t s_blockfile_groups;/* Groups acceptable for non-extent files */
	unsigned long s_overhead_last;  /* Last calculated overhead */
	unsigned long s_blocks_last;    /* Last seen block count */
	loff_t s_bitmap_maxbytes;	/* max bytes for bitmap files */
	struct buffer_head * s_sbh;	/* Buffer containing the super block */
	struct ext4_super_block *s_es;	/* Pointer to the super block in the buffer */
	struct buffer_head **s_group_desc;
	unsigned int s_mount_opt;
	unsigned int s_mount_flags;
	ext4_fsblk_t s_sb_block;
	uid_t s_resuid;
	gid_t s_resgid;
	unsigned short s_mount_state;
	unsigned short s_pad;
	int s_addr_per_block_bits;
	int s_desc_per_block_bits;
	int s_inode_size;
	int s_first_ino;
	unsigned int s_inode_readahead_blks;
	unsigned int s_inode_goal;
	spinlock_t s_next_gen_lock;
	u32 s_next_generation;
	u32 s_hash_seed[4];
	int s_def_hash_version;
	int s_hash_unsigned;	/* 3 if hash should be signed, 0 if not */
	struct percpu_counter s_freeblocks_counter;
	struct percpu_counter s_freeinodes_counter;
	struct percpu_counter s_dirs_counter;
	struct percpu_counter s_dirtyblocks_counter;
	struct blockgroup_lock *s_blockgroup_lock;
	struct proc_dir_entry *s_proc;
	struct kobject s_kobj;
	struct completion s_kobj_unregister;

	/* Journaling */
	struct inode *s_journal_inode;
	struct journal_s *s_journal;
	struct list_head s_orphan;
	struct mutex s_orphan_lock;
	struct mutex s_resize_lock;
	unsigned long s_commit_interval;
	u32 s_max_batch_time;
	u32 s_min_batch_time;
	struct block_device *journal_bdev;
#ifdef CONFIG_JBD2_DEBUG
	struct timer_list turn_ro_timer;	/* For turning read-only (crash simulation) */
	wait_queue_head_t ro_wait_queue;	/* For people waiting for the fs to go read-only */
#endif
#ifdef CONFIG_QUOTA
	char *s_qf_names[MAXQUOTAS];		/* Names of quota files with journalled quota */
	int s_jquota_fmt;			/* Format of quota to use */
#endif
	unsigned int s_want_extra_isize; /* New inodes should reserve # bytes */
	struct rb_root system_blks;

#ifdef EXTENTS_STATS
	/* ext4 extents stats */
	unsigned long s_ext_min;
	unsigned long s_ext_max;
	unsigned long s_depth_max;
	spinlock_t s_ext_stats_lock;
	unsigned long s_ext_blocks;
	unsigned long s_ext_extents;
#endif

	/* for buddy allocator */
	struct ext4_group_info ***s_group_info;
	struct inode *s_buddy_cache;
	long s_blocks_reserved;
	spinlock_t s_reserve_lock;
	spinlock_t s_md_lock;
	tid_t s_last_transaction;
	unsigned short *s_mb_offsets;
	unsigned int *s_mb_maxs;

	/* tunables */
	unsigned long s_stripe;
	unsigned int s_mb_stream_request;
	unsigned int s_mb_max_to_scan;
	unsigned int s_mb_min_to_scan;
	unsigned int s_mb_stats;
	unsigned int s_mb_order2_reqs;
	unsigned int s_mb_group_prealloc;
	unsigned int s_max_writeback_mb_bump;
	/* where last allocation was done - for stream allocation */
	unsigned long s_mb_last_group;
	unsigned long s_mb_last_start;

	/* stats for buddy allocator */
	spinlock_t s_mb_pa_lock;
	atomic_t s_bal_reqs;	/* number of reqs with len > 1 */
	atomic_t s_bal_success;	/* we found long enough chunks */
	atomic_t s_bal_allocated;	/* in blocks */
	atomic_t s_bal_ex_scanned;	/* total extents scanned */
	atomic_t s_bal_goals;	/* goal hits */
	atomic_t s_bal_breaks;	/* too long searches */
	atomic_t s_bal_2orders;	/* 2^order hits */
	spinlock_t s_bal_lock;
	unsigned long s_mb_buddies_generated;
	unsigned long long s_mb_generation_time;
	atomic_t s_mb_lost_chunks;
	atomic_t s_mb_preallocated;
	atomic_t s_mb_discarded;
	atomic_t s_lock_busy;

	/* locality groups */
	struct ext4_locality_group *s_locality_groups;

	/* for write statistics */
	unsigned long s_sectors_written_start;
	u64 s_kbytes_written;

	unsigned int s_log_groups_per_flex;
	struct flex_groups *s_flex_groups;

	/* workqueue for dio unwritten */
	struct workqueue_struct *dio_unwritten_wq;

	/* Lazy inode table initialization info */
	struct ext4_li_request *s_li_request;
	/* Wait multiplier for lazy initialization thread */
	unsigned int s_li_wait_mult;

	/* record the last minlen when FITRIM is called. */
	atomic_t s_last_trim_minblks;
};
#elif KERNEL_VERSION(3, 10, 0) <= LINUX_VERSION_CODE \
	&& KERNEL_VERSION(3, 11, 0) > LINUX_VERSION_CODE
struct ext4_ext_sb_info {
	unsigned int    s_opt;
#define EXT4_EXT_OPT_VALID		(1 << 0)
#define EXT4_EXT_OPT_DELAY_UPDATE_TIME	(1 << 1)
	struct mutex    s_mutex;
	struct kobject  s_kobj;
	unsigned long	s_delay_update_time;
};

struct ext4_inode_info {
	__le32	i_data[15];
	__u32	i_dtime;
	ext4_fsblk_t	i_file_acl;

	ext4_group_t	i_block_group;
	ext4_lblk_t	i_dir_start_lookup;
#if (BITS_PER_LONG < 64)
	unsigned long	i_state_flags;
#endif /* BITS_PER_LONG */
	unsigned long	i_flags;

	struct rw_semaphore xattr_sem;

	struct list_head i_orphan;

	loff_t	i_disksize;

	struct rw_semaphore i_data_sem;
	struct inode vfs_inode;
	struct jbd2_inode *jinode;

	spinlock_t i_raw_lock;

	struct diag_timespec i_crtime;

	struct list_head i_prealloc_list;
	spinlock_t i_prealloc_lock;

	struct ext4_es_tree i_es_tree;
	rwlock_t i_es_lock;
	struct list_head i_es_lru;
	unsigned int i_es_lru_nr;
	unsigned long i_touch_when;

	ext4_group_t	i_last_alloc_group;

	unsigned int i_reserved_data_blocks;
	unsigned int i_reserved_meta_blocks;
	unsigned int i_allocated_meta_blocks;
	ext4_lblk_t i_da_metadata_calc_last_lblock;
	int i_da_metadata_calc_len;

	__u16 i_extra_isize;

	u16 i_inline_off;
	u16 i_inline_size;

#ifdef CONFIG_QUOTA

	qsize_t i_reserved_quota;
#endif /* CONFIG_QUOTA */

	spinlock_t i_completed_io_lock;
	struct list_head i_rsv_conversion_list;
	struct list_head i_unrsv_conversion_list;
	atomic_t i_ioend_count;
	atomic_t i_unwritten;
	struct work_struct i_rsv_conversion_work;
	struct work_struct i_unrsv_conversion_work;

	spinlock_t i_block_reservation_lock;

	tid_t i_sync_tid;
	tid_t i_datasync_tid;

	__u32 i_csum_seed;

#ifdef CONFIG_EXT4_FS_SUBTREE
	__u32 i_subtree;
#endif /* CONFIG_EXT4_FS_SUBTREE */
};

struct ext4_sb_info {
#ifdef CONFIG_EXT4_FS_EXTEND
	struct ext4_ext_sb_info s_ext_sb_info;
#endif /* CONFIG_EXT4_FS_EXTEND */
	unsigned long s_desc_size;
	unsigned long s_inodes_per_block;
	unsigned long s_blocks_per_group;
	unsigned long s_clusters_per_group;
	unsigned long s_inodes_per_group;
	unsigned long s_itb_per_group;
	unsigned long s_gdb_count;
	unsigned long s_desc_per_block;
	ext4_group_t s_groups_count;
	ext4_group_t s_blockfile_groups;
	unsigned long s_overhead;
	unsigned int s_cluster_ratio;
	unsigned int s_cluster_bits;
	loff_t s_bitmap_maxbytes;
	struct buffer_head *s_sbh;
	struct ext4_super_block *s_es;
	struct buffer_head **s_group_desc;
	unsigned int s_mount_opt;
	unsigned int s_mount_opt2;
	unsigned int s_mount_flags;
	unsigned int s_def_mount_opt;
	ext4_fsblk_t s_sb_block;
	atomic64_t s_resv_clusters;
	kuid_t s_resuid;
	kgid_t s_resgid;
	unsigned short s_mount_state;
	unsigned short s_pad;
	int s_addr_per_block_bits;
	int s_desc_per_block_bits;
	int s_inode_size;
	int s_first_ino;
	unsigned int s_inode_readahead_blks;
	unsigned int s_inode_goal;
	spinlock_t s_next_gen_lock;
	u32 s_next_generation;
	u32 s_hash_seed[4];
	int s_def_hash_version;
	int s_hash_unsigned;
	struct percpu_counter s_freeclusters_counter;
	struct percpu_counter s_freeinodes_counter;
	struct percpu_counter s_dirs_counter;
	struct percpu_counter s_dirtyclusters_counter;
	struct blockgroup_lock *s_blockgroup_lock;
	struct proc_dir_entry *s_proc;
	struct kobject s_kobj;
	struct completion s_kobj_unregister;
	struct super_block *s_sb;


	struct journal_s *s_journal;
	struct list_head s_orphan;
	struct mutex s_orphan_lock;
	unsigned long s_resize_flags;
	unsigned long s_commit_interval;
	u32 s_max_batch_time;
	u32 s_min_batch_time;
	struct block_device *journal_bdev;
#ifdef CONFIG_QUOTA
	char *s_qf_names[MAXQUOTAS];
	int s_jquota_fmt;
#endif /* CONFIG_QUOTA */
	unsigned int s_want_extra_isize;
	struct rb_root system_blks;

#ifdef EXTENTS_STATS
	unsigned long s_ext_min;
	unsigned long s_ext_max;
	unsigned long s_depth_max;
	spinlock_t s_ext_stats_lock;
	unsigned long s_ext_blocks;
	unsigned long s_ext_extents;
#endif /* EXTENTS_STATS */

	struct ext4_group_info ***s_group_info;
	struct inode *s_buddy_cache;
	spinlock_t s_md_lock;
	unsigned short *s_mb_offsets;
	unsigned int *s_mb_maxs;
	unsigned int s_group_info_size;

	unsigned long s_stripe;
	unsigned int s_mb_stream_request;
	unsigned int s_mb_max_to_scan;
	unsigned int s_mb_min_to_scan;
	unsigned int s_mb_stats;
	unsigned int s_mb_order2_reqs;
	unsigned int s_mb_group_prealloc;
	unsigned int s_max_dir_size_kb;
	unsigned long s_mb_last_group;
	unsigned long s_mb_last_start;

	atomic_t s_bal_reqs;
	atomic_t s_bal_success;
	atomic_t s_bal_allocated;
	atomic_t s_bal_ex_scanned;
	atomic_t s_bal_goals;
	atomic_t s_bal_breaks;
	atomic_t s_bal_2orders;
	spinlock_t s_bal_lock;
	unsigned long s_mb_buddies_generated;
	unsigned long long s_mb_generation_time;
	atomic_t s_mb_lost_chunks;
	atomic_t s_mb_preallocated;
	atomic_t s_mb_discarded;
	atomic_t s_lock_busy;

	struct ext4_locality_group __percpu *s_locality_groups;

	unsigned long s_sectors_written_start;
	u64 s_kbytes_written;

	unsigned int s_extent_max_zeroout_kb;

	unsigned int s_log_groups_per_flex;
	struct flex_groups *s_flex_groups;
	ext4_group_t s_flex_groups_allocated;

	struct workqueue_struct *unrsv_conversion_wq;
	struct workqueue_struct *rsv_conversion_wq;


	struct timer_list s_err_report;

	struct ext4_li_request *s_li_request;
	unsigned int s_li_wait_mult;

	struct task_struct *s_mmp_tsk;

	atomic_t s_last_trim_minblks;

	struct crypto_shash *s_chksum_driver;

	__u32 s_csum_seed;

	struct shrinker s_es_shrinker;
	struct list_head s_es_lru;
	unsigned long s_es_last_sorted;
	struct percpu_counter s_extent_cache_cnt;
	spinlock_t s_es_lru_lock ____cacheline_aligned_in_smp;

	struct ratelimit_state s_err_ratelimit_state;
	struct ratelimit_state s_warning_ratelimit_state;
	struct ratelimit_state s_msg_ratelimit_state;

	unsigned int s_expose_stale_data;
};

#elif KERNEL_VERSION(4, 9, 0) <= LINUX_VERSION_CODE \
	&& KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE

#define EXT4_MAXQUOTAS 3

#ifdef CONFIG_EXT4_FS_ENCRYPTION
  #define EXT4_KEY_DESC_PREFIX "ext4:"
  #define EXT4_KEY_DESC_PREFIX_SIZE 5
#endif /* CONFIG_EXT4_FS_ENCRYPTION */


struct ext4_ext_sb_info {
	unsigned int    s_opt;
#define EXT4_EXT_OPT_VALID		(1 << 0)
#define EXT4_EXT_OPT_DELAY_UPDATE_TIME	(1 << 1)
#define EXT4_EXT_OPT_WB_NICE		(1 << 2)
#define EXT4_EXT_OPT_INODE_DIST	(1 << 3)
	struct mutex    s_mutex;
	struct kobject  s_kobj;
	unsigned long	s_delay_update_time;
	unsigned int    s_wb_enable;
	unsigned int    s_inode_dist;
};

struct ext4_es_stats {
	unsigned long es_stats_shrunk;
	unsigned long es_stats_cache_hits;
	unsigned long es_stats_cache_misses;
	u64 es_stats_scan_time;
	u64 es_stats_max_scan_time;
	struct percpu_counter es_stats_all_cnt;
	struct percpu_counter es_stats_shk_cnt;
};

struct ext4_inode_info {
	__le32	i_data[15];
	__u32	i_dtime;
	ext4_fsblk_t	i_file_acl;

	ext4_group_t	i_block_group;
	ext4_lblk_t	i_dir_start_lookup;
#if (BITS_PER_LONG < 64)
	unsigned long	i_state_flags;
#endif /* BITS_PER_LONG */
	unsigned long	i_flags;

	struct rw_semaphore xattr_sem;

	struct list_head i_orphan;

	loff_t	i_disksize;

	struct rw_semaphore i_data_sem;
	struct rw_semaphore i_mmap_sem;
	struct inode vfs_inode;
	struct jbd2_inode *jinode;

	spinlock_t i_raw_lock;

	struct diag_timespec i_crtime;

	struct list_head i_prealloc_list;
	spinlock_t i_prealloc_lock;

	struct ext4_es_tree i_es_tree;
	rwlock_t i_es_lock;
	struct list_head i_es_list;
	unsigned int i_es_all_nr;
	unsigned int i_es_shk_nr;
	ext4_lblk_t i_es_shrink_lblk;

	ext4_group_t	i_last_alloc_group;

	unsigned int i_reserved_data_blocks;
	unsigned int i_reserved_meta_blocks;
	unsigned int i_allocated_meta_blocks;
	ext4_lblk_t i_da_metadata_calc_last_lblock;
	int i_da_metadata_calc_len;

	__u16 i_extra_isize;

	u16 i_inline_off;
	u16 i_inline_size;

#ifdef CONFIG_QUOTA
	qsize_t i_reserved_quota;
#endif /* CONFIG_QUOTA */

	spinlock_t i_completed_io_lock;
	struct list_head i_rsv_conversion_list;
	struct work_struct i_rsv_conversion_work;
	atomic_t i_unwritten;

	spinlock_t i_block_reservation_lock;

	tid_t i_sync_tid;
	tid_t i_datasync_tid;

#ifdef CONFIG_QUOTA
	struct dquot *i_dquot[MAXQUOTAS];
#endif /* CONFIG_QUOTA */

	__u32 i_csum_seed;

	kprojid_t i_projid;
};

struct ext4_sb_info {
#ifdef CONFIG_EXT4_FS_EXTEND
	struct ext4_ext_sb_info s_ext_sb_info;
#endif /* CONFIG_EXT4_FS_EXTEND */
	unsigned long s_desc_size;
	unsigned long s_inodes_per_block;
	unsigned long s_blocks_per_group;
	unsigned long s_clusters_per_group;
	unsigned long s_inodes_per_group;
	unsigned long s_itb_per_group;
	unsigned long s_gdb_count;
	unsigned long s_desc_per_block;
	ext4_group_t s_groups_count;
	ext4_group_t s_blockfile_groups;
	unsigned long s_overhead;
	unsigned int s_cluster_ratio;
	unsigned int s_cluster_bits;
	loff_t s_bitmap_maxbytes;
	struct buffer_head *s_sbh;
	struct ext4_super_block *s_es;
	struct buffer_head **s_group_desc;
	unsigned int s_mount_opt;
	unsigned int s_mount_opt2;
	unsigned int s_mount_flags;
	unsigned int s_def_mount_opt;
	ext4_fsblk_t s_sb_block;
	atomic64_t s_resv_clusters;
	kuid_t s_resuid;
	kgid_t s_resgid;
	unsigned short s_mount_state;
	unsigned short s_pad;
	int s_addr_per_block_bits;
	int s_desc_per_block_bits;
	int s_inode_size;
	int s_first_ino;
	unsigned int s_inode_readahead_blks;
	unsigned int s_inode_goal;
	spinlock_t s_next_gen_lock;
	u32 s_next_generation;
	u32 s_hash_seed[4];
	int s_def_hash_version;
	int s_hash_unsigned;
	struct percpu_counter s_freeclusters_counter;
	struct percpu_counter s_freeinodes_counter;
	struct percpu_counter s_dirs_counter;
	struct percpu_counter s_dirtyclusters_counter;
	struct blockgroup_lock *s_blockgroup_lock;
	struct proc_dir_entry *s_proc;
	struct kobject s_kobj;
	struct completion s_kobj_unregister;
	struct super_block *s_sb;

	struct journal_s *s_journal;
	struct list_head s_orphan;
	struct mutex s_orphan_lock;
	unsigned long s_resize_flags;
	unsigned long s_commit_interval;
	u32 s_max_batch_time;
	u32 s_min_batch_time;
	struct block_device *journal_bdev;
#ifdef CONFIG_QUOTA
	char *s_qf_names[EXT4_MAXQUOTAS];
	int s_jquota_fmt;
#endif /* CONFIG_QUOTA */
	unsigned int s_want_extra_isize;
	struct rb_root system_blks;

#ifdef EXTENTS_STATS
	unsigned long s_ext_min;
	unsigned long s_ext_max;
	unsigned long s_depth_max;
	spinlock_t s_ext_stats_lock;
	unsigned long s_ext_blocks;
	unsigned long s_ext_extents;
#endif /* EXTENTS_STATS */

	struct ext4_group_info ***s_group_info;
	struct inode *s_buddy_cache;
	spinlock_t s_md_lock;
	unsigned short *s_mb_offsets;
	unsigned int *s_mb_maxs;
	unsigned int s_group_info_size;
	unsigned int s_mb_free_pending;

	unsigned long s_stripe;
	unsigned int s_mb_stream_request;
	unsigned int s_mb_max_to_scan;
	unsigned int s_mb_min_to_scan;
	unsigned int s_mb_stats;
	unsigned int s_mb_order2_reqs;
	unsigned int s_mb_group_prealloc;
	unsigned int s_max_dir_size_kb;
	unsigned long s_mb_last_group;
	unsigned long s_mb_last_start;

	atomic_t s_bal_reqs;
	atomic_t s_bal_success;
	atomic_t s_bal_allocated;
	atomic_t s_bal_ex_scanned;
	atomic_t s_bal_goals;
	atomic_t s_bal_breaks;
	atomic_t s_bal_2orders;
	spinlock_t s_bal_lock;
	unsigned long s_mb_buddies_generated;
	unsigned long long s_mb_generation_time;
	atomic_t s_mb_lost_chunks;
	atomic_t s_mb_preallocated;
	atomic_t s_mb_discarded;
	atomic_t s_lock_busy;

	struct ext4_locality_group __percpu *s_locality_groups;

	unsigned long s_sectors_written_start;
	u64 s_kbytes_written;

	unsigned int s_extent_max_zeroout_kb;

	unsigned int s_log_groups_per_flex;
	struct flex_groups *s_flex_groups;
	ext4_group_t s_flex_groups_allocated;

	struct workqueue_struct *rsv_conversion_wq;

	struct timer_list s_err_report;

	struct ext4_li_request *s_li_request;
	unsigned int s_li_wait_mult;

	struct task_struct *s_mmp_tsk;

	atomic_t s_last_trim_minblks;

	struct crypto_shash *s_chksum_driver;

	__u32 s_csum_seed;

	struct shrinker s_es_shrinker;
	struct list_head s_es_list;
	long s_es_nr_inode;
	struct ext4_es_stats s_es_stats;
	struct mb_cache *s_mb_cache;
	spinlock_t s_es_lock ____cacheline_aligned_in_smp;

	struct ratelimit_state s_err_ratelimit_state;
	struct ratelimit_state s_warning_ratelimit_state;
	struct ratelimit_state s_msg_ratelimit_state;

	struct percpu_rw_semaphore s_journal_flag_rwsem;

#ifdef CONFIG_EXT4_FS_ENCRYPTION
	u8 key_prefix[EXT4_KEY_DESC_PREFIX_SIZE];
	u8 key_prefix_size;
#endif /* CONFIG_EXT4_FS_ENCRYPTION */
};

#elif KERNEL_VERSION(4, 19, 0) <= LINUX_VERSION_CODE \
	&& KERNEL_VERSION(4, 20, 0) > LINUX_VERSION_CODE

struct ext4_pending_tree {
	struct rb_root root;
};

/* Number of quota types we support */
#define EXT4_MAXQUOTAS 3
struct ext4_es_stats {
	unsigned long es_stats_shrunk;
	unsigned long es_stats_cache_hits;
	unsigned long es_stats_cache_misses;
	u64 es_stats_scan_time;
	u64 es_stats_max_scan_time;
	struct percpu_counter es_stats_all_cnt;
	struct percpu_counter es_stats_shk_cnt;
};

/*
 * fourth extended file system inode data in memory
 */
struct ext4_inode_info {
	__le32	i_data[15];	/* unconverted */
	__u32	i_dtime;
	ext4_fsblk_t	i_file_acl;

	/*
	 * i_block_group is the number of the block group which contains
	 * this file's inode.  Constant across the lifetime of the inode,
	 * it is used for making block allocation decisions - we try to
	 * place a file's data blocks near its inode block, and new inodes
	 * near to their parent directory's inode.
	 */
	ext4_group_t	i_block_group;
	ext4_lblk_t	i_dir_start_lookup;
#if (BITS_PER_LONG < 64)
	unsigned long	i_state_flags;		/* Dynamic state flags */
#endif
	unsigned long	i_flags;

	/*
	 * Extended attributes can be read independently of the main file
	 * data. Taking i_mutex even when reading would cause contention
	 * between readers of EAs and writers of regular file data, so
	 * instead we synchronize on xattr_sem when reading or changing
	 * EAs.
	 */
	struct rw_semaphore xattr_sem;

	struct list_head i_orphan;	/* unlinked but open inodes */

	/*
	 * i_disksize keeps track of what the inode size is ON DISK, not
	 * in memory.  During truncate, i_size is set to the new size by
	 * the VFS prior to calling ext4_truncate(), but the filesystem won't
	 * set i_disksize to 0 until the truncate is actually under way.
	 *
	 * The intent is that i_disksize always represents the blocks which
	 * are used by this file.  This allows recovery to restart truncate
	 * on orphans if we crash during truncate.  We actually write i_disksize
	 * into the on-disk inode when writing inodes out, instead of i_size.
	 *
	 * The only time when i_disksize and i_size may be different is when
	 * a truncate is in progress.  The only things which change i_disksize
	 * are ext4_get_block (growth) and ext4_truncate (shrinkth).
	 */
	loff_t	i_disksize;

	/*
	 * i_data_sem is for serialising ext4_truncate() against
	 * ext4_getblock().  In the 2.4 ext2 design, great chunks of inode's
	 * data tree are chopped off during truncate. We can't do that in
	 * ext4 because whenever we perform intermediate commits during
	 * truncate, the inode and all the metadata blocks *must* be in a
	 * consistent state which allows truncation of the orphans to restart
	 * during recovery.  Hence we must fix the get_block-vs-truncate race
	 * by other means, so we have i_data_sem.
	 */
	struct rw_semaphore i_data_sem;
	/*
	 * i_mmap_sem is for serializing page faults with truncate / punch hole
	 * operations. We have to make sure that new page cannot be faulted in
	 * a section of the inode that is being punched. We cannot easily use
	 * i_data_sem for this since we need protection for the whole punch
	 * operation and i_data_sem ranks below transaction start so we have
	 * to occasionally drop it.
	 */
	struct rw_semaphore i_mmap_sem;
	struct inode vfs_inode;
	struct jbd2_inode *jinode;

	spinlock_t i_raw_lock;	/* protects updates to the raw inode */

	/*
	 * File creation time. Its function is same as that of
	 * struct diag_timespec i_{a,c,m}time in the generic inode.
	 */
	struct timespec64 i_crtime;

	/* mballoc */
	struct list_head i_prealloc_list;
	spinlock_t i_prealloc_lock;

	/* extents status tree */
	struct ext4_es_tree i_es_tree;
	rwlock_t i_es_lock;
	struct list_head i_es_list;
	unsigned int i_es_all_nr;	/* protected by i_es_lock */
	unsigned int i_es_shk_nr;	/* protected by i_es_lock */
	ext4_lblk_t i_es_shrink_lblk;	/* Offset where we start searching for
					   extents to shrink. Protected by
					   i_es_lock  */

	/* ialloc */
	ext4_group_t	i_last_alloc_group;

	/* allocation reservation info for delalloc */
	/* In case of bigalloc, this refer to clusters rather than blocks */
	unsigned int i_reserved_data_blocks;
	ext4_lblk_t i_da_metadata_calc_last_lblock;
	int i_da_metadata_calc_len;

	/* pending cluster reservations for bigalloc file systems */
	struct ext4_pending_tree i_pending_tree;

	/* on-disk additional length */
	__u16 i_extra_isize;

	/* Indicate the inline data space. */
	u16 i_inline_off;
	u16 i_inline_size;

#ifdef CONFIG_QUOTA
	/* quota space reservation, managed internally by quota code */
	qsize_t i_reserved_quota;
#endif

	/* Lock protecting lists below */
	spinlock_t i_completed_io_lock;
	/*
	 * Completed IOs that need unwritten extents handling and have
	 * transaction reserved
	 */
	struct list_head i_rsv_conversion_list;
	struct work_struct i_rsv_conversion_work;
	atomic_t i_unwritten; /* Nr. of inflight conversions pending */

	spinlock_t i_block_reservation_lock;

	/*
	 * Transactions that contain inode's metadata needed to complete
	 * fsync and fdatasync, respectively.
	 */
	tid_t i_sync_tid;
	tid_t i_datasync_tid;

#ifdef CONFIG_QUOTA
	struct dquot *i_dquot[MAXQUOTAS];
#endif

	/* Precomputed uuid+inum+igen checksum for seeding inode checksums */
	__u32 i_csum_seed;

	kprojid_t i_projid;
};

/*
 * fourth extended-fs super-block data in memory
 */
struct ext4_sb_info {
	unsigned long s_desc_size;	/* Size of a group descriptor in bytes */
	unsigned long s_inodes_per_block;/* Number of inodes per block */
	unsigned long s_blocks_per_group;/* Number of blocks in a group */
	unsigned long s_clusters_per_group; /* Number of clusters in a group */
	unsigned long s_inodes_per_group;/* Number of inodes in a group */
	unsigned long s_itb_per_group;	/* Number of inode table blocks per group */
	unsigned long s_gdb_count;	/* Number of group descriptor blocks */
	unsigned long s_desc_per_block;	/* Number of group descriptors per block */
	ext4_group_t s_groups_count;	/* Number of groups in the fs */
	ext4_group_t s_blockfile_groups;/* Groups acceptable for non-extent files */
	unsigned long s_overhead;  /* # of fs overhead clusters */
	unsigned int s_cluster_ratio;	/* Number of blocks per cluster */
	unsigned int s_cluster_bits;	/* log2 of s_cluster_ratio */
	loff_t s_bitmap_maxbytes;	/* max bytes for bitmap files */
	struct buffer_head * s_sbh;	/* Buffer containing the super block */
	struct ext4_super_block *s_es;	/* Pointer to the super block in the buffer */
	struct buffer_head **s_group_desc;
	unsigned int s_mount_opt;
	unsigned int s_mount_opt2;
	unsigned int s_mount_flags;
	unsigned int s_def_mount_opt;
	ext4_fsblk_t s_sb_block;
	atomic64_t s_resv_clusters;
	kuid_t s_resuid;
	kgid_t s_resgid;
	unsigned short s_mount_state;
	unsigned short s_pad;
	int s_addr_per_block_bits;
	int s_desc_per_block_bits;
	int s_inode_size;
	int s_first_ino;
	unsigned int s_inode_readahead_blks;
	unsigned int s_inode_goal;
	u32 s_hash_seed[4];
	int s_def_hash_version;
	int s_hash_unsigned;	/* 3 if hash should be signed, 0 if not */
	struct percpu_counter s_freeclusters_counter;
	struct percpu_counter s_freeinodes_counter;
	struct percpu_counter s_dirs_counter;
	struct percpu_counter s_dirtyclusters_counter;
	struct blockgroup_lock *s_blockgroup_lock;
	struct proc_dir_entry *s_proc;
	struct kobject s_kobj;
	struct completion s_kobj_unregister;
	struct super_block *s_sb;

	/* Journaling */
	struct journal_s *s_journal;
	struct list_head s_orphan;
	struct mutex s_orphan_lock;
	unsigned long s_ext4_flags;		/* Ext4 superblock flags */
	unsigned long s_commit_interval;
	u32 s_max_batch_time;
	u32 s_min_batch_time;
	struct block_device *journal_bdev;
#ifdef CONFIG_QUOTA
	/* Names of quota files with journalled quota */
	char __rcu *s_qf_names[EXT4_MAXQUOTAS];
	int s_jquota_fmt;			/* Format of quota to use */
#endif
	unsigned int s_want_extra_isize; /* New inodes should reserve # bytes */
	struct rb_root system_blks;

#ifdef EXTENTS_STATS
	/* ext4 extents stats */
	unsigned long s_ext_min;
	unsigned long s_ext_max;
	unsigned long s_depth_max;
	spinlock_t s_ext_stats_lock;
	unsigned long s_ext_blocks;
	unsigned long s_ext_extents;
#endif

	/* for buddy allocator */
	struct ext4_group_info ***s_group_info;
	struct inode *s_buddy_cache;
	spinlock_t s_md_lock;
	unsigned short *s_mb_offsets;
	unsigned int *s_mb_maxs;
	unsigned int s_group_info_size;
	unsigned int s_mb_free_pending;
	struct list_head s_freed_data_list;	/* List of blocks to be freed
						   after commit completed */

	/* tunables */
	unsigned long s_stripe;
	unsigned int s_mb_stream_request;
	unsigned int s_mb_max_to_scan;
	unsigned int s_mb_min_to_scan;
	unsigned int s_mb_stats;
	unsigned int s_mb_order2_reqs;
	unsigned int s_mb_group_prealloc;
	unsigned int s_max_dir_size_kb;
	/* where last allocation was done - for stream allocation */
	unsigned long s_mb_last_group;
	unsigned long s_mb_last_start;

	/* stats for buddy allocator */
	atomic_t s_bal_reqs;	/* number of reqs with len > 1 */
	atomic_t s_bal_success;	/* we found long enough chunks */
	atomic_t s_bal_allocated;	/* in blocks */
	atomic_t s_bal_ex_scanned;	/* total extents scanned */
	atomic_t s_bal_goals;	/* goal hits */
	atomic_t s_bal_breaks;	/* too long searches */
	atomic_t s_bal_2orders;	/* 2^order hits */
	spinlock_t s_bal_lock;
	unsigned long s_mb_buddies_generated;
	unsigned long long s_mb_generation_time;
	atomic_t s_mb_lost_chunks;
	atomic_t s_mb_preallocated;
	atomic_t s_mb_discarded;
	atomic_t s_lock_busy;

	/* locality groups */
	struct ext4_locality_group __percpu *s_locality_groups;

	/* for write statistics */
	unsigned long s_sectors_written_start;
	u64 s_kbytes_written;

	/* the size of zero-out chunk */
	unsigned int s_extent_max_zeroout_kb;

	unsigned int s_log_groups_per_flex;
	struct flex_groups *s_flex_groups;
	ext4_group_t s_flex_groups_allocated;

	/* workqueue for reserved extent conversions (buffered io) */
	struct workqueue_struct *rsv_conversion_wq;

	/* timer for periodic error stats printing */
	struct timer_list s_err_report;

	/* Lazy inode table initialization info */
	struct ext4_li_request *s_li_request;
	/* Wait multiplier for lazy initialization thread */
	unsigned int s_li_wait_mult;

	/* Kernel thread for multiple mount protection */
	struct task_struct *s_mmp_tsk;

	/* record the last minlen when FITRIM is called. */
	atomic_t s_last_trim_minblks;

	/* Reference to checksum algorithm driver via cryptoapi */
	struct crypto_shash *s_chksum_driver;

	/* Precomputed FS UUID checksum for seeding other checksums */
	__u32 s_csum_seed;

	/* Reclaim extents from extent status tree */
	struct shrinker s_es_shrinker;
	struct list_head s_es_list;	/* List of inodes with reclaimable extents */
	long s_es_nr_inode;
	struct ext4_es_stats s_es_stats;
	struct mb_cache *s_ea_block_cache;
	struct mb_cache *s_ea_inode_cache;
	spinlock_t s_es_lock ____cacheline_aligned_in_smp;

	/* Ratelimit ext4 messages. */
	struct ratelimit_state s_err_ratelimit_state;
	struct ratelimit_state s_warning_ratelimit_state;
	struct ratelimit_state s_msg_ratelimit_state;

	/* Barrier between changing inodes' journal flags and writepages ops. */
	struct percpu_rw_semaphore s_journal_flag_rwsem;
	struct dax_device *s_daxdev;
};
#endif /* LINUX_VERSION */
#endif /* __DIAG_EXT4_H */
