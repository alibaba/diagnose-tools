/*
 * Linux内核诊断工具--内核态文件系统相关功能入口
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/proc_fs.h>

#include "internal.h"
#include "fs_internal.h"

int diag_fs_init(void)
{
	int retval = 0;

	retval = diag_fs_orphan_init();
	if (retval != 0)
		goto out_dump_orphan;

	retval = diag_rw_top_init();
	if (retval != 0)
		goto out_rw_top;

	retval = diag_fs_shm_init();
	if (retval != 0)
		goto out_fs_shm;

	retval = diag_fs_cache_init();
	if (retval != 0)
		goto out_fs_cache;

	return retval;

out_fs_cache:
	diag_fs_shm_exit();
out_fs_shm:
	diag_rw_top_exit();
out_rw_top:
	diag_fs_orphan_exit();
out_dump_orphan:
	return retval;
}

void diag_fs_exit(void)
{
	diag_fs_cache_exit();
	diag_fs_shm_exit();
	diag_fs_orphan_exit();
	diag_rw_top_exit();
}
