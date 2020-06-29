/*
 * Linux内核诊断工具--用户接口API
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef UAPI_VARIANT_BUFFER_H
#define UAPI_VARIANT_BUFFER_H

#define DIAG_VARIANT_BUFFER_HEAD_MAGIC_SEALED 197612031122
#define DIAG_VARIANT_BUFFER_HEAD_MAGIC_UNSEALED 197612031234

struct diag_variant_buffer_head {
	unsigned long magic;
	unsigned long len;
};

#endif /* UAPI_VARIANT_BUFFER_H */
