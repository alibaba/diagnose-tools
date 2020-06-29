/*
 * Linux内核诊断工具--内核态kprobe公共函数头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef __DIAG_PUB_KPROBE_H
#define __DIAG_PUB_KPROBE_H

#include <linux/kprobes.h>
#include <linux/version.h>

extern int hook_kprobe(struct kprobe *kp, const char *name,
        kprobe_pre_handler_t pre, kprobe_post_handler_t post);
extern void unhook_kprobe(struct kprobe *kp);
int hook_kretprobe(struct kretprobe *ptr_kretprobe, char *kretprobe_func,
	kretprobe_handler_t kretprobe_entry_handler,
	kretprobe_handler_t kretprobe_ret_handler,
	size_t data_size);
void unhook_kretprobe(struct kretprobe *ptr_kretprobe);

#endif /* __DIAG_PUB_KPROBE_H */
