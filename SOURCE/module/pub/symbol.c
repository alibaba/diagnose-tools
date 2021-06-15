
/*
 * Linux内核诊断工具--内核态kprobe公共函数实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/kallsyms.h>
#include <linux/version.h>

#include "pub/kprobe.h"
#include "symbol.h"

unsigned long (*diag_kallsyms_lookup_name)(const char *name);

static int (*diag_kallsyms_on_each_symbol)(int (*fn)(void *, const char *,
						    struct module *,
						    unsigned long),
					  void *data);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#include <linux/kprobes.h>
static struct kprobe kprobe_kallsyms_lookup_name = {
    .symbol_name = "kallsyms_lookup_name"
};

int diag_init_symbol(void)
{
    register_kprobe(&kprobe_kallsyms_lookup_name);
    diag_kallsyms_lookup_name = (void *)kprobe_kallsyms_lookup_name.addr;
    unregister_kprobe(&kprobe_kallsyms_lookup_name);

	printk("xby-debug, diag_kallsyms_lookup_name is %p\n", diag_kallsyms_lookup_name);
	
    if (!diag_kallsyms_lookup_name) {
        return -EINVAL;
    }

	diag_kallsyms_on_each_symbol = (void *)diag_kallsyms_lookup_name("kallsyms_on_each_symbol");
	if (!diag_kallsyms_on_each_symbol) {
		return -EINVAL;
	}

    return 0;
}
#else
static int symbol_walk_callback(void *data, const char *name,
	struct module *mod, unsigned long addr)
{
	if (strcmp(name, "kallsyms_lookup_name") == 0) {
		diag_kallsyms_lookup_name = (void *)addr;
		return addr;
	}

	return 0;
}

int diag_init_symbol(void)
{
    int ret = 0;

	diag_kallsyms_on_each_symbol = &kallsyms_on_each_symbol;
	ret = diag_kallsyms_on_each_symbol(symbol_walk_callback, NULL);
	if (!ret || !diag_kallsyms_lookup_name) {
		ret = -EINVAL;
		goto out;
	}

    ret = 0;

out:
    return ret;
}
#endif

struct diag_symbol_info {
    char *symbol;
    int count;
};

static inline int get_symbol_count_callback(void *data, const char *name,
            struct module *mod, unsigned long addr)
{
    struct diag_symbol_info *info = data;

    if (strcmp(name, info->symbol) == 0) {
        info->count++;
        return 0;
    }

    return 0;
}

int diag_get_symbol_count(char *symbol)
{
	struct diag_symbol_info info;

	info.symbol = symbol;
	info.count = 0;  
	diag_kallsyms_on_each_symbol(get_symbol_count_callback, &info);

	return info.count;
}

