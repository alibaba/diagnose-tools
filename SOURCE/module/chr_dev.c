/*
 * Linux内核诊断工具--字符设备实现，用于用户态与内核态之间的交互
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/notifier.h>
#include <linux/sched.h>
#include <linux/kdebug.h>
#include <linux/nmi.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/cpumask.h>
#include <linux/mm_types.h>
#include <linux/pid_namespace.h>
#include <net/net_namespace.h>
#include <linux/inetdevice.h>
#include <asm/irq_regs.h>
#include <asm/ptrace.h>
#include <linux/stacktrace.h>
#include <asm/stacktrace.h>
#include <asm/syscall.h>
#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/highmem.h>

#include <linux/kallsyms.h>
#include <linux/hardirq.h>

#include "uapi/ali_diagnose.h"

static int diag_dev_major = -1;
static struct class *diag_dev_class = NULL;
static struct device *diag_dev = NULL;

struct diag_dev {
    struct cdev cdev;
};

static long diag_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret = -EINVAL;
    int nr;

    if (_IOC_TYPE(cmd) == DIAG_IOCTL_TEST_TYPE) {
        nr = _IOC_NR(cmd);
        if (nr == 1) {
            struct diag_ioctl_test val;

            ret = copy_from_user(&val, (void *)arg, sizeof(struct diag_ioctl_test));
            if (!ret) {
                val.out = val.in + 1;
                ret = copy_to_user((void *)arg, &val, sizeof(struct diag_ioctl_test));
            }
        } else {
            return -EINVAL;
        }
    }

    return ret;
}

static int diag_open(struct inode *inode, struct file *file)
{
    __module_get(THIS_MODULE);

    return 0;
}

static int diag_release(struct inode *inode, struct file *file)
{
    module_put(THIS_MODULE);

    return 0;
}

static const struct file_operations diag_fops = {
    .open       = diag_open,
    .release    = diag_release,
    .unlocked_ioctl = diag_ioctl,
};

static char *diag_devnode(struct device *dev, umode_t *mode)
{
    if (mode)
	    *mode = S_IRUGO | S_IRWXUGO | S_IALLUGO;

    return kstrdup("diagnose-tools", GFP_KERNEL);;
}

int diag_dev_init(void)
{
    int ret = 0;
    diag_dev_major = register_chrdev(0, DIAG_DEV_NAME, &diag_fops);;

    if (diag_dev_major < 0) {
        printk("diagnose-tools: failed to register device\n");
        return diag_dev_major;
    }

    diag_dev_class = class_create(THIS_MODULE, DIAG_DEV_NAME);
    if (IS_ERR(diag_dev_class)) {
        ret = PTR_ERR(diag_dev_class);
        printk(KERN_ERR "diagnose-tools: class_create err=%d", ret);
        unregister_chrdev(diag_dev_major, DIAG_DEV_NAME);

        return ret;
    }
    diag_dev_class->devnode = diag_devnode;

    diag_dev = device_create(diag_dev_class, NULL, MKDEV(diag_dev_major, 0), NULL, DIAG_DEV_NAME);
    if (IS_ERR(diag_dev)) {
        ret = PTR_ERR(diag_dev);
        printk(KERN_ERR "diagnose-tools: device_create err=%d", ret);
        unregister_chrdev(diag_dev_major, DIAG_DEV_NAME);
        class_destroy(diag_dev_class);

        return ret;
    }

    return 0;
}

void diag_dev_cleanup(void)
{
    if (diag_dev_major >= 0) {
        unregister_chrdev(diag_dev_major, DIAG_DEV_NAME);
    }

    if (diag_dev != NULL) {
        device_destroy(diag_dev_class, MKDEV(diag_dev_major, 0));
    }

    if (diag_dev_class != NULL) {
        class_unregister(diag_dev_class);
        class_destroy(diag_dev_class);
    }

    diag_dev_major = -1;
    diag_dev = NULL;
    diag_dev_class = NULL;
}
