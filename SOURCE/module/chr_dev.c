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
    int type, nr;

    type = _IOC_TYPE(cmd);
    nr = _IOC_NR(cmd);

    switch (type) {
    case DIAG_IOCTL_TYPE_TEST:
        if (nr == 1) {
            struct diag_ioctl_test val;

            ret = copy_from_user(&val, (void *)arg, sizeof(struct diag_ioctl_test));
            if (!ret) {
                val.out = val.in + 1;
                ret = copy_to_user((void *)arg, &val, sizeof(struct diag_ioctl_test));
            }
        }
        break;
    case DIAG_IOCTL_TYPE_VERSION:
        if (nr == 1) {
            ret = DIAG_VERSION;
        }
        break;
    case DIAG_IOCTL_TYPE_PUPIL:
        ret = diag_ioctl_pupil_task(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_SYS_DELAY:
        ret = diag_ioctl_sys_delay(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_SYS_COST:
        ret = diag_ioctl_sys_cost(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_SCHED_DELAY:
        ret = diag_ioctl_sched_delay(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_IRQ_DELAY:
        ret = diag_ioctl_irq_delay(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_IRQ_STATS:
        ret = diag_ioctl_irq_stats(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_IRQ_TRACE:
        ret = diag_ioctl_irq_trace(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_LOAD_MONITOR:
        ret = diag_ioctl_load_monitor(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_RUN_TRACE:
        ret = diag_ioctl_run_trace(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_PERF:
        ret = diag_ioctl_perf(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_KPROBE:
        ret = diag_ioctl_kprobe(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_UPROBE:
        ret = diag_ioctl_uprobe(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_UTILIZATION:
        ret = diag_ioctl_utilization(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_EXIT_MONITOR:
        ret = diag_ioctl_exit_monitor(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_MUTEX_MONITOR:
        ret = diag_ioctl_mutex_monitor(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_EXEC_MONITOR:
        ret = diag_ioctl_exec_monitor(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_ALLOC_TOP:
        ret = diag_ioctl_alloc_top(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_HIGH_ORDER:
        ret = diag_ioctl_high_order(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_DROP_PACKET:
        ret = diag_ioctl_drop_packet(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_TCP_RETRANS:
        ret = diag_ioctl_tcp_retrans(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_PING_DELAY:
        ret = diag_ioctl_ping_delay(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_RW_TOP:
        ret = diag_ioctl_rw_top(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_FS_SHM:
        ret = diag_ioctl_fs_shm(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_FS_ORPHAN:
        ret = diag_ioctl_fs_orphan(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_FS_CACHE:
        ret = diag_ioctl_fs_cache(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_REBOOT:
        ret = diag_ioctl_reboot(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_NET_BANDWIDTH:
        ret = diag_ioctl_net_bandwidth(nr, arg);
        break;
    case DIAG_IOCTL_TYPE_SIG_INFO:
        ret = diag_ioctl_sig_info(nr, arg);
        break;
    default:
        break;
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
        class_destroy(diag_dev_class);
    }

    diag_dev_major = -1;
    diag_dev = NULL;
    diag_dev_class = NULL;
}
