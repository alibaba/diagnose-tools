#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <syscall.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "internal.h"
#include "attach.h"


static int global_mnt_ns_fd = -1;
static char global_mnt_ns_name[NS_NAME_LEN];
static char g_mnt_ns_name[128];

int init_global_env(void) {
    struct utsname utsname;
    int ret = uname(&utsname);
    if (ret < 0) {
        return -1;
    }

    if (readlink("/proc/1/ns/mnt", g_mnt_ns_name, sizeof(g_mnt_ns_name)) < 0) {
        return -1;
    }

    ret = readlink("/proc/1/ns/mnt", global_mnt_ns_name, NS_NAME_LEN);
    if (ret <= 0) {
        return -1;
    } else {
        global_mnt_ns_fd = open("/proc/1/ns/mnt", 0);
        if (global_mnt_ns_fd < 0) {
            return -1;
        }
    }
    return 0;
}

int attach_mount_namespace(int pid, const char *mnt_ns_name) {
    int mntfd = -1;
    int ret = -1;

    char mnt_ns_path[NS_PATH_LEN];

    if (is_linux_2_6_x()) {
        return -1;
    }

    snprintf(mnt_ns_path, sizeof(mnt_ns_path), "/proc/%d/ns/mnt", pid);
    if (strcmp(mnt_ns_name, global_mnt_ns_name) != 0 && global_mnt_ns_fd > 0) {
        mntfd = open(mnt_ns_path, O_RDONLY);
        if (mntfd < 0) {
            return -1;
        }
        ret = syscall(__NR_setns, mntfd, 0);
        if (ret < 0) {
            close(mntfd);
            return -1;
        }
    }
    return mntfd;
}

void detach_mount_namespace(int mntfd) {
    if (is_linux_2_6_x()) {
        return;
    }
    if (mntfd >= 0) {
        close(mntfd);
        if (syscall(__NR_setns, global_mnt_ns_fd, 0) < 0) {
            exit(-1);
        }
    }
}
