#ifndef __ATTACH_H__
#define __ATTACH_H__
#define NS_NAME_LEN 128
#define NS_PATH_LEN 128
int init_global_env(void);
int attach_mount_namespace(int pid, const char *mnt_ns_name);
void detach_mount_namespace(int mntfd);
#endif
