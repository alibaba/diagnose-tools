/*
 * Linux内核诊断工具--用户态java符号表解析
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <syscall.h>
#include <netinet/in.h>

#include <string>
#include <map>
#include <vector>
#include <set>
#include <sys/utsname.h>

#include "internal.h"

#define PROC_DIR    "/proc"
#define PROC_NS_PID "ns/pid"
#define PROC_NS_MNT "ns/mnt"
#define PROC_CWD    "cwd"
#define LIB_AGENT   "/usr/diagnose-tools/libperfmap.so"
#define TMP_AGENT   "/tmp/libperfmap.so"
#define PERF_FMT    "/tmp/perf-%d.map"
#define CHECK_PRINT(ret, fmt, arg...)                \
    if((ret)) printf("[ERROR] %s:%d - %s (%d) " fmt, \
        __FUNCTION__, __LINE__, strerror(errno),     \
        errno, ##arg);

class ns_fd_info
{
public:
    ns_fd_info()
    {
        pid_fd = -1;
        mnt_fd = -1;
    }
    ~ns_fd_info()
    {
        if (pid_fd >= 0)
            close(pid_fd);
        if (mnt_fd >= 0)
            close(mnt_fd);
    }
    int open_ns_fd(int pid);
    void attach_ns_fd();
public:
    int pid_fd;
    int mnt_fd;
};

class process_info
{
public:
    int pid;
    int cpid;
    int euid;
    int egid;
    long addr;
    int perf_fd;
};
typedef std::map<long, process_info> PROCESS_MAP;

class namespace_info
{
public:
    namespace_info() {}
public:
    std::string name;
    PROCESS_MAP proc_map;
    ns_fd_info ns_fd;
    int is_host;
};
typedef std::map<std::string, namespace_info> NAMESPACE_MAP;

int        agent_fd;
ns_fd_info cur_ns;

int read_process_info_5u(const char *name, process_info *info)
{
    int ret;
    int fd;
    char fullname[64];
    char buf[1024];
    char *p;

    snprintf(fullname, sizeof(fullname),
            "%s/%s/stat", PROC_DIR, name);
    fd = open(fullname, 0);
    if (!fd)
        return -1;

    ret = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (ret > 0)
        buf[ret] = '\0';

    p = strchr(buf, ' ');
    if (!p)
        return -1;

    if (memcmp(p, " (java) ", 8))
        return -1;

    *p = 0;
    info->pid = atoi(buf);
    info->cpid = info->pid;
    info->euid = 0;
    info->egid = 0;
    info->perf_fd = -1;

    return 0;
}

int read_process_info_7u(const char *name, process_info *info)
{
    int cnt, ret;
    int fd;
    char fullname[64];
    char buf[1024];
    char *p;

    snprintf(fullname, sizeof(fullname),
             "%s/%s/stat", PROC_DIR, name);
    fd = open(fullname, 0);
    if (!fd)
        return -1;

    ret = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (ret > 0)
        buf[ret] = '\0';

    p = strchr(buf, ' ');
    if (!p)
        return -1;

    if (memcmp(p, " (java) ", 8))
        return -1;

    *p = 0;
    info->pid = atoi(buf);
    info->cpid = info->pid;
    info->euid = 0;
    info->egid = 0;
    info->perf_fd = -1;

    cnt = 0;
    while(p && cnt < 49) {
        p = strchr(p+1, ' ');
        cnt ++;
    }

    if (sscanf(p, " %lu ", &info->addr) != 1)
        return 1;

    return 0;
}

int read_process_info(const char *name, process_info *info)
{
   if (linux_2_6_x)
      return read_process_info_5u(name, info);
   else
      return read_process_info_7u(name, info);
}

void get_euid(process_info *pi)
{
    int cnt;
    FILE *fp;
    char fullname[64];
    char buf[1024];

    snprintf(fullname, sizeof(fullname),
             "%s/%d/status", PROC_DIR, pi->pid);
    fp = fopen(fullname, "rb");
    while(fgets(buf, sizeof(buf), fp)) {
        if (memcmp(buf, "Uid:", 4) == 0) {
            if (sscanf(buf + 4, "\t%*u\t%u", &cnt) == 1) {
                pi->euid = cnt;
            }
        } else if (memcmp(buf, "Gid:", 4) == 0) {
            if (sscanf(buf + 4, "\t%*u\t%u", &cnt) == 1) {
                pi->egid = cnt;
            }
        }
    }
    fclose(fp);
}

std::string get_link_dir(int pid, const char *subdir)
{
    int ret;
    char fn[64];
    char buf[1024];

    buf[0] = '\0';
    snprintf(fn, sizeof(fn), "/proc/%d/%s", pid, subdir);
    ret = readlink(fn, buf, sizeof(buf) - 1);
    if (ret > 0)
        buf[ret] = '\0';
    return buf;
}

int scan_proc_dir_5u(PROCESS_MAP *m, int pid)
{
    DIR *d;
    struct dirent *ent;
    struct process_info info;

    if (pid > 0) {
        char d_name[255];

        snprintf(d_name, 255, "%d", pid);
        if (read_process_info(d_name, &info))
            return -1;
        (*m)[info.pid] = info;
    } else {
        d = opendir(PROC_DIR);
        if (!d)
            return -1;

        while((ent = readdir(d)) != NULL) {
            if(!(ent->d_name &&
                    *ent->d_name > '0' &&
                    *ent->d_name <= '9'))
                continue;

            if (read_process_info(ent->d_name, &info))
                continue;

            (*m)[info.pid] = info;
        }
        closedir(d);
    }

    return 0;
}

int scan_proc_dir_7u(PROCESS_MAP *m, int pid)
{
    DIR *d;
    struct dirent *ent;
    struct process_info info;

    if (pid > 0) {
        char d_name[255];

        snprintf(d_name, 255, "%d", pid);
        if (read_process_info(d_name, &info))
            return -1;
        (*m)[info.addr] = info;
    } else {
        d = opendir(PROC_DIR);
        if (!d)
            return -1;

        while((ent = readdir(d)) != NULL) {
            if(!(ent->d_name &&
                *ent->d_name > '0' &&
                *ent->d_name <= '9'))
                continue;

            if (read_process_info(ent->d_name, &info))
                continue;
            (*m)[info.addr] = info;
        }
        closedir(d);
    }

    return 0;
}

int scan_proc_dir(PROCESS_MAP *m, int pid)
{
    if (linux_2_6_x)
        return scan_proc_dir_5u(m, pid);
    else
        return scan_proc_dir_7u(m, pid);
}

int open_file(int pid, const char *subdir)
{
    int fd;
    char fn[128];

    snprintf(fn, sizeof(fn), "/proc/%d/%s", pid, subdir);
    fd = open(fn, 0);
    CHECK_PRINT(fd < 0, "%s\n", fn);

    return fd;
}

void touch_file(const char *fn)
{
    int fd;
    ssize_t __attribute__ ((unused)) size;

    fd = open(fn, O_WRONLY|O_CREAT, 0666);
    if (fd >= 0) {
        size = write(fd, "\n", 1);
        close(fd);
    } else {
        CHECK_PRINT(fd, "touch_file: %s\n", fn);
    }
}

void copy_file(int sfd, const char *fn)
{
    int fd;
    int size;
    int len, ret, err;
    struct stat st;
    char buf[4096];

    if (fstat(sfd, &st))
        return;

    fd = open(fn, O_RDWR|O_TRUNC|O_CREAT, 0666);
    if (fd < 0)
        return;

    size = st.st_size;
    lseek(sfd, 0, SEEK_SET);
    do {
        len = sizeof(buf);
        if (len > size)
            len = size;
        ret = read(sfd, buf, len);
        if (ret <= 0)
            break;
        size -= ret;
        err = write(fd, buf, ret);
        CHECK_PRINT(err != ret, "write: %d\n", ret);
        if (err != ret)
            break;
    } while(size > 0);

    close(fd);
}

void fill_cpid(PROCESS_MAP *dst, PROCESS_MAP *src)
{
    PROCESS_MAP::iterator fit;
    for(PROCESS_MAP::iterator it = src->begin();
        it != src->end(); ++it) {
        fit = dst->find(it->second.addr);
        if (fit == dst->end())
            continue;
        fit->second.cpid = it->second.pid;
    }
}

void get_java_process(int pid)
{
    PROCESS_MAP::iterator it;
    PROCESS_MAP cmap;
    std::string root_ns_pid;
    PROCESS_MAP root_map;
    process_info *pi;

    scan_proc_dir(&root_map, pid);

    for(it = root_map.begin(); it != root_map.end(); ++it) {
        pi = &it->second;
        get_euid(pi);
        printf("[INFO] found: pid: %d cpid: %d euid: %d\n",
                pi->pid, pi->cpid, pi->euid);
    }
}

void get_java_process(NAMESPACE_MAP &ns_map, int pid, int container_pid)
{
    NAMESPACE_MAP::iterator nit;
    PROCESS_MAP::iterator it;
    PROCESS_MAP root_map;
    PROCESS_MAP cmap;
    std::string root_ns_pid;
    namespace_info *ns;
    process_info *pi;
    std::string name;
    int sw = 0;

    root_ns_pid = get_link_dir(1, PROC_NS_PID);
    scan_proc_dir(&root_map, pid);

    for(it = root_map.begin(); it != root_map.end(); ++it) {
        pi = &it->second;
        get_euid(pi);

        name = get_link_dir(pi->pid, PROC_NS_PID);
        ns = &ns_map[name];
        ns->proc_map[pi->addr] = *pi;
        ns->is_host = (name == root_ns_pid);
        if (!ns->is_host) {
            ns->ns_fd.open_ns_fd(pi->pid);
        }
    }

    for(nit = ns_map.begin(); nit != ns_map.end(); ++nit) {
        ns = &nit->second;
        sw++;
        ns->ns_fd.attach_ns_fd();
        scan_proc_dir(&cmap, container_pid);
        fill_cpid(&ns->proc_map, &cmap);
        cmap.clear();
    }

    if (sw)
        cur_ns.attach_ns_fd();

    for(nit = ns_map.begin(); nit != ns_map.end(); ++nit) {
        ns = &nit->second;
        for(it = ns->proc_map.begin(); it != ns->proc_map.end(); ++it) {
            pi = &it->second;
            printf("[INFO] found: pid: %d cpid: %d euid: %d is_host: %d\n",
                   pi->pid, pi->cpid, pi->euid, ns->is_host);
        }
    }
}

int attach_java_pid(int pid)
{
    int fd = -1;
    int cnt = 0;
    struct sockaddr_un addr;
    struct stat st;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path),
             "/tmp/.java_pid%u", pid);

    while(stat(addr.sun_path, &st) && ++cnt < 5) {
        usleep(100000);
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        return fd;
    }

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(fd);
        printf("connect %s failure: %s (%d)\n",
               addr.sun_path, strerror(errno), errno);
        return -1;
    }

    return fd;
}

std::string build_load_cmd(const char *agent)
{
    int i, len;
    char buf[256];

    len = snprintf(buf, sizeof(buf), "1\nload\n%s\ntrue\n\n", agent);
    for(i=0; i<len; i++) {
        if (buf[i] == '\n')
            buf[i] = '\0';
    }
    return std::string(buf, len);
}

int safe_write(int fd, const char *cmd, int len)
{
    int ret = 0;
    do {
        ret = write(fd, cmd, len);
        if (ret <= 0 && errno != EAGAIN)
            break;
        if (ret > 0) {
            cmd += ret;
            len -= ret;
        }
    } while(len > 0);
    return ret;
}

static int need_attached(int pid, const char *agent)
{
	char fn[64] = {};
	snprintf(fn, sizeof(fn), "/proc/%d/maps", pid);

	FILE *fp = fopen(fn, "r");
	if (!fp) {
		return 0;
	}
	int found = 0;
	char buf[1024];
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (strstr(buf, agent) != NULL) {
			found = 1;
			break;
		}
	}

	fclose(fp);
	if (found) {
		return -1;
	}
	return 0;
}

int dump_perf_map(process_info *pi, const char *agent, int need_check)
{
    char buf[128];
    std::string cwd;
    std::string cmd;
    int fd, ret;

    if (need_check && need_attached(pi->cpid, agent) < 0) {
        return 0;
    }

    fd = -1;
    snprintf(buf, sizeof(buf), "/.attach_pid%u", pi->cpid);
    cwd = get_link_dir(pi->cpid, PROC_CWD);
    cwd += buf;
    touch_file(cwd.c_str());

    ret = chown(cwd.c_str(), pi->euid, pi->egid);
    CHECK_PRINT(ret, "chown: euid:%d egid:%d\n", pi->euid, pi->egid);

    ret = kill(pi->pid, SIGQUIT);
    CHECK_PRINT(ret, "kill -3 %d\n", pi->pid);

    ret = setegid(pi->egid);
    CHECK_PRINT(ret, "setegid: egid: %d\n", pi->egid);
    ret = seteuid(pi->euid);
    CHECK_PRINT(ret, "seteuid: euid: %d\n", pi->euid);

    buf[0] = '\0';
    fd = attach_java_pid(pi->cpid);

    if (fd < 0)
        goto error_exit;

    cmd = build_load_cmd(agent);
    if (safe_write(fd, cmd.c_str(), cmd.size()) < 0)
        goto error_exit;

    ret = read(fd, buf, sizeof(buf) - 1);

    if (ret > 1 && buf[0] == '0' && buf[1] == '\n')
        ret = 0;

error_exit:
    if (fd >= 0)
        close(fd);

    ret = setegid(0);
    CHECK_PRINT(ret, "setegid: egid: 0\n");
    ret = seteuid(0);
    CHECK_PRINT(ret, "seteuid: euid: 0\n");
    unlink(cwd.c_str());

    return ret;
}

std::string read_file(const char *fn)
{
    int fd;
    struct stat st;
    std::string ret;
    ssize_t __attribute__ ((unused)) size;

    fd = open(fn, 0);
    if (fd < 0)
        return "";

    fstat(fd, &st);
    ret.resize(st.st_size);
    size = read(fd, (char *)ret.data(), st.st_size);
    close(fd);

    return ret;
}

void dump_namespace_perf(namespace_info *mi, int need_check)
{
    int ret;
    char name[64];
    process_info *pi;
    PROCESS_MAP::iterator it;

    if (mi->is_host == 0) {
        mi->ns_fd.attach_ns_fd();
        unlink(TMP_AGENT);
        copy_file(agent_fd, TMP_AGENT);
    }

    for(it = mi->proc_map.begin();
        it != mi->proc_map.end(); ++it) {
        pi = &it->second;

        if (mi->is_host == 0) {
            ret = dump_perf_map(pi, TMP_AGENT, need_check);
            snprintf(name, sizeof(name), PERF_FMT, pi->cpid);
            pi->perf_fd = open(name, 0);
            CHECK_PRINT(pi->perf_fd < 0, "%s Not Found\n", name);
        } else {
            ret = dump_perf_map(pi, LIB_AGENT, need_check);
        }
        printf("[INFO] dump: pid:%u cpid:%u euid:%d ishost:%d ret:%d\n",
               pi->pid, pi->cpid, pi->euid, mi->is_host, ret);
    }

    if (mi->is_host)
        return;

    cur_ns.attach_ns_fd();

    for(it = mi->proc_map.begin();
        it != mi->proc_map.end(); ++it) {
        pi = &it->second;
        if (pi->perf_fd < 0)
            continue;
        snprintf(name, sizeof(name), PERF_FMT, pi->pid);
        copy_file(pi->perf_fd, name);
        close(pi->perf_fd);
        pi->perf_fd = -1;
    }
}

void attach_java_process(NAMESPACE_MAP &ns_map, int need_check)
{
    NAMESPACE_MAP::iterator it;

    for(it = ns_map.begin(); it != ns_map.end(); ++it) {
        dump_namespace_perf(&it->second, need_check);
    }
}

void get_java_process(PROCESS_MAP &root_map, int pid)
{
    PROCESS_MAP::iterator it;
    PROCESS_MAP cmap;
    std::string root_ns_pid;
    process_info *pi;

    scan_proc_dir(&root_map, pid);

    for(it = root_map.begin(); it != root_map.end(); ++it) {
        pi = &it->second;
        get_euid(pi);
        printf("[INFO] found: pid: %d cpid: %d euid: %d\n",
                pi->pid, pi->cpid, pi->euid);
    }
}

void dump_proc_perf(PROCESS_MAP &root_map, int need_check)
{
    int ret;
    process_info *pi;
    PROCESS_MAP::iterator it;

    for(it = root_map.begin();
            it != root_map.end(); ++it) {
        pi = &it->second;

        ret = dump_perf_map(pi, LIB_AGENT, need_check);
        printf("[INFO] dump: pid:%u cpid:%u euid:%d ret:%d\n",
                pi->pid, pi->cpid, pi->euid, ret);
    }
}

void attach_java_process(PROCESS_MAP &root_map, int need_check)
{
    dump_proc_perf(root_map, need_check);
}

int java_attach_once(void)
{
    NAMESPACE_MAP ns_map;
    PROCESS_MAP root_map;

    char buf[1024] = {0};

    getcwd(buf, sizeof(buf));

    signal(SIGPIPE, SIG_IGN);
    agent_fd = open(LIB_AGENT, 0);
    if (agent_fd < 0) {
        chdir(buf);
        printf("%s not exist.\n", LIB_AGENT);
        return 1;
    }

    if (linux_2_6_x) {
        get_java_process(root_map, -1);
        attach_java_process(root_map, 1);
    } else {
        if (cur_ns.open_ns_fd(1)) {
            chdir(buf);
            printf("ns file not found.\n");
            return 1;
        }

        get_java_process(ns_map, -1, -1);
        attach_java_process(ns_map, 1);
    }

    chdir(buf);
    return 0;
}

int java_attach_proc(int pid, int container_pid, int need_check)
{
    NAMESPACE_MAP ns_map;
    PROCESS_MAP root_map;

    signal(SIGPIPE, SIG_IGN);
    agent_fd = open(LIB_AGENT, 0);
    if (agent_fd < 0) {
        printf("%s not exist.\n", LIB_AGENT);
        return 1;
    }

    if (linux_2_6_x) {
        get_java_process(root_map, pid);
        attach_java_process(ns_map, need_check);
    } else {
        if (cur_ns.open_ns_fd(1)) {
            printf("ns file not found.\n");
            return 1;
        }

        get_java_process(ns_map, pid, container_pid);
        attach_java_process(ns_map, need_check);
    }
    return 0;
}

// agent:    javaagent filepath, must be `/tmp/xxx.so`
// pid:      java process global pid
// ns_pid:   java process container namespace pid
void init_java_env(const char *agent, int pid, int ns_pid, const char *comm, std::set<int>& proc_map)
{
    std::set<int>::iterator it;

    if (strcmp(basename(comm), "java") != 0)
        return;

    it = proc_map.find(pid);
    if (it == proc_map.end()) {
        if (need_attached(pid, agent) < 0) {
            return;
        }

        proc_map.insert(pid);
        java_attach_proc(pid, ns_pid, 0);
    }
}

int jmaps_main(int argc, char **argv)
{
    return java_attach_once();
}

///////////////////////////////////////////////////////////////////////////////
int ns_fd_info::open_ns_fd(int pid)
{
    if (pid_fd < 0)
        pid_fd = open_file(pid, PROC_NS_PID);
    if (mnt_fd < 0)
        mnt_fd = open_file(pid, PROC_NS_MNT);
    return (pid_fd < 0 || mnt_fd < 0);
}
void ns_fd_info::attach_ns_fd()
{
#ifdef __NR_setns
    int ret;
    if (pid_fd >= 0) {
        ret = syscall(__NR_setns, pid_fd, 0);
        CHECK_PRINT(ret, "setns %d\n", pid_fd);
    }
    if (mnt_fd >= 0) {
        ret = syscall(__NR_setns, mnt_fd, 0);
        CHECK_PRINT(ret, "setns %d\n", mnt_fd);
    }
#endif
}
