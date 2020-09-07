/*
 * Linux内核诊断工具--杂项定义头文件
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <string>
#include <set>
#include "uapi/ali_diagnose.h"
#include "json/json.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

extern std::set<int> g_proc_map;

int run_trace_main(int argc, char **argv);
int sys_delay_main(int argc, char **argv);
int sched_delay_main(int argc, char **argv);
int load_monitor_main(int argc, char **argv);
int exit_monitor_main(int argc, char **argv);
int utilization_main(int argc, char **argv);
int perf_main(int argc, char **argv);
int tcp_retrans_main(int argc, char **argv);
int rw_top_main(int argc, char **argv);
int irq_delay_main(int argc, char **argv);
int mutex_monitor_main(int argc, char **argv);
int alloc_top_main(int argc, char **argv);
int alloc_load_main(int argc, char **argv);
int drop_packet_main(int argc, char **argv);
int fs_orphan_main(int argc, char **argv);
int df_du_main(int argc, char **argv);
int exec_monitor_main(int argc, char **argv);
int fs_shm_main(int argc, char **argv);
int irq_stats_main(int argc, char **argv);
int irq_trace_main(int argc, char **argv);
int kprobe_main(int argc, char **argv);
int mm_leak_main(int argc, char **argv);
int proc_monitor_main(int argc, char **argv);
int runq_info_main(int argc, char **argv);
int reboot_main(int argc, char **argv);
int pi_main(int argc, char *argv[]);
int memcpy_main(int argc, char* argv[]);
int md5_main(int argc, char *argv[]);
int net_bandwidth_main(int argc, char *argv[]);

void usage_run_trace(void);
void usage_sys_delay(void);
void usage_load_monitor(void);
void usage_exit_monitor(void);
void usage_utilization(void);
void usage_perf();
void usage_tcp_retrans();
void usage_rw_top();
void usage_irq_delay();
void usage_mutex_monitor();
void usage_alloc_top();
void usage_drop_packet();
void usage_fs_orphan();
void usage_exec_monitor();
void usage_fs_shm();
void usage_irq_stats();
void usage_irq_trace();
void usage_kprobe();
void usage_mm_leak();
void usage_testcase(void);
void usage_pupil(void);
void usage_sched_delay(void);
void usage_reboot(void);
void usage_test_memcpy(void);
void usage_test_pi(void);
void usage_test_md5(void);
void usage_net_bandwidth(void);

int uprobe_main(int argc, char **argv);
void usage_uprobe();

int ping_delay_main(int argc, char *argv[]);
void usage_ping_delay(void);

int test_run_trace_main(int argc, char *argv[]);
void usage_test_run_trace(void);

int diag_activate(const char func[]);
int diag_deactivate(const char func[]);

void diag_printf_inode(struct diag_inode_detail *inode);
void diag_printf_time(struct timeval *tv);
void diag_printf_task(struct diag_task_detail *task);
void diag_printf_proc_chains(struct diag_proc_chains_detail *proc_chains);
void diag_printf_proc_chains(struct diag_proc_chains_detail *proc_chains, int reverse);
void diag_printf_proc_chains(struct diag_proc_chains_detail *proc_chains, int reverse, int detail);
void diag_printf_kern_stack(struct diag_kern_stack_detail *kern_stack);
void diag_printf_kern_stack(struct diag_kern_stack_detail *kern_stack, int reverse);
void diag_printf_user_stack(int pid, int ns_pid, const char *comm,
	struct diag_user_stack_detail *user_stack);
void diag_printf_user_stack(int pid, int ns_pid, const char *comm,
	struct diag_user_stack_detail *user_stack, int attach);
void diag_printf_user_stack(int pid, int ns_pid, const char *comm,
	struct diag_user_stack_detail *user_stack, int attach, int reverse);
void diag_printf_raw_stack(int pid, int ns_pid, const char *comm,
	struct diag_raw_stack_detail *raw_stack);
void diag_printf_raw_stack(int pid, int ns_pid, const char *comm,
	struct diag_raw_stack_detail *raw_stack, int attach);
void init_java_env(const char *agent, int pid, int ns_pid, const char *comm, std::set<int> &);

void diag_sls_time(struct timeval *tv, Json::Value &owner);
void diag_sls_task(struct diag_task_detail *tsk_info, Json::Value &task);
void diag_sls_proc_chains(struct diag_proc_chains_detail *proc_chains, Json::Value &task);
void diag_sls_kern_stack(struct diag_kern_stack_detail *kern_stack, Json::Value &task);
void diag_sls_user_stack(pid_t pid, pid_t ns_pid, const char *comm,
	struct diag_user_stack_detail *user_stack, Json::Value &task);
void diag_sls_user_stack(pid_t pid, pid_t ns_pid, const char *comm,
	struct diag_user_stack_detail *user_stack, Json::Value &task, int attach);
void diag_sls_inode(struct diag_inode_detail *inode, Json::Value &root);
int log_config(char *arg, char *sls_file, int *p_syslog_enabled);
void write_syslog(int enabled, const char mod[], struct timeval *tv, unsigned long id, int seq, Json::Value &root);
void write_file(char *sls_file, const char mod[], struct timeval *tv, unsigned long id, int seq, Json::Value &root);
void diag_ip_addr_to_str(unsigned char *ip_addr,const char type[], Json::Value &root);
#define ULONG_MAX	(~0UL)
#define STACK_IS_END(v) ((v) == 0 || (v) == ULONG_MAX)

class pid_cmdline {
	private:
		std::map<int, std::string> cmdlines;
	public:
		void clear(void);
		std::string & get_pid_cmdline(int pid);
};

int jmaps_main(int argc, char **argv);
void restore_global_env();
int attach_ns_env(int pid);
int java_attach_once();

extern class pid_cmdline pid_cmdline;

extern void clear_symbol_info(class pid_cmdline &pid_cmdline, std::set<int> &procs, int dist);
extern unsigned int ipstr2int(const char *ipstr);
extern char *int2ipstr(const unsigned int ip, char *ipstr, const unsigned int ip_str_len);

extern int is_linux_2_6_x(void);
extern int linux_2_6_x;

int sys_cost_main(int argc, char **argv);
void usage_sys_cost();

int fs_cache_main(int argc, char *argv[]);
void usage_fs_cache(void);

int high_order_main(int argc, char *argv[]);
void usage_high_order(void);

int testcase_main(int argc, char *argv[]);
