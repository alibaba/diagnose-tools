/*
 * Linux内核诊断工具--用户接口API
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 * 作者: Wllabs <wllabs@163.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef UAPI_SIG_INFO_H
#define UAPI_SIG_INFO_H

#include <linux/ioctl.h>

int sig_info_syscall(struct pt_regs *regs, long id);

enum DIAG_SIGNAL {
    DIAG_SIGNAL_NOP        =  0, /* No constant in POSIX/Linux */
    DIAG_SIGNAL_HUP        =  1, /* SIGHUP */
    DIAG_SIGNAL_INT        =  2, /* SIGINT */
    DIAG_SIGNAL_QUIT       =  3, /* SIGQUIT */
    DIAG_SIGNAL_ILL        =  4, /* SIGILL */
    DIAG_SIGNAL_TRAP       =  5, /* SIGTRAP */
    DIAG_SIGNAL_ABRT       =  6, /* SIGABRT */
    DIAG_SIGNAL_BUS        =  7, /* SIGBUS */
    DIAG_SIGNAL_FPE        =  8, /* SIGFPE */
    DIAG_SIGNAL_KILL       =  9, /* SIGKILL */

    DIAG_SIGNAL_USR1       = 10, /* SIGUSR1 */
    DIAG_SIGNAL_SEGV       = 11, /* SIGSEGV */
    DIAG_SIGNAL_USR2       = 12, /* SIGUSR2 */
    DIAG_SIGNAL_PIPE       = 13, /* SIGPIPE */
    DIAG_SIGNAL_ALRM       = 14, /* SIGALRM */
    DIAG_SIGNAL_TERM       = 15, /* SIGTERM */
    DIAG_SIGNAL_STKFLT     = 16, /* Not in POSIX (SIGSTKFLT on Linux )*/
    DIAG_SIGNAL_CHLD       = 17, /* SIGCHLD */
    DIAG_SIGNAL_CONT       = 18, /* SIGCONT */
    DIAG_SIGNAL_STOP       = 19, /* SIGSTOP */

    DIAG_SIGNAL_TSTP       = 20, /* SIGTSTP */
    DIAG_SIGNAL_TTIN       = 21, /* SIGTTIN */
    DIAG_SIGNAL_TTOU       = 22, /* SIGTTOU */
    DIAG_SIGNAL_URG        = 23, /* SIGURG */
    DIAG_SIGNAL_XCPU       = 24, /* SIGXCPU */
    DIAG_SIGNAL_XFSZ       = 25, /* SIGXFSZ */
    DIAG_SIGNAL_VTALRM     = 26, /* SIGVTALRM */
    DIAG_SIGNAL_PROF       = 27, /* SIGPROF */
    DIAG_SIGNAL_WINCH      = 28, /* Not in POSIX (SIGWINCH on Linux) */
    DIAG_SIGNAL_POLL       = 29, /* SIGPOLL (also known as SIGIO on Linux) */

    DIAG_SIGNAL_PWR        = 30, /* Not in POSIX (SIGPWR on Linux) */
    DIAG_SIGNAL_SYS        = 31, /* SIGSYS (also known as SIGUNUSED on Linux) */
    DIAG_SIGNAL_RT0        = 32, /* SIGRTMIN */
    DIAG_SIGNAL_RT1        = 33, /* SIGRTMIN + 1 */
    DIAG_SIGNAL_RT2        = 34, /* SIGRTMIN + 2 */
    DIAG_SIGNAL_RT3        = 35, /* SIGRTMIN + 3 */
    DIAG_SIGNAL_RT4        = 36, /* SIGRTMIN + 4 */
    DIAG_SIGNAL_RT5        = 37, /* SIGRTMIN + 5 */
    DIAG_SIGNAL_RT6        = 38, /* SIGRTMIN + 6 */
    DIAG_SIGNAL_RT7        = 39, /* SIGRTMIN + 7 */

    DIAG_SIGNAL_RT8        = 40, /* SIGRTMIN + 8 */
    DIAG_SIGNAL_RT9        = 41, /* SIGRTMIN + 9 */
    DIAG_SIGNAL_RT10       = 42, /* SIGRTMIN + 10 */
    DIAG_SIGNAL_RT11       = 43, /* SIGRTMIN + 11 */
    DIAG_SIGNAL_RT12       = 44, /* SIGRTMIN + 12 */
    DIAG_SIGNAL_RT13       = 45, /* SIGRTMIN + 13 */
    DIAG_SIGNAL_RT14       = 46, /* SIGRTMIN + 14 */
    DIAG_SIGNAL_RT15       = 47, /* SIGRTMIN + 15 */
    DIAG_SIGNAL_RT16       = 48, /* SIGRTMIN + 16 */
    DIAG_SIGNAL_RT17       = 49, /* SIGRTMIN + 17 */

    DIAG_SIGNAL_RT18       = 50, /* SIGRTMIN + 18 */
    DIAG_SIGNAL_RT19       = 51, /* SIGRTMIN + 19 */
    DIAG_SIGNAL_RT20       = 52, /* SIGRTMIN + 20 */
    DIAG_SIGNAL_RT21       = 53, /* SIGRTMIN + 21 */
    DIAG_SIGNAL_RT22       = 54, /* SIGRTMIN + 22 */
    DIAG_SIGNAL_RT23       = 55, /* SIGRTMIN + 23 */
    DIAG_SIGNAL_RT24       = 56, /* SIGRTMIN + 24 */
    DIAG_SIGNAL_RT25       = 57, /* SIGRTMIN + 25 */
    DIAG_SIGNAL_RT26       = 58, /* SIGRTMIN + 26 */
    DIAG_SIGNAL_RT27       = 59, /* SIGRTMIN + 27 */

    DIAG_SIGNAL_RT28       = 60, /* SIGRTMIN + 28 */
    DIAG_SIGNAL_RT29       = 61, /* SIGRTMIN + 29 */
    DIAG_SIGNAL_RT30       = 62, /* SIGRTMIN + 30 */
    DIAG_SIGNAL_RT31       = 63, /* SIGRTMIN + 31 */
    DIAG_SIGNAL_RT32       = 64, /* SIGRTMIN + 32 / SIGRTMAX */

    DIAG_SIGNAL_LAST
};

#define DIAG_SIG_INFO_SET (DIAG_BASE_SYSCALL_SIG_INFO)
#define DIAG_SIG_INFO_SETTINGS (DIAG_SIG_INFO_SET + 1)
#define DIAG_SIG_INFO_DUMP (DIAG_SIG_INFO_SETTINGS + 1)

struct diag_sig_info_settings {
	unsigned int activated;
	unsigned long tgid;
	char     comm[TASK_COMM_LEN];
	char     signum[256];
    signed long sig_bitmap[128 / sizeof(unsigned long)];
};

struct sig_info_detail {
	int et_type;
	unsigned long id;
	unsigned long seq;
	unsigned long sig;
	struct timeval tv;
	struct diag_proc_chains_detail proc_chains;
	struct diag_task_detail task;
	struct diag_kern_stack_detail kern_stack;
	struct diag_user_stack_detail user_stack;
    struct diag_task_detail receive_task;
};

#define CMD_SIG_INFO_SET (0)
#define CMD_SIG_INFO_SETTINGS (CMD_SIG_INFO_SET + 1)
#define CMD_SIG_INFO_DUMP (CMD_SIG_INFO_SETTINGS + 1)
#define DIAG_IOCTL_SIG_INFO_SET _IOWR(DIAG_IOCTL_TYPE_SIG_INFO, CMD_SIG_INFO_SET, struct diag_sig_info_settings)
#define DIAG_IOCTL_SIG_INFO_SETTINGS _IOWR(DIAG_IOCTL_TYPE_SIG_INFO, CMD_SIG_INFO_SETTINGS, struct diag_sig_info_settings)
#define DIAG_IOCTL_SIG_INFO_DUMP _IOWR(DIAG_IOCTL_TYPE_SIG_INFO, CMD_SIG_INFO_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_SIG_INFO_H */
