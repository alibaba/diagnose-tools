/*
 * Linux内核诊断工具--用户态run-trace功能实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

#include <sys/time.h>
#include <string.h>
#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <iomanip>

#include "internal.h"
#include "symbol.h"
#include "json/json.h"
#include <iostream>
#include <fstream>
#include <fcntl.h>

#include "uapi/run_trace.h"
#include "params_parse.h"

using namespace std;

static char sls_file[256];
static int syslog_enabled;

void usage_run_trace(void)
{
	printf("    run-trace usage:\n");
	printf("        --help run-trace help info\n");
	printf("        --activate\n");
	printf("            verbose VERBOSE\n");
	printf("            threshold default THRESHOLD(MS), you may set special value in code\n");
	printf("            threshold-us default THRESHOLD(US)\n");
	printf("            buf-size-k set buf size(k) for per-thread\n");
	printf("            timer-us perf timer(us)\n");
	printf("        --deactivate\n");
	printf("        --settings print settings.\n");
	printf("        --report dump log with text.\n");
	printf("        --test testcase for run-trace.\n");
	printf("        --set-syscall PID SYSCALL THRESHOLD monitor special syscall\n");
	printf("        --clear-syscall PID do not monitor syscall\n");
	printf("        --uprobe set uprobe to start/stop trace\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	unsigned long threshold;
	struct params_parser parse(arg);
	struct diag_run_trace_settings settings;

	memset(&settings, 0, sizeof(struct diag_run_trace_settings));
	
	threshold = parse.int_value("threshold");
	if (threshold)
		settings.threshold_us = threshold * 1000;
	threshold = parse.int_value("threshold-us");
	if (threshold)
		settings.threshold_us = threshold;
	if (settings.threshold_us == 0)
		settings.threshold_us = 500 * 1000;

	settings.verbose = parse.int_value("verbose");
	settings.buf_size_k = parse.int_value("buf-size-k");
	settings.timer_us = parse.int_value("timer-us");

	ret = -ENOSYS;
	syscall(DIAG_RUN_TRACE_SET, &ret, &settings, sizeof(struct diag_run_trace_settings));
	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    阀值(us)：%d\n", settings.threshold_us);
	printf("    输出级别：%d\n", settings.verbose);
	printf("    TIMER_US：%d\n", settings.timer_us);
	printf("    BUF-SIZE-K：%d\n", settings.buf_size_k);

	ret = diag_activate("run-trace");
	if (ret == 1) {
		printf("run-trace activated\n");
	} else {
		printf("run-trace is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;
	
	ret = diag_deactivate("run-trace");
	if (ret == 0) {
		printf("run-trace is not activated\n");
	} else {
		printf("deactivate run-trace fail, ret is %d\n", ret);
	}
}

static void do_settings(const char *arg)
{
	struct diag_run_trace_settings settings;
	int ret;
	int enable_json = 0;
	Json::Value root;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	ret = -ENOSYS;
	syscall(DIAG_RUN_TRACE_SETTINGS, &ret, &settings, sizeof(struct diag_run_trace_settings));
	if (ret == 0) {

		if ( 1 != enable_json)
		{
			printf("功能设置：\n");
			printf("    是否激活：%s\n", settings.activated ? "√" : "×");
			printf("    阀值(us)：%d\n", settings.threshold_us);
			printf("    输出级别：%d\n", settings.verbose);
			printf("    TIMER_US：%d\n", settings.timer_us);
			printf("    线程监控项：%d\n", settings.threads_count);
			printf("    系统调用监控项：%d\n", settings.syscall_count);
		}
		else
		{
			root["activated"] = Json::Value(settings.activated);
			root["threshold_us"] = Json::Value(settings.threshold_us);
			root["verbose"] = Json::Value(settings.verbose);
			root["timer_us"] = Json::Value(settings.timer_us);
			root["threads_count"] = Json::Value(settings.threads_count);
			root["syscall_count"] = Json::Value(settings.syscall_count);
		}
	} else {
		if ( 1 != enable_json)
		{
			printf("获取run-trace设置失败，请确保正确安装了diagnose-tools工具\n");
		}
		else
		{
			root["err"]=Json::Value("found run-trace settings failed, please check diagnose-tools installed or not\n");
		}

	}

	if (1 == enable_json)
	{
		std::string str_log;
		str_log.append(root.toStyledString());
		printf("%s", str_log.c_str());
	}

}
	
static void do_monitor_syscall(char *arg)
{
	int ret;
	unsigned int pid, nr_syscall, threshold_ms;

	ret = sscanf(arg, "%d %d %d", &pid, &nr_syscall, &threshold_ms);
	if (ret != 3)
		return;
	ret = -ENOSYS;
	syscall(DIAG_RUN_TRACE_MONITOR_SYSCALL, &ret, pid, nr_syscall, threshold_ms);
	printf("set-syscall for run-trace: pid %d, syscall %d, threshold %dms, ret is %d\n",
		pid, nr_syscall, threshold_ms, ret);
}

static void do_clear_syscall(char *arg)
{
	int ret;
	unsigned int pid;

	ret = sscanf(arg, "%d", &pid);
	if (ret != 1)
		return;
	ret = -ENOSYS;
	syscall(DIAG_RUN_TRACE_CLEAR_SYSCALL, &ret, pid);
	printf("clear-syscall for run-trace: pid %d, ret is %d\n", pid, ret);
}

static void do_uprobe(const char *arg)
{
	int ret;
	struct params_parser parse(arg);
	string file_start;
	string file_stop;
	unsigned long offset_start;
	unsigned long offset_stop;
	unsigned long tgid;
	unsigned long fd_start, fd_stop;

	tgid = parse.int_value("tgid");
	file_start = parse.string_value("start-file");
	file_stop = parse.string_value("stop-file");
	offset_start = parse.int_value("start-offset");
	offset_stop = parse.int_value("stop-offset");
	if (file_start.length() <= 0 || file_stop.length() <= 0
		|| offset_start <= 0 || offset_stop <= 0
		|| tgid <= 0) {
		printf("tgid/start-file/stop-file/start-offset/stop-offset param missed\n");
		return;
	}

	fd_start = open(file_start.c_str(), O_RDONLY, 0);
	if(fd_start < 0) {
		printf("can not open %s\n", file_start.c_str());
		return;
	}
	fd_stop = open(file_stop.c_str(), O_RDONLY, 0);
	if(fd_stop < 0) {
		close(fd_start);
		printf("can not open %s\n", file_stop.c_str());
		return;
	}

	ret = -ENOSYS;
	syscall(DIAG_RUN_TRACE_UPROBE, &ret, tgid, fd_start, offset_start,
			fd_stop, offset_stop);
	printf("uprobe for run-trace: tgid %lu, start-file: %s, start-offset: %lu, stop-file: %s, stop-offset: %lu, ret is %d\n",
		tgid, file_start.c_str(), offset_start, file_stop.c_str(), offset_stop, ret);
}

static int run_trace_extract_2(void *buf, unsigned int len, void *)
{
	int i;
	symbol sym;
	elf_file file;
	int *et_type;
	static stringstream ss;

	if (len == 0)
		return 0;

	et_type = (int *)buf;

	switch (*et_type) {
	case et_start:
	{
		struct event_start *event = (struct event_start *)buf;

		if (len < sizeof(struct event_start))
			break;
		
		printf("开始跟踪：PID：%d[%lu:%lu]\n", event->header.task.pid,
				event->header.tv.tv_sec, event->header.tv.tv_usec);
		ss.str("");
		ss << "**" << "step " << setw(4) << setfill('0') << event->header.seq << "：开始跟踪" << ";";
		ss << "CGROUP:[" << event->header.task.cgroup_buf << "]" << ";";
		ss << event->header.task.comm << ";";
		for (i = 0; i < 20; i++) {
			ss << " " << ";";
		}
		ss << " " << "1000000" << endl;
		
		break;
	}
	case et_sched_in:
	{
		struct event_sched_in *event = (struct event_sched_in *)buf;

		if (len < sizeof(struct event_sched_in))
			break;

		printf("    事件类型：调入，PID：%d, 距离上次事件(ns)：%lu\n",
			event->header.task.pid,
			event->header.delta_ns);
		diag_printf_kern_stack(&event->kern_stack);

		ss << "**" << "step " << setw(4) << setfill('0') << event->header.seq << "：调度延迟" << ";";
		ss << " " << event->header.delta_ns << endl;

		break;
	}
	case et_sched_out:
	{
		struct event_sched_out *event = (struct event_sched_out *)buf;

		if (len < sizeof(struct event_sched_out))
			break;

		printf("    事件类型：调出，PID：%d, 距离上次事件(ns)：%lu\n",
			event->header.task.pid,
			event->header.delta_ns);
		diag_printf_kern_stack(&event->kern_stack);

		ss << "**" << "step " << setw(4) << setfill('0') << event->header.seq << "：运行后阻塞" << ";";
			int i;

		for (i = 0; i < BACKTRACE_DEPTH; i++) {
			if (event->kern_stack.stack[i] == (size_t)-1 || event->kern_stack.stack[i] == 0) {
				break;
			}
			sym.reset(event->kern_stack.stack[i]);
			if (g_symbol_parser.find_kernel_symbol(sym)) {
				ss << sym.name.c_str() << ";";
			} else {
				ss << "UNKNOWN" << ";";
			}
		}
		ss << " " << event->header.delta_ns << endl;

		break;
	}
	case et_sched_wakeup:
	{
		struct event_sched_wakeup *event = (struct event_sched_wakeup *)buf;
		
		if (len < sizeof(struct event_sched_wakeup))
			break;

		printf("    事件类型：唤醒线程，PID：%d, 距离上次事件(ns)：%lu\n",
			event->header.task.pid,
			event->header.delta_ns);
		diag_printf_kern_stack(&event->kern_stack);

		ss << "**" << "step " << setw(4) << setfill('0') << event->header.seq << "：阻塞" << ";";
		for (i = 0; i < BACKTRACE_DEPTH; i++) {
			if (event->kern_stack.stack[i] == (size_t)-1 || event->kern_stack.stack[i] == 0) {
				break;
			}
			sym.reset(event->kern_stack.stack[i]);
			if (g_symbol_parser.find_kernel_symbol(sym)) {
				ss << sym.name.c_str() << ";";
			} else {
				ss << "UNKNOWN" << ";";
			}
		}
		ss << " " << event->header.delta_ns << endl;

		break;
	}
	case et_sys_enter:
	{
		struct event_sys_enter *event = (struct event_sys_enter *)buf;

		if (len < sizeof(struct event_sys_enter))
			break;

		printf("    事件类型：进入系统调用，PID：%d，系统调用号：%ld, 距离上次事件(ns)：%lu\n",
			event->header.task.pid,
			event->syscall_id,
			event->header.delta_ns);
		diag_printf_user_stack(event->header.task.tgid,
				event->header.task.container_tgid,
				event->header.task.comm,
				&event->user_stack);

		ss << "**" << "step " << setw(4) << setfill('0') << event->header.seq << "：用户态运行，进入系统调用" << ";";
		for (i = 0; i < BACKTRACE_DEPTH; i++) {
			if (event->user_stack.stack[i] == (size_t)-1 || event->user_stack.stack[i] == 0) {
				break;
			}
			sym.reset(event->user_stack.stack[i]);
			init_java_env("/tmp/libperfmap.so",
				event->header.task.tgid,
				event->header.task.container_tgid,
				event->header.task.comm,
				g_symbol_parser.get_java_procs());
					
			if (g_symbol_parser.get_symbol_info(event->header.task.tgid, sym, file)) {
				if (g_symbol_parser.find_elf_symbol(sym, file, event->header.task.tgid, event->header.task.container_tgid)) {
					ss << sym.name.c_str() << ";";
				} else {
					ss << "UNKNOWN" << ";";
				}
			} else {
				ss << "UNKNOWN" << ";";
			}
		}
		for (i = 0; i < 15; i++) {
			ss << " " << ";";
		}
		ss << " " << event->header.delta_ns + 500000 << endl;

		break;
	}
	case et_sys_exit:
	{
		struct event_sys_exit *event = (struct event_sys_exit *)buf;
		
		if (len < sizeof(struct event_sys_exit))
			break;

		printf("    事件类型：退出系统调用，PID：%d, 距离上次事件(ns)：%lu\n",
			event->header.task.pid,
			event->header.delta_ns);

		ss << "**" << "step " << setw(4) << setfill('0') << event->header.seq << "：系统调用运行，退回用户态" << ";";
		for (i = 0; i < 15; i++) {
			ss << " " << ";";
		}
		ss << " " << event->header.delta_ns + 500000 << endl;

		break;
	}
	case et_irq_handler_entry:
	{
		struct event_irq_handler_entry *event = (struct event_irq_handler_entry *)buf;

		if (len < sizeof(struct event_irq_handler_entry))
			break;
		
		printf("    事件类型：进入中断[%d]，PID：%d, 距离上次事件(ns)：%lu\n",
			event->irq,
			event->header.task.pid,
			event->header.delta_ns);

		ss << "**" << "step " << setw(4) << setfill('0') << event->header.seq << "：运行，进入中断" << ";";
		ss << " " << event->header.delta_ns << endl;
	
		break;
	}
	case et_irq_handler_exit:
	{
		struct event_irq_handler_exit *event = (struct event_irq_handler_exit *)buf;

		if (len < sizeof(struct event_irq_handler_exit))
			break;

		printf("    事件类型：退出中断[%d]，PID：%d, 距离上次事件(ns)：%lu\n",
			event->irq,
			event->header.task.pid,
			event->header.delta_ns);

		ss << "**" << "step " << setw(4) << setfill('0') << event->header.seq << "：中断运行，退出中断" << ";";
		ss << " " << event->header.delta_ns << endl;

		break;
	}
	case et_softirq_entry:
	{
		struct event_softirq_entry *event = (struct event_softirq_entry *)buf;

		if (len < sizeof(struct event_softirq_entry))
			break;

		printf("    事件类型：进入软中断[%d]，PID：%d, 距离上次事件(ns)：%lu\n",
			event->nr_sirq,
			event->header.task.pid,
			event->header.delta_ns);

		ss << "**" << "step " << setw(4) << setfill('0') << event->header.seq << "：运行，进入软中断" << ";";
		ss << " " << event->header.delta_ns << endl;

		break;
	}
	case et_softirq_exit:
	{
		struct event_softirq_exit *event = (struct event_softirq_exit *)buf;
		
		if (len < sizeof(struct event_softirq_exit))
			break;

		printf("    事件类型：退出软中断[%d]，PID：%d, 距离上次事件(ns)：%lu\n",
			event->nr_sirq,
			event->header.task.pid,
			event->header.delta_ns);

		ss << "**" << "step " << setw(4) << setfill('0') << event->header.seq << "：软中断运行，退出软中断" << ";";
		ss << " " << event->header.delta_ns << endl;

		break;
	}
	case et_timer_expire_entry:
	{
		struct event_timer_expire_entry *event = (struct event_timer_expire_entry *)buf;
		
		if (len < sizeof(struct event_timer_expire_entry))
			break;
		
		printf("    事件类型：进入定时器[%lx]，PID：%d, 距离上次事件(ns)：%lu\n",
			(unsigned long)event->func,
			event->header.task.pid,
			event->header.delta_ns);

		ss << "**" << "step " << setw(4) << setfill('0') << event->header.seq << "：运行，进入定时器" << ";";
		ss << " " << event->header.delta_ns << endl;
	
		break;
	}
	case et_timer_expire_exit:
	{
		struct event_timer_expire_exit *event = (struct event_timer_expire_exit *)buf;

		if (len < sizeof(struct event_timer_expire_exit))
			break;

		printf("    事件类型：退出定时器[%ld]，PID：%d, 距离上次事件(ns)：%lu\n",
			(unsigned long)event->func,
			event->header.task.pid,
			event->header.delta_ns);

		ss << "**" << "step " << setw(4) << setfill('0') << event->header.seq << "：定时器运行，退出定时器" << ";";
		ss << " " << event->header.delta_ns << endl;

		break;
	}
	case et_run_trace_perf:
	{
		struct event_run_trace_perf *event = (struct event_run_trace_perf *)buf;

		if (len < sizeof(struct event_run_trace_perf))
			break;

		printf("    事件类型：采样，PID：%d, 距离上次事件(ns)：%lu\n",
			event->task.pid,
			event->delta_ns);

		diag_printf_kern_stack(&event->kern_stack);
		diag_printf_user_stack(event->task.tgid,
				event->task.container_tgid,
				event->task.comm,
				&event->user_stack);

		break;
	}
	case et_stop:
	{
		struct event_stop *event = (struct event_stop *)buf;

		if (len < sizeof(struct event_stop))
			break;

		printf("    结束跟踪：PID：%d[%lu:%lu], 距离上次事件(ns)：%lu, 总时长(ns)：%lu\n",
			event->header.task.pid,
			event->header.tv.tv_sec, event->header.tv.tv_usec,
			event->header.delta_ns,
			event->duration_ns);

		ss << "**" << "step " << setw(4) << setfill('0') << event->header.seq << "：结束跟踪" << ";";
		ss << "CGROUP:[" << event->header.task.cgroup_buf << "]" << ";";
		ss << event->header.task.comm << ";";
		for (i = 0; i < 20; i++) {
			ss << " " << ";";
		}
		ss << " " << "1000000" << endl;
		printf("%s\n", ss.str().c_str());
		ss.str("");

		break;
	}
	case et_stop_raw_stack:
	{
		struct event_stop_raw_stack *event = (struct event_stop_raw_stack *)buf;

		if (len < sizeof(struct event_stop))
			break;

		printf("    结束跟踪：PID：%d[%lu:%lu], 距离上次事件(ns)：%lu, 总时长(ns)：%lu\n",
			event->header.task.pid,
			event->header.tv.tv_sec, event->header.tv.tv_usec,
			event->header.delta_ns,
			event->duration_ns);
		printf("        原始堆栈：%lu, %p\n", event->raw_stack.stack_size, event->raw_stack.stack);

		ss << "**" << "step " << setw(4) << setfill('0') << event->header.seq << "：结束跟踪" << ";";
		ss << "CGROUP:[" << event->header.task.cgroup_buf << "]" << ";";
		ss << event->header.task.comm << ";";
		for (i = 0; i < 20; i++) {
			ss << " " << ";";
		}
		ss << " " << "1000000" << endl;

		printf("%s\n", ss.str().c_str());
		ss.str("");

		break;
	}
	default:
		break;
	}

	return 0;
}

static void do_extract_2(char *buf, int len)
{
	extract_variant_buffer(buf, len, run_trace_extract_2, NULL);
}

static int run_trace_extract(void *buf, unsigned int len, void *)
{
	int *et_type;

	if (len == 0)
		return 0;

	et_type = (int *)buf;

	switch (*et_type) {
	case et_run_trace:
	{
		do_extract_2((char *)buf + sizeof(int), len - sizeof(int));
		break;
	}
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, run_trace_extract, NULL);
}

static void do_dump(void)
{
	static char variant_buf[1024 * 1024];
	int len;
	int ret = 0;

	ret = -ENOSYS;
	syscall(DIAG_RUN_TRACE_DUMP, &ret, &len, variant_buf, 1024 * 1024);
	if (ret == 0 && len > 0) {
		do_extract(variant_buf, len);
	}
}

static int sls_extract_2(void *buf, unsigned int len, void *)
{
	int *et_type;
	Json::Value root;
	Json::Value task;

	if (len == 0)
		return 0;

	et_type = (int *)buf;

	switch (*et_type) {
	case et_start:
	{
		struct event_start *event = (struct event_start *)buf;

		if (len < sizeof(struct event_start))
			break;

		root["event_type"] = Json::Value("event_start");
		root["id"] = Json::Value(event->header.id);
		root["seq"] = Json::Value(event->header.seq);
		diag_sls_task(&event->header.task, task);
		root["task"] = task;
		diag_sls_time(&event->header.tv, root);

		write_file(sls_file, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);
		write_syslog(syslog_enabled, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);

		break;
	}
	case et_sched_in:
	{
		struct event_sched_in *event = (struct event_sched_in *)buf;

		if (len < sizeof(struct event_sched_in))
			break;

		root["event_type"] = Json::Value("event_sched_in");
		root["id"] = Json::Value(event->header.id);
		root["seq"] = Json::Value(event->header.seq);
		diag_sls_task(&event->header.task, task);
		root["task"] = task;
		diag_sls_time(&event->header.tv, root);
		root["delta_ns"] = Json::Value(event->header.delta_ns);
		diag_sls_kern_stack(&event->kern_stack, root);

		write_file(sls_file, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);
		write_syslog(syslog_enabled, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);

		break;
	}
	case et_sched_out:
	{
		struct event_sched_out *event = (struct event_sched_out *)buf;

		if (len < sizeof(struct event_sched_out))
			break;

		root["event_type"] = Json::Value("event_sched_out");
		root["id"] = Json::Value(event->header.id);
		root["seq"] = Json::Value(event->header.seq);
		diag_sls_task(&event->header.task, task);
		root["task"] = task;
		diag_sls_time(&event->header.tv, root);
		root["delta_ns"] = Json::Value(event->header.delta_ns);
		diag_sls_kern_stack(&event->kern_stack, root);

		write_file(sls_file, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);
		write_syslog(syslog_enabled, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);

		break;
	}
	case et_sched_wakeup:
	{
		struct event_sched_wakeup *event = (struct event_sched_wakeup *)buf;
		
		if (len < sizeof(struct event_sched_wakeup))
			break;

		root["event_type"] = Json::Value("event_sched_wakeup");
		root["id"] = Json::Value(event->header.id);
		root["seq"] = Json::Value(event->header.seq);
		diag_sls_task(&event->header.task, task);
		root["task"] = task;
		diag_sls_time(&event->header.tv, root);
		root["delta_ns"] = Json::Value(event->header.delta_ns);
		diag_sls_kern_stack(&event->kern_stack, root);

		write_file(sls_file, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);
		write_syslog(syslog_enabled, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);

		break;
	}
	case et_sys_enter:
	{
		struct event_sys_enter *event = (struct event_sys_enter *)buf;

		if (len < sizeof(struct event_sys_enter))
			break;

		root["event_type"] = Json::Value("event_sys_enter");
		root["id"] = Json::Value(event->header.id);
		root["seq"] = Json::Value(event->header.seq);
		root["event_type"] = Json::Value("event_sys_enter");
		diag_sls_task(&event->header.task, task);
		root["task"] = task;
		diag_sls_time(&event->header.tv, root);
		root["syscall_id"] = Json::Value(event->syscall_id);
		root["delta_ns"] = Json::Value(event->header.delta_ns);
		diag_sls_user_stack(event->header.task.tgid,
			event->header.task.container_tgid,
			event->header.task.comm,
			&event->user_stack, root);
	
		write_file(sls_file, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);
		write_syslog(syslog_enabled, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);

		break;
	}
	case et_sys_exit:
	{
		struct event_sys_exit *event = (struct event_sys_exit *)buf;
		
		if (len < sizeof(struct event_sys_exit))
			break;

		root["event_type"] = Json::Value("event_sys_exit");
		root["id"] = Json::Value(event->header.id);
		root["seq"] = Json::Value(event->header.seq);
		diag_sls_task(&event->header.task, task);
		root["task"] = task;
		diag_sls_time(&event->header.tv, root);
		root["delta_ns"] = Json::Value(event->header.delta_ns);

		write_file(sls_file, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);
		write_syslog(syslog_enabled, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);

		break;
	}
	case et_irq_handler_entry:
	{
		struct event_irq_handler_entry *event = (struct event_irq_handler_entry *)buf;

		if (len < sizeof(struct event_irq_handler_entry))
			break;

		root["event_type"] = Json::Value("event_irq_handler_entry");
		root["id"] = Json::Value(event->header.id);
		root["seq"] = Json::Value(event->header.seq);
		diag_sls_task(&event->header.task, task);
		root["task"] = task;
		diag_sls_time(&event->header.tv, root);
		root["irq"] = Json::Value(event->irq);
		root["delta_ns"] = Json::Value(event->header.delta_ns);
	
		write_file(sls_file, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);
		write_syslog(syslog_enabled, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);

		break;
	}
	case et_irq_handler_exit:
	{
		struct event_irq_handler_exit *event = (struct event_irq_handler_exit *)buf;

		if (len < sizeof(struct event_irq_handler_exit))
			break;

		root["event_type"] = Json::Value("event_irq_handler_exit");
		root["id"] = Json::Value(event->header.id);
		root["seq"] = Json::Value(event->header.seq);
		diag_sls_task(&event->header.task, task);
		root["task"] = task;
		diag_sls_time(&event->header.tv, root);
		root["irq"] = Json::Value(event->irq);
		root["delta_ns"] = Json::Value(event->header.delta_ns);

		write_file(sls_file, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);
		write_syslog(syslog_enabled, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);

		break;
	}
	case et_softirq_entry:
	{
		struct event_softirq_entry *event = (struct event_softirq_entry *)buf;

		if (len < sizeof(struct event_softirq_entry))
			break;

		root["event_type"] = Json::Value("event_softirq_entry");
		root["id"] = Json::Value(event->header.id);
		root["seq"] = Json::Value(event->header.seq);
		diag_sls_task(&event->header.task, task);
		root["task"] = task;
		diag_sls_time(&event->header.tv, root);
		root["sirq"] = Json::Value(event->nr_sirq);
		root["delta_ns"] = Json::Value(event->header.delta_ns);

		write_file(sls_file, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);
		write_syslog(syslog_enabled, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);

		break;
	}
	case et_softirq_exit:
	{
		struct event_softirq_exit *event = (struct event_softirq_exit *)buf;
		
		if (len < sizeof(struct event_softirq_exit))
			break;

		root["event_type"] = Json::Value("event_softirq_exit");
		root["id"] = Json::Value(event->header.id);
		root["seq"] = Json::Value(event->header.seq);
		diag_sls_task(&event->header.task, task);
		root["task"] = task;
		diag_sls_time(&event->header.tv, root);
		root["sirq"] = Json::Value(event->nr_sirq);
		root["delta_ns"] = Json::Value(event->header.delta_ns);

		write_file(sls_file, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);
		write_syslog(syslog_enabled, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);

		break;
	}
	case et_timer_expire_entry:
	{
		struct event_timer_expire_entry *event = (struct event_timer_expire_entry *)buf;
		
		if (len < sizeof(struct event_timer_expire_entry))
			break;

		root["event_type"] = Json::Value("event_timer_expire_entry");
		root["id"] = Json::Value(event->header.id);
		root["seq"] = Json::Value(event->header.seq);
		diag_sls_task(&event->header.task, task);
		root["task"] = task;
		diag_sls_time(&event->header.tv, root);
		root["func"] = Json::Value(event->func);
		root["delta_ns"] = Json::Value(event->header.delta_ns);

		write_file(sls_file, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);
		write_syslog(syslog_enabled, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);

		break;
	}
	case et_timer_expire_exit:
	{
		struct event_timer_expire_exit *event = (struct event_timer_expire_exit *)buf;

		if (len < sizeof(struct event_timer_expire_exit))
			break;

		root["event_type"] = Json::Value("event_timer_expire_exit");
		root["id"] = Json::Value(event->header.id);
		root["seq"] = Json::Value(event->header.seq);
		diag_sls_task(&event->header.task, task);
		root["task"] = task;
		diag_sls_time(&event->header.tv, root);
		root["func"] = Json::Value(event->func);
		root["delta_ns"] = Json::Value(event->header.delta_ns);

		write_file(sls_file, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);
		write_syslog(syslog_enabled, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);

		break;
	}
	case et_stop:
	{
		struct event_stop *event = (struct event_stop *)buf;

		if (len < sizeof(struct event_stop))
			break;

		root["event_type"] = Json::Value("event_stop");
		root["id"] = Json::Value(event->header.id);
		root["seq"] = Json::Value(event->header.seq);
		diag_sls_task(&event->header.task, task);
		root["task"] = task;
		diag_sls_time(&event->header.tv, root);
		root["delta_ns"] = Json::Value(event->header.delta_ns);
		root["duration_ns"] = Json::Value(event->duration_ns);

		write_file(sls_file, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);
		write_syslog(syslog_enabled, "run-trace", &event->header.start_tv, event->header.id, event->header.seq, root);

		break;
	}
	default:
		break;
	}

	return 0;
}

static void sls_extract_2(char *buf, int len)
{
	extract_variant_buffer(buf, len, sls_extract_2, NULL);
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;

	if (len == 0)
		return 0;

	et_type = (int *)buf;

	switch (*et_type) {
	case et_run_trace:
	{
		sls_extract_2((char *)buf + sizeof(int), len - sizeof(int));
		break;
	}
	default:
		break;
	}

	return 0;
}

__attribute__((unused)) static void sls_test(void)
{
	int i;
	struct timeval delay;
	int ret;

	do_activate("");
	ret = -ENOSYS;
	//syscall(DIAG_RUN_TRACE_MONITOR_SYSCALL, &ret, 0, 35, 50);
	syscall(DIAG_RUN_TRACE_START, &ret, 100);

	for (i = 0; i < 3000000; i++) {
		static int tmp = 0;
		tmp = tmp + 2 * i;
	}
	delay.tv_sec = 0;
	delay.tv_usec = 60 * 1000; // 20 ms
	select(0, NULL, NULL, NULL, &delay);
	for (i = 0; i < 3000000; i++) {
		static int tmp = 0;
		tmp = tmp + i;
	}
	delay.tv_sec = 0;
	delay.tv_usec = 100 * 1000; // 20 ms
	select(0, NULL, NULL, NULL, &delay);
	ret = -ENOSYS;
	syscall(DIAG_RUN_TRACE_STOP, &ret);
	do_deactivate();
}

static void do_sls(char *arg)
{
	int ret;
	static char variant_buf[1024 * 1024];
	int len;
	int jiffies_sls = 0;

	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	//sls_test();

	java_attach_once();
	while (1) {
		ret = -ENOSYS;
		syscall(DIAG_RUN_TRACE_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		if (ret == 0 && len > 0) {
			/**
			 * 10 min
			 */
			if (jiffies_sls >= 60) {
				jiffies_sls = 0;
				clear_symbol_info(pid_cmdline, g_symbol_parser.get_java_procs(), 1);
				java_attach_once();
			}

			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
		jiffies_sls++;
	}
}

static void do_test(void)
{
	int i = 0;
	int ret;
	struct timeval delay;

	ret = -ENOSYS;
	//syscall(DIAG_RUN_TRACE_MONITOR_SYSCALL, &ret, 0, 35, 50);
	syscall(DIAG_RUN_TRACE_START, &ret, 100);

	for (i = 0; i < 3000000; i++) {
		static int tmp = 0;
		tmp = tmp + 2 * i;
	}
	delay.tv_sec = 0;
	delay.tv_usec = 60 * 1000; // 20 ms
	select(0, NULL, NULL, NULL, &delay);
	for (i = 0; i < 3000000; i++) {
		static int tmp = 0;
		tmp = tmp + i;
	}
	delay.tv_sec = 0;
	delay.tv_usec = 100 * 1000; // 20 ms
	select(0, NULL, NULL, NULL, &delay);
	ret = -ENOSYS;
	syscall(DIAG_RUN_TRACE_STOP, &ret);
}

int run_trace_main(int argc, char **argv)
{
	static struct option long_options[] = {
			{"help",     no_argument, 0,  0 },
			{"activate",     optional_argument, 0,  0 },
			{"deactivate", no_argument,       0,  0 },
			{"settings",     optional_argument, 0,  0 },
			{"report",     no_argument, 0,  0 },
			{"test",     no_argument, 0,  0 },
			{"log",     required_argument, 0,  0 },
			{"set-syscall",     required_argument, 0,  0 },
			{"clear-syscall",     required_argument, 0,  0 },
			{"uprobe",     required_argument, 0,  0 },
			{0,         0,                 0,  0 }
		};
	int c;

	if (argc <= 1) {
		usage_run_trace();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (option_index) {
		case 0:
			usage_run_trace();
			break;
	  case 1:
			do_activate(optarg ? optarg : "");
			break;
		case 2:
			do_deactivate();
			break;
		case 3:
			do_settings(optarg ? optarg : "");
			break;
		case 4:
			do_dump();
			break;
		case 5:
			do_test();
			break;
		case 6:
			do_sls(optarg);
			break;
		case 7:
			do_monitor_syscall(optarg);
			break;
		case 8:
			do_clear_syscall(optarg);
			break;
		case 9:
			do_uprobe(optarg);
			break;
		default:
			usage_run_trace();
			break;
		}
	}

	return 0;
}

