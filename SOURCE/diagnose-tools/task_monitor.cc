/*
 * Linux内核诊断工具--用户态task-monitor功能实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Wen Yang <simon.wy@linux.alibaba.com>
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

#include <iostream>  
#include <fstream>  

#include <sys/time.h>
#include <string.h>
#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */

#include "internal.h"
#include "symbol.h"
#include "json/json.h"
#include "uapi/task_monitor.h"
#include "params_parse.h"
#include <iostream>
#include <fstream>

using namespace std;

static char sls_file[256];
static int syslog_enabled;
static int process_chains = 0;

#define TASK_MONITOR_DEFAULT_INTERVAL 10000
#define TASK_MONITOR_MINIMUM_INTERVAL 100

void usage_task_monitor(void)
{
	printf("    task-monitor usage:\n");
	printf("        --help task-monitor help info\n");
	printf("        --activate\n");
	printf("            verbose VERBOSE\n");
	printf("            style dump style: 0 - common, 1 - process chains\n");
	printf("            task.a threshold for running or uninterruptible tasks, default is 500\n");
	printf("            task.r threshold for running tasks, default is 400\n");
	printf("            task.d threshold for uninterruptible tasks, default is 100\n");
	printf("            interval milliseconds for reporting, default is 10000ms and minimum is 100ms\n");
	printf("        --settings print settings.\n");
	printf("        --deactivate\n");
	printf("        --report dump log with text.\n");
	printf("          out output raw stack into special file.\n");
	printf("          in input one raw-stack file to extract.\n");
	printf("          inlist input filename including raw-stack file list to extract.\n");
	printf("          input filename including raw-stack file list to extract.\n");
	printf("          console get raw-stack file list from console to extract.\n");
	printf("        --sls save detail into sls files.\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_task_monitor_settings settings;

	memset(&settings, 0, sizeof(struct diag_task_monitor_settings));
	
	settings.threshold_task_a = parse.int_value("task.a");
	if (!settings.threshold_task_a)
		settings.threshold_task_a = 500;

	settings.threshold_task_r = parse.int_value("task.r");
	if (!settings.threshold_task_r)
		settings.threshold_task_r = 400;

	settings.threshold_task_d = parse.int_value("task.d");
	if (!settings.threshold_task_d)
		settings.threshold_task_d = 100;

	settings.interval = parse.int_value("interval");
	if (!settings.interval) 
		settings.interval = TASK_MONITOR_DEFAULT_INTERVAL;
	if (settings.interval < TASK_MONITOR_MINIMUM_INTERVAL)
		settings.interval = TASK_MONITOR_MINIMUM_INTERVAL;

	settings.verbose = parse.int_value("verbose");
	settings.style = parse.int_value("style");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_TASK_MONITOR_SET, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_TASK_MONITOR_SET, &ret, &settings, sizeof(struct diag_task_monitor_settings));
	}

	printf("功能设置%s, 返回值: %d\n", ret ? "失败" : "成功", ret);
	printf("    Task.A: \t%d\n", settings.threshold_task_a);
	printf("    Task.R: \t%d\n", settings.threshold_task_r);
	printf("    Task.D: \t%d\n", settings.threshold_task_d);
	printf("    Interval: \t%d\n", settings.interval);
	printf("    输出级别: \t%d\n", settings.verbose);
	printf("    STYLE: \t%d\n", settings.style);
	if (ret)
		return;

	ret = diag_activate("task-monitor");
	if (ret == 1) {
		printf("task-monitor activated\n");
	} else {
		printf("task-monitor is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("task-monitor");
	if (ret == 0) {
		printf("task-monitor is not activated\n");
	} else {
		printf("deactivate task-monitor fail, ret is %d\n", ret);
	}
}

static void do_settings(const char *arg)
{
	struct diag_task_monitor_settings settings;
	int ret;
	int enable_json = 0;
	Json::Value root;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_TASK_MONITOR_SETTINGS, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_TASK_MONITOR_SETTINGS, &ret, &settings, sizeof(struct diag_task_monitor_settings));
	}

	if (ret == 0) {
		if (1 != enable_json)
		{
			printf("功能设置: \n");
			printf("    是否激活: \t%s\n", settings.activated ? "√" : "×");
			printf("    Task.A: \t%d\n", settings.threshold_task_a);
			printf("    Task.R: \t%d\n", settings.threshold_task_r);
			printf("    Task.D: \t%d\n", settings.threshold_task_d);
			printf("    Interval: \t%dms\n", settings.interval);
			printf("    输出级别: \t%d\n", settings.verbose);
			printf("    STYLE: \t%d\n", settings.style);
		}
		else
		{
			root["activated"] = Json::Value(settings.activated);
			root["Task.A"] = Json::Value(settings.threshold_task_a);
			root["Task.R"] = Json::Value(settings.threshold_task_r);
			root["Task.D"] = Json::Value(settings.threshold_task_d);
			root["Interval"] = Json::Value(settings.interval);
			root["verbose"] = Json::Value(settings.verbose);
			root["STYLE"] = Json::Value(settings.style);
		}
	} else {
		if ( 1 != enable_json)
		{
			printf("获取task-monitor设置失败，请确保正确安装了diagnose-tools工具\n");
		}

		else
		{
			root["err"]=Json::Value("found task-monitor settings failed, please check diagnose-tools installed or not\n");
		}
	}

	if (1 == enable_json)
	{
		std::string str_log;
		str_log.append(root.toStyledString());
		printf("%s", str_log.c_str());
	}

	return;
}

static int task_monitor_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct task_monitor_summary *summary;
	struct task_monitor_detail *detail;
	static int seq = 0;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_task_monitor_summary:
		if (len < sizeof(struct task_monitor_summary))
			break;
		summary = (struct task_monitor_summary *)buf;

		if (!summary->task_r && !summary->task_d)
			break;

		printf("进程监控-摘要信息: [%lu:%lu]\n",
					summary->tv.tv_sec, summary->tv.tv_usec);
		printf("\tTask.R: %d\n", summary->task_r);
		printf("\tTask.D: %d\n", summary->task_d);

		break;
	case et_task_monitor_detail:
		if (len < sizeof(struct task_monitor_detail))
			break;
		detail = (struct task_monitor_detail *)buf;
		seq++;
		printf("进程监控-详细信息: [%lu:%lu]\n",
					detail->tv.tv_sec, detail->tv.tv_usec);
		printf("##CGROUP:[%s]  %d      [%03d]  采样命中[%s]\n",
				detail->task.cgroup_buf,
				detail->task.pid,
				seq,
				detail->task.state == 0 ? "R" : "D");
		diag_printf_kern_stack(&detail->kern_stack);
		diag_printf_user_stack(run_in_host ? detail->task.tgid : detail->task.container_tgid,
				detail->task.container_tgid,
				detail->task.comm,
				&detail->user_stack);

		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				detail->task.comm);
		diag_printf_proc_chains(&detail->proc_chains, 0, process_chains);
		printf("##\n");

		detail++;

		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, task_monitor_extract, NULL);
}

static void do_dump(const char *arg)
{
	static char variant_buf[1024 * 1024];
	struct params_parser parse(arg);
	int len;
	int ret = 0;
	int console=0;

	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 1024 * 1024,
		.user_buf = variant_buf,
	};

	string in_file;
	string out_file;
	string inlist_file;
	string line = "";
	string input_line;
	
	process_chains = parse.int_value("process-chains");
	console = parse.int_value("console");
	in_file = parse.string_value("in");
	out_file = parse.string_value("out");
	inlist_file = parse.string_value("inlist");
	
	memset(variant_buf, 0, 1024 * 1024);
	if (console) {
	         while (cin) {
	                 getline(cin, input_line);
	                 if (!cin.eof()){
	                         ifstream fin(input_line, ios::binary);
	                         fin.read(variant_buf, 1024 * 1024);
	                         len = fin.gcount();
	                         if (len > 0) {
	                                 do_extract(variant_buf, len);
	                                 memset(variant_buf, 0,  1024 * 1024);
	                         }
	                         fin.close();
	                  }
	         }
	 } else if (in_file.length() > 0) {
	         ifstream fin(in_file, ios::binary);
	         fin.read(variant_buf, 1024 * 1024);
	         len = fin.gcount();
	         if (len > 0) {
	                 do_extract(variant_buf, len);
	         }
	         fin.close();
	} else if (inlist_file.length() > 0) {
	        ifstream in(inlist_file);
	        if(in) {
	                while (getline(in, line)){
	                        ifstream fin(line.c_str());
	                        fin.read(variant_buf, 1024 * 1024);
	                        len = fin.gcount();
	                        if (len > 0) {
	                                do_extract(variant_buf, len);
	                                memset(variant_buf, 0, 1024 * 1024);
	                        }
	                        fin.close();
	                }
	        in.close();
		}
	} else {
		
		if (run_in_host) {
			ret = diag_call_ioctl(DIAG_IOCTL_TASK_MONITOR_DUMP, (long)&dump_param);
		} else {
			ret = -ENOSYS;
			syscall(DIAG_TASK_MONITOR_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		}
	
		if (out_file.length() > 0) {
			if (ret == 0 && len > 0) {
	                	ofstream fout(out_file);
	                        fout.write(variant_buf, len);
	                        fout.close();
	                }
		} else {
			if (ret == 0) {
				do_extract(variant_buf, len);
			}
		}
	}
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct task_monitor_summary *summary;
	struct task_monitor_detail *detail;
	Json::Value root;
	Json::Value tsk;
	stringstream ss;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_task_monitor_summary:
		if (len < sizeof(struct task_monitor_summary))
			break;
		summary = (struct task_monitor_summary *)buf;

		root["tv_sec"] = Json::Value(summary->tv.tv_sec);
		root["tv_usec"] = Json::Value(summary->tv.tv_usec);

		ss.str("");
		ss << summary->task_r;
		root["task_r"] = Json::Value(ss.str());

		ss.str("");
		ss << summary->task_d;
		root["task_d"] = Json::Value(ss.str());

		write_file(sls_file, "task-monitor-summary", &summary->tv, summary->id, 0, root);
		write_syslog(syslog_enabled, "task-monitor-summary", &summary->tv, summary->id, 0, root);

		break;
	case et_task_monitor_detail:
		if (len < sizeof(struct task_monitor_detail))
			break;
		detail= (struct task_monitor_detail *)buf;

		tsk["id"] = Json::Value(detail->id);
		diag_sls_task(&detail->task, tsk);
		diag_sls_kern_stack(&detail->kern_stack, tsk);
		diag_sls_proc_chains(&detail->proc_chains, tsk);

		write_file(sls_file, "task-monitor-task", &detail->tv, detail->id, 0, tsk);
		write_syslog(syslog_enabled, "task-monitor-task", &detail->tv, detail->id, 0, tsk);
		
		break;
	default:
		break;
	}

	return 0;
}

static void do_sls(char *arg)
{
	int ret;
	static char variant_buf[1024 * 1024];
	int len;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 1024 * 1024,
		.user_buf = variant_buf,
	};

	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	while (1) {
		if (run_in_host) {
			ret = diag_call_ioctl(DIAG_IOCTL_TASK_MONITOR_DUMP, (long)&dump_param);
		} else {
			ret = -ENOSYS;
			syscall(DIAG_TASK_MONITOR_DUMP, &ret, &len, variant_buf, 1024 * 1024);
		}

		if (ret == 0) {
			pid_cmdline.clear();
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}
}

int task_monitor_main(int argc, char **argv)
{
	static struct option long_options[] = {
			{"help",     no_argument, 0,  0 },
			{"activate",     optional_argument, 0,  0 },
			{"deactivate", no_argument,       0,  0 },
			{"settings",     optional_argument, 0,  0 },
			{"report",     optional_argument, 0,  0 },
			{"log",     required_argument, 0,  0 },
			{0,         0,                 0,  0 }
		};
	int c;

	if (argc <= 1) {
		usage_task_monitor();
		return 0;
	}

	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_task_monitor();
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
			do_dump(optarg ? optarg : "");
			break;
		case 5:
			do_sls(optarg);
			break;
		default:
			usage_task_monitor();
			break;
		}
	}

	return 0;
}

