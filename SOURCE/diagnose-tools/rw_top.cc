/*
 * Linux内核诊断工具--用户态rw-top功能实现
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
#include <iostream>
#include <fstream>

#include "internal.h"
#include "symbol.h"
#include "uapi/rw_top.h"
#include "params_parse.h"

using namespace std;

static char sls_file[256];
static int syslog_enabled;
static int out_json = 0;
static int out_flame = 1;

static Json::FastWriter fast_writer;

void usage_rw_top(void)
{
	printf("    rw-top usage:\n");
	printf("        --help rw-top help info\n");
	printf("        --activate\n");
	printf("          verbose VERBOSE\n");
	printf("          top how many items to dump\n");
	printf("          shm set 1 if want dump shm\n");
	printf("          perf set 1 if want perf detail\n");
	printf("          raw-stack output raw stack\n");
	printf("          device the device which you are insterested in\n");
	printf("        --deactivate\n");
	printf("        --report dump log with text.\n");
	printf("          out output raw stack into special file.\n");
	printf("          in input one raw-stack file to extract.\n");
	printf("          inlist input filename including raw-stack file list to extract .\n");
	printf("          input filename including raw-stack file list to extract .\n");
	printf("          console get raw-stack file list from console to extract .\n");
	printf("        --log\n");
	printf("          sls=/tmp/1.log store in file\n");
	printf("          syslog=1 store in syslog\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_rw_top_settings settings;
	string str;

	memset(&settings, 0, sizeof(struct diag_rw_top_settings));
	
	settings.verbose = parse.int_value("verbose");
	settings.shm = parse.int_value("shm");
	settings.top = parse.int_value("top");
	settings.perf = parse.int_value("perf");
	settings.raw_stack = parse.int_value("raw-stack");
	
	str = parse.string_value("device");
	if (str.length() > 0) {
		strncpy(settings.device_name, str.c_str(), DIAG_DEVICE_LEN);
		settings.device_name[DIAG_DEVICE_LEN - 1] = 0;
	}
	if (settings.top == 0)
		settings.top = 100;	

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_RW_TOP_SET, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_RW_TOP_SET, &ret, &settings, sizeof(struct diag_rw_top_settings));
	}

	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    TOP：%d\n", settings.top);
	printf("    SHM：%d\n", settings.shm);
	printf("    PERF：%d\n", settings.perf);
	printf("    输出级别：%d\n", settings.verbose);
	printf("    DEVICE: %s\n", settings.device_name);

	if (ret)
		return;

	ret = diag_activate("rw-top");
	if (ret == 1) {
		printf("rw-top activated\n");
	} else {
		printf("rw-top is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("rw-top");
	if (ret == 0) {
		printf("rw-top is not activated\n");
	} else {
		printf("deactivate rw-top fail, ret is %d\n", ret);
	}
}

static void print_settings_in_json(struct diag_rw_top_settings *settings, int ret)
{
	Json::Value root;
	std::string str_log;

	if (ret == 0) {
		root["activated"] = Json::Value(settings->activated);
		root["TOP"] = Json::Value(settings->top);
		root["SHM"] = Json::Value(settings->shm);
		root["PERF"] = Json::Value(settings->perf);
		root["verbose"] = Json::Value(settings->verbose);
	} else {
		root["err"] = Json::Value("found rw-top settings failed, please check if diagnose-tools is installed correctly or not.");
	}

	str_log.append(root.toStyledString());
	printf("%s", str_log.c_str());

	return;
}

static void do_settings(const char *arg)
{
	struct diag_rw_top_settings settings;
	int ret;
	int enable_json = 0;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_RW_TOP_SETTINGS, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_RW_TOP_SETTINGS, &ret, &settings, sizeof(struct diag_rw_top_settings));
	}

	if (1 == enable_json) {
		return print_settings_in_json(&settings, ret);
	}

	if (ret == 0) {
		printf("功能设置：\n");
		printf("    是否激活：%s\n", settings.activated ? "√" : "×");
		printf("    TOP：%d\n", settings.top);
		printf("    SHM：%d\n", settings.shm);
		printf("    PERF：%d\n", settings.perf);
		printf("    输出级别：%d\n", settings.verbose);
		printf("    RAW-STACK：%lu\n", settings.raw_stack);
		printf("    DEVICE: %s\n", settings.device_name);
	} else {
		printf("获取rw-top设置失败，请确保正确安装了diagnose-tools工具\n");
	}
}

static int rw_top_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct rw_top_detail *detail;
	struct rw_top_perf *perf;
	struct rw_top_raw_perf *raw_perf;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_rw_top_detail:
		if (len < sizeof(struct rw_top_detail))
			break;
		detail = (struct rw_top_detail *)buf;

		printf("%5d%18lu%18lu%18lu%18lu%8lu%16s%32s        %-100s\n",
			detail->seq,
			detail->r_size,
			detail->w_size,
			detail->map_size,
			detail->rw_size,
			detail->pid,
			detail->comm,
			detail->device_name,
			detail->path_name);

		break;
	case et_rw_top_perf:
		if (len < sizeof(struct rw_top_perf))
			break;
		perf = (struct rw_top_perf *)buf;

		printf("##CGROUP:[%s]  %d      [%03d]  采样命中\n",
				perf->task.cgroup_buf,
				perf->task.pid,
				0);
		printf("#*        0xffffffffffffff %s    %s (UNKNOWN)\n",
				perf->path_name, perf->device_name);
		diag_printf_kern_stack(&perf->kern_stack);
		diag_printf_user_stack(perf->task.tgid,
				perf->task.container_tgid,
				perf->task.comm,
				&perf->user_stack, 0);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				perf->task.comm);
		diag_printf_proc_chains(&perf->proc_chains);
		printf("##\n");
		break;
	case et_rw_top_raw_perf:
		if (len < sizeof(struct rw_top_raw_perf))
			break;
		raw_perf = (struct rw_top_raw_perf *)buf;

		printf("##CGROUP:[%s]  %d      [%03d]  采样命中\n",
				raw_perf->task.cgroup_buf,
				raw_perf->task.pid,
				0);
		printf("#*        0xffffffffffffff %s    %s (UNKNOWN)\n",
				raw_perf->path_name, raw_perf->device_name);
		diag_printf_kern_stack(&raw_perf->kern_stack);
		diag_printf_raw_stack(run_in_host ? raw_perf->task.tgid : raw_perf->task.container_tgid,
			raw_perf->task.container_tgid,
			raw_perf->task.comm,
			&raw_perf->raw_stack);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				raw_perf->task.comm);
		diag_printf_proc_chains(&raw_perf->proc_chains);
		printf("##\n");
		break;
	default:
		break;
	}

	return 0;
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct rw_top_detail *detail;
	Json::Value root;
	struct diag_timespec tv;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_rw_top_detail:
		if (len < sizeof(struct rw_top_detail))
			break;
		detail = (struct rw_top_detail *)buf;
		root["seq"] = Json::Value(detail->seq);
		root["r_size"] = Json::Value(detail->r_size);
		root["w_size"] = Json::Value(detail->w_size);
		root["map_size"] = Json::Value(detail->map_size);
		root["rw_size"] = Json::Value(detail->rw_size);
		root["pid"] = Json::Value(detail->pid);
		root["comm"] = Json::Value(detail->comm);
		root["path_name"] = Json::Value(detail->path_name);

		diag_gettimeofday(&tv, NULL);
		write_file(sls_file, "rw-top", &tv, detail->id, detail->seq, root);
		write_syslog(syslog_enabled, "rw-top", &tv, detail->id, detail->seq, root);

		break;
	default:
		break;
	}

	return 0;
}

static int json_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct rw_top_detail *detail;
	struct rw_top_perf *perf;
	struct rw_top_raw_perf *raw_perf;
	Json::Value root;
	Json::Value task;
	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_rw_top_detail:
		if (len < sizeof(struct rw_top_detail))
			break;
		detail = (struct rw_top_detail *)buf;
		root["type"] = Json::Value("rw-top");
		root["seq"] = Json::Value(detail->seq);
		root["r_size"] = Json::Value(detail->r_size);
		root["w_size"] = Json::Value(detail->w_size);
		root["map_size"] = Json::Value(detail->map_size);
		root["rw_size"] = Json::Value(detail->rw_size);
		root["pid"] = Json::Value(detail->pid);
		root["comm"] = Json::Value(detail->comm);
		root["device_name"] = Json::Value(detail->device_name);
		root["path_name"] = Json::Value(detail->path_name);

		std::cout << "#$" << fast_writer.write(root);
		break;
	case et_rw_top_perf:
		if (len < sizeof(struct rw_top_perf))
			break;
		perf = (struct rw_top_perf *)buf;

		root["type"] = Json::Value("rw-top");
		root["path_name"] = Json::Value(perf->path_name);
		root["device_name"] = Json::Value(perf->device_name);

		diag_sls_task(&perf->task, task);
		diag_sls_kern_stack(&perf->kern_stack, task);
		diag_sls_user_stack(perf->task.tgid,
				perf->task.container_tgid,
				perf->task.comm,
				&perf->user_stack, task, 0);
		diag_sls_proc_chains(&perf->proc_chains, task);

		root["task"] = task;
		root["tv_sec"] = Json::Value(perf->tv.tv_sec);
		root["tv_usec"] = Json::Value(perf->tv.tv_usec);

		std::cout << "#$" << fast_writer.write(root);
		break;
	case et_rw_top_raw_perf:
		//to be done
		break;
	default:
		break;
	}

	return 0;
}

static void do_extract(char *buf, int len)
{
	if (out_json) {
		extract_variant_buffer(buf, len, json_extract, NULL);
	}

	if (out_flame) {
		extract_variant_buffer(buf, len, rw_top_extract, NULL);
	}
}

static void do_dump(const char *arg)
{
	static char variant_buf[50 * 1024 * 1024];
	int len;
	int ret = 0;
	int console=0;
	struct params_parser parse(arg);
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 50 * 1024 * 1024,
		.user_buf = variant_buf,
	};

	string in_file;
	string out_file;
	string inlist_file;
	string line = "";
	string input_line;

	console = parse.int_value("console");
	in_file = parse.string_value("in");
	out_file = parse.string_value("out");
	inlist_file = parse.string_value("inlist");

	memset(variant_buf, 0, 50 * 1024 * 1024);
	if (console) {
                while (cin) {
                        getline(cin, input_line);
                        if (!cin.eof()){
                                ifstream fin(input_line, ios::binary);
                                fin.read(variant_buf, 50 * 1024 * 1024);
                                len = fin.gcount();
                                if (len > 0) {
                                        do_extract(variant_buf, len);
                                        memset(variant_buf, 0, 50 * 1024 * 1024);
                                }
                                fin.close();
                         }
                }
        } else if (in_file.length() > 0) {
                ifstream fin(in_file, ios::binary);
                fin.read(variant_buf, 50 * 1024 * 1024);
                len = fin.gcount();
                if (len > 0) {
                        do_extract(variant_buf, len);
                        fin.close();
                }
       } else if (inlist_file.length() > 0) {
               ifstream in(inlist_file);
               if(in) {
                       while (getline(in, line)){
                               ifstream fin(line.c_str());
                               fin.read(variant_buf, 50 * 1024 * 1024);
                               len = fin.gcount();
                               if (len > 0) {
                                       do_extract(variant_buf, len);
                                       memset(variant_buf, 0, 50 * 1024 * 1024);
                               }
                               fin.close();
                       }
               in.close();
               }
       } else {

		out_json = parse.int_value("json", 0);
		out_flame = parse.int_value("flame", 1);
		if (run_in_host) {
			ret = diag_call_ioctl(DIAG_IOCTL_RW_TOP_DUMP, (long)&dump_param);
		} else {
			ret = -ENOSYS;
			syscall(DIAG_RW_TOP_DUMP, &ret, &len, variant_buf, 50 * 1024 * 1024);
		}
		
		if (out_file.length() > 0) {
			if (ret == 0 && len > 0) {
				ofstream fout(out_file);
				fout.write(variant_buf, len);
				fout.close();
			}
		} else {
			if (ret == 0 && len > 0) {
				printf("  序号           R-SIZE            W-SIZE          MAP-SIZE           RW-SIZE     PID          进程名                            设备        文件名\n");
				do_extract(variant_buf, len);
			}
		}
	}

}

static void do_sls(char *arg)
{
	int ret;
	int len;
	static char variant_buf[50 * 1024 * 1024];
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 50 * 1024 * 1024,
		.user_buf = variant_buf,
	};

	ret = log_config(arg, sls_file, &syslog_enabled);
	if (ret != 1)
		return;

	while (1) {
		if (run_in_host) {
			ret = diag_call_ioctl(DIAG_IOCTL_RW_TOP_DUMP, (long)&dump_param);
		} else {
			syscall(DIAG_RW_TOP_DUMP, &ret, &len, variant_buf, 50 * 1024 * 1024);
		}

		if (ret == 0 && len > 0) {
			extract_variant_buffer(variant_buf, len, sls_extract, NULL);
		}

		sleep(10);
	}	

}

int rw_top_main(int argc, char **argv)
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
		usage_rw_top();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_rw_top();
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
			usage_rw_top();
			break;
		}
	}

	return 0;
}
