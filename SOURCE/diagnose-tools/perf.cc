/*
 * Linux内核诊断工具--用户态perf功能实现
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

#include <set>

#include "internal.h"
#include "symbol.h"
#include "json/json.h"
#include <iostream>
#include <fstream>

#include "uapi/perf.h"
#include "params_parse.h"
#include <syslog.h>

using namespace std;

static char sls_file[256];
static int report_reverse = 0;
static int syslog_enabled;

void usage_perf(void)
{
	printf("    perf usage:\n");
	printf("        --help perf help info\n");
	printf("        --activate\n");
	printf("            style dump style: 0 - common, 1 - process chains\n");
	printf("            verbose VERBOSE\n");
	printf("            tgid process group that monitored\n");
	printf("            pid thread id that monitored\n");
	printf("            comm comm that monitored\n");
	printf("            cpu cpu-list that monitored\n");
	printf("            idle set 1 if want monitor idle\n");
	printf("            bvt set 1 if want monitor idle\n");
	printf("            sys set 1 if want monitor syscall only\n");
	printf("            raw-stack output raw stack\n");
	printf("        --deactivate\n");
	printf("        --report dump log with text/file.\n");
	printf("        --test testcase for perf.\n");
}

static void do_activate(const char *arg)
{
	int ret = 0;
	string str;
	struct params_parser parse(arg);
	struct diag_perf_settings settings;

	memset(&settings, 0, sizeof(struct diag_perf_settings));
	
	settings.style = parse.int_value("style");
	settings.verbose = parse.int_value("verbose");
	settings.tgid = parse.int_value("tgid");
	settings.pid = parse.int_value("pid");
	settings.idle = parse.int_value("idle");
	settings.bvt = parse.int_value("bvt");
	settings.sys = parse.int_value("sys");
	settings.raw_stack = parse.int_value("raw-stack");

	str = parse.string_value("comm");
	if (str.length() > 0) {
		strncpy(settings.comm, str.c_str(), TASK_COMM_LEN);
		settings.comm[TASK_COMM_LEN - 1] = 0;
	}
	str = parse.string_value("cpu");
	if (str.length() > 0) {
		strncpy(settings.cpus, str.c_str(), 512);
		settings.cpus[511] = 0;
	}

	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_PERF_SET, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_PERF_SET, &ret, &settings, sizeof(struct diag_perf_settings));
	}
	printf("功能设置%s，返回值：%d\n", ret ? "失败" : "成功", ret);
	printf("    STYLE：\t%d\n", settings.style);
	printf("    输出级别：\t%d\n", settings.verbose);
	printf("    进程ID：\t%d\n", settings.tgid);
	printf("    线程ID：\t%d\n", settings.pid);
	printf("    进程名称：\t%s\n", settings.comm);
	printf("    CPUS：\t%s\n", settings.cpus);
	printf("    IDLE：\t%d\n", settings.idle);
	printf("    BVT：\t%d\n", settings.bvt);
	printf("    SYS：\t%d\n", settings.sys);
	printf("    RAW-STACK：%lu\n", settings.raw_stack);
	
	if (ret)
		return;

	ret = diag_activate("perf");
	if (ret == 1) {
		printf("perf activated\n");
	} else {
		printf("perf is not activated, ret %d\n", ret);
	}
}

static void do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("perf");
	if (ret == 0) {
		printf("perf is not activated\n");
	} else {
		printf("deactivate perf fail, ret is %d\n", ret);
	}
}

static void do_settings(const char *arg)
{
	struct diag_perf_settings settings;
	int ret;
	int enable_json = 0;
	Json::Value root;
	struct params_parser parse(arg);
	enable_json = parse.int_value("json");


	if (run_in_host) {
		ret = diag_call_ioctl(DIAG_IOCTL_PERF_SETTINGS, (long)&settings);
	} else {
		ret = -ENOSYS;
		syscall(DIAG_PERF_SETTINGS, &ret, &settings, sizeof(struct diag_perf_settings));
	}
	if (ret == 0) {
		if (1 != enable_json)
		{
			printf("功能设置：\n");
			printf("    是否激活：\t%s\n", settings.activated ? "√" : "×");
			printf("    进程ID：\t%d\n", settings.pid);
			printf("    线程ID：\t%d\n", settings.pid);
			printf("    进程名称：\t%s\n", settings.comm);
			printf("    CPUS：\t%s\n", settings.cpus);
			printf("    IDLE：\t%d\n", settings.idle);
			printf("    BVT：\t%d\n", settings.bvt);
			printf("    SYS：\t%d\n", settings.sys);
			printf("    STYLE：\t%d\n", settings.style);
			printf("    RAW-STACK：%lu\n", settings.raw_stack);
		}
		else
		{
			root["activated"] = Json::Value(settings.activated);
			root["pid"] = Json::Value(settings.pid);
			root["tid"] = Json::Value(settings.pid);
			root["comm"] = Json::Value(settings.comm);
			root["cpus"] = Json::Value(settings.cpus);
			root["idle"] = Json::Value(settings.idle);
			root["bvt"] = Json::Value(settings.bvt);
			root["style"] = Json::Value(settings.style);
			root["sys"] = Json::Value(settings.sys);
			root["verbose"] = Json::Value(settings.verbose);
		}
	} else {
		if (1 != enable_json)
		{
			printf("获取perf设置失败，请确保正确安装了diagnose-tools工具\n");
		}
		else
		{
			root["err"]=Json::Value("found perf settings failed, please check diagnose-tools installed or not\n");
		}
	}

	if (1 == enable_json)
	{
		std::string str_log;
		str_log.append(root.toStyledString());
		printf("%s", str_log.c_str());
	}

}

static int perf_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct perf_detail *detail;
	struct perf_raw_detail *raw_detail;
	static int seq;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_perf_detail:
		if (len < sizeof(struct perf_detail))
			break;
		detail = (struct perf_detail *)buf;

		seq++;
		if (report_reverse) {
			printf("##CGROUP:[%s]  %d      [%03d]  采样命中\n",
					detail->task.cgroup_buf,
					detail->task.pid,
					seq);
			printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
					detail->task.comm);
			diag_printf_user_stack(run_in_host ? detail->task.tgid : detail->task.container_tgid,
					detail->task.container_tgid,
					detail->task.comm,
					&detail->user_stack, 0, report_reverse);
			diag_printf_proc_chains(&detail->proc_chains, report_reverse);
			diag_printf_kern_stack(&detail->kern_stack, report_reverse);
			printf("##\n");
		} else {
			printf("##CGROUP:[%s]  %d      [%03d]  采样命中\n",
					detail->task.cgroup_buf,
					detail->task.pid,
					seq);
			diag_printf_kern_stack(&detail->kern_stack, report_reverse);
			diag_printf_user_stack(run_in_host ? detail->task.tgid : detail->task.container_tgid,
					detail->task.container_tgid,
					detail->task.comm,
					&detail->user_stack, 0, report_reverse);
			printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
					detail->task.comm);
			diag_printf_proc_chains(&detail->proc_chains, report_reverse);
			printf("##\n");
		}

		break;
	case et_perf_raw_detail:
		if (len < sizeof(struct perf_raw_detail))
			break;
		raw_detail = (struct perf_raw_detail *)buf;

		seq++;
		printf("##CGROUP:[%s]  %d      [%03d]  采样命中\n",
				raw_detail->task.cgroup_buf,
				raw_detail->task.pid,
				seq);
		diag_printf_kern_stack(&raw_detail->kern_stack, report_reverse);
		diag_printf_raw_stack(run_in_host ? raw_detail->task.tgid : raw_detail->task.container_tgid,
			raw_detail->task.container_tgid,
			raw_detail->task.comm,
			&raw_detail->raw_stack);
		printf("#*        0xffffffffffffff %s (UNKNOWN)\n",
				raw_detail->task.comm);
		diag_printf_proc_chains(&raw_detail->proc_chains, report_reverse);
		printf("##\n");

		break;
	default:
		break;
	}
	return 0;
}

static void do_extract(char *buf, int len)
{
	extract_variant_buffer(buf, len, perf_extract, NULL);
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

	report_reverse = parse.int_value("reverse");
	console = parse.int_value("console");
	in_file = parse.string_value("in");
	out_file = parse.string_value("out");
	inlist_file = parse.string_value("inlist");

	memset(variant_buf, 0, 50 * 1024 * 1024);
	if (console) {
		java_attach_once();
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
			java_attach_once();
			do_extract(variant_buf, len);
                        fin.close();
		}
       } else if(inlist_file.length() > 0) {
               ifstream in(inlist_file);
               if(in) {
                       while (getline(in, line)){
                               ifstream fin(line.c_str());
                               fin.read(variant_buf, 50 * 1024 * 1024);
                               len = fin.gcount();
                               if (len > 0) {
                                       java_attach_once();
                                       do_extract(variant_buf, len);
                                       memset(variant_buf, 0, 50 * 1024 * 1024);
                               }
                               fin.close();
                       }
               in.close(); 
	       }	
       }else{
		if (run_in_host) {
			ret = diag_call_ioctl(DIAG_IOCTL_PERF_DUMP, (long)&dump_param);
		} else {
			ret = -ENOSYS;
			syscall(DIAG_PERF_DUMP, &ret, &len, variant_buf, 50 * 1024 * 1024);
		}

		if (out_file.length() > 0) {
			if (ret == 0 && len > 0) {
				ofstream fout(out_file);
				fout.write(variant_buf, len);
				fout.close();
			}
		} else {
			if (ret == 0 && len > 0) {
				java_attach_once();
				do_extract(variant_buf, len);
			}
		}
	}
}

static int sls_extract(void *buf, unsigned int len, void *)
{
	int *et_type;
	struct perf_detail *detail;
    symbol sym;
	
	Json::Value root;
	Json::Value task;
	Json::Value kern_stack;
	Json::Value user_stack;
	Json::Value proc_chains;

	if (len == 0)
		return 0;

	Json::StreamWriterBuilder builder;
	builder.settings_["indentation"] = " ";
	std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
	writer->newline = false;

	ofstream os;
	os.open(sls_file, std::ios::out | std::ios::app);

	et_type = (int *)buf;
	switch (*et_type) {
	case et_perf_detail:
		if (len < sizeof(struct perf_detail))
			break;
		detail = (struct perf_detail *)buf;
		root["id"] = detail->id;
		root["seq"] = detail->seq;
		diag_sls_time(&detail->tv, root);
		diag_sls_task(&detail->task, task);
		diag_sls_kern_stack(&detail->kern_stack, task);
		diag_sls_user_stack(detail->task.tgid,
			detail->task.container_tgid,
			detail->task.comm,
			&detail->user_stack, task, 0);
		diag_sls_proc_chains(&detail->proc_chains, task);
		root["task"] = task;
		os << "diagnose-tools | perf | ";
		os << detail->tv.tv_sec << "." << detail->tv.tv_usec << " | ";
		os << detail->id << " | ";
		os << 0 << " | ";
		writer->write(root, &os);
		os << endl;

		break;
	default:
		break;
	}

	return 0;
}

static void write_log(const char *src_file, char *dest_file)
{
	int write_file = 0;
	fstream src;
	ofstream os;
	string tp;

	src.open(src_file, ios::in);
	if (1 != src.is_open())
	{
		return;
	}

	os.open(dest_file, std::ios::out | std::ios::app);
	write_file = os.is_open();

	while (getline(src, tp))
	{
		if (tp.empty())
		{
			continue;
		}

		if (1 == write_file)
		{
			os << tp;
			os << endl;
		}

		if (1 == syslog_enabled)
		{
			syslog(LOG_DEBUG, "%s", tp.c_str());
		}
	}

	return;
}

static void do_sls(char *arg)
{
	int ret;
	static char variant_buf[50 * 1024 * 1024];
	int len;
	static char store_file[256];
	std::string buf;
	int jiffies_sls = 0;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 50 * 1024 * 1024,
		.user_buf = variant_buf,
	};

	ret = log_config(arg, store_file, &syslog_enabled);
	if (ret != 1)
		return;

	strncpy(sls_file, "/tmp/perf.txt", 20);
	java_attach_once();

	while (1) {
		if (run_in_host) {
			ret = diag_call_ioctl(DIAG_IOCTL_PERF_DUMP, (long)&dump_param);
		} else {
			ret = -ENOSYS;
			syscall(DIAG_PERF_DUMP, &ret, &len, variant_buf, 50 * 1024 * 1024);
		}
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

			ret = system("python /usr/diagnose-tools/flame-graph/encode.py /tmp/perf.txt | /usr/diagnose-tools/flame-graph/stackcollapse.pl > /tmp/flame.txt");

			buf.append("python /usr/diagnose-tools/flame-graph/decode.py /tmp/flame.txt > /tmp/perf_stripped.txt");
			ret = system(buf.c_str());

			write_log("/tmp/perf_stripped.txt", store_file);
			ret = system("echo \"\"> /tmp/perf.txt");
		}

		sleep(10);
		jiffies_sls++;
	}
}

int perf_main(int argc, char **argv)
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
		usage_perf();
		return 0;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_perf();
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
			usage_perf();
			break;
		}
	}

	return 0;
}

