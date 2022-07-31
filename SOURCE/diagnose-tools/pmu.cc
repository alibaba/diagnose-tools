/*
 * Linux内核诊断工具--用户态pmu功能实现
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Wen Yang <simon.wy@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>

#include "json/json.h"
#include "internal.h"
#include "params_parse.h"
#include "uapi/pmu.h"

using namespace std;

#define NSEC_PER_SEC	1000000000L

#define PMC_INSTRUCTIONS	"instructions"
#define PMC_CYCLES		"cycles"
#define PMC_REF_CYCLES		"ref-cycles"
#define PMC_FIXED_COUNTERS	"fixed-counters"
#define PMC_BRANCH_MISSES	"branch-misses"
#define PMC_LAST_CACHE_MISSES	"llc-misses"
#define PMC_RAW_PMU_EVENT1	"raw-pmu-event1"
#define PMC_RAW_PMU_EVENT2	"raw-pmu-event2"

extern unsigned long debug_mode;

static unsigned long instructions_sum;
static unsigned long cycles_sum;
static unsigned long ref_cycles_sum;
static unsigned long branch_misses_sum;
static unsigned long last_cache_misses_sum;
static unsigned long raw_pmu_event1_sum;
static unsigned long raw_pmu_event2_sum;
static std::stringstream ss_cpu;

void usage_pmu(void)
{
	printf("    pmu usage:\n");
	printf("        --activate\n");
	printf("            style: whether to use hrtimers to probe long-running processes\n");
	printf("            sample: whether to sample the PMU registers\n");
	printf("            %s: whether to enable the collection of the %s, default is true\n",
			        PMC_FIXED_COUNTERS, PMC_FIXED_COUNTERS);
	printf("            %s: whether to enable the collection of the %s\n",
			        PMC_BRANCH_MISSES, PMC_BRANCH_MISSES);
	printf("            %s: whether to enable the collection of the %s\n",
			        PMC_LAST_CACHE_MISSES, PMC_LAST_CACHE_MISSES);
	printf("            %s: a raw PMU event (eventsel+umask) in the form of NNN where NNN is a hexadecimal event descriptor.\n",
			        PMC_RAW_PMU_EVENT1);
	printf("            %s: a raw PMU event (eventsel+umask) in the form of NNN where NNN is a hexadecimal event descriptor.\n",
			        PMC_RAW_PMU_EVENT2);
	printf("        --deactivate\n");
	printf("        --settings print settings.\n");
	printf("        --report dump log with text.\n");
	printf("        --record\n");
	printf("            sls=/tmp/1.json stored core events in the specified file\n");
	printf("        --sample stop sample if it is 0\n");
}

static void print_settings(struct diag_pmu_settings *settings, int is_activate_oper)
{
	printf("SETTINGS:	\n");

	if (!is_activate_oper)
		printf("    ACTIVE:        %s\n", settings->activated ? "Yes" : "No");

	printf("    STYLE:           %d\n", settings->style);
	printf("    SAMPLE:          %d\n", settings->sample);
	printf("    FIXED-COUNTERS:  %d\n", settings->conf_fixed_counters);
	printf("    BRANCH-MISSES:   %d\n", settings->conf_branch_misses);
	printf("    LLC-MISSES:      %d\n", settings->conf_last_cache_misses);
	printf("    RAW-PMU-EVENT1:  0X%04X\n", settings->conf_raw_pmu_event1);
	printf("    RAW-PMU-EVENT2:  0X%04X\n", settings->conf_raw_pmu_event2);
}

static int do_activate(const char *arg)
{
	int ret = 0;
	struct params_parser parse(arg);
	struct diag_pmu_settings settings;
	string str;

	memset(&settings, 0, sizeof(struct diag_pmu_settings));

	settings.style = parse.int_value("style");
	settings.sample = parse.bool_value("sample");
	settings.conf_fixed_counters = (parse.string_value(PMC_FIXED_COUNTERS).length()
			== 0)  ?  1 : parse.bool_value(PMC_FIXED_COUNTERS);
	settings.conf_branch_misses = parse.bool_value(PMC_BRANCH_MISSES);
	settings.conf_last_cache_misses = parse.bool_value(PMC_LAST_CACHE_MISSES);
	settings.conf_raw_pmu_event1 = parse.int_value(PMC_RAW_PMU_EVENT1, 16);
	settings.conf_raw_pmu_event2 = parse.int_value(PMC_RAW_PMU_EVENT2, 16);

	ret = diag_call_ioctl(DIAG_IOCTL_PMU_SET, (long)&settings);
	printf("Operation %s, return: %d\n", ret ? "failed" : "successful", ret);
	print_settings(&settings, 1);
	if (ret)
		return ret;

	ret = diag_activate("pmu");
	if (ret == 1) {
		printf("pmu activated\n");
		ret = 0;
	} else {
		printf("pmu is not activated, ret %d\n", ret);
	}

	return ret;
}

static int do_deactivate(void)
{
	int ret = 0;

	ret = diag_deactivate("pmu");
	if (ret == 0) {
		printf("pmu is not activated\n");
	} else {
		printf("deactivate pmu fail, ret is %d\n", ret);
	}
	return ret;
}

static int do_settings(const char *arg)
{
	struct diag_pmu_settings settings;
	int ret;

	memset(&settings, 0, sizeof(struct diag_pmu_settings));
	ret = diag_call_ioctl(DIAG_IOCTL_PMU_SETTINGS, (long)&settings);
	if (ret == 0) {
		print_settings(&settings, 0);
	} else {
		printf("The operation failed!\n");
		printf("Make sure that the diagnose tool is installed correctly.\n");
	}
	return ret;
}

static inline char *ns_to_timespec_str(long long nsec)
{
	static char str[128] = {0};
	struct timespec ts;

	if (!nsec) {
		ts.tv_sec = 0;
		ts.tv_nsec = 0;
	} else {
		ts.tv_sec = nsec / NSEC_PER_SEC;
		ts.tv_nsec = nsec % NSEC_PER_SEC;
	}

	snprintf(str, sizeof(str)-1, "%ld.%ld", ts.tv_sec, ts.tv_nsec);
	return str;
}

static int pmu_extract(void *buf, unsigned int len, void *unused)
{
	int *et_type;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
	case et_pmu_detail:
		struct diag_pmu_detail *detail;

		if (len < sizeof(struct diag_pmu_detail))
			break;

		detail = (struct diag_pmu_detail *)buf;
		if (!detail)
			break;

		instructions_sum += detail->instructions;
		cycles_sum += detail->cycles;
		ref_cycles_sum += detail->ref_cycles;
		branch_misses_sum += detail->branch_misses;
		last_cache_misses_sum += detail->last_cache_misses;
		raw_pmu_event1_sum += detail->raw_pmu_event1;
		raw_pmu_event2_sum += detail->raw_pmu_event2;

		ss_cpu << detail->cgrp_buf << "; "
			<< detail->cpu << "; "
			<< detail->instructions << "; "
			<< detail->cycles << "; "
			<< detail->ref_cycles << "; "
			<< detail->branch_misses << "; "
			<< detail->last_cache_misses << "; "
			<< detail->raw_pmu_event1 << "; "
			<< detail->raw_pmu_event2 << endl;
		break;

	default:
		break;
	}

	return 0;
}

static void print_columns_core_events()
{
	printf("cgroup; cpu; instructions; cycles; ref-cycles; branch_misses; "
			"last_cache_misses; raw_pmu_event1; raw_pmu_event2\n");
	printf("-----------------------------------------------------------"
			"-------------------------------------------------\n");
}

static void do_extract(char *buf, int len)
{
	struct timespec ts;

	instructions_sum = 0;
	cycles_sum = 0;
	ref_cycles_sum = 0;
	branch_misses_sum = 0;
	last_cache_misses_sum = 0;
	raw_pmu_event1_sum = 0;
	raw_pmu_event2_sum = 0;
	ss_cpu.str("");

	extract_variant_buffer(buf, len, pmu_extract, NULL);
	print_columns_core_events();
	printf("%s\n", ss_cpu.str().c_str());

	clock_gettime(CLOCK_REALTIME, &ts);
	printf("time: %lu.%lu, the core events are summarized as follows, "
			"instructions: %lu, cycles: %lu, ref_cycles: %lu, "
			"branch_misses: %lu, llc_misses: %lu, raw_pmu_event1: %lu, "
			"raw_pmu_event2: %lu.\n",
			ts.tv_sec, ts.tv_nsec, 
			instructions_sum, cycles_sum, ref_cycles_sum,
		   	branch_misses_sum, last_cache_misses_sum, raw_pmu_event1_sum,
			raw_pmu_event2_sum);

	printf("\n");
}

static int do_dump(void)
{
	static char variant_buf[DIAG_PMU_VARIANT_BUF_LEN];
	int len;
	int ret = 0;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = DIAG_PMU_VARIANT_BUF_LEN,
		.user_buf = variant_buf,
	};

	memset(variant_buf, 0, DIAG_PMU_VARIANT_BUF_LEN);
	ret = diag_call_ioctl(DIAG_IOCTL_PMU_DUMP, (long)&dump_param);
	if (ret == 0) {
		do_extract(variant_buf, len);
	}
	return ret;
}

void write_json_file(const char *sls_file, Json::Value &root)
{
    ofstream os;
    Json::StreamWriterBuilder builder;
    builder.settings_["indentation"] = " ";
    std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
    writer->newline = false;

    if (*sls_file == '\0') {
        return;
    }

    os.open(sls_file, std::ios::out);
    if (1 != os.is_open()) {
        return;
    }

    writer->write(root, &os);
    os << endl;

    return;
}

static int sls_extract(void *buf, unsigned int len, void *param)
{
	Json::Value *root = (Json::Value *)param;
	struct diag_pmu_detail *detail;
	Json::Value event;
	static int i = 0;
	int *et_type;

	if (len == 0)
		return 0;

	et_type = (int *)buf;
	switch (*et_type) {
		case et_pmu_detail:
			if (len < sizeof(struct diag_pmu_detail))
				break;

			detail = (struct diag_pmu_detail *)buf;
			if (!detail)
				break;

			event["cgroup"] = Json::Value(detail->cgrp_buf);
			event["cpu"] = Json::Value(detail->cpu);
			event[PMC_INSTRUCTIONS] = Json::Value(detail->instructions);
			event[PMC_CYCLES] = Json::Value(detail->cycles);
			event[PMC_REF_CYCLES] = Json::Value(detail->ref_cycles);
			event[PMC_BRANCH_MISSES] = Json::Value(detail->branch_misses);
			event[PMC_LAST_CACHE_MISSES] = Json::Value(detail->last_cache_misses);
			event[PMC_RAW_PMU_EVENT1] = Json::Value(detail->raw_pmu_event1);
			event[PMC_RAW_PMU_EVENT2] = Json::Value(detail->raw_pmu_event2);
			(*root)[i++] = event;
			break;

		default:
			break;
	}

	return 0;
}

static int do_sls(char *arg)
{
	static char variant_buf[20 * 1024 * 1024];
	int ret, len;
	struct diag_ioctl_dump_param dump_param = {
		.user_ptr_len = &len,
		.user_buf_len = 20 * 1024 * 1024,
		.user_buf = variant_buf,
	};

	struct params_parser parse(arg);
	string sls_file = parse.string_value("sls");
	string imc_file = parse.string_value("imc");
	if (!sls_file.length() && !imc_file.length())
		return -EINVAL;

	if (debug_mode) {
		printf("sls=%s, imc=%s\n", sls_file.c_str(), imc_file.c_str());
	}

	ret = diag_call_ioctl(DIAG_IOCTL_PMU_DUMP, (long)&dump_param);
	if (ret == 0 && len > 0) {
#if 0
		clock_gettime(CLOCK_REALTIME, &ts);
		root["tv_sec"] = Json::Value(ts.tv_sec);
		root["tv_nsec"] = Json::Value(ts.tv_nsec);
#endif
		Json::Value root_core;
		Json::Value root_imc;

		extract_variant_buffer(variant_buf, len, sls_extract, &root_core);
		write_json_file(sls_file.c_str(), root_core);
		write_json_file(imc_file.c_str(), root_imc);
	}

	return ret;
}

static int do_sample(char *arg)
{
	int ret;
	unsigned int sample;

	ret = sscanf(arg, "%d", &sample);
	if (ret < 1)
		return -EINVAL;

	ret = diag_call_ioctl(DIAG_IOCTL_PMU_SAMPLE, (long)&sample);
	printf("set sample for pmu: %d, ret is %d\n", sample, ret);
	return ret;
}

int pmu_main(int argc, char **argv)
{
	static struct option long_options[] = {
			{"help",      no_argument, 0,  0 },
			{"activate",  optional_argument, 0,  0 },
			{"deactivate",no_argument,       0,  0 },
			{"settings",  optional_argument, 0,  0 },
			{"report",    no_argument, 0,  0 },
			{"record",    required_argument, 0,  0 },
			{"sample",    required_argument, 0,  0 },
			{0,         0,                 0,  0 }
		};
	int ret = -EINVAL;
	int c;

	if (argc <= 1) {
		usage_pmu();
		return -EINVAL;
	}
	while (1) {
		int option_index = -1;

		c = getopt_long_only(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (option_index) {
		case 0:
			usage_pmu();
			break;
		case 1:
			ret = do_activate(optarg ? optarg : "");
			break;
		case 2:
			ret = do_deactivate();
			break;
		case 3:
			ret = do_settings(optarg ? optarg : "");
			break;
		case 4:
			ret = do_dump();
			break;
		case 5:
			ret = do_sls(optarg);
			break;
		case 6:
			ret = do_sample(optarg);
			break;
		default:
			usage_pmu();
			break;
		}
	}

	return ret;
}
