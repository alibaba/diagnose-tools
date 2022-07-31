/*
 * Linux内核诊断工具--用户接口API
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Wen Yang <wenyang@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef UAPI_CGROUP_STAT_H
#define UAPI_CGROUP_STAT_H

#include <linux/ioctl.h>
#include "ali_diagnose.h"

#define DIAG_PMU_VARIANT_BUF_LEN (20 * 1024 * 1024)

enum pmu_counters
{
	PMU_INDEX_CYCLES = 0,
	PMU_INDEX_INSTRUCTIONS,
	PMU_INDEX_REF_CYCLES,
	PMU_INDEX_BRANCH_MISSES,
	PMU_INDEX_LLC_MISSES,
	PMU_INDEX_RAW_EVENT1,
	PMU_INDEX_RAW_EVENT2,
	PMU_INDEX_MAX,
};

struct diag_pmu_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int style;
	unsigned int sample;
	unsigned int conf_fixed_counters;
	unsigned int conf_branch_misses;
	unsigned int conf_last_cache_misses;
	unsigned int conf_raw_pmu_event1;
	unsigned int conf_raw_pmu_event2;
};

struct diag_pmu_detail {
	int et_type;
	int cpu;
	char cgrp_buf[CGROUP_NAME_LEN];
	unsigned long instructions;
	unsigned long cycles;
	unsigned long ref_cycles;
	unsigned long branch_misses;
	unsigned long last_cache_misses;
	unsigned long raw_pmu_event1;
	unsigned long raw_pmu_event2;
};

#define CMD_PMU_SET (0)
#define CMD_PMU_SETTINGS (CMD_PMU_SET + 1)
#define CMD_PMU_DUMP (CMD_PMU_SETTINGS + 1)
#define CMD_PMU_ISOLATE (CMD_PMU_DUMP + 1)
#define CMD_PMU_SAMPLE (CMD_PMU_ISOLATE + 1)
#define DIAG_IOCTL_PMU_SET _IOWR(DIAG_IOCTL_TYPE_PMU, CMD_PMU_SET, struct diag_pmu_settings)
#define DIAG_IOCTL_PMU_SETTINGS _IOWR(DIAG_IOCTL_TYPE_PMU, CMD_PMU_SETTINGS, struct diag_pmu_settings)
#define DIAG_IOCTL_PMU_DUMP _IOWR(DIAG_IOCTL_TYPE_PMU, CMD_PMU_DUMP, struct diag_ioctl_dump_param)
#define DIAG_IOCTL_PMU_SAMPLE _IOWR(DIAG_IOCTL_TYPE_PMU, CMD_PMU_SAMPLE, int)

#endif /* UAPI_CGROUP_STAT_H */
