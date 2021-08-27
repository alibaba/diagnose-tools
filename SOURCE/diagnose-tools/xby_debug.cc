/*
 * ali-devops--用户态工具主入口
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@alibaba-inc.com>
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
#include <sys/resource.h>
#include <iostream>
#include <fstream>

#include <sys/time.h>
#include <string.h>
#include <stdio.h>     /* for printf */
#include <stdio_ext.h>
#include <stdlib.h>    /* for exit */
#include <time.h>
#include <set>
#include <cassert>
#include <fcntl.h>

#include "json/json.h"
#include "json/reader.h"

#include "internal.h"
#include "containers.h"

using namespace std;

int to_do_xby_debug;

int do_xby_debug(int argc, char *argv[])
{
	map<string, struct diag_container>::iterator iter;

	diag_init_env_path();
	refill_map_containers();
	open_root_ns_fd();

	for (iter = map_containers.begin(); iter != map_containers.end(); iter++) {
		struct diag_container &container = iter->second;

		if (container.enter() != 0) {
			continue;
		}

		system("/usr/bin/uptime; hostname;");
		enter_root_ns();
	}

	system("/usr/bin/uptime; hostname;");

	return 0;
}
