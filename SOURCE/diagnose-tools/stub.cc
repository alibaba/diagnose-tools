#include <iostream>
#include <string>
#include <map>
#include <stdio.h>

#include "containers.h"

using namespace std;

map<string, struct diag_container> map_containers;

int __attribute__((weak)) diag_container::load(std::string type, std::string id)
{
	return 1;
}

void __attribute__((weak)) diag_container::dump(void)
{
	//
}

int __attribute__((weak)) diag_container::enter(void)
{
	return 0;
}

int __attribute__((weak)) refill_map_containers(void)
{
	return 0;
}

int __attribute__((weak)) open_root_ns_fd(void)
{
	return 0;
}

int __attribute__((weak)) enter_root_ns(void)
{
	return 0;
}

int __attribute__((weak)) diag_init_env_path(void)
{
	return 0;
}
