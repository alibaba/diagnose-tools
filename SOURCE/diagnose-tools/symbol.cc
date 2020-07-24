/*
 * Linux内核诊断工具--用户态符号表解析
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <vector>
#include <string.h>
#include <algorithm>

#include "symbol.h"
#include "elf.h"
#include "internal.h"

void restore_global_env();
int attach_ns_env(int pid);

//using namespace boost::icl;

symbol_parser g_symbol_parser;

bool symbol_parser::add_pid_maps(int pid, size_t start, size_t end, size_t offset, const char *name)
{
    std::map<int, proc_vma>::iterator it;
    it = machine_vma.find(pid);
    if (it == machine_vma.end()) {
        proc_vma proc;
        machine_vma.insert(make_pair(pid, proc));
        it = machine_vma.find(pid);
        if (it == machine_vma.end()) {
            return false;
        }
    }

    vma vm(start, end, offset, name);
    it->second.insert(std::make_pair(vm.start, vm));

    return true;
}

bool symbol_parser::load_pid_maps(int pid)
{
    std::map<int, proc_vma>::iterator it;
    it = machine_vma.find(pid);
    if (it != machine_vma.end()) {
        return true;
    }

    proc_vma proc;
    machine_vma.insert(make_pair(pid, proc));
    it = machine_vma.find(pid);
    if (it == machine_vma.end()) {
        return false;
    }
    char fn[256];
    sprintf(fn, "/proc/%d/maps", pid);
    FILE *fp = fopen(fn, "r");
    if (!fp) {
        return false;
    }

    char buf[4096];
    char exename[4096];
    size_t start, end, offset;
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        start = end = offset = 0;
        exename[0] = '\0';
        sscanf(buf, "%lx-%lx %*s %lx %*x:%*x %*u %s %*s\n", &start, &end, &offset, exename);
        if (exename[0] == '\0') {
            strcpy(exename, "[anon]");
        }
        vma vm(start, end, offset, exename);
        it->second.insert(std::make_pair(vm.start, vm));
    }

    fclose(fp);
    return true;
}

bool symbol_parser::load_perf_map(int pid, int pid_ns)
{
#if 0
	if (pid != pid_ns) {
		if (attach_ns_env(pid) < 0) {
			return false;
		}
	}
#endif
    char perfmapfile[64];
    snprintf(perfmapfile, sizeof(perfmapfile), "/tmp/perf-%d.map", pid);
    FILE *fp = fopen(perfmapfile, "r");
    if (fp == NULL) {
		printf("cannot read perf map %d\n", pid);
        return false;
    }
    char line[256];
    char *buf;
    long start;
    int size;
    char name[256];
    std::set<symbol> syms;
    symbol sym;
    while ((buf = fgets(line, sizeof(line), fp)) != NULL) {
        sscanf(buf, "%lx %x %s\n", &start, &size, name);
        sym.start = start;
        sym.end = sym.start + size;
        sym.ip = sym.start;
        sym.name = name;
        syms.insert(sym);
    }
    java_symbols.insert(make_pair(pid, syms));
#if 0
	if (pid != pid_ns) {
		restore_global_env();
	}
#endif
    return true;
}

bool symbol_parser::find_java_symbol(symbol &sym, int pid, int pid_ns)
{
    std::set<symbol> ss;
    std::map<int, std::set<symbol> >::iterator it;
    //bool load_now = false;
    it = java_symbols.find(pid);
    if (it == java_symbols.end()) {
        if (!load_perf_map(pid, pid_ns)) {
            return false;
        }
        //load_now = true;
        it = java_symbols.find(pid);
        return search_symbol(it->second, sym);
    } else {
        return search_symbol(it->second, sym);
    }
    return true;
    
    //bool ret = search_symbol(syms, sym);
#if 0
    if (!ret && !load_now) {
        java_symbols.erase(pid);
        if (!load_perf_map(pid)) {
            return false;
        }
        syms = java_symbols.find(pid)->second;
        return search_symbol(syms, sym);
    }
#endif
    //return ret;
}

static bool load_kernel_symbol_list(std::vector<std::string> &sym_list)
{
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp) {
        return -1;
    }

    char buf[256];
    char type;
    int len;
    while (fgets(buf, sizeof(buf), fp) != NULL) {
        sscanf(buf, "%*p %c %*s\n", &type);
        if ((type | 0x20) != 't') {
            continue;
        }
        len = strlen(buf); 
        if (buf[len-1] == '\n') {
            buf[len-1] = ' ';
        }
        sym_list.push_back(buf);
    }
    fclose(fp);

    std::sort(sym_list.begin(), sym_list.end());
    return true;
}

bool is_space(int ch) {
    return std::isspace(ch);
}

static inline void rtrim(std::string &s)
{
    s.erase(std::find_if(s.rbegin(), s.rend(), is_space).base(), s.end());
}

static bool get_next_kernel_symbol(
        std::set<symbol> &syms,
        std::vector<std::string> &sym_list,
        std::vector<std::string>::iterator cursor)
{
    if (cursor == sym_list.end()) {
        return false; 
    }
    symbol sym;
    size_t start, end;
    sscanf(cursor->c_str(), "%p %*c %*s\n", (void **)&start);
    sym.name = cursor->c_str() + 19;
    rtrim(sym.name);
#if 0
    if (sym.name[sym.name.size()-1] == '\n') {
        sym.name[sym.name.size()-1] = '\0';
    }
#endif
    cursor++;
    if (cursor != sym_list.end()) {
        sscanf(cursor->c_str(), "%p %*c %*s\n", (void **)&end);
    }
    else {
        end = INVALID_ADDR;
    }
    sym.start = start;
    sym.end = end;
    sym.ip = start;

    syms.insert(sym);
    return true;
}

bool symbol_parser::load_kernel()
{
    if (kernel_symbols.size() != 0) {
        return true;
    }

    std::vector<std::string> sym_list;
    if (!load_kernel_symbol_list(sym_list)) {
        exit(0);
        return false;
    }

    std::vector<std::string>::iterator cursor = sym_list.begin();
    while (get_next_kernel_symbol(kernel_symbols, sym_list, cursor)) {
        cursor++;
    }
    return true;
}

bool symbol_parser::load_elf(const elf_file &file)
{
    std::map<elf_file, std::set<symbol> >::iterator it;
    it = file_symbols.find(file);
    std::set<symbol> tmp;
    std::set<symbol> &syms = tmp;
    if (it != file_symbols.end()) {
        return true;
    }
    if (get_symbol_in_elf(syms, file.filename.c_str())) {
        file_symbols.insert(make_pair(file, std::move(syms)));
        return true;
    }
    return false;
}

bool symbol_parser::find_kernel_symbol(symbol &sym)
{
    load_kernel();
    sym.end = sym.start = 0;
    std::set<symbol>::iterator it = kernel_symbols.find(sym);
    if (it != kernel_symbols.end()) {
        sym.end = it->end;
        sym.start = it->start;
        sym.name = it->name;
        return true;
    }
    return false;
}

bool symbol_parser::get_symbol_info(int pid, symbol &sym, elf_file &file)
{
    std::map<int, proc_vma>::iterator it;
    it = machine_vma.find(pid);
    proc_vma proc;
    if (it == machine_vma.end()) {
        if (!load_pid_maps(pid)) {
            printf("load pid maps failed\n");
            return false;
        }
    }

    vma area(sym.ip);
    if (!find_vma(pid, area)) {
        printf("find vma failed\n");
        return false;
    }
    if (area.name == "[anon]") {
        file.type = JIT_TYPE;
    }
    file.reset(area.name);
    if (file.type != JIT_TYPE) {
        sym.reset(area.map(sym.ip));
    }
    return true;
}

bool symbol_parser::find_elf_symbol(symbol &sym, const elf_file &file, int pid, int pid_ns)
{
    if (file.type == JIT_TYPE) {
        return find_java_symbol(sym, pid, pid_ns);
    }
    std::map<elf_file, std::set<symbol> >::iterator it;
    it = file_symbols.find(file);
    std::set<symbol> ss;
    if (it == file_symbols.end()) {
        if (!load_elf(file)) {
            return false;
        }
        it = file_symbols.find(file);
        return search_symbol(it->second, sym);
    } else {
        return search_symbol(it->second, sym);
    }
    return true;
    //return search_symbol(syms, sym);
}

vma* symbol_parser::find_vma(pid_t pid, size_t pc)
{
    std::map<int, proc_vma>::iterator it;
    it = machine_vma.find(pid);
    if (it == machine_vma.end()) {
        return NULL;
    }
    proc_vma::iterator vmit = it->second.upper_bound(pc);
    if (vmit == it->second.end() || vmit->second.end < pc) {
        return NULL;
    }
    if (vmit != it->second.begin()) {
        --vmit;
    }
    return &vmit->second;
}

bool symbol_parser::find_vma(pid_t pid, vma &vm)
{
    std::map<int, proc_vma>::iterator it;
    it = machine_vma.find(pid);
    if (it == machine_vma.end()) {
        return false;
    }
    
    proc_vma::const_iterator vmit = it->second.upper_bound(vm.pc);
    if (vmit == it->second.end()) {
        printf("no address in memory maps\n");
        return false;
    }
    if (vmit->second.end < vm.pc) {
        printf("no address in memory maps\n");
        return false;
    }
    if (vmit != it->second.begin()) {
        --vmit;
    }
    
    vm.start = vmit->second.start;
    vm.end = vmit->second.end;
    vm.name = vmit->second.name;
    vm.offset = vmit->second.offset;
    return true;
}

void clear_symbol_info(class pid_cmdline &pid_cmdline, std::set<int> &procs, int dist)
{
    pid_cmdline.clear();
    procs.clear();
    g_symbol_parser.clear_symbol_info(dist);
}

void symbol_parser::clear_symbol_info(int dist)
{
    machine_vma.clear();
    java_symbols.clear();
    if (dist) {
        kernel_symbols.clear();
        file_symbols.clear();
    }
}

