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

#ifndef __PERF_SYMBOL_H__
#define __PERF_SYMBOL_H__

#include <map>
#include <set>
#include <string>

//#include <boost/icl/interval_map.hpp>

#define INVALID_ADDR ((size_t)(-1))
enum {
    NATIVE_TYPE = 0,
    JIT_TYPE = 1
};


struct elf_file {
    unsigned char elf_read_error;
    size_t		  eh_frame_hdr_offset;
    size_t		  fde_count;
    size_t		  table_data;
    std::string filename;
    std::string buildid;
    std::string mnt_ns_name;
    int type;

    // TODO get builid from elf header or build hash for elf
    elf_file(const std::string &name) : filename(name), type(NATIVE_TYPE) {
        buildid = filename;
        elf_read_error = 0;
        eh_frame_hdr_offset = 0;
        fde_count = 0;
        table_data = 0;
    }

    elf_file() :type(NATIVE_TYPE) {}

    // TODO get builid from elf header or build hash for elf
    void reset(const std::string &name) {
        filename = name;
        buildid = name;
        elf_read_error = 0;
        eh_frame_hdr_offset = 0;
        fde_count = 0;
        table_data = 0;
    }

    bool operator<  (const elf_file &rhs) const {
        if (buildid == rhs.buildid) {
            return mnt_ns_name < rhs.mnt_ns_name;
        }
        return buildid < rhs.buildid;
    }
};

struct symbol {
    size_t start;
    size_t end;
    size_t ip;
    std::string name;

    symbol() :start(0), end(0), ip(0) {}
    symbol(size_t pc) :start(0), end(0), ip(pc) {}

    void reset(size_t va) { start = end = 0; ip = va; }
    bool operator< (const symbol &sym) const {
        return sym.ip < start;
    }
};

struct vma {
    size_t start;
    size_t end;
    size_t offset;
    size_t pc;
    int type;
    std::string name;
    struct {
        unsigned char elf_read_error;
        size_t		  eh_frame_hdr_offset;
        size_t		  fde_count;
        size_t		  table_data;
    };

    size_t map(size_t pc) {
        return pc - start + offset;
    }

    void set_type(int t) { type = t; }

    vma(size_t s, size_t e, size_t o, const std::string &n)
        :start(s), end(e), offset(o), pc(0), type(NATIVE_TYPE), name(n)  {}

    vma() : start(0), end(0), offset(0), pc(0), type(NATIVE_TYPE) {}

    vma(size_t addr) : start(0), end(0), offset(0), pc(addr), type(NATIVE_TYPE) {}

    bool operator<(const vma &vm) {
       return vm.start < vm.pc;
    }

    vma &operator=(const vma &vm) {
        if (this == &vm) {
            return *this;
        }
        start = vm.start;
        end = vm.end;
        offset = vm.offset;
        name = vm.name;
        return *this;
    }
};

class symbol_parser {
private:
    typedef std::map<size_t, vma> proc_vma;

    std::map<elf_file, std::set<symbol> > file_symbols;
    std::map<int, std::set<symbol> > java_symbols;
    std::set<symbol> kernel_symbols;
    std::map<int, proc_vma> machine_vma;
    std::set<int> java_procs;
public:
    bool load_kernel();
    std::set<int>& get_java_procs() { return java_procs; }

    bool find_kernel_symbol(symbol &sym);
    bool find_elf_symbol(symbol &sym, const elf_file &file, int pid, int pid_ns);
    bool find_java_symbol(symbol &sym, int pid, int pid_ns);

    bool get_symbol_info(int pid, symbol &sym, elf_file &file);

    bool find_vma(pid_t pid, vma &vm);
    vma* find_vma(pid_t pid, size_t pc);
    void clear_symbol_info(int);
    bool add_pid_maps(int pid, size_t start, size_t end, size_t offset, const char *name);

private:
    bool load_pid_maps(int pid);
    bool load_elf(pid_t pid, const elf_file& file);
    bool load_perf_map(int pid, int pid_ns);
};

extern symbol_parser g_symbol_parser;

#endif
