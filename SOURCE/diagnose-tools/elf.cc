/*
 * Linux内核诊断工具--elf相关公共函数
 *
 * Copyright (C) 2020 Alibaba Ltd.
 *
 * 作者: Baoyou Xie <baoyou.xie@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <elf.h>
#include <libelf.h>
#include <gelf.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "elf.h"

struct sym_section_ctx {
    Elf_Data *syms;
    Elf_Data *symstrs;
    Elf_Data *rel_data;
    int is_reloc;
    int is_plt;
    int sym_count;
    int plt_rel_type;
    unsigned long plt_offset;
    unsigned long plt_entsize;
};

struct symbol_sections_ctx {
    sym_section_ctx symtab;
    sym_section_ctx symtab_in_dynsym;
    sym_section_ctx dynsymtab;
};

struct section_info {
    Elf_Scn *sec;
    GElf_Shdr *hdr;
};

struct plt_ctx {
    section_info dynsym;
    section_info plt_rel;
    section_info plt;
};

static int is_function(const GElf_Sym *sym)
{
    return GELF_ST_TYPE(sym->st_info) == STT_FUNC &&
        sym->st_name != 0 &&
        sym->st_shndx != SHN_UNDEF;
}


static int get_symbols_in_section(sym_section_ctx *sym, Elf *elf, Elf_Scn *sec, GElf_Shdr *shdr, int is_reloc)
{
    sym->syms = elf_getdata(sec, NULL);
    if (!sym->syms) {
        return -1;
    }
    Elf_Scn *symstrs_sec = elf_getscn(elf, shdr->sh_link);
    if (!sec) {
        return -1;
    }
    sym->symstrs = elf_getdata(symstrs_sec, NULL);
    if (!sym->symstrs) {
        return -1;
    }
    sym->sym_count = shdr->sh_size / shdr->sh_entsize;
    sym->is_plt = 0;
    sym->is_reloc = is_reloc;
    return 0;
}

static int get_plt_symbols_in_section(sym_section_ctx *sym, Elf *elf, plt_ctx *plt)
{
    sym->syms = elf_getdata(plt->dynsym.sec, NULL);
    if (!sym->syms) {
        return -1;
    }
    sym->rel_data = elf_getdata(plt->plt_rel.sec, NULL);       
    if (!sym->rel_data) {
        return -1;
    }
    Elf_Scn *symstrs_sec = elf_getscn(elf, plt->dynsym.hdr->sh_link);
    if (!symstrs_sec) {
        return -1;
    }
    sym->symstrs = elf_getdata(symstrs_sec, NULL);
    if (!sym->symstrs) {
        return -1;
    }
    sym->is_plt = 1;
    sym->plt_entsize = plt->plt.hdr->sh_type;
    sym->plt_offset = plt->plt.hdr->sh_offset;
    sym->sym_count = plt->plt_rel.hdr->sh_size / plt->plt_rel.hdr->sh_entsize;
    sym->plt_rel_type = plt->plt_rel.hdr->sh_type;
    return 0;
}

static void __get_plt_symbol(std::set<symbol> &ss, symbol_sections_ctx *si, Elf *elf)
{
    symbol s;
    GElf_Sym sym;
    int symidx;
    int index = 0;
    const char *sym_name = NULL;

    s.end = 0;
    s.start = 0;

    if (!si->dynsymtab.syms) {
        return;
    }

    while (index < si->dynsymtab.sym_count) {
        if (si->dynsymtab.plt_rel_type == SHT_RELA) {
            GElf_Rela pos_mem, *pos;
            pos = gelf_getrela(si->dynsymtab.rel_data, index, &pos_mem);
            symidx = GELF_R_SYM(pos->r_info);
        }
        else if (si->dynsymtab.plt_rel_type == SHT_REL) {
            GElf_Rel pos_mem, *pos;
            pos = gelf_getrel(si->dynsymtab.rel_data, index, &pos_mem);
            symidx = GELF_R_SYM(pos->r_info);
        }
        else {
            return;
        }
        index++;
        si->dynsymtab.plt_offset += si->dynsymtab.plt_entsize;
        gelf_getsym(si->dynsymtab.syms, symidx, &sym);

        sym_name = (const char *)si->dynsymtab.symstrs->d_buf + sym.st_name;
        s.start = si->dynsymtab.plt_offset;
        s.end = s.start + si->dynsymtab.plt_entsize;
        s.ip = s.start;
        s.name = sym_name;
        ss.insert(s);
    }
}

static void __get_symbol_without_plt(std::set<symbol> &ss, sym_section_ctx *tab, Elf *elf)
{
    GElf_Sym sym;
    int index = 0;
    const char *sym_name;
    symbol s;
    s.end = 0;
    s.start = 0;

    while (index < tab->sym_count) {
        gelf_getsym(tab->syms, index, &sym);
        index++;
        if (sym.st_shndx == SHN_ABS) {
            continue;
        }
        if (!is_function(&sym)) {
            continue;
        } 
        sym_name = (const char *)tab->symstrs->d_buf + sym.st_name;
        if (tab->is_reloc) {
            Elf_Scn *sec = elf_getscn(elf, sym.st_shndx);
            if (!sec) {
                continue;
            }
            GElf_Shdr shdr;
            gelf_getshdr(sec, &shdr);
            sym.st_value -= shdr.sh_addr - shdr.sh_offset;
        }
        s.start = sym.st_value & 0xffffffff; 
        s.end = s.start + sym.st_size;
        s.ip = s.start;
        s.name = sym_name;
        ss.insert(s);
    }
}

static void __get_symbol(std::set<symbol> &ss, symbol_sections_ctx *si, Elf *elf)
{
    symbol s;
    s.end = 0;
    s.start = 0;

    if (!si->symtab.syms && !si->dynsymtab.syms) {
        return;
    }

    sym_section_ctx *tab = &si->symtab;
    __get_symbol_without_plt(ss, tab, elf);
    tab = &si->symtab_in_dynsym;
    __get_symbol_without_plt(ss, tab, elf);
}

static void get_all_symbols(std::set<symbol> &ss, symbol_sections_ctx *si, Elf *elf)
{
    __get_symbol(ss, si, elf);
    __get_plt_symbol(ss, si, elf);
}

bool search_symbol(const std::set<symbol> &ss, symbol &sym)
{
    std::set<symbol>::const_iterator it = ss.find(sym);
    if (it != ss.end()) {
        sym.end = it->end;
        sym.start = it->start;
        sym.name = it->name;
        return true;
    }
    return false;
}

bool get_symbol_in_elf(std::set<symbol> &ss, const char *path)
{
    int is_reloc = 0;

    elf_version(EV_CURRENT);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (elf == NULL) {
        close(fd);
        return false;
    }

    Elf_Kind ek = elf_kind(elf);
    if (ek != ELF_K_ELF) {
        elf_end(elf);
        close(fd);
        return false;
    }
    GElf_Ehdr hdr;
    if (gelf_getehdr(elf, &hdr) == NULL) {
        elf_end(elf);
        close(fd);
        return false;
    }

    if (hdr.e_type == ET_EXEC) {
        is_reloc = 1;
    }

    if (!elf_rawdata(elf_getscn(elf, hdr.e_shstrndx), NULL)) {
        elf_end(elf);
        close(fd);
        return false;
    }

    GElf_Shdr shdr;
    GElf_Shdr symtab_shdr;
    GElf_Shdr dynsym_shdr;
    GElf_Shdr plt_shdr;
    GElf_Shdr plt_rel_shdr;
    memset(&shdr, 0, sizeof(shdr));
    memset(&symtab_shdr, 0, sizeof(symtab_shdr));
    memset(&dynsym_shdr, 0, sizeof(dynsym_shdr));
    memset(&plt_shdr, 0, sizeof(plt_shdr));
    memset(&plt_rel_shdr, 0, sizeof(plt_rel_shdr));

    Elf_Scn *sec = NULL;
    Elf_Scn *dynsym_sec = NULL;
    Elf_Scn *symtab_sec = NULL;
    Elf_Scn *plt_sec = NULL;
    Elf_Scn *plt_rel_sec = NULL;

    while ((sec = elf_nextscn(elf, sec)) != NULL) {
        char *str;
        gelf_getshdr(sec, &shdr);
        str = elf_strptr(elf, hdr.e_shstrndx, shdr.sh_name);

        if (str && strcmp(".symtab", str) == 0) {
            symtab_sec = sec;
            memcpy(&symtab_shdr, &shdr, sizeof(dynsym_shdr));
        }
        if (str && strcmp(".dynsym", str) == 0) {
            dynsym_sec = sec;
            memcpy(&dynsym_shdr, &shdr, sizeof(dynsym_shdr));
        }
        if (str && strcmp(".rela.plt", str) == 0) {
            plt_rel_sec = sec;
            memcpy(&plt_rel_shdr, &shdr, sizeof(plt_rel_shdr));
        }
        if (str && strcmp(".plt", str) == 0) {
            plt_sec = sec;
            memcpy(&plt_shdr, &shdr, sizeof(plt_shdr));
        }
        if (str && strcmp(".gnu.prelink_undo", str) == 0) {
            is_reloc = 1;
        }
    }

    plt_ctx plt;  
    plt.dynsym.hdr = &dynsym_shdr;
    plt.dynsym.sec = dynsym_sec;
    plt.plt.hdr = &plt_shdr;
    plt.plt.sec = plt_sec;
    plt.plt_rel.hdr = &plt_rel_shdr;
    plt.plt_rel.sec = plt_rel_sec;

    symbol_sections_ctx si;
    memset(&si, 0, sizeof(si));
    if (symtab_sec) {
        if (get_symbols_in_section(&si.symtab, elf, symtab_sec, &symtab_shdr, is_reloc) < 0) {
            elf_end(elf);
            close(fd);
        }
    }
    if (dynsym_sec) {
        if (get_symbols_in_section(&si.symtab_in_dynsym, elf, dynsym_sec, &dynsym_shdr, is_reloc) < 0) {
            elf_end(elf);
            close(fd);
        }
    }
    if (dynsym_sec && plt_sec) {
        if (get_plt_symbols_in_section(&si.dynsymtab, elf, &plt) < 0) {
            elf_end(elf);
            close(fd);
        }
    }

    get_all_symbols(ss, &si, elf);
    elf_end(elf);
    close(fd);
    return true;
}
