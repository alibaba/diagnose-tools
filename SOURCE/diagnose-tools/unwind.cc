/*
 * Post mortem Dwarf CFI based unwinding on top of regs and stack dumps.
 *
 * Lots of this code have been borrowed or heavily inspired from parts of
 * the libunwind 0.99 code which are (amongst other contributors I may have
 * forgotten):
 *
 * Copyright (C) 2002-2007 Hewlett-Packard Co
 *	Contributed by David Mosberger-Tang <davidm@hpl.hp.com>
 *
 * And the bugs have been added by:
 *
 * Copyright (C) 2010, Frederic Weisbecker <fweisbec@gmail.com>
 * Copyright (C) 2012, Jiri Olsa <jolsa@redhat.com>
 *
 */

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <limits.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

//#include <perf_regs.h>
#include <elf.h>
#include <gelf.h>
#include <libunwind.h>
#include <libunwind-ptrace.h>


#include "unwind.h"
#include "symbol.h"


extern "C" {
int UNW_OBJ(dwarf_search_unwind_table) (unw_addr_space_t as,
				    unw_word_t ip,
				    unw_dyn_info_t *di,
				    unw_proc_info_t *pi,
				    int need_unwind_info, void *arg);
}

#define dwarf_search_unwind_table UNW_OBJ(dwarf_search_unwind_table)

#define DW_EH_PE_FORMAT_MASK	0x0f	/* format of the encoded value */
#define DW_EH_PE_APPL_MASK	0x70	/* how the value is to be applied */

/* Pointer-encoding formats: */
#define DW_EH_PE_omit		0xff
#define DW_EH_PE_ptr		0x00	/* pointer-sized unsigned value */
#define DW_EH_PE_udata4		0x03	/* unsigned 32-bit value */
#define DW_EH_PE_udata8		0x04	/* unsigned 64-bit value */
#define DW_EH_PE_sdata4		0x0b	/* signed 32-bit value */
#define DW_EH_PE_sdata8		0x0c	/* signed 64-bit value */

/* Pointer-encoding application: */
#define DW_EH_PE_absptr		0x00	/* absolute value */
#define DW_EH_PE_pcrel		0x10	/* rel. to addr. of encoded value */

/*
 * The following are not documented by LSB v1.3, yet they are used by
 * GCC, presumably they aren't documented by LSB since they aren't
 * used on Linux:
 */
#define DW_EH_PE_funcrel	0x40	/* start-of-procedure-relative */
#define DW_EH_PE_aligned	0x50	/* aligned pointer */

/* Flags intentionaly not handled, since they're not needed:
 * #define DW_EH_PE_indirect      0x80
 * #define DW_EH_PE_uleb128       0x01
 * #define DW_EH_PE_udata2        0x02
 * #define DW_EH_PE_sleb128       0x09
 * #define DW_EH_PE_sdata2        0x0a
 * #define DW_EH_PE_textrel       0x20
 * #define DW_EH_PE_datarel       0x30
 */


struct unwind_info {
	struct perf_sample	    *sample;
    int                     pid;
    int                     pid_ns;
    symbol_parser           *sp;
};

#define dw_read(ptr, type, end) ({	\
	type *__p = (type *) ptr;	\
	type  __v;			\
	if ((__p + 1) > (type *) end)	\
		return -EINVAL;		\
	__v = *__p++;			\
	ptr = (typeof(ptr)) __p;	\
	__v;				\
	})

#ifdef __x86_64__
int unwind__arch_reg_id(int regnum)
{
	int id;

	switch (regnum) {
	case UNW_X86_64_RBP:
		id = PERF_REG_BP;
		break;
	case UNW_X86_64_RSP:
		id = PERF_REG_SP;
		break;
	case UNW_X86_64_RIP:
		id = PERF_REG_IP;
		break;
	default:
		return -EINVAL;
	}

	return id;
}
#else
int unwind__arch_reg_id(int regnum)
{
	int id;
	switch (regnum) {
	case UNW_AARCH64_SP:
		id = PERF_REG_SP;
		break;
	case UNW_AARCH64_PC:
		id = PERF_REG_IP;
		break;
    default:
        return -EINVAL;
    }

    return id;
}
#endif

static int __dw_read_encoded_value(u8 **p, u8 *end, u64 *val,
				   u8 encoding)
{
	u8 *cur = *p;
	*val = 0;

	switch (encoding) {
	case DW_EH_PE_omit:
		*val = 0;
		goto out;
	case DW_EH_PE_ptr:
		*val = dw_read(cur, unsigned long, end);
		goto out;
	default:
		break;
	}

	switch (encoding & DW_EH_PE_APPL_MASK) {
	case DW_EH_PE_absptr:
		break;
	case DW_EH_PE_pcrel:
		*val = (unsigned long) cur;
		break;
	default:
		return -EINVAL;
	}

	if ((encoding & 0x07) == 0x00)
		encoding |= DW_EH_PE_udata4;

	switch (encoding & DW_EH_PE_FORMAT_MASK) {
	case DW_EH_PE_sdata4:
		*val += dw_read(cur, s32, end);
		break;
	case DW_EH_PE_udata4:
		*val += dw_read(cur, u32, end);
		break;
	case DW_EH_PE_sdata8:
		*val += dw_read(cur, s64, end);
		break;
	case DW_EH_PE_udata8:
		*val += dw_read(cur, u64, end);
		break;
	default:
		return -EINVAL;
	}

 out:
	*p = cur;
	return 0;
}

#define dw_read_encoded_value(ptr, end, enc) ({			\
	u64 __v;						\
	if (__dw_read_encoded_value(&ptr, end, &__v, enc)) {	\
		return -EINVAL;                                 \
	}                                                       \
	__v;                                                    \
	})

static Elf_Scn *elf_section_by_name(Elf *elf, GElf_Ehdr *ep,
				    GElf_Shdr *shp, const char *name)
{
	Elf_Scn *sec = NULL;

	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *str;

		gelf_getshdr(sec, shp);
		str = elf_strptr(elf, ep->e_shstrndx, shp->sh_name);
		if (!strcmp(name, str))
			break;
	}

	return sec;
}

static u64 elf_section_offset(int fd, const char *name)
{
	Elf *elf;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;
	u64 offset = 0;

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL)
		return 0;

	do {
		if (gelf_getehdr(elf, &ehdr) == NULL)
			break;

		if (!elf_section_by_name(elf, &ehdr, &shdr, name))
			break;

		offset = shdr.sh_offset;
	} while (0);

	elf_end(elf);
	return offset;
}

struct table_entry {
	u32 start_ip_offset;
	u32 fde_offset;
};

struct eh_frame_hdr {
	unsigned char version;
	unsigned char eh_frame_ptr_enc;
	unsigned char fde_count_enc;
	unsigned char table_enc;

	/*
	 * The rest of the header is variable-length and consists of the
	 * following members:
	 *
	 *	encoded_t eh_frame_ptr;
	 *	encoded_t fde_count;
	 */

	/* A single encoded pointer should not be more than 8 bytes. */
	u64 enc[2];

	/*
	 * struct {
	 *    encoded_t start_ip;
	 *    encoded_t fde_addr;
	 * } binary_search_table[fde_count];
	 */
	char data[0];
} __attribute__((__packed__));

int dso_data_fd(vma* dso)
{
    return open(dso->name.c_str(), O_RDONLY);
}

ssize_t dso_read(vma *dso, u64 offset, u8 *data, ssize_t size)
{
	ssize_t ret = -1;
	int fd;

	fd = dso_data_fd(dso);
	if (fd < 0)
		return -1;

	do {
		if (-1 == lseek(fd, offset, SEEK_SET))
			break;

		ret = read(fd, data, size);
		if (ret <= 0)
			break;
	} while (0);

	close(fd);
	return ret;
}

ssize_t dso__data_read_offset(vma *dso, u64 offset, u8 *data, ssize_t size)
{
    ssize_t r = 0;
    u8 *p = data;

    do {
        ssize_t ret;
        ret = dso_read(dso, offset, p, size);
        if (ret <= 0) {
            return -1;
        }
        if (ret > size) {
            return -1;
        }
        r += ret;
        p += ret;
        offset += ret;
        size -= ret;
    } while (size);
    return r;
}

ssize_t dso__data_read_addr(vma *map,
                    u64 addr, u8 *data, ssize_t size)
{
	u64 offset;

	if (map->name.size() > 0 && map->name[0] != '/')
		return 0;

	offset = addr - map->start + map->offset;
	return dso__data_read_offset(map, offset, data, size);
}


static int unwind_spec_ehframe(vma *dso,
			       u64 offset, u64 *table_data, u64 *segbase,
			       u64 *fde_count)
{
	struct eh_frame_hdr hdr;
	u8 *enc = (u8 *) &hdr.enc;
	u8 *end = (u8 *) &hdr.data;
	ssize_t r;

	r = dso__data_read_offset(dso, offset, (u8 *) &hdr, sizeof(hdr));
	if (r != sizeof(hdr)) {
		return -EINVAL;
	}

	/* We dont need eh_frame_ptr, just skip it. */
	dw_read_encoded_value(enc, end, hdr.eh_frame_ptr_enc);

	*fde_count  = dw_read_encoded_value(enc, end, hdr.fde_count_enc);
	*segbase    = offset;
	*table_data = (enc - (u8 *) &hdr) + offset;

	return 0;
}

static int read_unwind_spec(vma* dso, u64 *table_data, u64 *segbase, u64 *fde_count)
{
	int ret = -EINVAL, fd;

	if (dso->eh_frame_hdr_offset == 0 && dso->elf_read_error == 0) {
		fd = dso_data_fd(dso);
		if (fd < 0)
			return -EINVAL;

		dso->eh_frame_hdr_offset = elf_section_offset(fd, ".eh_frame_hdr");
		close(fd);
		ret = unwind_spec_ehframe(dso, dso->eh_frame_hdr_offset,
								  &dso->table_data, &dso->eh_frame_hdr_offset,
								  &dso->fde_count);
		if (ret != 0) {
			dso->eh_frame_hdr_offset = 0;
			dso->elf_read_error = 1;
			return -EINVAL;
		}
	}

	*table_data = dso->table_data;
	*segbase = dso->eh_frame_hdr_offset;
	*fde_count = dso->fde_count;

	/* TODO .debug_frame check if eh_frame_hdr fails */
	return 0;
}

static vma* find_map(unw_word_t ip, struct unwind_info *ui)
{
    return ui->sp->find_vma(ui->pid, ip);
}

static int
find_proc_info(unw_addr_space_t as, unw_word_t ip, unw_proc_info_t *pi,
	       int need_unwind_info, void *arg)
{
	struct unwind_info *ui = (struct unwind_info *)arg;
	unw_dyn_info_t di;
	u64 table_data, segbase, fde_count;

    vma* map;
	map = find_map(ip, ui);
    if (!map) {
		return -EINVAL;
	}

	if (!read_unwind_spec(map, &table_data, &segbase, &fde_count)) {
		memset(&di, 0, sizeof(di));
		di.format   = UNW_INFO_FORMAT_REMOTE_TABLE;
		di.start_ip = map->start;
		di.end_ip   = map->end;
		di.u.rti.segbase    = map->start + segbase;
		di.u.rti.table_data = map->start + table_data;
		di.u.rti.table_len  = fde_count * sizeof(struct table_entry)
				      / sizeof(unw_word_t);
		return dwarf_search_unwind_table(as, ip, &di, pi,
						 need_unwind_info, arg);
	}
	//return -EINVAL;
	return -UNW_ENOINFO;
}

static int access_fpreg(unw_addr_space_t as,
			unw_regnum_t num,
			unw_fpreg_t *val,
			int __write,
			void *arg)
{
	return -UNW_EINVAL;
}

static int get_dyn_info_list_addr(unw_addr_space_t as,
				  unw_word_t *dil_addr,
				  void *arg)
{
	return -UNW_ENOINFO;
}

static int resume(unw_addr_space_t as,
		  unw_cursor_t *cu,
		  void *arg)
{
	return -UNW_EINVAL;
}

static int
get_proc_name(unw_addr_space_t as,
	      unw_word_t addr,
		char *bufp, size_t buf_len,
		unw_word_t *offp, void *arg)
{
	return -UNW_EINVAL;
}

struct map *last_map = NULL;
static int access_dso_mem(struct unwind_info *ui, unw_word_t addr,
			  unw_word_t *data)
{
	ssize_t size;

    // ip in the first page is invalid
    if ( addr == 0 || addr == (unsigned long)(-1) || (long)addr < 4096 )  {
        return -UNW_ENOINFO;
    }

    vma *map;
    map = find_map(addr, ui);
    if (!map) {
        return -UNW_ENOINFO;
    }

    if (map->type != NATIVE_TYPE) {
        return -UNW_ENOINFO;
    }

	size = dso__data_read_addr(map,
				   addr, (u8 *) data, sizeof(*data));

	return !(size == sizeof(*data));
}

/*
 * Optimization point.
 */
static int reg_value(unw_word_t *valp, struct regs_dump *regs, int id)
{
	/* we only support 3 registers. RIP, RSP and RBP */
	if (id < 0 || id > 2)
		return -EINVAL;

	*valp = regs->regs[id];
	return 0;
}

unw_word_t last_addr = 0;
unw_word_t last_val = 0;
int stack_offset = 0;

static int access_mem(unw_addr_space_t as,
		      unw_word_t addr, unw_word_t *valp,
		      int __write, void *arg)
{
	struct unwind_info *ui = (struct unwind_info *)arg;
	struct stack_dump *stack = &ui->sample->user_stack;
	unw_word_t start, end;
	int offset;
	int ret;

	if (addr == last_addr) {
		(*valp) = last_val;
		return 0;
	}

	last_addr = addr;

	/* Don't support write, probably not needed. */
	if (__write || !stack || !ui->sample->user_regs.regs) {
		*valp = 0;
		// fprintf(stderr, "access_mem: __write memory\n");
		last_val = *valp;
		return 0;
	}

	/* start is the SP */
	ret = reg_value(&start, &ui->sample->user_regs, PERF_REG_SP);
	if (ret) {
		// fprintf(stderr, "access_mem: reg_value error (ret: %d)\n", ret);
		return ret;
	}

	end = start + stack->size;

	/* Check overflow. */
	if (addr + sizeof(unw_word_t) < addr) {
		// fprintf(stderr, "access_mem: Check overflow.\n");
		return -EINVAL;
	}

	if (addr < start || addr + sizeof(unw_word_t) >= end) {
		ret = access_dso_mem(ui, addr, valp);
		if (ret) {
			// pr_debug("unwind: access_mem %p not inside range %p-%p\n",
			//	(void *)addr, (void *)start, (void *)end);
			*valp = 0;
			last_val = 0;
			return ret;
		}
		last_val = *valp;
		return 0;
	}

	offset = addr - start;
	*valp  = *(unw_word_t *)&stack->data[offset];
	last_val = *valp;
	stack_offset = offset;

	//pr_debug("unwind: access_mem addr %p, val %lx, offset %d\n",
    // (void *)addr, (unsigned long)*valp, offset);
	return 0;
}

static int access_reg(unw_addr_space_t as,
		      unw_regnum_t regnum, unw_word_t *valp,
		      int __write, void *arg)
{
	struct unwind_info *ui = (struct unwind_info *)arg;
	int id, ret;

	/* Don't support write, I suspect we don't need it. */
	if (__write) {
		//pr_err("unwind: access_reg w %d\n", regnum);
		return 0;
	}

	if (!ui->sample->user_regs.regs) {
		*valp = 0;
		return 0;
	}

	id = unwind__arch_reg_id(regnum);
	if (id < 0) {
		//fprintf(stderr, "Cannot get reg: %d\n", regnum);
		return -EINVAL;
	}

	ret = reg_value(valp, &ui->sample->user_regs, id);
	if (ret) {
		//pr_err("unwind: can't read reg %d\n", regnum);
		return ret;
	}

	//pr_debug("unwind: reg %d, val %lx\n", regnum, (unsigned long)*valp);
	return 0;
}

static void put_unwind_info(unw_addr_space_t as,
			    unw_proc_info_t *pi,
			    void *arg)
{
	//pr_debug("unwind: put_unwind_info called\n");
}

static int entry(u64 ip, int pid, int pid_ns, unwind_entry_cb_t cb, void *arg)
{
	struct unwind_entry e;

	e.ip = ip;
	e.pid = pid;
    e.pid_ns = pid_ns;

	return cb(&e, arg);
}

static unw_accessors_t accessors = {
	.find_proc_info		= find_proc_info,
	.put_unwind_info	= put_unwind_info,
	.get_dyn_info_list_addr	= get_dyn_info_list_addr,
	.access_mem		= access_mem,
	.access_reg		= access_reg,
	.access_fpreg		= access_fpreg,
	.resume			= resume,
	.get_proc_name		= get_proc_name,
};

static int get_entries(struct unwind_info *ui, unwind_entry_cb_t cb,
		       void *arg)
{
	unw_addr_space_t addr_space;
	unw_cursor_t c;
	entry_cb_arg_t *cb_arg = (entry_cb_arg_t *)arg;
	int ret;
	int loops = 0;

	addr_space = unw_create_addr_space(&accessors, 0);
	if (!addr_space) {
		//pr_err("unwind: Can't create unwind address space.\n");
		return -ENOMEM;
	}

	unw_set_caching_policy(addr_space, UNW_CACHE_GLOBAL);

	ret = unw_init_remote(&c, addr_space, ui); /* @ui is args */

	while (!ret && (unw_step(&c) > 0)) {
		unw_word_t ip;

		unw_get_reg(&c, UNW_REG_IP, &ip); //get IP from current step;
		cb_arg->arg = &c;
		ret = entry(ip, ui->pid, ui->pid_ns, cb, cb_arg);

		loops++;
		if (loops >= 50)
			break;
	}

	unw_destroy_addr_space(addr_space);
	return ret;
}

int unwind__get_entries(unwind_entry_cb_t cb, void *arg,
			symbol_parser *sp, int pid, int pid_ns,
			struct perf_sample *data)
{
	unw_word_t ip;
	struct unwind_info ui = {
		.sample       = data,
        .pid          = pid,
        .pid_ns       = pid_ns,
		.sp           = sp,
	};
	int ret;

	if (!data->user_regs.regs)
		return -EINVAL;

	ret = reg_value(&ip, &data->user_regs, PERF_REG_IP);
	if (ret)
		return ret;

	ret = entry(ip, pid, pid_ns, cb, arg);
	if (ret)
		return -ENOMEM;

	return get_entries(&ui, cb, arg);
}
