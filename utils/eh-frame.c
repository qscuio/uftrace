/*
 * eh-frame parsing for function discovery in stripped binaries
 *
 * Copyright (C) 2024, uftrace contributors
 * Released under the GPL v2.
 *
 * This module parses the .eh_frame section to extract function boundaries
 * from Frame Description Entries (FDEs). ELF exception handling frames
 * contain Call Frame Information (CFI) that includes:
 *   - CIE (Common Information Entry): shared data for multiple FDEs
 *   - FDE (Frame Description Entry): address range for each function
 *
 * Even in stripped binaries, .eh_frame is usually preserved because it's
 * required for exception handling and stack unwinding.
 */

#include <string.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "eh-frame"
#define PR_DOMAIN DBG_SYMBOL

#include "utils/eh-frame.h"
#include "utils/symbol.h"
#include "utils/utils.h"

#ifdef HAVE_LIBELF
#include "utils/symbol-libelf.h"
#else
#include "utils/symbol-rawelf.h"
#endif

/* DWARF CFI encoding constants */
#define DW_EH_PE_absptr		0x00
#define DW_EH_PE_omit		0xff
#define DW_EH_PE_uleb128	0x01
#define DW_EH_PE_udata2		0x02
#define DW_EH_PE_udata4		0x03
#define DW_EH_PE_udata8		0x04
#define DW_EH_PE_sleb128	0x09
#define DW_EH_PE_sdata2		0x0a
#define DW_EH_PE_sdata4		0x0b
#define DW_EH_PE_sdata8		0x0c
#define DW_EH_PE_pcrel		0x10
#define DW_EH_PE_datarel	0x30
#define DW_EH_PE_indirect	0x80

/**
 * Read unsigned LEB128 encoded value
 */
static uint64_t read_uleb128(const uint8_t **ptr, const uint8_t *end)
{
	uint64_t result = 0;
	int shift = 0;

	while (*ptr < end) {
		uint8_t byte = *(*ptr)++;
		result |= (uint64_t)(byte & 0x7f) << shift;
		if ((byte & 0x80) == 0)
			break;
		shift += 7;
	}
	return result;
}

/**
 * Read signed LEB128 encoded value
 */
static int64_t read_sleb128(const uint8_t **ptr, const uint8_t *end)
{
	int64_t result = 0;
	int shift = 0;
	uint8_t byte;

	while (*ptr < end) {
		byte = *(*ptr)++;
		result |= (int64_t)(byte & 0x7f) << shift;
		shift += 7;
		if ((byte & 0x80) == 0)
			break;
	}

	/* Sign extend if negative */
	if (shift < 64 && (byte & 0x40))
		result |= -(1LL << shift);

	return result;
}

/**
 * Read encoded pointer value based on encoding type
 */
static uint64_t read_encoded_ptr(const uint8_t **ptr, const uint8_t *end,
				 uint8_t encoding, uint64_t base_addr,
				 uint64_t pc_addr)
{
	uint64_t value = 0;
	const uint8_t *start = *ptr;

	if (encoding == DW_EH_PE_omit)
		return 0;

	/* Read the value based on format */
	switch (encoding & 0x0f) {
	case DW_EH_PE_absptr:
		if (*ptr + sizeof(void *) > end)
			return 0;
		if (sizeof(void *) == 8) {
			memcpy(&value, *ptr, 8);
			*ptr += 8;
		} else {
			uint32_t v32;
			memcpy(&v32, *ptr, 4);
			value = v32;
			*ptr += 4;
		}
		break;
	case DW_EH_PE_uleb128:
		value = read_uleb128(ptr, end);
		break;
	case DW_EH_PE_udata2:
		if (*ptr + 2 > end)
			return 0;
		memcpy(&value, *ptr, 2);
		value &= 0xffff;
		*ptr += 2;
		break;
	case DW_EH_PE_udata4:
		if (*ptr + 4 > end)
			return 0;
		memcpy(&value, *ptr, 4);
		value &= 0xffffffff;
		*ptr += 4;
		break;
	case DW_EH_PE_udata8:
		if (*ptr + 8 > end)
			return 0;
		memcpy(&value, *ptr, 8);
		*ptr += 8;
		break;
	case DW_EH_PE_sleb128:
		value = (uint64_t)read_sleb128(ptr, end);
		break;
	case DW_EH_PE_sdata2:
		if (*ptr + 2 > end)
			return 0;
		{
			int16_t v16;
			memcpy(&v16, *ptr, 2);
			value = (uint64_t)(int64_t)v16;
			*ptr += 2;
		}
		break;
	case DW_EH_PE_sdata4:
		if (*ptr + 4 > end)
			return 0;
		{
			int32_t v32;
			memcpy(&v32, *ptr, 4);
			value = (uint64_t)(int64_t)v32;
			*ptr += 4;
		}
		break;
	case DW_EH_PE_sdata8:
		if (*ptr + 8 > end)
			return 0;
		{
			int64_t v64;
			memcpy(&v64, *ptr, 8);
			value = (uint64_t)v64;
			*ptr += 8;
		}
		break;
	default:
		pr_dbg2("unsupported encoding format: %#x\n", encoding & 0x0f);
		return 0;
	}

	/* Apply relocation based on application */
	switch (encoding & 0x70) {
	case 0:
		/* Absolute, no adjustment */
		break;
	case DW_EH_PE_pcrel:
		value += pc_addr + (start - (const uint8_t *)pc_addr);
		break;
	case DW_EH_PE_datarel:
		value += base_addr;
		break;
	default:
		pr_dbg2("unsupported encoding application: %#x\n", encoding & 0x70);
		return 0;
	}

	return value;
}

/**
 * Parse .eh_frame section and extract function boundaries
 */
int parse_eh_frame_functions(const char *filename, unsigned long base_addr,
			     struct eh_frame_func **funcs, size_t *nr_funcs)
{
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	uint8_t *eh_frame_data = NULL;
	size_t eh_frame_size = 0;
	uint64_t eh_frame_addr = 0;
	const uint8_t *ptr, *end;
	size_t alloc_funcs = 0;
	uint8_t fde_encoding = DW_EH_PE_absptr;
	int ret = -1;

	*funcs = NULL;
	*nr_funcs = 0;

	if (elf_init(filename, &elf) < 0) {
		pr_dbg("failed to open ELF file: %s\n", filename);
		return -1;
	}

	/* Find .eh_frame section */
	elf_for_each_shdr(&elf, &iter) {
		char *name = elf_get_name(&elf, &iter, iter.shdr.sh_name);

		if (strcmp(name, ".eh_frame") == 0) {
			eh_frame_size = iter.shdr.sh_size;
			eh_frame_addr = iter.shdr.sh_addr;
			elf_get_secdata(&elf, &iter);

			eh_frame_data = xmalloc(eh_frame_size);
			elf_read_secdata(&elf, &iter, 0, eh_frame_data, eh_frame_size);
			break;
		}
	}

	if (eh_frame_data == NULL) {
		pr_dbg("no .eh_frame section found in %s\n", filename);
		goto out;
	}

	pr_dbg2("parsing .eh_frame: size=%zu, addr=%#lx\n", eh_frame_size,
		(unsigned long)eh_frame_addr);

	ptr = eh_frame_data;
	end = eh_frame_data + eh_frame_size;

	while (ptr < end) {
		uint32_t length;
		uint64_t extended_length = 0;
		const uint8_t *entry_start;
		const uint8_t *entry_end;
		uint32_t cie_id;
		int is_64bit = 0;

		/* Read length */
		if (ptr + 4 > end)
			break;
		memcpy(&length, ptr, 4);
		ptr += 4;

		if (length == 0)
			break;  /* End of .eh_frame */

		if (length == 0xffffffff) {
			/* 64-bit DWARF format */
			if (ptr + 8 > end)
				break;
			memcpy(&extended_length, ptr, 8);
			ptr += 8;
			is_64bit = 1;
			length = extended_length;
		}

		entry_start = ptr;
		entry_end = ptr + length;

		if (entry_end > end)
			break;

		/* Read CIE ID / CIE pointer */
		if (is_64bit) {
			if (ptr + 8 > entry_end)
				goto next_entry;
			uint64_t cie_ptr64;
			memcpy(&cie_ptr64, ptr, 8);
			cie_id = (cie_ptr64 == 0) ? 0 : 1;
			ptr += 8;
		} else {
			if (ptr + 4 > entry_end)
				goto next_entry;
			memcpy(&cie_id, ptr, 4);
			ptr += 4;
		}

		if (cie_id == 0) {
			/* This is a CIE (Common Information Entry) */
			uint8_t version;
			const char *augmentation;

			if (ptr >= entry_end)
				goto next_entry;

			version = *ptr++;
			(void)version;

			augmentation = (const char *)ptr;
			ptr += strlen(augmentation) + 1;

			/* Skip code alignment factor */
			read_uleb128(&ptr, entry_end);
			/* Skip data alignment factor */
			read_sleb128(&ptr, entry_end);
			/* Skip return address register */
			if (version == 1)
				ptr++;
			else
				read_uleb128(&ptr, entry_end);

			/* Parse augmentation data if present */
			if (augmentation[0] == 'z') {
				uint64_t aug_len = read_uleb128(&ptr, entry_end);
				const uint8_t *aug_end = ptr + aug_len;
				const char *aug = augmentation + 1;

				while (*aug && ptr < aug_end) {
					switch (*aug) {
					case 'L':
						ptr++;  /* LSDA encoding */
						break;
					case 'P':
						{
							uint8_t enc = *ptr++;
							read_encoded_ptr(&ptr, aug_end, enc,
									 base_addr, eh_frame_addr);
						}
						break;
					case 'R':
						fde_encoding = *ptr++;
						break;
					default:
						break;
					}
					aug++;
				}
				ptr = aug_end;
			}
		} else {
			/* This is an FDE (Frame Description Entry) */
			uint64_t pc_begin, pc_range;
			const char *aug = NULL;

			/* Read PC begin and range */
			uint64_t pc_addr = eh_frame_addr + (ptr - eh_frame_data);
			pc_begin = read_encoded_ptr(&ptr, entry_end, fde_encoding,
						    base_addr, pc_addr);

			/* PC range is always same format but without relocation */
			uint8_t range_enc = fde_encoding & 0x0f;
			pc_range = read_encoded_ptr(&ptr, entry_end, range_enc, 0, 0);

			if (pc_begin != 0 && pc_range != 0) {
				/* Valid function entry */
				if (*nr_funcs >= alloc_funcs) {
					alloc_funcs = alloc_funcs ? alloc_funcs * 2 : 64;
					*funcs = xrealloc(*funcs, alloc_funcs *
							  sizeof(struct eh_frame_func));
				}

				(*funcs)[*nr_funcs].addr = pc_begin;
				(*funcs)[*nr_funcs].size = pc_range;
				(*nr_funcs)++;

				pr_dbg4("FDE: pc_begin=%#lx, size=%lu\n",
					(unsigned long)pc_begin, (unsigned long)pc_range);
			}
		}

next_entry:
		ptr = entry_end;
	}

	pr_dbg2("found %zu functions from .eh_frame\n", *nr_funcs);
	ret = 0;

out:
	free(eh_frame_data);
	elf_finish(&elf);
	return ret;
}

/**
 * Load symbol table entries from .eh_frame discovered functions
 */
int load_symtab_from_eh_frame(struct uftrace_symtab *symtab, const char *filename,
			      unsigned long offset)
{
	struct eh_frame_func *funcs = NULL;
	size_t nr_funcs = 0;
	size_t i;

	if (parse_eh_frame_functions(filename, offset, &funcs, &nr_funcs) < 0)
		return -1;

	if (nr_funcs == 0) {
		free(funcs);
		return 0;
	}

	symtab->nr_alloc = nr_funcs;
	symtab->sym = xmalloc(nr_funcs * sizeof(*symtab->sym));

	for (i = 0; i < nr_funcs; i++) {
		struct uftrace_symbol *sym = &symtab->sym[symtab->nr_sym++];
		char name[32];

		sym->addr = funcs[i].addr;
		sym->size = funcs[i].size;
		sym->type = ST_LOCAL_FUNC;

		/* Generate synthetic function name */
		snprintf(name, sizeof(name), "func_%lx", (unsigned long)funcs[i].addr);
		sym->name = xstrdup(name);
	}

	free(funcs);

	pr_dbg("loaded %zu symbols from .eh_frame\n", symtab->nr_sym);
	return symtab->nr_sym;
}
