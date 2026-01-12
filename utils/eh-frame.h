/*
 * eh-frame parsing for function discovery in stripped binaries
 *
 * Copyright (C) 2024, uftrace contributors
 * Released under the GPL v2.
 *
 * This module parses the .eh_frame section to extract function boundaries
 * from Frame Description Entries (FDEs). This is useful for stripped
 * binaries where symbol tables have been removed but .eh_frame remains.
 */

#ifndef UFTRACE_EH_FRAME_H
#define UFTRACE_EH_FRAME_H

#include <stdbool.h>
#include <stdint.h>

struct uftrace_elf_data;
struct uftrace_symtab;

/**
 * struct eh_frame_func - Function boundary discovered from .eh_frame
 * @addr: Function start address (relative to base)
 * @size: Function size in bytes
 */
struct eh_frame_func {
	uint64_t addr;
	uint64_t size;
};

/**
 * parse_eh_frame_functions - Parse .eh_frame to discover function boundaries
 * @filename: Path to ELF binary
 * @base_addr: Base address offset for PIE binaries
 * @funcs: Output array of discovered functions (caller must free)
 * @nr_funcs: Output number of functions found
 *
 * Returns 0 on success, -1 on failure
 */
int parse_eh_frame_functions(const char *filename, unsigned long base_addr,
			     struct eh_frame_func **funcs, size_t *nr_funcs);

/**
 * load_symtab_from_eh_frame - Load symbol table entries from .eh_frame data
 * @symtab: Symbol table to populate
 * @filename: Path to ELF binary
 * @offset: Address offset
 *
 * Returns number of symbols loaded, or -1 on failure
 */
int load_symtab_from_eh_frame(struct uftrace_symtab *symtab, const char *filename,
			      unsigned long offset);

#endif /* UFTRACE_EH_FRAME_H */
