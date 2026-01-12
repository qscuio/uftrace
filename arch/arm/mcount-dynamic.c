/*
 * ARM32 dynamic tracing implementation for uftrace
 *
 * Copyright (C) 2024, uftrace contributors
 * Released under the GPL v2.
 */

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "dynamic"
#define PR_DOMAIN DBG_DYNAMIC

#include "libmcount/dynamic.h"
#include "libmcount/internal.h"
#include "libmcount/mcount.h"
#include "mcount-arch.h"
#include "utils/rbtree.h"
#include "utils/symbol.h"
#include "utils/utils.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE MAP_FIXED
#endif

/* ARM NOP patterns for patchable function entry */
static const uint32_t arm_nop = 0xe1a00000;  /* MOV r0, r0 (NOP) */
static const uint32_t arm_nop2[] = { 0xe1a00000, 0xe1a00000 };  /* 2x NOP */

/* Target instrumentation functions */
extern void __fentry__(void);
extern void __dentry__(void);

static void save_orig_code(struct mcount_disasm_info *info)
{
	/*
	 * ARM32 jump instruction to return to function body:
	 * LDR pc, [pc, #-4]  @ Load PC from memory after this instruction
	 * .word <target>     @ Target address
	 */
	uint32_t jmp_insn[2] = {
		0xe51ff004,  /* LDR pc, [pc, #-4] */
		info->addr + CODE_SIZE,  /* Target address */
	};

	mcount_save_code(info, CODE_SIZE, jmp_insn, sizeof(jmp_insn));
}

int mcount_setup_trampoline(struct mcount_dynamic_info *mdi)
{
	uintptr_t dentry_addr = (uintptr_t)(void *)&__dentry__;
	uintptr_t fentry_addr = (uintptr_t)(void *)&__fentry__;
	unsigned long page_offset;

	/*
	 * Trampoline code for ARM32:
	 *   PUSH {fp, lr}           @ Save frame pointer and link register
	 *   LDR ip, [pc]            @ Load target address to ip (r12)
	 *   BX ip                   @ Branch to target
	 *   .word <target_addr>     @ Target function address
	 */
	uint32_t trampoline[] = {
		0xe92d4800,  /* PUSH {fp, lr} */
		0xe59fc000,  /* LDR ip, [pc] */
		0xe12fff1c,  /* BX ip */
		(uint32_t)dentry_addr,  /* Target address */
	};

	if (mdi->type == DYNAMIC_FENTRY_NOP || mdi->type == DYNAMIC_PATCHABLE) {
		trampoline[3] = (uint32_t)fentry_addr;
	}

	/* Find unused space at the end of the code segment */
	mdi->trampoline = ALIGN(mdi->text_addr + mdi->text_size, PAGE_SIZE);
	mdi->trampoline -= sizeof(trampoline);

	if (unlikely(mdi->trampoline < mdi->text_addr + mdi->text_size)) {
		void *trampoline_check;

		mdi->trampoline += sizeof(trampoline);
		mdi->text_size += PAGE_SIZE;

		pr_dbg("adding a page for trampoline at %#lx\n", mdi->trampoline);

		trampoline_check = mmap((void *)mdi->trampoline, PAGE_SIZE,
					PROT_READ | PROT_WRITE | PROT_EXEC,
					MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (trampoline_check != (void *)mdi->trampoline) {
			pr_err("could not map trampoline at desired location %#lx, got %#lx: %m\n",
			       mdi->trampoline, (uintptr_t)trampoline_check);
		}
	}

	page_offset = mdi->text_addr & (PAGE_SIZE - 1);
	if (mprotect((void *)(mdi->text_addr - page_offset), mdi->text_size + page_offset,
		     PROT_READ | PROT_WRITE | PROT_EXEC)) {
		pr_dbg("cannot setup trampoline due to protection: %m\n");
		return -1;
	}

	memcpy((void *)mdi->trampoline, trampoline, sizeof(trampoline));
	return 0;
}

void mcount_cleanup_trampoline(struct mcount_dynamic_info *mdi)
{
	/* Restore original text segment protection */
	unsigned long page_offset = mdi->text_addr & (PAGE_SIZE - 1);
	mprotect((void *)(mdi->text_addr - page_offset), mdi->text_size + page_offset,
		 PROT_READ | PROT_EXEC);
}

static void read_patchable_loc(struct mcount_dynamic_info *mdi, struct uftrace_elf_data *elf,
			       struct uftrace_elf_iter *iter, unsigned long offset)
{
	typeof(iter->shdr) *shdr = &iter->shdr;
	unsigned i;
	unsigned long *patchable_loc;
	unsigned long sh_addr;

	mdi->nr_patch_target = shdr->sh_size / sizeof(long);
	mdi->patch_target = xmalloc(shdr->sh_size);
	patchable_loc = mdi->patch_target;

	sh_addr = shdr->sh_addr;
	if (elf->ehdr.e_type == ET_DYN)
		sh_addr += offset;

	for (i = 0; i < mdi->nr_patch_target; i++) {
		unsigned long *entry = (unsigned long *)sh_addr + i;
		patchable_loc[i] = *entry - offset;
	}
}

void mcount_arch_find_module(struct mcount_dynamic_info *mdi, struct uftrace_symtab *symtab)
{
	struct uftrace_elf_data elf;
	struct uftrace_elf_iter iter;
	unsigned i = 0;

	mdi->type = DYNAMIC_NONE;

	if (elf_init(mdi->map->libname, &elf) < 0)
		goto out;

	elf_for_each_shdr(&elf, &iter) {
		char *shstr = elf_get_name(&elf, &iter, iter.shdr.sh_name);

		if (!strcmp(shstr, PATCHABLE_SECT)) {
			mdi->type = DYNAMIC_PATCHABLE;
			read_patchable_loc(mdi, &elf, &iter, mdi->base_addr);
			goto out;
		}
	}

	/*
	 * Check first few functions for patchable function entry signature.
	 */
	for (i = 0; i < symtab->nr_sym; i++) {
		struct uftrace_symbol *sym = &symtab->sym[i];
		void *code_addr = (void *)sym->addr + mdi->map->start;

		if (sym->type != ST_LOCAL_FUNC && sym->type != ST_GLOBAL_FUNC)
			continue;

		/* Skip special functions */
		if (sym->name[0] == '_')
			continue;

		/* Check for NOP pattern */
		if (!memcmp(code_addr, arm_nop2, sizeof(arm_nop2))) {
			mdi->type = DYNAMIC_FENTRY_NOP;
			goto out;
		}
	}

	/* Check for mcount-based tracing */
	switch (check_trace_functions(mdi->map->libname)) {
	case TRACE_MCOUNT:
		mdi->type = DYNAMIC_PG;
		break;
	default:
		break;
	}

out:
	pr_dbg("dynamic patch type: %s: %d (%s)\n", uftrace_basename(mdi->map->libname), mdi->type,
	       mdi_type_names[mdi->type]);

	elf_finish(&elf);
}

static unsigned long get_target_offset(struct mcount_dynamic_info *mdi, unsigned long addr)
{
	/*
	 * ARM BL instruction uses 24-bit signed offset (shifted left by 2).
	 * Total range is ±32MB.
	 */
	long offset = (long)(mdi->trampoline - addr - 8) >> 2;

	/* Check if within range */
	if (offset < -0x800000 || offset > 0x7fffff) {
		pr_dbg("trampoline offset out of range: %ld\n", offset);
		return 0;
	}

	return offset & 0x00ffffff;
}

/*
 * Inline 12-byte trampoline for ARM32 using absolute addressing:
 *
 *   LDR pc, [pc, #-4]   ; 4 bytes: E51FF004 - Load PC from next word
 *   .word target_addr   ; 4 bytes: absolute address
 *
 * Total: 8 bytes minimum. For safety with padding, use 12 bytes.
 * This allows jumping to any address without range limitations.
 */
#define ARM_INLINE_TRAMPOLINE_SIZE 12

/*
 * Try to patch using an inline absolute jump trampoline.
 * This is used when the function prologue is large enough (>= 12 bytes)
 * to contain an absolute jump without needing a separate trampoline.
 *
 * Returns: 1 if patching succeeded, 0 if not applicable, -1 on error.
 */
static int patch_inline_trampoline(struct mcount_dynamic_info *mdi,
				   struct mcount_disasm_info *info)
{
	/*
	 * ARM32 inline trampoline:
	 *   PUSH {fp, lr}        @ Save frame pointer and link register
	 *   LDR pc, [pc, #-4]    @ Load PC from next word
	 *   .word __dentry__     @ Target address
	 */
	uint32_t push_insn = 0xe92d4800;  /* PUSH {fp, lr} */
	uint32_t ldr_pc = 0xe51ff004;     /* LDR pc, [pc, #-4] */
	uint32_t target_addr = (uint32_t)(uintptr_t)__dentry__;
	void *patch_addr;
	size_t patch_size;

	/* Need at least 12 bytes for inline trampoline */
	if (info->orig_size < ARM_INLINE_TRAMPOLINE_SIZE)
		return 0;

	patch_addr = (void *)info->addr;
	patch_size = info->orig_size;

	/* Write inline trampoline: PUSH {fp,lr}; LDR pc, [pc, #-4]; .word target */
	memcpy(patch_addr, &push_insn, sizeof(push_insn));
	memcpy(patch_addr + 4, &ldr_pc, sizeof(ldr_pc));
	memcpy(patch_addr + 8, &target_addr, sizeof(target_addr));

	/* Fill remaining bytes with NOPs */
	if (patch_size > ARM_INLINE_TRAMPOLINE_SIZE) {
		uint32_t nop = 0xe1a00000;  /* MOV r0, r0 (NOP) */
		size_t remaining = patch_size - ARM_INLINE_TRAMPOLINE_SIZE;
		size_t i;
		for (i = 0; i < remaining / 4; i++)
			memcpy(patch_addr + ARM_INLINE_TRAMPOLINE_SIZE + i * 4, &nop, 4);
	}

	/* Flush instruction cache */
	__builtin___clear_cache(patch_addr, patch_addr + patch_size);

	pr_dbg2("patched with ARM32 inline trampoline: %s (size: %zu)\n",
		info->sym->name, patch_size);

	return 1;
}

/*
 * Scan for code caves (NOP sleds, alignment padding) within the text segment
 * that can be used for trampoline placement.
 *
 * @mdi: module dynamic info
 * @target: target function address (for range check)
 * @min_size: minimum size needed for the trampoline
 *
 * Returns: address of found code cave, or 0 if not found
 */
static unsigned long find_code_cave(struct mcount_dynamic_info *mdi,
				    unsigned long target, size_t min_size)
{
	unsigned long addr;
	unsigned long start = mdi->text_addr;
	unsigned long end = mdi->text_addr + mdi->text_size;
	size_t consecutive_nops = 0;
	unsigned long cave_start = 0;

	/* ARM32 NOP instruction: MOV r0, r0 */
	static const uint32_t arm_nop = 0xe1a00000;

	pr_dbg3("scanning for code cave near %#lx (need %zu bytes)\n",
		target, min_size);

	/*
	 * Scan from end of text segment backwards
	 */
	for (addr = end - 4; addr >= start && addr > end - PAGE_SIZE; addr -= 4) {
		uint32_t insn = *(uint32_t *)addr;

		if (insn == arm_nop || insn == 0) {
			if (consecutive_nops == 0)
				cave_start = addr;
			consecutive_nops += 4;

			if (consecutive_nops >= min_size) {
				unsigned long cave_addr = cave_start - min_size + 4;

				/* Check if within ±32MB range for BL instruction */
				long offset = ((long)cave_addr - (long)target - 8) >> 2;
				if (offset >= -0x800000 && offset <= 0x7fffff) {
					pr_dbg2("found code cave at %#lx (size: %zu)\n",
						cave_addr, consecutive_nops);
					return cave_addr;
				}
			}
		} else {
			consecutive_nops = 0;
		}
	}

	pr_dbg3("no suitable code cave found\n");
	return 0;
}


static int patch_code(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym)
{
	/*
	 * Replace function prologue with:
	 *   PUSH {fp, lr}   @ Save frame pointer and link register
	 *   BL trampoline   @ Call trampoline
	 */
	uint32_t push_insn = 0xe92d4800;  /* PUSH {fp, lr} */
	uint32_t bl_insn;
	unsigned long offset;
	void *insn = (void *)sym->addr + mdi->map->start;

	offset = get_target_offset(mdi, (unsigned long)insn + 4);
	if (offset == 0)
		return INSTRUMENT_FAILED;

	/* Create BL instruction with offset */
	bl_insn = 0xeb000000 | offset;

	/* Write the patch */
	memcpy(insn, &push_insn, sizeof(push_insn));
	memcpy(insn + 4, &bl_insn, sizeof(bl_insn));

	/* Flush instruction cache */
	__builtin___clear_cache(insn, insn + CODE_SIZE);

	return INSTRUMENT_SUCCESS;
}

static int patch_patchable_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym)
{
	void *insn = (void *)sym->addr + mdi->map->start;

	/* Only support calls to 2 NOPs at the beginning */
	if (memcmp(insn, arm_nop2, sizeof(arm_nop2))) {
		pr_dbg4("skip non-applicable functions: %s\n", sym->name);
		return INSTRUMENT_SKIPPED;
	}

	if (patch_code(mdi, sym) < 0)
		return INSTRUMENT_FAILED;

	pr_dbg3("update %p for '%s' function dynamically\n", insn, sym->name);

	return INSTRUMENT_SUCCESS;
}

static int patch_normal_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
			     struct mcount_disasm_engine *disasm)
{
	struct mcount_disasm_info info = {
		.sym = sym,
		.addr = sym->addr + mdi->map->start,
	};

	if (disasm_check_insns(disasm, mdi, &info) < 0)
		return INSTRUMENT_FAILED;

	/*
	 * Try inline 12-byte trampoline for large prologues.
	 * This is more efficient as it doesn't require saving/restoring
	 * original instructions to a separate location.
	 */
	if (info.orig_size >= ARM_INLINE_TRAMPOLINE_SIZE) {
		int ret = patch_inline_trampoline(mdi, &info);
		if (ret > 0)
			return INSTRUMENT_SUCCESS;
		/* Fall through to standard patching if inline trampoline failed */
	}

	save_orig_code(&info);

	if (patch_code(mdi, sym) < 0)
		return INSTRUMENT_FAILED;

	pr_dbg3("force patch normal func: %s (patch size: %d)\n", sym->name, info.orig_size);

	return INSTRUMENT_SUCCESS;
}

int mcount_patch_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
		      struct mcount_disasm_engine *disasm, unsigned min_size)
{
	int result = INSTRUMENT_SKIPPED;

	if (min_size < CODE_SIZE + 1)
		min_size = CODE_SIZE + 1;

	if (sym->size < min_size)
		return result;

	switch (mdi->type) {
	case DYNAMIC_PATCHABLE:
	case DYNAMIC_FENTRY_NOP:
		result = patch_patchable_func(mdi, sym);
		break;

	case DYNAMIC_NONE:
		result = patch_normal_func(mdi, sym, disasm);
		break;

	default:
		break;
	}
	return result;
}

int mcount_unpatch_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
			struct mcount_disasm_engine *disasm)
{
	/* Not supported yet for ARM32 */
	return -1;
}

static void revert_normal_func(struct mcount_dynamic_info *mdi, struct uftrace_symbol *sym,
			       struct mcount_disasm_engine *disasm)
{
	void *addr = (void *)(uintptr_t)sym->addr + mdi->map->start;
	void *saved_insn;

	saved_insn = mcount_find_code((uintptr_t)addr + CODE_SIZE);
	if (saved_insn == NULL)
		return;

	memcpy(addr, saved_insn, CODE_SIZE);
	__builtin___clear_cache(addr, addr + CODE_SIZE);
}

void mcount_arch_dynamic_recover(struct mcount_dynamic_info *mdi,
				 struct mcount_disasm_engine *disasm)
{
	struct dynamic_bad_symbol *badsym, *tmp;

	list_for_each_entry_safe(badsym, tmp, &mdi->bad_syms, list) {
		if (!badsym->reverted)
			revert_normal_func(mdi, badsym->sym, disasm);

		list_del(&badsym->list);
		free(badsym);
	}
}
