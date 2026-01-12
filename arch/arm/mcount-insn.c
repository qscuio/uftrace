/*
 * ARM32 instruction analysis for dynamic tracing
 *
 * Copyright (C) 2024, uftrace contributors
 * Released under the GPL v2.
 */

#include "libmcount/dynamic.h"
#include "libmcount/internal.h"
#include "mcount-arch.h"

#define INSN_SIZE 8

#ifdef HAVE_LIBCAPSTONE
#include <capstone/capstone.h>
#include <capstone/platform.h>

void mcount_disasm_init(struct mcount_disasm_engine *disasm)
{
	cs_mode mode = CS_MODE_ARM;

	/* Try to detect THUMB mode - most modern ARM32 code uses THUMB2 */
	if (cs_open(CS_ARCH_ARM, mode, &disasm->engine) != CS_ERR_OK) {
		pr_dbg("failed to init Capstone disasm engine for ARM\n");
		return;
	}

	if (cs_option(disasm->engine, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
		pr_dbg("failed to set detail option\n");
}

void mcount_disasm_finish(struct mcount_disasm_engine *disasm)
{
	cs_close(&disasm->engine);
}

/*
 * check_prologue - Check if instruction is safe to relocate
 *
 * Returns:
 *   0 if instruction is safe and can be copied as-is
 *  -1 if instruction cannot be safely relocated
 *   1 if instruction needs modification (PC-relative)
 */
static int check_prologue(struct mcount_disasm_engine *disasm, cs_insn *insn)
{
	int i;
	cs_arm *arm;
	cs_detail *detail;
	bool branch = false;
	int status = -1;

	if (insn->detail == NULL)
		return -1;

	detail = insn->detail;

	/* Check for control flow instructions */
	for (i = 0; i < detail->groups_count; i++) {
		switch (detail->groups[i]) {
		case CS_GRP_JUMP:
			branch = true;
			break;
		case CS_GRP_CALL:
		case CS_GRP_RET:
		case CS_GRP_IRET:
#if CS_API_MAJOR >= 4
		case CS_GRP_BRANCH_RELATIVE:
#endif
			return -1;
		default:
			break;
		}
	}

	arm = &insn->detail->arm;

	if (!arm->op_count)
		return 0;

	for (i = 0; i < arm->op_count; i++) {
		cs_arm_op *op = &arm->operands[i];

		switch (op->type) {
		case ARM_OP_REG:
			/* PC-relative instructions need special handling */
			if (op->reg == ARM_REG_PC)
				return 1;
			status = 0;
			break;
		case ARM_OP_IMM:
			if (branch)
				return -1;
			status = 0;
			break;
		case ARM_OP_MEM:
			/* PC-relative memory access needs relocation */
			if (op->mem.base == ARM_REG_PC)
				return 1;
			status = 0;
			break;
		default:
			break;
		}
	}
	return status;
}

/*
 * check_body - Validate remaining function body for safety
 */
static bool check_body(struct mcount_disasm_engine *disasm, cs_insn *insn,
		       struct mcount_dynamic_info *mdi, struct mcount_disasm_info *info)
{
	int i;
	cs_arm *arm;
	cs_detail *detail = insn->detail;
	unsigned long target;
	bool jump = false;

	if (detail == NULL)
		return false;

	for (i = 0; i < detail->groups_count; i++) {
		if (detail->groups[i] == CS_GRP_JUMP)
			jump = true;
	}

	if (!jump)
		return true;

	arm = &insn->detail->arm;
	for (i = 0; i < arm->op_count; i++) {
		cs_arm_op *op = &arm->operands[i];

		switch (op->type) {
		case ARM_OP_IMM:
			target = op->imm;

			/* Disallow jump to the prologue */
			if (info->addr < target && target < info->addr + info->copy_size)
				return false;

			/* Disallow jump to middle of other function */
			if (info->addr > target || target >= info->addr + info->sym->size) {
				return !mcount_add_badsym(mdi, insn->address, target);
			}
			break;
		case ARM_OP_MEM:
			/* Indirect jumps are not allowed */
			return false;
		case ARM_OP_REG:
			/* Allow register-based jumps (common in ARM) */
			return true;
		default:
			break;
		}
	}

	return true;
}

int disasm_check_insns(struct mcount_disasm_engine *disasm, struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	cs_insn *insn = NULL;
	uint32_t count, i;
	int ret = INSTRUMENT_FAILED;
	struct dynamic_bad_symbol *badsym;

	badsym = mcount_find_badsym(mdi, info->addr);
	if (badsym != NULL) {
		badsym->reverted = true;
		return INSTRUMENT_FAILED;
	}

	count = cs_disasm(disasm->engine, (void *)info->addr, info->sym->size, info->addr, 0,
			  &insn);

	for (i = 0; i < count; i++) {
		int state = check_prologue(disasm, &insn[i]);

		if (state < 0) {
			pr_dbg3("instruction not supported: %s\t %s\n", insn[i].mnemonic,
				insn[i].op_str);
			goto out;
		}

		if (state) {
			/* PC-relative instruction - cannot handle without modification */
			pr_dbg3("PC-relative instruction not supported: %s\t %s\n", 
				insn[i].mnemonic, insn[i].op_str);
			goto out;
		}
		else {
			memcpy(info->insns + info->copy_size, insn[i].bytes, insn[i].size);
			info->copy_size += insn[i].size;
		}
		info->orig_size += insn[i].size;

		if (info->orig_size >= INSN_SIZE) {
			ret = INSTRUMENT_SUCCESS;
			break;
		}
	}

	while (++i < count) {
		if (!check_body(disasm, &insn[i], mdi, info)) {
			ret = INSTRUMENT_FAILED;
			break;
		}
	}

out:
	if (count)
		cs_free(insn, count);

	return ret;
}

#else /* !HAVE_LIBCAPSTONE */

/*
 * Simple instruction check without Capstone
 * Only allows basic instructions that don't use PC
 */
static bool check_arm_insn(uint32_t insn)
{
	uint32_t cond = (insn >> 28) & 0xf;
	uint32_t op1 = (insn >> 25) & 0x7;

	/* Unconditional instructions - be conservative */
	if (cond == 0xf)
		return false;

	switch (op1) {
	case 0:
	case 1:
		/* Data processing - check for PC usage */
		if ((insn & 0xf) == 15 || ((insn >> 12) & 0xf) == 15 ||
		    ((insn >> 16) & 0xf) == 15)
			return false;
		return true;
	case 2:
	case 3:
		/* Load/Store - check for PC-relative */
		if (((insn >> 16) & 0xf) == 15)
			return false;
		return true;
	case 4:
		/* Load/Store multiple - allow if not involving PC */
		if (insn & (1 << 15))
			return false;
		return true;
	case 5:
		/* Branch - not allowed in prologue */
		return false;
	case 6:
	case 7:
		/* Coprocessor / undefined - be conservative */
		return false;
	}

	return false;
}

int disasm_check_insns(struct mcount_disasm_engine *disasm, struct mcount_dynamic_info *mdi,
		       struct mcount_disasm_info *info)
{
	uint32_t *insn = (void *)info->addr;

	/* Check first two instructions (8 bytes minimum) */
	if (!check_arm_insn(insn[0]) || !check_arm_insn(insn[1]))
		return INSTRUMENT_FAILED;

	memcpy(info->insns, insn, INSN_SIZE);
	info->orig_size = INSN_SIZE;
	info->copy_size = INSN_SIZE;

	return INSTRUMENT_SUCCESS;
}

#endif /* HAVE_LIBCAPSTONE */
