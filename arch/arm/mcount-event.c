/*
 * ARM32 event support for uftrace
 *
 * Copyright (C) 2024, uftrace contributors
 * Released under the GPL v2.
 *
 * This implements SDT (Static Defined Tracepoint) event support for ARM32.
 */

#include <signal.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <ucontext.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "event"
#define PR_DOMAIN DBG_EVENT

#include "libmcount/internal.h"

/*
 * ARM32 uses UDF instruction to trigger SIGILL for SDT probes.
 * UDF #0 is encoded as 0xe7f000f0 in ARM mode.
 * In THUMB mode, it's 0xde00.
 */
#define ARM_INVALID_OPCODE   0xe7f000f0  /* UDF #0 in ARM mode */
#define THUMB_INVALID_OPCODE 0xde00      /* UDF #0 in THUMB mode */

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define PAGE_ADDR(a) ((void *)((a) & ~(PAGE_SIZE - 1)))

/*
 * sdt_handler - Signal handler for SDT events
 *
 * When an SDT probe is hit, the UDF instruction causes SIGILL.
 * This handler records the event and advances past the instruction.
 */
static void sdt_handler(int sig, siginfo_t *info, void *arg)
{
	ucontext_t *ctx = arg;
	unsigned long addr = ctx->uc_mcontext.arm_pc;
	struct mcount_event_info *mei;
	int insn_size;

	mei = mcount_lookup_event(addr);
	ASSERT(mei != NULL);

	/* Record the event */
	mcount_save_event(mei);

	/*
	 * Determine instruction size based on mode (ARM vs THUMB).
	 * In THUMB mode, the CPSR T bit (bit 5) is set.
	 */
	if (ctx->uc_mcontext.arm_cpsr & (1 << 5)) {
		/* THUMB mode - 2 byte instruction */
		insn_size = 2;
	} else {
		/* ARM mode - 4 byte instruction */
		insn_size = 4;
	}

	/* Skip the UDF instruction and continue */
	ctx->uc_mcontext.arm_pc = addr + insn_size;
}

/*
 * mcount_arch_enable_event - Enable an SDT event probe
 *
 * @mei: Event information structure
 *
 * Replace the NOP instruction at the probe location with UDF
 * to trigger SIGILL when the probe is hit.
 *
 * Returns 0 on success, -1 on failure.
 */
int mcount_arch_enable_event(struct mcount_event_info *mei)
{
	static bool sdt_handler_set = false;
	bool is_thumb;
	
	if (!sdt_handler_set) {
		struct sigaction act = {
			.sa_flags = SA_SIGINFO,
			.sa_sigaction = sdt_handler,
		};

		sigemptyset(&act.sa_mask);
		sigaction(SIGILL, &act, NULL);

		sdt_handler_set = true;
	}

	/* Make the page writable */
	if (mprotect(PAGE_ADDR(mei->addr), PAGE_SIZE, PROT_READ | PROT_WRITE)) {
		pr_dbg("cannot enable event due to protection: %m\n");
		return -1;
	}

	/*
	 * Determine if the address is in THUMB mode.
	 * THUMB addresses have the LSB set.
	 */
	is_thumb = (mei->addr & 1) != 0;
	
	if (is_thumb) {
		/* THUMB mode - use 16-bit UDF instruction */
		uint16_t udf_insn = THUMB_INVALID_OPCODE;
		unsigned long actual_addr = mei->addr & ~1;  /* Clear THUMB bit */
		memcpy((void *)actual_addr, &udf_insn, sizeof(udf_insn));
		__builtin___clear_cache((void *)actual_addr, 
					(void *)actual_addr + sizeof(udf_insn));
	} else {
		/* ARM mode - use 32-bit UDF instruction */
		uint32_t udf_insn = ARM_INVALID_OPCODE;
		memcpy((void *)mei->addr, &udf_insn, sizeof(udf_insn));
		__builtin___clear_cache((void *)mei->addr, 
					(void *)mei->addr + sizeof(udf_insn));
	}

	/* Restore execute permission */
	if (mprotect(PAGE_ADDR(mei->addr), PAGE_SIZE, PROT_READ | PROT_EXEC))
		pr_err("cannot setup event due to protection");

	return 0;
}
