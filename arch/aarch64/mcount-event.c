/*
 * AArch64 event support for uftrace
 *
 * Copyright (C) 2024, uftrace contributors
 * Released under the GPL v2.
 *
 * This implements SDT (Static Defined Tracepoint) event support for AArch64.
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
 * AArch64 uses UDF instruction to trigger SIGILL for SDT probes.
 * UDF #0 is encoded as 0x00000000 (all zeros) which is guaranteed
 * to cause SIGILL on all AArch64 implementations.
 */
#define INVALID_OPCODE 0x00000000

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
	unsigned long addr = ctx->uc_mcontext.pc;
	struct mcount_event_info *mei;

	mei = mcount_lookup_event(addr);
	ASSERT(mei != NULL);

	/* Record the event */
	mcount_save_event(mei);

	/* Skip the UDF instruction (4 bytes on AArch64) and continue */
	ctx->uc_mcontext.pc = addr + 4;
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
	uint32_t udf_insn = INVALID_OPCODE;

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

	/* Replace NOP with UDF instruction to trigger SIGILL */
	memcpy((void *)mei->addr, &udf_insn, sizeof(udf_insn));

	/* Flush instruction cache */
	__builtin___clear_cache((void *)mei->addr, (void *)mei->addr + sizeof(udf_insn));

	/* Restore execute permission */
	if (mprotect(PAGE_ADDR(mei->addr), PAGE_SIZE, PROT_READ | PROT_EXEC))
		pr_err("cannot setup event due to protection");

	return 0;
}
