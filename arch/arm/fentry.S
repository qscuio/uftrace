/*
 * ARM32 __fentry__ implementation for uftrace
 *
 * Copyright (C) 2024, uftrace contributors
 * Released under the GPL v2.
 *
 * This implements __fentry__ for ARM32 architecture.
 * __fentry__ is called at function entry BEFORE the prologue,
 * when compiled with -fpatchable-function-entry.
 */

#include "utils/asm.h"

.syntax unified
.arm

/*
 * __fentry__ - Function entry tracing hook
 *
 * Called at the very beginning of a function, before the prologue.
 * The function was compiled with -fpatchable-function-entry=N
 * which reserves N bytes (typically NOPs) at the function start.
 *
 * On entry:
 *   lr = return address (points to instruction after the call)
 *
 * We need to:
 *   1. Save all caller-saved registers
 *   2. Call mcount_entry(parent_loc, child_ip, mcount_args)
 *   3. Restore registers and return
 */
GLOBAL(__fentry__)
	.fnstart
	/* Push lr and some padding for 8-byte alignment */
	push	{r0-r3, lr}

	/* child_ip = lr (address we were called from, i.e., function start) */
	mov	r1, lr

	/* parent_loc = sp + 16 (saved lr location) */
	add	r0, sp, #16

	/* mcount_args = sp (points to saved r0-r3) */
	mov	r2, sp

	/* Align stack to 8-byte boundary */
	mov	r3, sp
	bic	sp, sp, #7
	push	{r3}

	/* Call mcount_entry */
	bl	mcount_entry

	/* Restore stack */
	pop	{r3}
	mov	sp, r3

	/* Restore registers and return */
	pop	{r0-r3, pc}
	.fnend
END(__fentry__)


/*
 * Note: mcount_return is defined in mcount.S
 * Do not duplicate it here.
 */
