/*
 * ARM32 XRay instrumentation support for uftrace
 *
 * Copyright (C) 2024, uftrace contributors
 * Released under the GPL v2.
 *
 * This implements XRay entry/exit handlers for ARM32 architecture.
 * XRay is LLVM's function call tracing instrumentation.
 */

#include "utils/asm.h"

.syntax unified
.arm

/*
 * XRay sled format for ARM32:
 * Entry sled: Multiple NOP instructions that can be patched
 * Exit sled: Multiple NOP instructions before return
 *
 * When enabled, the NOPs are replaced with:
 * Entry: BL __xray_entry
 * Exit:  BL __xray_exit (or B for tail calls)
 */

/*
 * __xray_entry - XRay function entry handler
 *
 * Called at function entry when XRay tracing is enabled.
 *
 * On entry:
 *   lr = return address (points after the sled)
 *   Stack is properly aligned (8-byte on ARM EABI)
 *
 * We need to:
 *   1. Save all argument registers (r0-r3)
 *   2. Call mcount_entry(parent_loc, child_ip, mcount_args)
 *   3. Restore registers and return
 */
GLOBAL(__xray_entry)
	.fnstart
	/* Save frame pointer, link register, and argument registers */
	push	{r0-r3, fp, lr}

	/* parent_loc = sp + 20 (where lr was saved) */
	add	r0, sp, #20

	/* child_ip = lr (return address, which is after the sled) */
	mov	r1, lr

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
	pop	{r0-r3, fp, pc}
	.fnend
END(__xray_entry)


/*
 * __xray_exit - XRay function exit handler
 *
 * Called at function exit when XRay tracing is enabled.
 *
 * On entry:
 *   r0-r1 = return values (potentially 64-bit)
 *   lr = address after the exit sled
 */
GLOBAL(__xray_exit)
	.fnstart
	/* Save return value registers and lr */
	push	{r0-r3, lr}

	/* Pointer to return values for mcount_exit */
	mov	r0, sp

	/* Align stack */
	mov	r1, sp
	bic	sp, sp, #7
	push	{r1}

	/* Call mcount_exit - returns original return address */
	bl	mcount_exit

	/* Save the return address */
	mov	r12, r0

	/* Restore stack */
	pop	{r1}
	mov	sp, r1

	/* Restore return value registers */
	pop	{r0-r3, lr}

	/* Return to original caller */
	bx	r12
	.fnend
END(__xray_exit)
