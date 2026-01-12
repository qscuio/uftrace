/*
 * ARM32 dynamic tracing entry point for uftrace
 *
 * Copyright (C) 2024, uftrace contributors
 * Released under the GPL v2.
 *
 * This implements __dentry__ for ARM32 architecture.
 * It handles both ARM and THUMB mode code.
 */

#include "utils/asm.h"

.syntax unified
.arm

/*
 * __dentry__ - Dynamic tracing entry point
 *
 * This function is called when a dynamically patched function
 * is entered. The prologue of the original function has been
 * replaced with:
 *   PUSH {fp, lr}     @ or STP for stack setup
 *   BL __dentry__
 *
 * On entry:
 *   - fp (r11) and lr are already pushed to stack
 *   - lr contains the return address (child_ip + 4)
 *   - [sp, #4] contains the original lr (parent_ip)
 *
 * We need to:
 *   1. Save all caller-saved registers
 *   2. Call mcount_entry(parent_loc, child_ip, mcount_args)
 *   3. Find and execute the saved original instructions
 *   4. Return to continue function execution
 */
GLOBAL(__dentry__)
	.fnstart
	/* Save caller-saved registers and make room for mcount_args */
	push	{r0-r3}

	/* child_ip = lr - 4 (we were called with BL, so lr points after BL) */
	sub	r1, lr, #4

	/* parent_loc = sp + 16 (skip r0-r3, then fp at +16, lr at +20) */
	add	r0, sp, #20

	/* mcount_args = sp (points to saved r0-r3) */
	mov	r2, sp

	/* Align stack to 8-byte boundary (AAPCS requirement) */
	mov	r3, sp
	bic	sp, sp, #7

	/* Save the original sp on the aligned stack */
	push	{r3}

	/* Call mcount_entry */
	bl	mcount_entry

	/* Restore original sp */
	pop	{r3}
	mov	sp, r3

	/* Now find the saved code to execute */
	/* child_ip = return address on stack - 4 */
	ldr	r0, [sp, #16]	/* Get saved lr */
	sub	r0, r0, #4	/* Adjust to child_ip */
	add	r0, r0, #8	/* Skip the patched prologue (CODE_SIZE) */

	push	{r4}		/* Save r4 for use */
	bl	mcount_find_code
	mov	r4, r0		/* r4 = address of saved code */
	pop	{r0}		/* Restore saved r4 into r0 temporarily */

	/* If mcount_find_code returned NULL, just continue */
	cmp	r4, #0
	beq	.Lno_saved_code

	/* Replace return address with saved code address */
	/* The saved code will jump back to function body */
	str	r4, [sp, #16]

.Lno_saved_code:
	mov	r4, r0		/* Restore r4 */

	/* Restore caller-saved registers */
	pop	{r0-r3}

	/* Return - will go to saved code or original lr */
	pop	{fp, lr}
	bx	lr
	.fnend
END(__dentry__)


/*
 * dynamic_return - Return trampoline for dynamic tracing
 *
 * This is called when the traced function returns.
 * It records the return and restores the original return path.
 */
ENTRY(dynamic_return)
	.fnstart
	/* Save return value registers */
	push	{r0-r3}

	/* Set up argument for mcount_exit: pointer to return values */
	mov	r0, sp

	/* Align stack */
	mov	r1, sp
	bic	sp, sp, #7
	push	{r1}

	/* Call mcount_exit - returns original parent address */
	bl	mcount_exit

	/* Save the return address */
	mov	r12, r0

	/* Restore stack */
	pop	{r1}
	mov	sp, r1

	/* Restore return value registers */
	pop	{r0-r3}

	/* Jump to original return address */
	bx	r12
	.fnend
END(dynamic_return)
