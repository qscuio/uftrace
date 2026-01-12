/*
 * AArch64 XRay instrumentation support for uftrace
 *
 * Copyright (C) 2024, uftrace contributors
 * Released under the GPL v2.
 *
 * This implements XRay entry/exit handlers for AArch64 architecture.
 * XRay is LLVM's function call tracing instrumentation that inserts
 * sleds (NOP sequences) at function entry/exit that can be patched
 * at runtime.
 */

#include "utils/asm.h"

/*
 * XRay sled format for AArch64:
 * Entry sled: 32 bytes (usually 8 NOP instructions)
 * Exit sled: 32 bytes (usually 8 NOP instructions)
 *
 * When enabled, the NOPs are replaced with:
 * Entry: BL __xray_entry
 * Exit:  BL __xray_exit
 */

/*
 * __xray_entry - XRay function entry handler
 *
 * Called at function entry when XRay tracing is enabled.
 * The sled at function entry is patched to call this function.
 *
 * On entry:
 *   x30 (lr) = return address (points after the sled)
 *   Stack is properly aligned
 *
 * We need to:
 *   1. Save all argument registers (x0-x7)
 *   2. Save FP registers for HFA arguments (q0-q7)
 *   3. Call mcount_entry(parent_loc, child_ip, mcount_args)
 *   4. Restore registers and return
 */
GLOBAL(__xray_entry)
	/* Save frame pointer and link register */
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp

	/* Save argument registers */
	stp	x0, x1, [sp, #-16]!
	stp	x2, x3, [sp, #-16]!
	stp	x4, x5, [sp, #-16]!
	stp	x6, x7, [sp, #-16]!

	/* Save FP argument registers */
	stp	q0, q1, [sp, #-32]!
	stp	q2, q3, [sp, #-32]!
	stp	q4, q5, [sp, #-32]!
	stp	q6, q7, [sp, #-32]!

	/* parent_loc = frame pointer + 8 (where lr was saved) */
	add	x0, x29, #8

	/* child_ip = lr (return address, which is after the sled) */
	mov	x1, x30

	/* mcount_args = sp (points to saved registers) */
	mov	x2, sp

	/* Call mcount_entry */
	bl	mcount_entry

	/* Restore FP argument registers */
	ldp	q6, q7, [sp], #32
	ldp	q4, q5, [sp], #32
	ldp	q2, q3, [sp], #32
	ldp	q0, q1, [sp], #32

	/* Restore argument registers */
	ldp	x6, x7, [sp], #16
	ldp	x4, x5, [sp], #16
	ldp	x2, x3, [sp], #16
	ldp	x0, x1, [sp], #16

	/* Restore frame pointer and link register */
	ldp	x29, x30, [sp], #16

	ret
END(__xray_entry)


/*
 * __xray_exit - XRay function exit handler
 *
 * Called at function exit when XRay tracing is enabled.
 * The sled at function exit is patched to jump here instead of returning.
 *
 * On entry:
 *   x0-x1 = return values (potentially 128-bit)
 *   q0-q3 = FP return values
 *   x30 (lr) = address after the exit sled
 */
GLOBAL(__xray_exit)
	/* Save return value registers */
	stp	x0, x1, [sp, #-16]!

	/* Save FP return value registers */
	stp	q0, q1, [sp, #-32]!
	stp	q2, q3, [sp, #-32]!

	/* Save lr */
	str	x30, [sp, #-16]!

	/* Pointer to return values for mcount_exit */
	add	x0, sp, #16

	/* Call mcount_exit - returns original return address */
	bl	mcount_exit

	/* Save the return address */
	mov	x16, x0

	/* Restore lr */
	ldr	x30, [sp], #16

	/* Restore FP return value registers */
	ldp	q2, q3, [sp], #32
	ldp	q0, q1, [sp], #32

	/* Restore return value registers */
	ldp	x0, x1, [sp], #16

	/* Return to original caller */
	br	x16
END(__xray_exit)
