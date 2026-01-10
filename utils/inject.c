/*
 * Process injection utilities for uftrace
 *
 * Copyright (C) 2024, uftrace contributors
 *
 * Released under the GPL v2.
 *
 * This file implements library injection into running processes using
 * ptrace. The technique involves:
 * 1. Attaching to the target process with PTRACE_ATTACH
 * 2. Saving the current register state
 * 3. Finding the address of __libc_dlopen_mode in the target
 * 4. Allocating memory in the target for the library path
 * 5. Setting up registers to call __libc_dlopen_mode
 * 6. Executing the call
 * 7. Restoring the original register state
 * 8. Detaching from the process
 */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "inject"
#define PR_DOMAIN DBG_UFTRACE

#include "utils/inject.h"
#include "utils/utils.h"

/* RTLD_NOW is 0x2 */
#define DLOPEN_FLAG_NOW 0x2

/**
 * waitpid_retry - wait for process with EINTR retry
 * @pid: process ID to wait for
 * @status: pointer to store status
 * @options: wait options
 *
 * Return: pid on success, -1 on error (with errno set)
 */
static pid_t waitpid_retry(pid_t pid, int *status, int options)
{
	pid_t ret;
	
	do {
		ret = waitpid(pid, status, options);
	} while (ret < 0 && errno == EINTR);
	
	return ret;
}

int check_ptrace_scope(void)
{
	FILE *fp;
	int scope = 0;

	fp = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
	if (fp == NULL) {
		if (errno == ENOENT)
			return 0; /* Yama not enabled, ptrace allowed */
		return -1;
	}

	if (fscanf(fp, "%d", &scope) != 1)
		scope = -1;

	fclose(fp);
	return scope;
}

/**
 * find_libc_base - find the base address of libc in target process
 * @pid: target process ID
 * @libc_path: output buffer for libc path (should be PATH_MAX size)
 *
 * Return: base address of libc, or 0 on failure
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"
static unsigned long find_libc_base(pid_t pid, char *libc_path)
{
	FILE *fp;
	char path[PATH_MAX];
	char line[PATH_MAX + 128];
	unsigned long base = 0;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	fp = fopen(path, "r");
	if (fp == NULL)
		return 0;

	while (fgets(line, sizeof(line), fp)) {
		unsigned long start, end;
		char prot[5];
		char filepath[PATH_MAX];

		if (sscanf(line, "%lx-%lx %4s %*x %*x:%*x %*d %s",
			   &start, &end, prot, filepath) != 4)
			continue;

		/* Look for libc with execute permission */
		if (prot[2] != 'x')
			continue;

		/* Match libc.so.6 or libc-*.so */
		if (strstr(filepath, "libc.so") || strstr(filepath, "libc-")) {
			base = start;
			if (libc_path) {
				strncpy(libc_path, filepath, PATH_MAX - 1);
				libc_path[PATH_MAX - 1] = '\0';
			}
			break;
		}
	}

	fclose(fp);
	return base;
}
#pragma GCC diagnostic pop

/**
 * find_symbol_offset - find the offset of a symbol in a shared library
 * @libpath: path to the shared library
 * @symbol: symbol name to find
 *
 * Return: offset of the symbol, or 0 on failure
 */
static unsigned long find_symbol_offset(const char *libpath, const char *symbol)
{
	void *handle;
	void *sym_addr;
	Dl_info info;
	unsigned long offset = 0;

	handle = dlopen(libpath, RTLD_NOW);
	if (handle == NULL) {
		pr_dbg("failed to open %s: %s\n", libpath, dlerror());
		return 0;
	}

	sym_addr = dlsym(handle, symbol);
	if (sym_addr == NULL) {
		pr_dbg("failed to find %s in %s\n", symbol, libpath);
		dlclose(handle);
		return 0;
	}

	if (dladdr(sym_addr, &info) == 0) {
		pr_dbg("dladdr failed for %s\n", symbol);
		dlclose(handle);
		return 0;
	}

	/* Calculate offset from base */
	offset = (unsigned long)sym_addr - (unsigned long)info.dli_fbase;

	dlclose(handle);
	return offset;
}

unsigned long find_libc_dlopen(pid_t pid)
{
	char libc_path[PATH_MAX] = {0};
	unsigned long libc_base;
	unsigned long dlopen_offset;

	libc_base = find_libc_base(pid, libc_path);
	if (libc_base == 0) {
		pr_dbg("failed to find libc base in process %d\n", pid);
		return 0;
	}
	pr_dbg("libc base in target: %lx (%s)\n", libc_base, libc_path);

	/* Find __libc_dlopen_mode offset in our own libc */
	dlopen_offset = find_symbol_offset(libc_path, "__libc_dlopen_mode");
	if (dlopen_offset == 0) {
		/* Fall back to dlopen if __libc_dlopen_mode not found */
		dlopen_offset = find_symbol_offset(libc_path, "dlopen");
		if (dlopen_offset == 0) {
			pr_dbg("failed to find dlopen in %s\n", libc_path);
			return 0;
		}
	}
	pr_dbg("dlopen offset: %lx\n", dlopen_offset);

	return libc_base + dlopen_offset;
}

#if defined(__x86_64__)

/**
 * inject_library_x86_64 - x86_64 specific library injection
 */
static int inject_library_x86_64(pid_t pid, const char *libpath,
				 unsigned long dlopen_addr)
{
	struct user_regs_struct orig_regs, regs;
	long orig_data;
	unsigned long stack_addr;
	unsigned long str_addr;
	size_t libpath_len;
	int status;
	int i;

	/* Get current registers */
	if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) < 0) {
		pr_err("PTRACE_GETREGS failed");
		return -1;
	}

	memcpy(&regs, &orig_regs, sizeof(regs));

	/* Use space below current stack for the library path string */
	libpath_len = strlen(libpath) + 1;
	stack_addr = (orig_regs.rsp - 256) & ~0xf; /* Align to 16 bytes */
	str_addr = stack_addr - ((libpath_len + 15) & ~0xf);

	pr_dbg("stack_addr=%lx str_addr=%lx\n", stack_addr, str_addr);

	/* Write the library path to the target's stack */
	for (i = 0; i < (int)((libpath_len + sizeof(long) - 1) / sizeof(long)); i++) {
		long word = 0;
		size_t to_copy = sizeof(long);
		if (i * sizeof(long) + to_copy > libpath_len)
			to_copy = libpath_len - i * sizeof(long);
		memcpy(&word, libpath + i * sizeof(long), to_copy);

		if (ptrace(PTRACE_POKEDATA, pid, str_addr + i * sizeof(long), word) < 0) {
			pr_err("PTRACE_POKEDATA failed");
			return -1;
		}
	}

	/* Save the original instruction at RIP */
	orig_data = ptrace(PTRACE_PEEKTEXT, pid, orig_regs.rip, NULL);
	if (errno != 0 && orig_data == -1) {
		pr_err("PTRACE_PEEKTEXT failed");
		return -1;
	}

	/*
	 * Write syscall instruction (0x050f) at current RIP to trigger a trap.
	 * We'll use mmap syscall to allocate executable memory, but for simplicity
	 * we'll just call dlopen directly by setting up registers and using a
	 * call instruction.
	 *
	 * For simplicity, we inject "int3" (0xcc) to cause a trap after
	 * the call completes.
	 */

	/* Set up registers for the call:
	 * RDI = first arg (path to library)
	 * RSI = second arg (RTLD_NOW = 2)
	 * RIP = address of __libc_dlopen_mode
	 * RSP = aligned stack with return address
	 */
	regs.rdi = str_addr;
	regs.rsi = DLOPEN_FLAG_NOW;
	regs.rip = dlopen_addr;

	/* Push a return address that will cause a trap (we'll use orig RIP) */
	regs.rsp = stack_addr - 8;
	if (ptrace(PTRACE_POKEDATA, pid, regs.rsp, orig_regs.rip) < 0) {
		pr_err("PTRACE_POKEDATA (return addr) failed");
		return -1;
	}

	/* Write int3 at the return address to trap when dlopen returns */
	if (ptrace(PTRACE_POKETEXT, pid, orig_regs.rip, (orig_data & ~0xff) | 0xcc) < 0) {
		pr_err("PTRACE_POKETEXT (int3) failed");
		return -1;
	}

	/* Set the new registers */
	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
		pr_err("PTRACE_SETREGS failed");
		return -1;
	}

	/* Resume the process and wait for it to hit the int3 */
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
		pr_err("PTRACE_CONT failed");
		return -1;
	}

	/* Wait for the process to stop (at int3) */
	if (waitpid_retry(pid, &status, 0) < 0) {
		pr_err("waitpid failed");
		return -1;
	}

	if (!WIFSTOPPED(status)) {
		pr_warn("process did not stop as expected (status=%x)\n", status);
		return -1;
	}

	/* Check RAX for dlopen return value */
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
		pr_err("PTRACE_GETREGS (after) failed");
		return -1;
	}

	if (regs.rax == 0) {
		pr_warn("dlopen failed in target process\n");
		/* Continue to restore state anyway */
	}
	else {
		pr_dbg("dlopen returned: %lx\n", regs.rax);
	}

	/* Restore the original instruction */
	if (ptrace(PTRACE_POKETEXT, pid, orig_regs.rip, orig_data) < 0) {
		pr_err("PTRACE_POKETEXT (restore) failed");
		return -1;
	}

	/* Restore the original registers */
	if (ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs) < 0) {
		pr_err("PTRACE_SETREGS (restore) failed");
		return -1;
	}

	return (regs.rax != 0) ? 0 : -1;
}

#elif defined(__aarch64__)

#include <elf.h>
#include <sys/uio.h>

/**
 * inject_library_aarch64 - aarch64 specific library injection
 *
 * AArch64 calling convention:
 *   - x0-x7: function arguments
 *   - x0: return value  
 *   - x30 (LR): link register (return address)
 *   - sp: stack pointer
 *   - pc: program counter
 */
static int inject_library_aarch64(pid_t pid, const char *libpath,
				  unsigned long dlopen_addr)
{
	struct user_regs_struct orig_regs, regs;
	struct iovec iov;
	unsigned long stack_addr;
	unsigned long str_addr;
	size_t libpath_len;
	int status;
	size_t i;
	unsigned long orig_word;  /* Full 8-byte word at PC */
	unsigned long brk_word;   /* Word with BRK instruction */
	/* BRK #0 instruction - causes SIGTRAP on AArch64 */
	unsigned int brk_insn = 0xd4200000;
	int inject_sig = 0;  /* Signal to inject on next continue */
	int stopsig;

	/* Get current registers using GETREGSET (aarch64 doesn't support GETREGS) */
	iov.iov_base = &orig_regs;
	iov.iov_len = sizeof(orig_regs);
	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
		pr_err("PTRACE_GETREGSET failed");
		return -1;
	}

	/*
	 * Check if we stopped inside a syscall.
	 * On aarch64, SVC #0 instruction is 0xd4000001.
	 * If the process is mid-syscall, we need to let it complete first
	 * before calling dlopen, otherwise the syscall state is corrupted.
	 */
	errno = 0;
	{
		unsigned long insn_word = ptrace(PTRACE_PEEKTEXT, pid, orig_regs.pc, NULL);
		unsigned int insn = insn_word & 0xffffffff;
		
		if (insn == 0xd4000001) {
			if (getenv("UFTRACE_ATTACH_COMPLETE_SYSCALL")) {
				pr_dbg("process stopped at syscall, completing it first\n");

				/* Use PTRACE_SYSCALL to step past the syscall entry */
				if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
					pr_err("PTRACE_SYSCALL (entry) failed");
					return -1;
				}
				if (waitpid_retry(pid, &status, 0) < 0 || !WIFSTOPPED(status)) {
					pr_err("waitpid (syscall entry) failed");
					return -1;
				}

				/* Step past syscall exit */
				if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) < 0) {
					pr_err("PTRACE_SYSCALL (exit) failed");
					return -1;
				}
				if (waitpid_retry(pid, &status, 0) < 0 || !WIFSTOPPED(status)) {
					pr_err("waitpid (syscall exit) failed");
					return -1;
				}

				/* Get the updated registers after syscall completion */
				iov.iov_base = &orig_regs;
				iov.iov_len = sizeof(orig_regs);
				if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
					pr_err("PTRACE_GETREGSET (after syscall) failed");
					return -1;
				}
				pr_dbg("syscall completed, new PC: 0x%lx\n", orig_regs.pc);
			}
			else {
				pr_dbg("process stopped at syscall entry, skipping completion\n");
			}
		}
	}

	memcpy(&regs, &orig_regs, sizeof(regs));

	/* Use space below current stack for the library path string */
	libpath_len = strlen(libpath) + 1;
	stack_addr = (orig_regs.sp - 256) & ~0xf; /* Align to 16 bytes */
	str_addr = stack_addr - ((libpath_len + 15) & ~0xf);

	pr_dbg("stack_addr=%lx str_addr=%lx\n", stack_addr, str_addr);

	/* Write the library path to the target's stack */
	for (i = 0; i < (libpath_len + sizeof(long) - 1) / sizeof(long); i++) {
		long word = 0;
		size_t to_copy = sizeof(long);
		if (i * sizeof(long) + to_copy > libpath_len)
			to_copy = libpath_len - i * sizeof(long);
		memcpy(&word, libpath + i * sizeof(long), to_copy);

		if (ptrace(PTRACE_POKEDATA, pid, str_addr + i * sizeof(long), word) < 0) {
			pr_err("PTRACE_POKEDATA failed");
			return -1;
		}
	}

	/* Save the original instruction word at PC (8 bytes on aarch64) */
	errno = 0;
	orig_word = ptrace(PTRACE_PEEKTEXT, pid, orig_regs.pc, NULL);
	if (errno != 0) {
		pr_err("PTRACE_PEEKTEXT failed");
		return -1;
	}
	pr_dbg("original word at PC: 0x%lx\n", orig_word);

	/*
	 * Set up registers for the call:
	 * x0 = first arg (path to library)
	 * x1 = second arg (RTLD_NOW = 2)
	 * x30 (LR) = return address (orig PC with BRK)
	 * pc = address of dlopen
	 * sp = new stack location (moved down to avoid corruption)
	 */
	regs.regs[0] = str_addr;
	regs.regs[1] = DLOPEN_FLAG_NOW;
	regs.regs[30] = orig_regs.pc;  /* LR = return to original PC */
	regs.pc = dlopen_addr;
	regs.sp = (orig_regs.sp - 512) & ~0xf;  /* Give dlopen plenty of stack space */

	/*
	 * Write BRK instruction at the return address to trap when dlopen returns.
	 * PTRACE_POKETEXT writes 8 bytes, but BRK is only 4 bytes.
	 * We need to preserve the upper 4 bytes of the original word.
	 */
	brk_word = (orig_word & 0xffffffff00000000UL) | brk_insn;
	pr_dbg("writing brk word: 0x%lx\n", brk_word);
	if (ptrace(PTRACE_POKETEXT, pid, orig_regs.pc, brk_word) < 0) {
		pr_err("PTRACE_POKETEXT (brk) failed");
		return -1;
	}

	/* Set the new registers */
	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);
	if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
		pr_err("PTRACE_SETREGSET failed");
		return -1;
	}

	/*
	 * Resume the process and wait for it to hit the BRK.
	 * The process may stop due to other signals (e.g., SIGPROF from timers)
	 * before hitting our BRK. In that case, re-inject the signal and continue.
	 * We're waiting for SIGTRAP (signal 5) from the BRK instruction.
	 */
	for (;;) {
		/* Continue execution, optionally injecting a pending signal */
		if (ptrace(PTRACE_CONT, pid, NULL, (void *)(long)inject_sig) < 0) {
			pr_err("PTRACE_CONT failed");
			return -1;
		}
		inject_sig = 0;  /* Clear after injection */

		if (waitpid_retry(pid, &status, 0) < 0) {
			pr_err("waitpid failed");
			return -1;
		}

		if (!WIFSTOPPED(status)) {
			if (WIFEXITED(status)) {
				pr_warn("process exited during dlopen\n");
			} else {
				pr_warn("process did not stop (status=%x)\n", status);
			}
			return -1;
		}

		stopsig = WSTOPSIG(status);
		pr_dbg("process stopped with signal %d\n", stopsig);

		/* SIGTRAP means we hit our BRK instruction */
		if (stopsig == SIGTRAP)
			break;

		/*
		 * Suppress certain signals that would slow down injection:
		 * - SIGPROF (27): profiling timer, fires frequently
		 * - SIGVTALRM (26): virtual timer
		 * For other signals, queue for re-injection.
		 */
		if (stopsig == SIGPROF || stopsig == SIGVTALRM) {
			pr_dbg("suppressing signal %d during injection\n", stopsig);
			inject_sig = 0;  /* Don't re-inject */
		} else {
			inject_sig = stopsig;
			pr_dbg("will re-inject signal %d\n", stopsig);
		}
	}

	pr_dbg("hit BRK instruction\n");

	/* Check x0 for dlopen return value */
	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);
	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
		pr_err("PTRACE_GETREGSET (after) failed");
		return -1;
	}

	pr_dbg("after dlopen: PC=0x%lx x0=0x%lx\n", regs.pc, regs.regs[0]);

	if (regs.regs[0] == 0) {
		pr_warn("dlopen failed in target process\n");
		/* Continue to restore state anyway */
	}
	else {
		pr_dbg("dlopen returned: %lx\n", regs.regs[0]);
	}

	/* Restore the original instruction word */
	if (ptrace(PTRACE_POKETEXT, pid, orig_regs.pc, orig_word) < 0) {
		pr_err("PTRACE_POKETEXT (restore) failed");
		return -1;
	}

	/* Restore the original registers */
	iov.iov_base = &orig_regs;
	iov.iov_len = sizeof(orig_regs);
	if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
		pr_err("PTRACE_SETREGSET (restore) failed");
		return -1;
	}

	return (regs.regs[0] != 0) ? 0 : -1;
}

#else

static int inject_library_generic(pid_t pid, const char *libpath,
				  unsigned long dlopen_addr)
{
	pr_err("Library injection not supported on this architecture\n");
	return -1;
}

#endif

int inject_library(pid_t pid, const char *libpath)
{
	int scope;
	unsigned long dlopen_addr;
	int status;
	int ret = -1;

	/* Check if ptrace is allowed */
	scope = check_ptrace_scope();
	if (scope > 0) {
		pr_warn("ptrace is restricted (yama ptrace_scope=%d)\n", scope);
		pr_warn("try: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope\n");
		return -1;
	}

	/* Verify the target process exists */
	if (kill(pid, 0) < 0) {
		pr_err("cannot access process %d: %s\n", pid, strerror(errno));
		return -1;
	}

	pr_dbg("attaching to process %d\n", pid);

	/* Attach to the process */
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
		pr_err("PTRACE_ATTACH failed for pid %d: %s\n",
		       pid, strerror(errno));
		return -1;
	}

	/* Wait for the process to stop */
	if (waitpid_retry(pid, &status, 0) < 0) {
		pr_err("waitpid failed");
		goto detach;
	}

	if (!WIFSTOPPED(status)) {
		pr_warn("process did not stop after attach\n");
		goto detach;
	}

	pr_dbg("process %d stopped, finding dlopen\n", pid);

	/* Find the address of dlopen in the target */
	dlopen_addr = find_libc_dlopen(pid);
	if (dlopen_addr == 0) {
		pr_err("failed to find dlopen in process %d\n", pid);
		goto detach;
	}

	pr_dbg("dlopen address in target: %lx\n", dlopen_addr);
	pr_dbg("injecting library: %s\n", libpath);

	/* Perform the architecture-specific injection */
#if defined(__x86_64__)
	ret = inject_library_x86_64(pid, libpath, dlopen_addr);
#elif defined(__aarch64__)
	ret = inject_library_aarch64(pid, libpath, dlopen_addr);
#else
	ret = inject_library_generic(pid, libpath, dlopen_addr);
#endif

	if (ret == 0)
		pr_dbg("library injection successful\n");

detach:
	/* Detach from the process */
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
		pr_warn("PTRACE_DETACH failed: %s\n", strerror(errno));
	}

	return ret;
}

int detach_from_process(pid_t pid)
{
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
		pr_err("PTRACE_DETACH failed for pid %d: %s\n",
		       pid, strerror(errno));
		return -1;
	}
	return 0;
}
