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

#include "utils/hook.h"
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

/**
 * find_any_symbol_offset - find offset of ANY symbol (including LOCAL/static)
 * @filepath: path to the ELF file (binary or library)
 * @symbol: symbol name to find
 *
 * Uses nm to find both local and global symbols.
 * Return: offset of the symbol, or 0 on failure
 */
static unsigned long find_any_symbol_offset(const char *filepath, const char *symbol)
{
	FILE *fp;
	char cmd[PATH_MAX + 128];
	char line[256];
	unsigned long offset = 0;

	/* Use nm to find the symbol (includes local symbols) */
	snprintf(cmd, sizeof(cmd), "nm %s 2>/dev/null | grep -E ' [tTwW] %s$' | awk '{print $1}'",
		 filepath, symbol);

	fp = popen(cmd, "r");
	if (fp == NULL)
		return 0;

	if (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%lx", &offset) != 1)
			offset = 0;
	}
	pclose(fp);

	if (offset != 0)
		pr_dbg("found local symbol %s at offset %lx in %s\n", symbol, offset, filepath);

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

/**
 * find_libc_dlclose - find the address of dlclose in target process
 * @pid: target process ID
 *
 * Return: address of dlclose, or 0 on failure
 */
static unsigned long find_libc_dlclose(pid_t pid)
{
	char libc_path[PATH_MAX] = {0};
	unsigned long libc_base;
	unsigned long dlclose_offset;

	libc_base = find_libc_base(pid, libc_path);
	if (libc_base == 0) {
		pr_dbg("failed to find libc base in process %d\n", pid);
		return 0;
	}
	pr_dbg("libc base in target: %lx (%s)\n", libc_base, libc_path);

	/* Find __libc_dlclose offset in libc */
	dlclose_offset = find_symbol_offset(libc_path, "__libc_dlclose");
	if (dlclose_offset == 0) {
		/* Fall back to dlclose if __libc_dlclose not found */
		dlclose_offset = find_symbol_offset(libc_path, "dlclose");
		if (dlclose_offset == 0) {
			pr_dbg("failed to find dlclose in %s\n", libc_path);
			return 0;
		}
	}
	pr_dbg("dlclose offset: %lx\n", dlclose_offset);

	return libc_base + dlclose_offset;
}

/**
 * find_library_handle - find the load address of a library in target process
 * @pid: target process ID
 * @libpath: path to the library (can be basename or full path)
 *
 * Return: base address of the library, or 0 if not found
 */
static unsigned long find_library_handle(pid_t pid, const char *libpath)
{
	FILE *fp;
	char path[PATH_MAX];
	char line[PATH_MAX + 128];
	unsigned long base = 0;
	const char *libname = uftrace_basename(libpath);

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

		/* Match by basename */
		if (strstr(filepath, libname)) {
			base = start;
			break;
		}
	}

	fclose(fp);
	return base;
}

#if defined(__x86_64__)

/**
 * uninject_library_x86_64 - x86_64 specific library unloading
 */
static int uninject_library_x86_64(pid_t pid, unsigned long lib_handle,
				   unsigned long dlclose_addr)
{
	struct user_regs_struct orig_regs, regs;
	long orig_data;
	unsigned long stack_addr;
	int status;

	/* Get current registers */
	if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) < 0) {
		pr_err("PTRACE_GETREGS failed");
		return -1;
	}

	memcpy(&regs, &orig_regs, sizeof(regs));

	/* Use space below current stack */
	stack_addr = (orig_regs.rsp - 256) & ~0xf;

	pr_dbg("stack_addr=%lx lib_handle=%lx\n", stack_addr, lib_handle);

	/* Save the original instruction at RIP */
	errno = 0;
	orig_data = ptrace(PTRACE_PEEKTEXT, pid, orig_regs.rip, NULL);
	if (errno != 0 && orig_data == -1) {
		pr_err("PTRACE_PEEKTEXT failed");
		return -1;
	}

	/* Set up registers for dlclose call:
	 * RDI = first arg (library handle)
	 * RIP = address of dlclose
	 * RSP = aligned stack with return address
	 */
	regs.rdi = lib_handle;
	regs.rip = dlclose_addr;

	/* Push return address and set up stack */
	regs.rsp = stack_addr - 8;
	if (ptrace(PTRACE_POKEDATA, pid, regs.rsp, orig_regs.rip) < 0) {
		pr_err("PTRACE_POKEDATA (return addr) failed");
		return -1;
	}

	/* Write int3 at the return address to trap when dlclose returns */
	if (ptrace(PTRACE_POKETEXT, pid, orig_regs.rip, (orig_data & ~0xff) | 0xcc) < 0) {
		pr_err("PTRACE_POKETEXT (int3) failed");
		return -1;
	}

	/* Set the new registers */
	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
		pr_err("PTRACE_SETREGS failed");
		return -1;
	}

	/* Resume and wait for trap */
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
		pr_err("PTRACE_CONT failed");
		return -1;
	}

	if (waitpid_retry(pid, &status, 0) < 0) {
		pr_err("waitpid failed");
		return -1;
	}

	if (!WIFSTOPPED(status)) {
		pr_warn("process did not stop as expected (status=%x)\n", status);
		return -1;
	}

	/* Check return value */
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
		pr_err("PTRACE_GETREGS (after) failed");
		return -1;
	}

	pr_dbg("dlclose returned: %lx\n", regs.rax);

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

	return (regs.rax == 0) ? 0 : -1;
}

#elif defined(__aarch64__)

#include <elf.h>
#include <sys/uio.h>

/**
 * uninject_library_aarch64 - aarch64 specific library unloading
 */
static int uninject_library_aarch64(pid_t pid, unsigned long lib_handle,
				    unsigned long dlclose_addr)
{
	struct user_regs_struct orig_regs, regs;
	struct iovec iov;
	unsigned long orig_word;
	unsigned long brk_word;
	unsigned int brk_insn = 0xd4200000; /* BRK #0 */
	int status;
	int inject_sig = 0;
	int stopsig;

	/* Get current registers */
	iov.iov_base = &orig_regs;
	iov.iov_len = sizeof(orig_regs);
	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
		pr_err("PTRACE_GETREGSET failed");
		return -1;
	}

	memcpy(&regs, &orig_regs, sizeof(regs));

	/* Save original instruction at PC */
	errno = 0;
	orig_word = ptrace(PTRACE_PEEKTEXT, pid, orig_regs.pc, NULL);
	if (errno != 0) {
		pr_err("PTRACE_PEEKTEXT failed");
		return -1;
	}

	/* Set up registers for dlclose:
	 * x0 = library handle
	 * x30 (LR) = return address (orig PC with BRK)
	 * pc = dlclose address
	 */
	regs.regs[0] = lib_handle;
	regs.regs[30] = orig_regs.pc;
	regs.pc = dlclose_addr;
	regs.sp = (orig_regs.sp - 512) & ~0xf;

	/* Write BRK at return address */
	brk_word = (orig_word & 0xffffffff00000000UL) | brk_insn;
	if (ptrace(PTRACE_POKETEXT, pid, orig_regs.pc, brk_word) < 0) {
		pr_err("PTRACE_POKETEXT (brk) failed");
		return -1;
	}

	/* Set new registers */
	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);
	if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
		pr_err("PTRACE_SETREGSET failed");
		return -1;
	}

	/* Resume and wait for BRK */
	for (;;) {
		if (ptrace(PTRACE_CONT, pid, NULL, (void *)(long)inject_sig) < 0) {
			pr_err("PTRACE_CONT failed");
			return -1;
		}
		inject_sig = 0;

		if (waitpid_retry(pid, &status, 0) < 0) {
			pr_err("waitpid failed");
			return -1;
		}

		if (!WIFSTOPPED(status)) {
			pr_warn("process did not stop (status=%x)\n", status);
			return -1;
		}

		stopsig = WSTOPSIG(status);
		if (stopsig == SIGTRAP)
			break;

		if (stopsig == SIGPROF || stopsig == SIGVTALRM)
			inject_sig = 0;
		else
			inject_sig = stopsig;
	}

	/* Check return value */
	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);
	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
		pr_err("PTRACE_GETREGSET (after) failed");
		return -1;
	}

	pr_dbg("dlclose returned: %lx\n", regs.regs[0]);

	/* Restore original instruction */
	if (ptrace(PTRACE_POKETEXT, pid, orig_regs.pc, orig_word) < 0) {
		pr_err("PTRACE_POKETEXT (restore) failed");
		return -1;
	}

	/* Restore original registers */
	iov.iov_base = &orig_regs;
	iov.iov_len = sizeof(orig_regs);
	if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
		pr_err("PTRACE_SETREGSET (restore) failed");
		return -1;
	}

	return (regs.regs[0] == 0) ? 0 : -1;
}

#endif

int uninject_library(pid_t pid, const char *libpath)
{
	unsigned long dlopen_addr;
	unsigned long dlclose_addr;
	unsigned long lib_handle;
	int status;
	int ret = -1;
	char abs_path[PATH_MAX];

	/* Verify the target process exists */
	if (kill(pid, 0) < 0) {
		pr_err("cannot access process %d: %s\n", pid, strerror(errno));
		return -1;
	}

	/* Convert to absolute path */
	if (!realpath(libpath, abs_path)) {
		/* If realpath fails, try the original path */
		strncpy(abs_path, libpath, PATH_MAX - 1);
		abs_path[PATH_MAX - 1] = '\0';
	}

	/* Check if library is loaded in target process */
	if (find_library_handle(pid, libpath) == 0) {
		pr_err("library %s not found in process %d\n", libpath, pid);
		return -1;
	}

	pr_dbg("attaching to process %d for uninject\n", pid);

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

	/* Find dlopen address to get handle */
	dlopen_addr = find_libc_dlopen(pid);
	if (dlopen_addr == 0) {
		pr_err("failed to find dlopen in process %d\n", pid);
		goto detach;
	}

	/* Find dlclose address */
	dlclose_addr = find_libc_dlclose(pid);
	if (dlclose_addr == 0) {
		pr_err("failed to find dlclose in process %d\n", pid);
		goto detach;
	}
	pr_dbg("dlopen=%lx dlclose=%lx\n", dlopen_addr, dlclose_addr);

	/*
	 * To unload the library:
	 * 1. Call dlopen with RTLD_NOLOAD to get handle without increasing refcount
	 * 2. Call dlclose on that handle to decrease refcount and unload
	 *
	 * Note: RTLD_NOLOAD = 0x4 - returns NULL if library not loaded,
	 * or returns the handle without incrementing refcount.
	 */
#define DLOPEN_FLAG_NOLOAD 0x4

	/* First, call dlopen with RTLD_NOLOAD to get the handle */
#if defined(__x86_64__)
	lib_handle = 0;
	{
		struct user_regs_struct orig_regs, regs;
		long orig_data;
		unsigned long stack_addr;
		size_t abs_len = strlen(abs_path) + 1;
		int i;

		if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) < 0) {
			pr_err("PTRACE_GETREGS failed");
			goto detach;
		}

		memcpy(&regs, &orig_regs, sizeof(regs));
		stack_addr = (orig_regs.rsp - 256) & ~0xf;
		unsigned long str_addr = stack_addr - ((abs_len + 15) & ~0xf);

		/* Write library path */
		for (i = 0; i < (int)((abs_len + sizeof(long) - 1) / sizeof(long)); i++) {
			long word = 0;
			size_t to_copy = sizeof(long);
			if (i * sizeof(long) + to_copy > abs_len)
				to_copy = abs_len - i * sizeof(long);
			memcpy(&word, abs_path + i * sizeof(long), to_copy);
			if (ptrace(PTRACE_POKEDATA, pid, str_addr + i * sizeof(long), word) < 0) {
				pr_err("PTRACE_POKEDATA failed");
				goto restore_x86;
			}
		}

		errno = 0;
		orig_data = ptrace(PTRACE_PEEKTEXT, pid, orig_regs.rip, NULL);
		if (errno != 0 && orig_data == -1) {
			pr_err("PTRACE_PEEKTEXT failed");
			goto restore_x86;
		}

		/* Call dlopen(path, RTLD_NOLOAD | RTLD_NOW) */
		regs.rdi = str_addr;
		regs.rsi = DLOPEN_FLAG_NOLOAD | DLOPEN_FLAG_NOW;
		regs.rip = dlopen_addr;
		regs.rsp = stack_addr - 8;

		if (ptrace(PTRACE_POKEDATA, pid, regs.rsp, orig_regs.rip) < 0 ||
		    ptrace(PTRACE_POKETEXT, pid, orig_regs.rip, (orig_data & ~0xff) | 0xcc) < 0 ||
		    ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0 ||
		    ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
			pr_err("ptrace setup failed");
			goto restore_x86;
		}

		if (waitpid_retry(pid, &status, 0) < 0 || !WIFSTOPPED(status)) {
			pr_err("waitpid failed");
			goto restore_x86;
		}

		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
			pr_err("PTRACE_GETREGS failed");
			goto restore_x86;
		}

		lib_handle = regs.rax;
		pr_dbg("dlopen(NOLOAD) returned handle: %lx\n", lib_handle);

		/* Restore */
		ptrace(PTRACE_POKETEXT, pid, orig_regs.rip, orig_data);
		ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);

		if (lib_handle == 0) {
			pr_err("dlopen(NOLOAD) returned NULL - library not loaded?\n");
			goto detach;
		}

		/* Call dlclose twice - once for NOLOAD's implicit ref, once for the original load */
		ret = uninject_library_x86_64(pid, lib_handle, dlclose_addr);
		if (ret == 0) {
			pr_dbg("calling dlclose again to fully unload\n");
			ret = uninject_library_x86_64(pid, lib_handle, dlclose_addr);
		}
		goto detach;

restore_x86:
		ptrace(PTRACE_POKETEXT, pid, orig_regs.rip, orig_data);
		ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
		goto detach;
	}

#elif defined(__aarch64__)
	lib_handle = 0;
	{
		struct user_regs_struct orig_regs, regs;
		struct iovec iov;
		unsigned long orig_word, brk_word;
		unsigned int brk_insn = 0xd4200000;
		size_t abs_len = strlen(abs_path) + 1;
		unsigned long stack_addr, str_addr;
		size_t i;
		int inject_sig = 0, stopsig;

		iov.iov_base = &orig_regs;
		iov.iov_len = sizeof(orig_regs);
		if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
			pr_err("PTRACE_GETREGSET failed");
			goto detach;
		}

		memcpy(&regs, &orig_regs, sizeof(regs));
		stack_addr = (orig_regs.sp - 256) & ~0xf;
		str_addr = stack_addr - ((abs_len + 15) & ~0xf);

		/* Write library path */
		for (i = 0; i < (abs_len + sizeof(long) - 1) / sizeof(long); i++) {
			long word = 0;
			size_t to_copy = sizeof(long);
			if (i * sizeof(long) + to_copy > abs_len)
				to_copy = abs_len - i * sizeof(long);
			memcpy(&word, abs_path + i * sizeof(long), to_copy);
			if (ptrace(PTRACE_POKEDATA, pid, str_addr + i * sizeof(long), word) < 0) {
				pr_err("PTRACE_POKEDATA failed");
				goto restore_aarch64;
			}
		}

		errno = 0;
		orig_word = ptrace(PTRACE_PEEKTEXT, pid, orig_regs.pc, NULL);
		if (errno != 0) {
			pr_err("PTRACE_PEEKTEXT failed");
			goto restore_aarch64;
		}

		/* Call dlopen(path, RTLD_NOLOAD | RTLD_NOW) */
		regs.regs[0] = str_addr;
		regs.regs[1] = DLOPEN_FLAG_NOLOAD | DLOPEN_FLAG_NOW;
		regs.regs[30] = orig_regs.pc;
		regs.pc = dlopen_addr;
		regs.sp = (orig_regs.sp - 512) & ~0xf;

		brk_word = (orig_word & 0xffffffff00000000UL) | brk_insn;
		if (ptrace(PTRACE_POKETEXT, pid, orig_regs.pc, brk_word) < 0) {
			pr_err("PTRACE_POKETEXT failed");
			goto restore_aarch64;
		}

		iov.iov_base = &regs;
		iov.iov_len = sizeof(regs);
		if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
			pr_err("PTRACE_SETREGSET failed");
			goto restore_aarch64;
		}

		/* Resume and wait for BRK */
		for (;;) {
			if (ptrace(PTRACE_CONT, pid, NULL, (void *)(long)inject_sig) < 0) {
				pr_err("PTRACE_CONT failed");
				goto restore_aarch64;
			}
			inject_sig = 0;
			if (waitpid_retry(pid, &status, 0) < 0 || !WIFSTOPPED(status)) {
				pr_err("waitpid failed");
				goto restore_aarch64;
			}
			stopsig = WSTOPSIG(status);
			if (stopsig == SIGTRAP)
				break;
			if (stopsig != SIGPROF && stopsig != SIGVTALRM)
				inject_sig = stopsig;
		}

		iov.iov_base = &regs;
		iov.iov_len = sizeof(regs);
		if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
			pr_err("PTRACE_GETREGSET failed");
			goto restore_aarch64;
		}

		lib_handle = regs.regs[0];
		pr_dbg("dlopen(NOLOAD) returned handle: %lx\n", lib_handle);

		/* Restore */
		ptrace(PTRACE_POKETEXT, pid, orig_regs.pc, orig_word);
		iov.iov_base = &orig_regs;
		iov.iov_len = sizeof(orig_regs);
		ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);

		if (lib_handle == 0) {
			pr_err("dlopen(NOLOAD) returned NULL - library not loaded?\n");
			goto detach;
		}

		/* Call dlclose twice - once for NOLOAD's implicit ref, once for the original load */
		ret = uninject_library_aarch64(pid, lib_handle, dlclose_addr);
		if (ret == 0) {
			pr_dbg("calling dlclose again to fully unload\n");
			ret = uninject_library_aarch64(pid, lib_handle, dlclose_addr);
		}
		goto detach;

restore_aarch64:
		ptrace(PTRACE_POKETEXT, pid, orig_regs.pc, orig_word);
		iov.iov_base = &orig_regs;
		iov.iov_len = sizeof(orig_regs);
		ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
		goto detach;
	}
#else
	pr_err("Library uninjection not supported on this architecture\n");
	ret = -1;
#endif

	if (ret == 0)
		pr_dbg("library uninjection successful\n");

detach:
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
		pr_warn("PTRACE_DETACH failed: %s\n", strerror(errno));
	}

	return ret;
}

/*
 * Function patching for plugin hooks
 */

/**
 * find_symbol_in_process - Find symbol address in target process
 * @pid: target process ID
 * @symbol: symbol name to find
 *
 * Return: address of symbol, or 0 if not found
 */
unsigned long find_symbol_in_process(pid_t pid, const char *symbol)
{
	FILE *fp;
	char path[PATH_MAX];
	char line[PATH_MAX + 128];

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	fp = fopen(path, "r");
	if (fp == NULL)
		return 0;

	while (fgets(line, sizeof(line), fp)) {
		unsigned long start, end;
		char prot[5];
		char filepath[PATH_MAX];
		unsigned long offset;

		if (sscanf(line, "%lx-%lx %4s %*x %*x:%*x %*d %s",
			   &start, &end, prot, filepath) != 4)
			continue;

		/* Skip non-executable regions */
		if (prot[2] != 'x')
			continue;

		/* Try to find symbol in this library/executable */
		offset = find_symbol_offset(filepath, symbol);
		if (offset != 0) {
			fclose(fp);
			return start + offset;
		}
	}

	fclose(fp);
	return 0;
}

#if defined(__x86_64__)

/**
 * patch_function_x86_64 - Patch function prologue with jump
 * @pid: target process ID
 * @target: address of function to patch
 * @replacement: address to jump to
 * @saved_bytes: buffer to save original bytes (5 bytes minimum)
 *
 * Patches the first 5 bytes with: jmp rel32
 * Return: 0 on success, -1 on failure
 */
int patch_function_x86_64(pid_t pid, unsigned long target,
			  unsigned long replacement, unsigned char *saved_bytes)
{
	long word1, word2;
	unsigned char patch[8];
	int32_t rel_offset;

	/* Read original bytes */
	errno = 0;
	word1 = ptrace(PTRACE_PEEKTEXT, pid, target, NULL);
	if (errno != 0) {
		pr_err("PTRACE_PEEKTEXT failed at %lx\n", target);
		return -1;
	}

	/* Save original bytes if buffer provided */
	if (saved_bytes)
		memcpy(saved_bytes, &word1, 5);

	/* Build 5-byte jmp rel32 instruction */
	rel_offset = replacement - (target + 5);
	patch[0] = 0xe9; /* jmp rel32 */
	memcpy(&patch[1], &rel_offset, 4);
	/* Keep remaining bytes from original */
	memcpy(&patch[5], ((unsigned char *)&word1) + 5, 3);

	/* Write the patch */
	memcpy(&word1, patch, sizeof(word1));
	if (ptrace(PTRACE_POKETEXT, pid, target, word1) < 0) {
		pr_err("PTRACE_POKETEXT failed at %lx\n", target);
		return -1;
	}

	pr_dbg("patched %lx -> jmp %lx\n", target, replacement);
	return 0;
}

#elif defined(__aarch64__)

#include <elf.h>
#include <sys/uio.h>

/**
 * patch_function_aarch64 - Patch function with branch instruction
 * @pid: target process ID
 * @target: address of function to patch
 * @replacement: address to jump to
 * @saved_bytes: buffer to save original bytes (4 bytes minimum)
 *
 * Patches with: b <offset> (unconditional branch)
 * Return: 0 on success, -1 on failure
 */
int patch_function_aarch64(pid_t pid, unsigned long target,
			   unsigned long replacement, unsigned char *saved_bytes)
{
	unsigned long word;
	uint32_t branch_insn;
	int64_t offset;

	/* Read original instruction */
	errno = 0;
	word = ptrace(PTRACE_PEEKTEXT, pid, target, NULL);
	if (errno != 0) {
		pr_err("PTRACE_PEEKTEXT failed at %lx\n", target);
		return -1;
	}

	/* Save original instruction if buffer provided */
	if (saved_bytes)
		memcpy(saved_bytes, &word, 4);

	/* Build branch instruction: b <offset>
	 * Format: 000101 imm26 (each unit is 4 bytes)
	 */
	offset = (int64_t)(replacement - target) / 4;
	if (offset < -(1 << 25) || offset >= (1 << 25)) {
		pr_err("branch offset out of range: %ld\n", offset);
		return -1;
	}

	branch_insn = 0x14000000 | (offset & 0x3ffffff);

	/* Replace first instruction, keep second */
	word = (word & 0xffffffff00000000UL) | branch_insn;

	if (ptrace(PTRACE_POKETEXT, pid, target, word) < 0) {
		pr_err("PTRACE_POKETEXT failed at %lx\n", target);
		return -1;
	}

	pr_dbg("patched %lx -> b %lx\n", target, replacement);
	return 0;
}

#endif

/**
 * apply_hooks - Apply function hooks from plugin
 * @pid: target process
 * @lib_base: base address of injected library in target
 * @libpath: path to library on disk (for symbol lookup)
 *
 * Finds uftrace_hooks table in the library and patches all targets.
 * Return: number of hooks applied, or -1 on error
 */
int apply_hooks(pid_t pid, unsigned long lib_base, const char *libpath)
{
	unsigned long hooks_addr, count_addr;
	unsigned long hooks_offset, count_offset;
	int hooks_count;
	int applied = 0;
	int i;
	int status;

	/* Find hook table symbols in the library */
	hooks_offset = find_symbol_offset(libpath, UFTRACE_HOOKS_SYMBOL);
	count_offset = find_symbol_offset(libpath, UFTRACE_HOOKS_COUNT_SYMBOL);

	if (hooks_offset == 0 || count_offset == 0) {
		pr_dbg("no hook table found in library\n");
		return 0;
	}

	hooks_addr = lib_base + hooks_offset;
	count_addr = lib_base + count_offset;

	pr_dbg("hooks table at %lx, count at %lx\n", hooks_addr, count_addr);

	/* Attach to process for ptrace operations */
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
		pr_err("PTRACE_ATTACH failed for hooks: %s\n", strerror(errno));
		return -1;
	}

	if (waitpid_retry(pid, &status, 0) < 0 || !WIFSTOPPED(status)) {
		pr_err("waitpid failed for hooks\n");
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		return -1;
	}

	/* Read hook count from target */
	errno = 0;
	hooks_count = (int)ptrace(PTRACE_PEEKDATA, pid, count_addr, NULL);
	if (errno != 0) {
		pr_err("failed to read hooks count\n");
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		return -1;
	}

	pr_dbg("found %d hooks\n", hooks_count);

	/* Process each hook entry */
	for (i = 0; i < hooks_count; i++) {
		unsigned long entry_addr = hooks_addr + i * sizeof(struct uftrace_hook);
		unsigned long target_name_ptr, replacement_ptr;
		char target_name[256];
		unsigned long target_addr;
		int j;

		/* Read hook entry from target process */
		errno = 0;
		target_name_ptr = ptrace(PTRACE_PEEKDATA, pid, entry_addr, NULL);
		if (errno != 0) {
			pr_warn("failed to read hook entry %d\n", i);
			continue;
		}

		/* Read replacement pointer */
		errno = 0;
		replacement_ptr = ptrace(PTRACE_PEEKDATA, pid,
					 entry_addr + sizeof(void *), NULL);
		if (errno != 0) {
			pr_warn("failed to read replacement for hook %d\n", i);
			continue;
		}

		/* Read target function name */
		memset(target_name, 0, sizeof(target_name));
		for (j = 0; j < (int)sizeof(target_name) - 8; j += 8) {
			long word;
			errno = 0;
			word = ptrace(PTRACE_PEEKDATA, pid, target_name_ptr + j, NULL);
			if (errno != 0)
				break;
			memcpy(target_name + j, &word, 8);
			if (memchr(&word, 0, 8))
				break;
		}

		if (target_name[0] == '\0') {
			pr_warn("empty target name for hook %d\n", i);
			continue;
		}

		pr_dbg("hook %d: %s -> %lx\n", i, target_name, replacement_ptr);

		/* Find target function address */
		target_addr = find_symbol_in_process(pid, target_name);
		if (target_addr == 0) {
			pr_warn("target function not found: %s\n", target_name);
			continue;
		}

		/* Apply the patch */
#if defined(__x86_64__)
		if (patch_function_x86_64(pid, target_addr, replacement_ptr, NULL) == 0)
			applied++;
#elif defined(__aarch64__)
		if (patch_function_aarch64(pid, target_addr, replacement_ptr, NULL) == 0)
			applied++;
#endif
	}

	/* Detach from process */
	ptrace(PTRACE_DETACH, pid, NULL, NULL);

	return applied;
}

/**
 * enable_features - Call feature init callbacks
 * @pid: target process
 * @lib_base: base of injected library
 * @libpath: path to library on disk
 *
 * Features are initialized by their init() callback which runs
 * inside the target process. We let the library's constructor
 * handle this since it already runs in the target context.
 *
 * Return: 0 (features are self-initializing via constructor)
 */
int enable_features(pid_t pid, unsigned long lib_base, const char *libpath)
{
	unsigned long features_offset, count_offset;

	features_offset = find_symbol_offset(libpath, UFTRACE_FEATURES_SYMBOL);
	count_offset = find_symbol_offset(libpath, UFTRACE_FEATURES_COUNT_SYMBOL);

	if (features_offset != 0 && count_offset != 0) {
		pr_dbg("feature table found - features init via library constructor\n");
	}

	return 0;
}

/*
 * Far Hook Solutions - for when direct branch is out of range
 */

/**
 * find_got_entry - Find GOT entry for a PLT function in target process
 * @pid: target process ID
 * @func_name: function name (e.g., "puts")
 * @got_addr: output - address of GOT entry
 * @plt_addr: output - address of PLT entry (optional, can be NULL)
 *
 * Parses the target's ELF to find the GOT entry for a given function.
 * Return: 0 on success, -1 on failure
 */
static int find_got_entry(pid_t pid, const char *func_name,
			  unsigned long *got_addr, unsigned long *plt_addr)
{
	FILE *fp;
	char path[PATH_MAX];
	char line[PATH_MAX + 128];
	char exe_path[PATH_MAX];
	unsigned long exe_base = 0;

	/* Find the main executable's base address */
	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	fp = fopen(path, "r");
	if (fp == NULL)
		return -1;

	while (fgets(line, sizeof(line), fp)) {
		unsigned long start;
		char prot[5];
		char filepath[PATH_MAX];

		if (sscanf(line, "%lx-%*x %4s %*x %*x:%*x %*d %s",
			   &start, prot, filepath) != 3)
			continue;

		/* Find the first executable mapping (main executable) */
		if (prot[2] == 'x' && strstr(filepath, "/") &&
		    !strstr(filepath, ".so")) {
			exe_base = start;
			strncpy(exe_path, filepath, sizeof(exe_path) - 1);
			exe_path[sizeof(exe_path) - 1] = '\0';
			break;
		}
	}
	fclose(fp);

	if (exe_base == 0)
		return -1;

	/* Parse ELF to find GOT entry for the function */
	/* For now, scan the relocation entries directly using readelf info */
	/* This is a simplified approach - in production, parse .rela.plt section */

	/* Read the executable and look for the symbol in relocations
	 * Match both versioned (func@GLIBC) and unversioned (func) symbols
	 */
	snprintf(path, sizeof(path),
		 "readelf -r %s 2>/dev/null | grep -E ' %s(@|$| )' | awk '{print $1}'",
		 exe_path, func_name);

	fp = popen(path, "r");
	if (fp == NULL)
		return -1;

	if (fgets(line, sizeof(line), fp)) {
		unsigned long offset;
		if (sscanf(line, "%lx", &offset) == 1) {
			*got_addr = exe_base + offset;
			if (plt_addr)
				*plt_addr = 0; /* PLT addr needs separate lookup */
			pclose(fp);
			pr_dbg("found GOT entry for %s at %lx\n", func_name, *got_addr);
			return 0;
		}
	}
	pclose(fp);

	return -1;
}

/**
 * patch_got_entry - Patch GOT entry to point to hook function
 * @pid: target process ID
 * @got_addr: address of GOT entry to patch
 * @new_func: address of replacement function
 * @old_func: output - original function address (for restoration)
 *
 * This is the most reliable hook method - simply changes the pointer
 * in the GOT so all calls through PLT go to the hook function.
 *
 * Return: 0 on success, -1 on failure
 */
int patch_got_entry(pid_t pid, unsigned long got_addr,
		    unsigned long new_func, unsigned long *old_func)
{
	long orig_val;

	/* Read original GOT entry */
	errno = 0;
	orig_val = ptrace(PTRACE_PEEKDATA, pid, got_addr, NULL);
	if (errno != 0) {
		pr_err("failed to read GOT at %lx\n", got_addr);
		return -1;
	}

	if (old_func)
		*old_func = (unsigned long)orig_val;

	/* Write new function address to GOT */
	if (ptrace(PTRACE_POKEDATA, pid, got_addr, new_func) < 0) {
		pr_err("failed to write GOT at %lx\n", got_addr);
		return -1;
	}

	pr_dbg("patched GOT %lx: %lx -> %lx\n", got_addr, (unsigned long)orig_val, new_func);
	return 0;
}

/**
 * hook_via_got - Hook a function by patching its GOT entry
 * @pid: target process ID
 * @func_name: name of function to hook
 * @replacement: address of hook function
 * @original: where to store original function address
 *
 * Return: 0 on success, -1 on failure
 */
int hook_via_got(pid_t pid, const char *func_name,
		 unsigned long replacement, unsigned long *original)
{
	unsigned long got_addr;
	int ret;

	ret = find_got_entry(pid, func_name, &got_addr, NULL);
	if (ret < 0) {
		pr_warn("could not find GOT entry for %s\n", func_name);
		return -1;
	}

	return patch_got_entry(pid, got_addr, replacement, original);
}

#if defined(__aarch64__)

/**
 * patch_function_far_aarch64 - Patch function for far jumps (>128MB)
 * @pid: target process ID
 * @target: address of function to patch
 * @far_addr: address of distant hook function
 * @saved_bytes: buffer to save original 16 bytes (optional)
 *
 * Writes a 16-byte inline trampoline at the function prologue:
 *   ldr x16, #8       ; load address from 8 bytes ahead
 *   br x16            ; branch to that address
 *   .quad <far_addr>  ; 8-byte target address
 *
 * This works for any distance as it uses an absolute address.
 * Return: 0 on success, -1 on failure
 */
int patch_function_far_aarch64(pid_t pid, unsigned long target,
			       unsigned long far_addr, unsigned char *saved_bytes)
{
	unsigned long word1, word2;
	unsigned long trampoline[2];

	/* Read original 16 bytes */
	errno = 0;
	word1 = ptrace(PTRACE_PEEKTEXT, pid, target, NULL);
	if (errno != 0) {
		pr_err("PTRACE_PEEKTEXT failed at %lx\n", target);
		return -1;
	}
	errno = 0;
	word2 = ptrace(PTRACE_PEEKTEXT, pid, target + 8, NULL);
	if (errno != 0) {
		pr_err("PTRACE_PEEKTEXT failed at %lx\n", target + 8);
		return -1;
	}

	/* Save original bytes if buffer provided */
	if (saved_bytes) {
		memcpy(saved_bytes, &word1, 8);
		memcpy(saved_bytes + 8, &word2, 8);
	}

	/* Build inline trampoline:
	 * ldr x16, #8  = 0x58000050 (load from PC+8 into x16)
	 * br x16       = 0xd61f0200 (branch to x16)
	 */
	trampoline[0] = (0xd61f0200UL << 32) | 0x58000050UL;  /* ldr x16, #8 ; br x16 */
	trampoline[1] = far_addr;                             /* target address */

	/* Write the trampoline */
	if (ptrace(PTRACE_POKETEXT, pid, target, trampoline[0]) < 0) {
		pr_err("PTRACE_POKETEXT failed at %lx\n", target);
		return -1;
	}
	if (ptrace(PTRACE_POKETEXT, pid, target + 8, trampoline[1]) < 0) {
		pr_err("PTRACE_POKETEXT failed at %lx\n", target + 8);
		return -1;
	}

	pr_dbg("patched %lx with inline trampoline -> %lx\n", target, far_addr);
	return 0;
}

/**
 * create_trampoline_aarch64 - Create trampoline for far jumps (legacy API)
 */
int create_trampoline_aarch64(pid_t pid, unsigned long target_near,
			      unsigned long far_addr, unsigned long *trampoline_addr)
{
	/* Use inline trampoline instead */
	pr_dbg("use patch_function_far_aarch64 for far jumps\n");
	return -1;
}


#elif defined(__x86_64__)

/**
 * create_trampoline_x86_64 - Create trampoline for far jumps (x86_64)
 * @pid: target process ID  
 * @target_near: address near the function to hook
 * @far_addr: address of the distant hook function
 * @trampoline_addr: output - address of allocated trampoline
 *
 * Uses absolute indirect jump: jmp *(%rip) followed by 8-byte address
 *
 * Return: 0 on success, -1 on failure
 */
int create_trampoline_x86_64(pid_t pid, unsigned long target_near,
			     unsigned long far_addr, unsigned long *trampoline_addr)
{
	pr_dbg("trampoline not yet implemented for x86_64, use GOT hooking\n");
	return -1;
}

#endif

/**
 * apply_hooks_advanced - Apply hooks using best available method
 * @pid: target process
 * @lib_base: base address of injected library
 * @libpath: path to library on disk
 * @sym_path: optional symbol file for stripped targets
 *
 * Tries multiple hooking methods in order of preference:
 * 1. GOT patching (most reliable, no range limits)
 * 2. Direct patching using symbol file (for local functions)
 *
 * Return: number of hooks applied, or -1 on error
 */
int apply_hooks_advanced(pid_t pid, unsigned long lib_base,
			 const char *libpath, const char *sym_path)
{
	unsigned long hooks_addr, count_addr;
	unsigned long hooks_offset, count_offset;
	unsigned long exe_base = 0;
	int hooks_count;
	int applied = 0;
	int i;
	int status;
	FILE *fp;
	char maps_path[PATH_MAX];
	char line[PATH_MAX + 128];

	/* Find hook table symbols in the library */
	hooks_offset = find_symbol_offset(libpath, UFTRACE_HOOKS_SYMBOL);
	count_offset = find_symbol_offset(libpath, UFTRACE_HOOKS_COUNT_SYMBOL);

	if (hooks_offset == 0 || count_offset == 0) {
		pr_dbg("no hook table found in library\n");
		return 0;
	}

	hooks_addr = lib_base + hooks_offset;
	count_addr = lib_base + count_offset;

	pr_dbg("hooks table at %lx, count at %lx\n", hooks_addr, count_addr);

	/* Find executable base address for direct patching */
	if (sym_path) {
		snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
		fp = fopen(maps_path, "r");
		if (fp) {
			while (fgets(line, sizeof(line), fp)) {
				unsigned long start;
				char prot[5];
				char filepath[PATH_MAX];

				if (sscanf(line, "%lx-%*x %4s %*x %*x:%*x %*d %s",
					   &start, prot, filepath) != 3)
					continue;

				if (prot[2] == 'x' && strstr(filepath, "/") &&
				    !strstr(filepath, ".so")) {
					exe_base = start;
					pr_dbg("exe base for direct patching: %lx\n", exe_base);
					break;
				}
			}
			fclose(fp);
		}
	}

	/* Attach to process for ptrace operations */
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
		pr_err("PTRACE_ATTACH failed: %s\n", strerror(errno));
		return -1;
	}

	if (waitpid_retry(pid, &status, 0) < 0 || !WIFSTOPPED(status)) {
		pr_err("waitpid failed\n");
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		return -1;
	}

	/* Read hook count */
	errno = 0;
	hooks_count = (int)ptrace(PTRACE_PEEKDATA, pid, count_addr, NULL);
	if (errno != 0) {
		pr_err("failed to read hooks count\n");
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		return -1;
	}

	pr_dbg("processing %d hooks with advanced methods\n", hooks_count);

	for (i = 0; i < hooks_count; i++) {
		unsigned long entry_addr = hooks_addr + i * sizeof(struct uftrace_hook);
		unsigned long target_name_ptr, replacement_ptr;
		char target_name[256];
		unsigned long got_addr;
		int j;

		/* Read hook entry */
		errno = 0;
		target_name_ptr = ptrace(PTRACE_PEEKDATA, pid, entry_addr, NULL);
		if (errno != 0)
			continue;

		errno = 0;
		replacement_ptr = ptrace(PTRACE_PEEKDATA, pid,
					 entry_addr + sizeof(void *), NULL);
		if (errno != 0)
			continue;

		/* Read target function name */
		memset(target_name, 0, sizeof(target_name));
		for (j = 0; j < (int)sizeof(target_name) - 8; j += 8) {
			long word;
			errno = 0;
			word = ptrace(PTRACE_PEEKDATA, pid, target_name_ptr + j, NULL);
			if (errno != 0)
				break;
			memcpy(target_name + j, &word, 8);
			if (memchr(&word, 0, 8))
				break;
		}

		if (target_name[0] == '\0')
			continue;

		pr_dbg("hook %d: %s -> %lx\n", i, target_name, replacement_ptr);

		/* Try GOT patching first (most reliable) */
		if (find_got_entry(pid, target_name, &got_addr, NULL) == 0) {
			if (patch_got_entry(pid, got_addr, replacement_ptr, NULL) == 0) {
				applied++;
				pr_out("hooked %s via GOT at %lx\n", target_name, got_addr);
				continue;
			}
		}

		/* Fall back to direct patching using symbol file */
		if (sym_path && exe_base != 0) {
			unsigned long sym_offset = find_any_symbol_offset(sym_path, target_name);
			if (sym_offset != 0) {
				unsigned long target_addr = exe_base + sym_offset;
				pr_dbg("found %s in symbol file at offset %lx (addr %lx)\n",
				       target_name, sym_offset, target_addr);
#if defined(__x86_64__)
				if (patch_function_x86_64(pid, target_addr, replacement_ptr, NULL) == 0) {
					applied++;
					pr_out("hooked %s via direct patch at %lx\n", target_name, target_addr);
					continue;
				}
#elif defined(__aarch64__)
				/* Use far-jump trampoline for local functions */
				if (patch_function_far_aarch64(pid, target_addr, replacement_ptr, NULL) == 0) {
					applied++;
					pr_out("hooked %s via trampoline at %lx\n", target_name, target_addr);
					continue;
				}
#endif
			}
		}

		pr_warn("hook failed for %s (no GOT entry, no symbol)\n", target_name);
	}

	ptrace(PTRACE_DETACH, pid, NULL, NULL);

	return applied;
}

