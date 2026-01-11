/*
 * Process injection utilities for uftrace
 *
 * Copyright (C) 2024, uftrace contributors
 *
 * Released under the GPL v2.
 */
#ifndef UFTRACE_INJECT_H
#define UFTRACE_INJECT_H

#include <sys/types.h>

/**
 * inject_library - inject a shared library into a running process
 * @pid: target process ID
 * @libpath: absolute path to the shared library
 *
 * This function uses ptrace to attach to the target process, then
 * forces it to call dlopen() to load the specified library.
 *
 * Return: 0 on success, -1 on failure
 */
int inject_library(pid_t pid, const char *libpath);

/**
 * detach_from_process - cleanly detach from a traced process
 * @pid: target process ID
 *
 * This function detaches from the process and allows it to continue
 * normal execution.
 *
 * Return: 0 on success, -1 on failure
 */
int detach_from_process(pid_t pid);

/**
 * check_ptrace_scope - check if ptrace is allowed on this system
 *
 * Check /proc/sys/kernel/yama/ptrace_scope to see if ptrace is
 * restricted. 
 *
 * Return: 0 if allowed, positive value indicating restriction level,
 *         -1 on error
 */
int check_ptrace_scope(void);

/**
 * find_libc_dlopen - find the address of __libc_dlopen_mode in target process
 * @pid: target process ID
 *
 * Return: address of __libc_dlopen_mode, or 0 on failure
 */
unsigned long find_libc_dlopen(pid_t pid);

/**
 * uninject_library - unload a shared library from a running process
 * @pid: target process ID
 * @libpath: path to the shared library to unload
 *
 * This function uses ptrace to attach to the target process, then
 * forces it to call dlclose() to unload the specified library.
 *
 * Return: 0 on success, -1 on failure
 */
int uninject_library(pid_t pid, const char *libpath);

/**
 * find_symbol_in_process - Find symbol address in target process
 * @pid: target process ID
 * @symbol: symbol name to find
 *
 * Return: address of symbol, or 0 if not found
 */
unsigned long find_symbol_in_process(pid_t pid, const char *symbol);

/**
 * apply_hooks - Apply function hooks from injected plugin
 * @pid: target process
 * @lib_base: base address of injected library in target
 * @libpath: path to library on disk (for symbol lookup)
 *
 * Return: number of hooks applied, or -1 on error
 */
int apply_hooks(pid_t pid, unsigned long lib_base, const char *libpath);

/**
 * enable_features - Enable features from injected plugin
 * @pid: target process
 * @lib_base: base of injected library
 * @libpath: path to library on disk
 *
 * Return: 0 on success
 */
int enable_features(pid_t pid, unsigned long lib_base, const char *libpath);

/**
 * hook_via_got - Hook a function by patching its GOT entry
 */
int hook_via_got(pid_t pid, const char *func_name,
		 unsigned long replacement, unsigned long *original);

/**
 * patch_got_entry - Patch GOT entry directly
 */
int patch_got_entry(pid_t pid, unsigned long got_addr,
		    unsigned long new_func, unsigned long *old_func);

/**
 * apply_hooks_advanced - Apply hooks with GOT patching priority
 * @sym_path: Optional symbol file for stripped targets (can be NULL)
 */
int apply_hooks_advanced(pid_t pid, unsigned long lib_base,
			 const char *libpath, const char *sym_path);

#endif /* UFTRACE_INJECT_H */

