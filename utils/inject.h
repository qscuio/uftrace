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

#endif /* UFTRACE_INJECT_H */
