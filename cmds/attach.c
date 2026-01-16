/*
 * Attach command for uftrace
 *
 * Copyright (C) 2024, uftrace contributors
 *
 * Released under the GPL v2.
 *
 * This file implements the attach functionality to trace already
 * running processes.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "attach"
#define PR_DOMAIN DBG_UFTRACE

#include "libmcount/mcount.h"
#include "uftrace.h"
#include "utils/inject.h"
#include "utils/socket.h"
#include "utils/symbol.h"
#include "utils/utils.h"

/* Communication socket path for attached libmcount */
#define ATTACH_SOCKET_DIR "/tmp/uftrace-attach"
#define ATTACH_SOCKET_FMT "/tmp/uftrace-attach/%d.sock"
#define ATTACH_CFG_FMT "/tmp/uftrace-attach/%d.cfg"

static volatile bool attach_done = false;
static struct uftrace_sym_info attach_sym_info;
static bool attach_sym_loaded;

/* Streaming symbol resolution helpers */
static bool symfile_matches_target(const char *symfile, const char *libpath, const char *build_id)
{
	char cand_build_id[BUILD_ID_STR_SIZE] = "";

	if (access(symfile, R_OK) != 0)
		return false;

	if (build_id && build_id[0]) {
		if (read_build_id(symfile, cand_build_id, sizeof(cand_build_id)) < 0)
			return false;
		if (cand_build_id[0] && strcmp(cand_build_id, build_id) != 0)
			return false;
		return true;
	}

	return strcmp(uftrace_basename(symfile), uftrace_basename(libpath)) == 0;
}

static bool find_sym_binary(const char *symdir, const char *libpath, const char *build_id,
			    char *out, size_t out_size)
{
	const char *base;
	size_t need_len;
	size_t symdir_len;
	size_t base_len;
	struct stat st;

	if (symdir == NULL || symdir[0] == '\0')
		return false;

	if (stat(symdir, &st) == 0 && S_ISREG(st.st_mode)) {
		size_t len;

		if (!symfile_matches_target(symdir, libpath, build_id))
			return false;

		len = strlen(symdir);
		if (len + 1 > out_size)
			return false;
		memcpy(out, symdir, len + 1);
		return true;
	}

	base = uftrace_basename(libpath);
	symdir_len = strlen(symdir);
	base_len = strlen(base);
	need_len = symdir_len + 1 + base_len + 1;
	if (need_len > out_size)
		return false;

	memcpy(out, symdir, symdir_len);
	out[symdir_len] = '/';
	memcpy(out + symdir_len + 1, base, base_len);
	out[symdir_len + 1 + base_len] = '\0';

	if (access(out, R_OK) != 0)
		return false;

	if (!symfile_matches_target(out, libpath, build_id))
		return false;

	return true;
}

static void read_live_proc_maps(int pid, struct uftrace_sym_info *sinfo, const char *exename,
				const char *symdir)
{
	FILE *fp;
	char path[PATH_MAX];
	char buf[PATH_MAX];
	struct uftrace_mmap **maps = &sinfo->maps;
	struct uftrace_mmap *prev_map = NULL;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	fp = fopen(path, "r");
	if (fp == NULL) {
		pr_dbg("cannot open %s\n", path);
		return;
	}

	while (fgets(buf, sizeof(buf), fp)) {
		unsigned long start, end;
		char prot[5];
		char libpath[PATH_MAX];
		char map_path[PATH_MAX];
		char build_id[BUILD_ID_STR_SIZE] = "";
		struct uftrace_mmap *map;
		size_t namelen;
		const char *path_to_use;

		/* parse: start-end prot offset dev inode pathname */
		if (sscanf(buf, "%lx-%lx %4s %*x %*x:%*x %*d %s",
			   &start, &end, prot, libpath) != 4)
			continue;

		/* skip special mappings like [heap], [vdso], [stack] */
		if (libpath[0] == '[')
			continue;

		/* skip non-file mappings */
		if (libpath[0] != '/')
			continue;

		read_build_id(libpath, build_id, sizeof(build_id));
		path_to_use = libpath;
		if (find_sym_binary(symdir, libpath, build_id, map_path, sizeof(map_path)))
			path_to_use = map_path;

		/* merge adjacent mappings of the same file */
		if (prev_map && !strcmp(path_to_use, prev_map->libname)) {
			prev_map->end = end;
			if (prot[2] == 'x')
				memcpy(prev_map->prot, prot, 4);
			continue;
		}

		namelen = ALIGN(strlen(path_to_use) + 1, 4);
		map = xzalloc(sizeof(*map) + namelen);

		map->start = start;
		map->end = end;
		map->len = namelen;
		memcpy(map->prot, prot, 4);
		memcpy(map->libname, path_to_use, strlen(path_to_use) + 1);
		if (!build_id[0] && path_to_use != libpath)
			read_build_id(path_to_use, build_id, sizeof(build_id));
		memcpy(map->build_id, build_id, sizeof(map->build_id));

		/* set mapping of main executable */
		if (sinfo->exec_map == NULL && exename && !strcmp(libpath, exename))
			sinfo->exec_map = map;

		*maps = map;
		maps = &map->next;
		prev_map = map;
	}

	fclose(fp);
}

static void init_attach_sym_info(pid_t pid, const char *exepath, struct uftrace_opts *opts)
{
	memset(&attach_sym_info, 0, sizeof(attach_sym_info));
	attach_sym_info.filename = xstrdup(exepath);
	attach_sym_info.flags = SYMTAB_FL_DEMANGLE | SYMTAB_FL_ADJ_OFFSET;
	if (opts->with_syms) {
		attach_sym_info.symdir = opts->with_syms;
		attach_sym_info.flags |= SYMTAB_FL_USE_SYMFILE | SYMTAB_FL_SYMS_DIR;
	}
	/* Disable kernel address detection for user-only streaming. */
	attach_sym_info.kernel_base = -1ULL;

	read_live_proc_maps(pid, &attach_sym_info, exepath, opts->with_syms);
	if (attach_sym_info.maps) {
		load_module_symtabs(&attach_sym_info);
		attach_sym_info.loaded = true;
		attach_sym_loaded = true;
		pr_dbg("attached streaming symbol resolution initialized\n");
	}
}

static void attach_sigint_handler(int sig)
{
	attach_done = true;
}

static bool parse_pid_arg(const char *arg, pid_t *pid_out)
{
	char *end = NULL;
	long val;

	if (arg == NULL || arg[0] == '\0')
		return false;

	errno = 0;
	val = strtol(arg, &end, 0);
	if (errno != 0 || end == arg || *end != '\0' || val <= 0)
		return false;

	*pid_out = (pid_t)val;
	return true;
}

/**
 * get_exe_path - get the executable path for a process
 * @pid: process ID
 * @buf: buffer to store the path
 * @size: size of buffer
 *
 * Return: 0 on success, -1 on failure
 */
static int get_exe_path(pid_t pid, char *buf, size_t size)
{
	char link[PATH_MAX];
	ssize_t len;

	snprintf(link, sizeof(link), "/proc/%d/exe", pid);
	len = readlink(link, buf, size - 1);
	if (len < 0)
		return -1;

	buf[len] = '\0';
	return 0;
}

/**
 * setup_attach_socket_dir - create the socket directory for attached processes
 */
static int setup_attach_socket_dir(void)
{
	if (mkdir(ATTACH_SOCKET_DIR, 0755) < 0) {
		if (errno != EEXIST) {
			pr_err("failed to create %s: %s\n",
			       ATTACH_SOCKET_DIR, strerror(errno));
			return -1;
		}
	}
	return 0;
}

/**
 * create_attach_fifo - create a FIFO for attached process communication
 * @pid: target process ID
 *
 * Return: file descriptor for reading from the FIFO, -1 on failure
 */
static int create_attach_fifo(pid_t pid)
{
	char fifo_path[PATH_MAX];
	int fd;

	snprintf(fifo_path, sizeof(fifo_path), ATTACH_SOCKET_FMT, pid);

	/* Remove existing FIFO if any */
	unlink(fifo_path);

	/* Create the FIFO */
	if (mkfifo(fifo_path, 0644) < 0) {
		pr_err("failed to create FIFO %s: %s\n",
		       fifo_path, strerror(errno));
		return -1;
	}

	pr_dbg("created FIFO: %s\n", fifo_path);

	/* Open non-blocking - we'll set blocking after injection */
	fd = open(fifo_path, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		pr_err("failed to open FIFO %s: %s\n",
		       fifo_path, strerror(errno));
		unlink(fifo_path);
		return -1;
	}

	return fd;
}

static bool target_has_libmcount(pid_t pid)
{
	FILE *fp;
	char path[PATH_MAX];
	char buf[PATH_MAX];

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	fp = fopen(path, "r");
	if (fp == NULL)
		return false;

	while (fgets(buf, sizeof(buf), fp)) {
		if (strstr(buf, "libmcount")) {
			fclose(fp);
			return true;
		}
	}

	fclose(fp);
	return false;
}

static void signal_attach_control(pid_t pid, int sig)
{
	if (kill(pid, sig) < 0)
		pr_dbg("failed to signal %d to pid %d: %s\n", sig, pid, strerror(errno));
}

/**
 * cleanup_attach_fifo - remove the FIFO after detaching
 * @pid: target process ID
 */
static void cleanup_attach_fifo(pid_t pid)
{
	char fifo_path[PATH_MAX];
	char cfg_path[PATH_MAX];

	snprintf(fifo_path, sizeof(fifo_path), ATTACH_SOCKET_FMT, pid);
	unlink(fifo_path);
	snprintf(cfg_path, sizeof(cfg_path), ATTACH_CFG_FMT, pid);
	unlink(cfg_path);
}

/**
 * setup_attach_environ - set environment variables for attached libmcount
 * @opts: uftrace options
 * @pid: target process ID
 */
static void setup_attach_environ(struct uftrace_opts *opts, pid_t pid)
{
	char buf[64];
	char pathbuf[PATH_MAX];
	const char *symdir;

	/* Mark that we're in attached mode */
	setenv("UFTRACE_ATTACHED", "1", 1);

	/* Set the socket path for communication */
	snprintf(buf, sizeof(buf), ATTACH_SOCKET_FMT, pid);
	setenv("UFTRACE_ATTACH_SOCKET", buf, 1);

	/* Enable streaming by default */
	setenv("UFTRACE_STREAM", "1", 1);

	if (opts->with_syms) {
		symdir = opts->with_syms;
		if (symdir[0] != '/' && realpath(symdir, pathbuf))
			symdir = pathbuf;
		setenv("UFTRACE_SYMBOL_DIR", symdir, 1);
	}

	/* Set depth if specified */
	if (opts->depth != OPT_DEPTH_DEFAULT) {
		snprintf(buf, sizeof(buf), "%d", opts->depth);
		setenv("UFTRACE_DEPTH", buf, 1);
	}

	/* Set time filter if specified */
	if (opts->threshold) {
		snprintf(buf, sizeof(buf), "%" PRIu64, opts->threshold);
		setenv("UFTRACE_THRESHOLD", buf, 1);
	}

	/* Set max stack depth if specified */
	if (opts->max_stack != OPT_RSTACK_DEFAULT) {
		snprintf(buf, sizeof(buf), "%d", opts->max_stack);
		setenv("UFTRACE_MAX_STACK", buf, 1);
	}

	/* Set size filter if specified */
	if (opts->size_filter) {
		snprintf(buf, sizeof(buf), "%d", opts->size_filter);
		setenv("UFTRACE_MIN_SIZE", buf, 1);
	}

	/* Set filter if specified */
	if (opts->filter)
		setenv("UFTRACE_FILTER", opts->filter, 1);

	/* Set trigger if specified */
	if (opts->trigger)
		setenv("UFTRACE_TRIGGER", opts->trigger, 1);

	/* Set argument spec if specified */
	if (opts->args)
		setenv("UFTRACE_ARGUMENT", opts->args, 1);

	/* Set return value spec if specified */
	if (opts->retval)
		setenv("UFTRACE_RETVAL", opts->retval, 1);

	/* Set patch filter if specified */
	if (opts->patch)
		setenv("UFTRACE_PATCH", opts->patch, 1);

	/* Set caller filter if specified */
	if (opts->caller)
		setenv("UFTRACE_CALLER", opts->caller, 1);

	/* Set pattern type if not default */
	if (opts->patt_type != PATT_REGEX)
		setenv("UFTRACE_PATTERN", get_filter_pattern(opts->patt_type), 1);

	/* Enable PLT hooking for attached processes - library call tracing */
	setenv("UFTRACE_PLTHOOK", "1", 1);
}

static void setup_attach_cfg(pid_t pid, struct uftrace_opts *opts)
{
	char cfg_path[PATH_MAX];
	char pathbuf[PATH_MAX];
	const char *symdir;
	FILE *fp;

	snprintf(cfg_path, sizeof(cfg_path), ATTACH_CFG_FMT, pid);
	unlink(cfg_path);

	if (!opts->with_syms)
		return;

	symdir = opts->with_syms;
	if (symdir[0] != '/' && realpath(symdir, pathbuf))
		symdir = pathbuf;

	fp = fopen(cfg_path, "w");
	if (fp == NULL) {
		pr_dbg("cannot create attach cfg %s: %s\n", cfg_path, strerror(errno));
		return;
	}

	fprintf(fp, "UFTRACE_SYMBOL_DIR=%s\n", symdir);
	fclose(fp);
}

static void parse_attach_args(int argc, char *argv[], struct uftrace_opts *opts)
{
	int i;

	for (i = 1; i < argc; i++) {
		const char *arg = argv[i];

		if (!strcmp(arg, "--with-syms") && i + 1 < argc) {
			opts->with_syms = argv[++i];
		}
		else if (!strncmp(arg, "--with-syms=", 12)) {
			opts->with_syms = (char *)arg + 12;
		}
	}
}

/**
 * print_stream_record - print a streaming trace record
 * @stream: the stream record
 * @sym: resolved symbol (may be NULL)
 */
static void __maybe_unused print_stream_record(struct uftrace_msg_stream *stream,
				struct uftrace_symbol *sym)
{
	char *name;
	int depth = stream->depth;
	int i;

	if (sym)
		name = sym->name;
	else
		name = NULL;

	if (stream->type == UFTRACE_ENTRY) {
		/* Print indentation and function entry */
		for (i = 0; i < depth; i++)
			pr_out("  ");

		if (name)
			pr_out("[%d] %s() {\n", stream->tid, name);
		else
			pr_out("[%d] <%lx>() {\n", stream->tid,
			       (unsigned long)stream->addr);
	}
	else {
		/* Print function exit with duration */
		for (i = 0; i < depth; i++)
			pr_out("  ");

		if (stream->duration >= 1000000000ULL) {
			pr_out("%6.3f s  [%d]   }",
			       stream->duration / 1000000000.0, stream->tid);
		}
		else if (stream->duration >= 1000000ULL) {
			pr_out("%6.3f ms [%d]   }",
			       stream->duration / 1000000.0, stream->tid);
		}
		else if (stream->duration >= 1000ULL) {
			pr_out("%6.3f us [%d]   }",
			       stream->duration / 1000.0, stream->tid);
		}
		else {
			pr_out("%6lu ns [%d]   }",
			       (unsigned long)stream->duration, stream->tid);
		}

		if (name)
			pr_out(" /* %s */\n", name);
		else
			pr_out(" /* <%lx> */\n", (unsigned long)stream->addr);
	}
}

/**
 * command_attach - main attach command implementation
 */
int command_attach(int argc, char *argv[], struct uftrace_opts *opts)
{
	pid_t pid = 0;
	char exepath[PATH_MAX];
	char *libpath;
	struct sigaction sa = { .sa_handler = attach_sigint_handler };
	int ret = UFTRACE_EXIT_FAILURE;
	int scope;
	int fifo_fd = -1;

	if (argc > 0)
		parse_pid_arg(argv[0], &pid);
	else if (opts->exename)
		parse_pid_arg(opts->exename, &pid);

	/* Validate target PID */
	if (pid <= 0) {
		pr_err("usage: uftrace attach <PID>\n");
		return UFTRACE_EXIT_FAILURE;
	}

	parse_attach_args(argc, argv, opts);

	/* Check if process exists */
	if (kill(pid, 0) < 0) {
		pr_err("cannot access process %d: %s\n", pid, strerror(errno));
		return UFTRACE_EXIT_FAILURE;
	}

	/* Get the executable path */
	if (get_exe_path(pid, exepath, sizeof(exepath)) < 0) {
		pr_err("failed to get executable path for pid %d\n", pid);
		return UFTRACE_EXIT_FAILURE;
	}
	pr_dbg("target executable: %s\n", exepath);

	/* Check ptrace restrictions */
	scope = check_ptrace_scope();
	if (scope > 0) {
		pr_warn("warning: ptrace is restricted (yama ptrace_scope=%d)\n", scope);
		pr_warn("you may need to run as root or adjust ptrace_scope\n");
	}

	/* Setup socket directory */
	if (setup_attach_socket_dir() < 0)
		return UFTRACE_EXIT_FAILURE;

	/* Create FIFO for receiving trace data */
	fifo_fd = create_attach_fifo(pid);
	if (fifo_fd < 0)
		return UFTRACE_EXIT_FAILURE;

	setup_attach_cfg(pid, opts);

	/* Set up environment for injected libmcount */
	setup_attach_environ(opts, pid);

	/*
	 * Set the exename to the target's executable so get_libmcount_path()
	 * can properly detect pthread dependencies and select the right variant.
	 * This allows attach to work without requiring --libmcount-path.
	 */
	opts->exename = exepath;

	/* Get libmcount path (uses default install path if not specified) */
	libpath = get_libmcount_path(opts);
	if (libpath == NULL) {
		pr_err("failed to find libmcount.so\n");
		goto cleanup;
	}

	pr_out("attaching to process %d (%s)...\n", pid, exepath);
	pr_out("injecting %s...\n", libpath);

	/* Install signal handler for clean exit */
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/* Inject libmcount into the target process */
	if (!target_has_libmcount(pid)) {
		if (inject_library(pid, libpath) < 0) {
			pr_err("failed to inject library into process %d\n", pid);
			put_libmcount_path(libpath);
			goto cleanup;
		}
	}
	else {
		pr_out("libmcount already loaded, skip injection\n");
	}

	put_libmcount_path(libpath);

	pr_out("injection successful, streaming trace output...\n");
	pr_out("(press Ctrl+C to detach)\n\n");

	init_attach_sym_info(pid, exepath, opts);
	signal_attach_control(pid, SIGUSR1);

	/*
	 * Read streaming trace data from the FIFO.
	 * The injected libmcount writes trace records to the FIFO.
	 */
	while (!attach_done) {
		struct uftrace_msg hdr;
		struct uftrace_msg_stream stream;
		struct uftrace_symbol *sym = NULL;
		ssize_t n;

		/* Check if target is still running */
		if (kill(pid, 0) < 0) {
			pr_out("\ntarget process exited\n");
			break;
		}

		/* Try to read from FIFO */
		n = read(fifo_fd, &hdr, sizeof(hdr));
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/* No data available, wait a bit */
				usleep(10000); /* 10ms */
				continue;
			}
			pr_dbg("read error: %s\n", strerror(errno));
			break;
		}
		else if (n == 0) {
			/* FIFO closed by writer */
			usleep(10000);
			continue;
		}
		else if ((size_t)n != sizeof(hdr)) {
			pr_dbg("short read of header\n");
			continue;
		}

		/* Validate message header */
		if (hdr.magic != UFTRACE_MSG_MAGIC) {
			pr_dbg("invalid message magic: %x\n", hdr.magic);
			continue;
		}

		if (hdr.type == UFTRACE_MSG_STREAM_TRACE && hdr.len == sizeof(stream)) {
			n = read(fifo_fd, &stream, sizeof(stream));
			if ((size_t)n == sizeof(stream)) {
				/* Print the trace record */
				if (attach_sym_loaded)
					sym = find_symtabs(&attach_sym_info, stream.addr);
				print_stream_record(&stream, sym);
			}
		}
		else {
			/* Skip unknown messages */
			char skip[256];
			while (hdr.len > 0) {
				size_t skip_len = hdr.len < sizeof(skip) ? hdr.len : sizeof(skip);
				n = read(fifo_fd, skip, skip_len);
				if (n <= 0)
					break;
				hdr.len -= n;
			}
		}
	}

	pr_out("\ndetaching from process %d\n", pid);
	signal_attach_control(pid, SIGUSR2);

	ret = UFTRACE_EXIT_SUCCESS;

cleanup:
	if (fifo_fd >= 0)
		close(fifo_fd);
	cleanup_attach_fifo(pid);

	return ret;
}
