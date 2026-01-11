/*
 * Inject command for uftrace
 *
 * Copyright (C) 2024, uftrace contributors
 *
 * Released under the GPL v2.
 *
 * This file implements library injection and function hooking
 * into running processes.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT "inject"
#define PR_DOMAIN DBG_UFTRACE

#include "uftrace.h"
#include "utils/inject.h"
#include "utils/symbol.h"
#include "utils/utils.h"

static const char inject_usage[] =
	"uftrace inject [options] <PID>\n"
	"\n"
	"OPTIONS:\n"
	"      --lib=PATH       Inject shared library into the target process\n"
	"      --uninstall=PATH Unload a previously injected library\n"
	"      --hook=SPEC      Hook a function (format: target=replacement)\n"
	"      --with-sym=PATH  Symbol file for stripped targets (local func hooks)\n"
	"  -h, --help           Show this help message\n"
	"\n"
	"EXAMPLES:\n"
	"  # Inject a library:\n"
	"  uftrace inject 1234 --lib /path/to/mylib.so\n"
	"\n"
	"  # Unload a library:\n"
	"  uftrace inject 1234 --uninstall /path/to/mylib.so\n"
	"\n"
	"  # Hook local functions in stripped binary:\n"
	"  uftrace inject 1234 --lib hooks.so --with-sym /path/to/unstripped-binary\n"
	"\n";

enum inject_options {
	OPT_lib = 301,
	OPT_uninstall,
	OPT_hook,
	OPT_with_sym,
};

static const struct option inject_opts[] = {
	{ "lib", required_argument, 0, OPT_lib },
	{ "uninstall", required_argument, 0, OPT_uninstall },
	{ "hook", required_argument, 0, OPT_hook },
	{ "with-sym", required_argument, 0, OPT_with_sym },
	{ "help", no_argument, 0, 'h' },
	{ 0 },
};

struct inject_config {
	pid_t pid;
	char *lib_path;
	char *uninstall_path;
	char *sym_path;      /* Symbol file for stripped targets */
	char **hooks;
	int nr_hooks;
};


static void free_inject_config(struct inject_config *cfg)
{
	int i;

	free(cfg->lib_path);
	free(cfg->uninstall_path);
	free(cfg->sym_path);
	for (i = 0; i < cfg->nr_hooks; i++)
		free(cfg->hooks[i]);
	free(cfg->hooks);
}

static int parse_inject_options(int argc, char *argv[], struct inject_config *cfg)
{
	int c;
	int i;

	memset(cfg, 0, sizeof(*cfg));

	/* First, look for PID in arguments (should be first positional arg) */
	for (i = 0; i < argc; i++) {
		char *end = NULL;
		long val;

		/* Skip options and option arguments */
		if (argv[i][0] == '-')
			continue;

		/* Try to parse as PID */
		val = strtol(argv[i], &end, 0);

		if (end != argv[i] && *end == '\0' && val > 0) {
			cfg->pid = (pid_t)val;
			break;
		}
	}


	/* Reset optind for getopt_long */
	optind = 0;

	while ((c = getopt_long(argc, argv, "h", inject_opts, NULL)) != -1) {
		switch (c) {
		case OPT_lib:
			free(cfg->lib_path);
			cfg->lib_path = xstrdup(optarg);
			break;
		case OPT_uninstall:
			free(cfg->uninstall_path);
			cfg->uninstall_path = xstrdup(optarg);
			break;
		case OPT_hook:
			cfg->hooks = xrealloc(cfg->hooks,
					      (cfg->nr_hooks + 1) * sizeof(char *));
			cfg->hooks[cfg->nr_hooks++] = xstrdup(optarg);
			break;
		case OPT_with_sym:
			free(cfg->sym_path);
			cfg->sym_path = xstrdup(optarg);
			break;
		case 'h':
			pr_out("%s", inject_usage);
			return -1;
		default:
			return -2;
		}
	}

	return 0;
}


static int validate_inject_config(struct inject_config *cfg)
{
	if (cfg->pid <= 0) {
		pr_err("usage: uftrace inject <PID> [options]\n");
		return -1;
	}

	/* Check if process exists */
	if (kill(cfg->pid, 0) < 0) {
		pr_err("cannot access process %d: %s\n", cfg->pid, strerror(errno));
		return -1;
	}

	/* Need either --lib or --uninstall */
	if (!cfg->lib_path && !cfg->uninstall_path) {
		pr_err("must specify --lib or --uninstall\n");
		return -1;
	}

	/* Cannot use both --lib and --uninstall together */
	if (cfg->lib_path && cfg->uninstall_path) {
		pr_err("cannot use --lib and --uninstall together\n");
		return -1;
	}

	/* --hook requires --lib */
	if (cfg->nr_hooks > 0 && !cfg->lib_path) {
		pr_err("--hook requires --lib\n");
		return -1;
	}

	/* Validate library path exists */
	if (cfg->lib_path && access(cfg->lib_path, R_OK) < 0) {
		pr_err("cannot access library: %s: %s\n",
		       cfg->lib_path, strerror(errno));
		return -1;
	}

	return 0;
}

static int do_inject(struct inject_config *cfg)
{
	char abs_path[PATH_MAX];
	int ret;
	unsigned long lib_base = 0;
	FILE *fp;
	char maps_path[64];
	char line[PATH_MAX + 128];

	/* Convert to absolute path for injection */
	if (!realpath(cfg->lib_path, abs_path)) {
		pr_err("failed to resolve path: %s\n", cfg->lib_path);
		return -1;
	}

	pr_out("injecting %s into process %d...\n", abs_path, cfg->pid);

	ret = inject_library(cfg->pid, abs_path);
	if (ret < 0) {
		pr_err("failed to inject library\n");
		return -1;
	}

	pr_out("injection successful\n");

	/* Find the library's base address in target process */
	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", cfg->pid);
	fp = fopen(maps_path, "r");
	if (fp) {
		const char *libname = uftrace_basename(abs_path);
		while (fgets(line, sizeof(line), fp)) {
			unsigned long start;
			if (strstr(line, libname) && sscanf(line, "%lx", &start) == 1) {
				lib_base = start;
				break;
			}
		}
		fclose(fp);
	}

	if (lib_base == 0) {
		pr_warn("could not find library base address\n");
		return 0;
	}

	pr_dbg("library loaded at %lx\n", lib_base);

	/* Apply function hooks using advanced methods (GOT patching preferred) */
	ret = apply_hooks_advanced(cfg->pid, lib_base, abs_path, cfg->sym_path);
	if (ret > 0)
		pr_out("applied %d function hooks\n", ret);
	else if (ret == 0)
		pr_dbg("no hooks to apply\n");

	/* Enable features (handled by constructor, just log) */
	enable_features(cfg->pid, lib_base, abs_path);

	return 0;
}



static int do_uninstall(struct inject_config *cfg)
{
	int ret;

	pr_out("uninstalling %s from process %d...\n",
	       cfg->uninstall_path, cfg->pid);

	ret = uninject_library(cfg->pid, cfg->uninstall_path);
	if (ret < 0) {
		pr_err("failed to uninstall library\n");
		return -1;
	}

	pr_out("uninstall successful\n");
	return 0;
}

/**
 * command_inject - main inject command implementation
 */
int command_inject(int argc, char *argv[], struct uftrace_opts *opts)
{
	struct inject_config cfg;
	int ret;
	int scope;

	ret = parse_inject_options(argc, argv, &cfg);
	if (ret < 0) {
		if (ret == -1)
			return UFTRACE_EXIT_SUCCESS; /* --help */
		return UFTRACE_EXIT_FAILURE;
	}

	if (validate_inject_config(&cfg) < 0) {
		free_inject_config(&cfg);
		return UFTRACE_EXIT_FAILURE;
	}

	/* Check ptrace restrictions */
	scope = check_ptrace_scope();
	if (scope > 0) {
		pr_warn("warning: ptrace is restricted (yama ptrace_scope=%d)\n",
			scope);
		pr_warn("you may need to run as root or adjust ptrace_scope\n");
	}

	if (cfg.lib_path)
		ret = do_inject(&cfg);
	else
		ret = do_uninstall(&cfg);

	free_inject_config(&cfg);

	return ret < 0 ? UFTRACE_EXIT_FAILURE : UFTRACE_EXIT_SUCCESS;
}
