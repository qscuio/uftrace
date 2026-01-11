/*
 * uftrace injection plugin API
 *
 * Copyright (C) 2024, uftrace contributors
 * Released under the GPL v2.
 *
 * This header defines the API for injection plugins.
 * Plugins can hook functions and register features.
 */

#ifndef UFTRACE_HOOK_H
#define UFTRACE_HOOK_H

#include <stddef.h>

/**
 * struct uftrace_hook - Function hook entry
 * @target: Name of function to hook (e.g., "printf")
 * @replacement: Pointer to replacement function
 * @original: Where to store pointer to original function (optional)
 *
 * Example:
 *   static int (*orig_printf)(const char *, ...);
 *   struct uftrace_hook hooks[] = {
 *       { "printf", my_printf, (void**)&orig_printf },
 *   };
 */
struct uftrace_hook {
	const char *target;
	void *replacement;
	void **original;
};

/**
 * struct uftrace_feature - Feature registration entry
 * @name: Feature name for logging/debugging
 * @init: Initialization callback, returns 0 on success
 * @fini: Cleanup callback, called on unload
 * @arg: Argument passed to init callback
 *
 * Example:
 *   static int start_logger(void *arg) { return 0; }
 *   static void stop_logger(void) { }
 *   struct uftrace_feature features[] = {
 *       { "logger", start_logger, stop_logger, NULL },
 *   };
 */
struct uftrace_feature {
	const char *name;
	int (*init)(void *arg);
	void (*fini)(void);
	void *arg;
};

/*
 * Plugin must export these symbols:
 *
 * struct uftrace_hook uftrace_hooks[];
 * int uftrace_hooks_count;
 * struct uftrace_feature uftrace_features[];
 * int uftrace_features_count;
 *
 * Any of these can be empty (count = 0) if not used.
 */

/* Symbol names that uftrace looks for in the plugin */
#define UFTRACE_HOOKS_SYMBOL         "uftrace_hooks"
#define UFTRACE_HOOKS_COUNT_SYMBOL   "uftrace_hooks_count"
#define UFTRACE_FEATURES_SYMBOL      "uftrace_features"
#define UFTRACE_FEATURES_COUNT_SYMBOL "uftrace_features_count"

#endif /* UFTRACE_HOOK_H */
