/*
 * Hotspot Profiling Plugin for uftrace inject
 *
 * Identifies hot functions in a target process using statistical sampling.
 * Uses SIGPROF timer to periodically sample the call stack of all threads,
 * aggregating samples to find where the program spends most of its time.
 *
 * Build:
 *   gcc -shared -fPIC -rdynamic -o hotspot.so hotspot.c -ldl -lpthread
 *
 * Usage:
 *   uftrace inject <PID> --lib /path/to/hotspot.so
 *
 * Output:
 *   - /tmp/hotspot_report.txt - Hotspot report (generated periodically and on exit)
 *   - SIGUSR1 - Force immediate report generation
 *   - SIGUSR2 - Reset statistics
 *
 * Environment Variables:
 *   - HOTSPOT_SAMPLE_INTERVAL_US: Sampling interval in microseconds (default: 10000)
 *   - HOTSPOT_TOP_N: Number of top functions to report (default: 20)
 *   - HOTSPOT_REPORT_INTERVAL: Seconds between automatic reports (default: 10)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <ucontext.h>

/* Hook API structures */
struct uftrace_hook {
	const char *target;
	void *replacement;
	void **original;
};

struct uftrace_feature {
	const char *name;
	int (*init)(void *arg);
	void (*fini)(void);
	void *arg;
};

/* Configuration */
#define MAX_STACK_DEPTH 32
#define HASH_TABLE_SIZE 16384
#define DEFAULT_SAMPLE_INTERVAL_US 10000 /* 10ms - safer default for timer */
#define DEFAULT_TOP_N 20
#define DEFAULT_REPORT_INTERVAL 10 /* 10 seconds */
#define SAMPLE_BUFFER_SIZE 1024	   /* Async-safe sample buffer */

/* Function statistics entry */
struct func_stats {
	void *addr;		   /* Function address */
	char *name;		   /* Resolved function name (or NULL) */
	size_t self_samples;	   /* Times this function was at top of stack */
	size_t total_samples;	   /* Times this function appeared in stack */
	struct func_stats *next;   /* Hash chain */
};

/* Async-safe sample record */
struct sample_record {
	void *stack[MAX_STACK_DEPTH];
	int depth;
};

/* Global state */
static struct func_stats *func_table[HASH_TABLE_SIZE];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int enabled = 0;
static time_t start_time;
static time_t last_report_time;

/* Async-safe sample buffer (ring buffer for signal handler) */
static struct sample_record sample_buffer[SAMPLE_BUFFER_SIZE];
static volatile int sample_write_idx = 0;
static volatile int sample_read_idx = 0;
static pthread_t processor_thread;
static int processor_running = 0;

/* Configuration (from environment) */
static int sample_interval_us = DEFAULT_SAMPLE_INTERVAL_US;
static int top_n = DEFAULT_TOP_N;
static int report_interval = DEFAULT_REPORT_INTERVAL;

/* Statistics */
static size_t total_samples = 0;
static size_t dropped_samples = 0;

/* Hash function for addresses */
static unsigned int addr_hash(void *addr)
{
	unsigned long val = (unsigned long)addr;
	return (val ^ (val >> 16)) % HASH_TABLE_SIZE;
}

/* Resolve address to function base address and name */
static void *resolve_func_addr(void *addr, const char **name_out)
{
	Dl_info info;
	if (dladdr(addr, &info) && info.dli_saddr) {
		if (name_out)
			*name_out = info.dli_sname;
		return info.dli_saddr; /* Return function base address */
	}
	/* If no symbol found, use the address as-is */
	if (name_out)
		*name_out = NULL;
	return addr;
}

/* Get or create function statistics entry (NOT signal safe - call from main thread only) */
static struct func_stats *get_func_stats(void *addr)
{
	const char *func_name = NULL;
	void *func_base = resolve_func_addr(addr, &func_name);
	unsigned int h = addr_hash(func_base);
	struct func_stats *fs;

	for (fs = func_table[h]; fs; fs = fs->next) {
		if (fs->addr == func_base)
			return fs;
	}

	/* Create new entry */
	fs = malloc(sizeof(*fs));
	if (!fs)
		return NULL;

	memset(fs, 0, sizeof(*fs));
	fs->addr = func_base;
	if (func_name)
		fs->name = strdup(func_name);
	fs->next = func_table[h];
	func_table[h] = fs;

	return fs;
}

/* Process a sample from the buffer (called from processor thread) */
static void process_sample(struct sample_record *rec)
{
	struct func_stats *fs;
	int i;

	pthread_mutex_lock(&lock);

	/* Record self sample - first frame should now be the actual PC */
	int start = 0; /* PC was inserted at position 0 */
	if (rec->depth > start) {
		fs = get_func_stats(rec->stack[start]);
		if (fs) {
			fs->self_samples++;
		}
	}

	/* Record total samples (all functions in stack) */
	for (i = start; i < rec->depth; i++) {
		fs = get_func_stats(rec->stack[i]);
		if (fs) {
			fs->total_samples++;
		}
	}

	total_samples++;
	pthread_mutex_unlock(&lock);
}

/* Get the program counter from ucontext */
static void *get_pc_from_ucontext(ucontext_t *uc)
{
#if defined(__x86_64__)
	return (void *)uc->uc_mcontext.gregs[REG_RIP];
#elif defined(__i386__)
	return (void *)uc->uc_mcontext.gregs[REG_EIP];
#elif defined(__aarch64__)
	return (void *)uc->uc_mcontext.pc;
#elif defined(__arm__)
	return (void *)uc->uc_mcontext.arm_pc;
#else
	return NULL;
#endif
}

/* Signal handler for SIGPROF - async-signal-safe only! */
static void sample_signal_handler(int sig, siginfo_t *info, void *ucontext)
{
	int next_idx;
	struct sample_record *rec;
	ucontext_t *uc = (ucontext_t *)ucontext;
	void *pc;

	(void)sig;
	(void)info;

	if (!enabled)
		return;

	/* Calculate next write index */
	next_idx = (sample_write_idx + 1) % SAMPLE_BUFFER_SIZE;

	/* Check if buffer is full */
	if (next_idx == sample_read_idx) {
		/* Buffer full - drop sample */
		dropped_samples++;
		return;
	}

	/* Get the record slot */
	rec = &sample_buffer[sample_write_idx];

	/* First, get the PC at the time of the signal */
	pc = get_pc_from_ucontext(uc);

	/* Capture the stack */
	rec->depth = backtrace(rec->stack, MAX_STACK_DEPTH);

	/* If we got a valid PC, insert it at the start (after backtrace frames) */
	if (pc && rec->depth > 0) {
		/* The first few frames are signal handler frames, overwrite the first with actual PC */
		rec->stack[0] = pc;
	}

	/* Commit the write */
	__sync_synchronize(); /* Memory barrier */
	sample_write_idx = next_idx;
}

/* Sample processor thread */
static void *processor_thread_func(void *arg)
{
	(void)arg;

	while (processor_running) {
		/* Process any pending samples */
		while (sample_read_idx != sample_write_idx) {
			struct sample_record *rec = &sample_buffer[sample_read_idx];
			process_sample(rec);
			__sync_synchronize(); /* Memory barrier */
			sample_read_idx = (sample_read_idx + 1) % SAMPLE_BUFFER_SIZE;
		}

		/* Check for periodic report */
		if (report_interval > 0) {
			time_t now = time(NULL);
			if (difftime(now, last_report_time) >= report_interval) {
				/* Forward declaration */
				extern void generate_report(const char *trigger);
				generate_report("Periodic");
				last_report_time = now;
			}
		}

		/* Sleep briefly to avoid busy-waiting */
		usleep(10000); /* 10ms */
	}

	return NULL;
}

/* Resolve function names for all entries using dladdr */
static void resolve_all_names(void)
{
	struct func_stats *fs;
	int i;
	Dl_info info;
	char buf[512];

	pthread_mutex_lock(&lock);

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		for (fs = func_table[i]; fs; fs = fs->next) {
			if (!fs->name) {
				if (dladdr(fs->addr, &info) && info.dli_sname) {
					/* Use actual symbol name if available */
					fs->name = strdup(info.dli_sname);
				} else if (dladdr(fs->addr, &info) && info.dli_fname) {
					/* Fall back to library + offset */
					unsigned long offset = (unsigned long)fs->addr -
							       (unsigned long)info.dli_fbase;
					snprintf(buf, sizeof(buf), "%s+0x%lx",
						 info.dli_fname, offset);
					fs->name = strdup(buf);
				} else {
					/* Last resort - just show the address */
					snprintf(buf, sizeof(buf), "0x%lx",
						 (unsigned long)fs->addr);
					fs->name = strdup(buf);
				}
			}
		}
	}

	pthread_mutex_unlock(&lock);
}

/* Comparison function for sorting by self_samples */
static int compare_by_self_samples(const void *a, const void *b)
{
	const struct func_stats *fa = *(const struct func_stats **)a;
	const struct func_stats *fb = *(const struct func_stats **)b;

	if (fb->self_samples > fa->self_samples)
		return 1;
	if (fb->self_samples < fa->self_samples)
		return -1;
	return 0;
}

/* Generate hotspot report */
void generate_report(const char *trigger)
{
	FILE *f;
	struct func_stats **sorted;
	struct func_stats *fs;
	int count = 0;
	int i;
	time_t now = time(NULL);
	double elapsed = difftime(now, start_time);
	double sample_rate;

	/* Resolve function names */
	resolve_all_names();

	/* Count entries */
	pthread_mutex_lock(&lock);
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		for (fs = func_table[i]; fs; fs = fs->next) {
			if (fs->self_samples > 0)
				count++;
		}
	}

	if (count == 0) {
		pthread_mutex_unlock(&lock);
		return;
	}

	/* Allocate array for sorting */
	sorted = malloc(count * sizeof(*sorted));
	if (!sorted) {
		pthread_mutex_unlock(&lock);
		return;
	}

	/* Fill array */
	count = 0;
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		for (fs = func_table[i]; fs; fs = fs->next) {
			if (fs->self_samples > 0) {
				sorted[count++] = fs;
			}
		}
	}
	pthread_mutex_unlock(&lock);

	/* Sort by self_samples (descending) */
	qsort(sorted, count, sizeof(*sorted), compare_by_self_samples);

	/* Write report */
	f = fopen("/tmp/hotspot_report.txt", "w");
	if (!f) {
		free(sorted);
		return;
	}

	if (elapsed > 0)
		sample_rate = total_samples / elapsed;
	else
		sample_rate = 0;

	fprintf(f, "============================================================\n");
	fprintf(f, "              HOTSPOT PROFILING REPORT\n");
	fprintf(f, "============================================================\n\n");
	fprintf(f, "Trigger:           %s\n", trigger);
	fprintf(f, "Elapsed Time:      %.1f seconds\n", elapsed);
	fprintf(f, "Total Samples:     %zu\n", total_samples);
	fprintf(f, "Dropped Samples:   %zu\n", dropped_samples);
	fprintf(f, "Sample Rate:       %.1f samples/sec\n", sample_rate);
	fprintf(f, "Sample Interval:   %d us\n", sample_interval_us);
	fprintf(f, "Unique Functions:  %d\n\n", count);

	fprintf(f, "------------------------------------------------------------\n");
	fprintf(f, "TOP %d HOTSPOT FUNCTIONS (by self time)\n", top_n < count ? top_n : count);
	fprintf(f, "------------------------------------------------------------\n\n");

	fprintf(f, "%6s  %8s  %8s  %s\n", "Rank", "Self %", "Total %", "Function");
	fprintf(f, "%6s  %8s  %8s  %s\n", "----", "------", "-------", "--------");

	for (i = 0; i < count && i < top_n; i++) {
		fs = sorted[i];
		double self_pct = total_samples > 0 ? (fs->self_samples * 100.0) / total_samples : 0;
		double total_pct = total_samples > 0 ? (fs->total_samples * 100.0) / total_samples : 0;

		fprintf(f, "%6d  %7.2f%%  %7.2f%%  %s\n",
			i + 1, self_pct, total_pct,
			fs->name ? fs->name : "(unknown)");
	}

	fprintf(f, "\n");
	fprintf(f, "------------------------------------------------------------\n");
	fprintf(f, "LEGEND:\n");
	fprintf(f, "  Self %%  - Time spent in function itself (excluding callees)\n");
	fprintf(f, "  Total %% - Time spent in function including callees\n");
	fprintf(f, "------------------------------------------------------------\n");

	/* Also show all functions if there are more */
	if (count > top_n) {
		fprintf(f, "\n");
		fprintf(f, "------------------------------------------------------------\n");
		fprintf(f, "ALL FUNCTIONS (Self > 0.1%%)\n");
		fprintf(f, "------------------------------------------------------------\n\n");

		for (i = 0; i < count; i++) {
			fs = sorted[i];
			double self_pct = total_samples > 0 ? (fs->self_samples * 100.0) / total_samples : 0;
			if (self_pct < 0.1)
				break;
			fprintf(f, "%7.2f%%  %s\n", self_pct,
				fs->name ? fs->name : "(unknown)");
		}
	}

	fclose(f);
	free(sorted);

	fprintf(stderr, "[hotspot] Report generated: /tmp/hotspot_report.txt "
			"(%d functions, %zu samples)\n", count, total_samples);
}

/* Reset all statistics */
static void reset_stats(void)
{
	struct func_stats *fs, *next;
	int i;

	pthread_mutex_lock(&lock);

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		for (fs = func_table[i]; fs; fs = next) {
			next = fs->next;
			if (fs->name)
				free(fs->name);
			free(fs);
		}
		func_table[i] = NULL;
	}

	total_samples = 0;
	dropped_samples = 0;

	pthread_mutex_unlock(&lock);

	fprintf(stderr, "[hotspot] Statistics reset\n");
}

/* Signal handlers for user control */
static void user_signal_handler(int sig)
{
	if (sig == SIGUSR1) {
		generate_report("SIGUSR1 signal");
	} else if (sig == SIGUSR2) {
		reset_stats();
	}
}

/* Read configuration from environment */
static void read_config(void)
{
	const char *val;

	val = getenv("HOTSPOT_SAMPLE_INTERVAL_US");
	if (val) {
		sample_interval_us = atoi(val);
		if (sample_interval_us < 1000)
			sample_interval_us = 1000; /* Minimum 1ms for SIGPROF */
	}

	val = getenv("HOTSPOT_TOP_N");
	if (val) {
		top_n = atoi(val);
		if (top_n < 1)
			top_n = 1;
		if (top_n > 1000)
			top_n = 1000;
	}

	val = getenv("HOTSPOT_REPORT_INTERVAL");
	if (val) {
		report_interval = atoi(val);
		if (report_interval < 0)
			report_interval = 0; /* Disable periodic reports */
	}
}

/* Start the profiling timer */
static int start_profiling_timer(void)
{
	struct itimerval timer;
	struct sigaction sa;

	/* Set up signal handler with SA_SIGINFO to get ucontext */
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = sample_signal_handler;
	sa.sa_flags = SA_RESTART | SA_SIGINFO;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGPROF, &sa, NULL) < 0) {
		fprintf(stderr, "[hotspot] Failed to set SIGPROF handler: %s\n",
			strerror(errno));
		return -1;
	}

	/* Set up interval timer */
	timer.it_value.tv_sec = 0;
	timer.it_value.tv_usec = sample_interval_us;
	timer.it_interval.tv_sec = 0;
	timer.it_interval.tv_usec = sample_interval_us;

	if (setitimer(ITIMER_PROF, &timer, NULL) < 0) {
		fprintf(stderr, "[hotspot] Failed to set profiling timer: %s\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

/* Stop the profiling timer */
static void stop_profiling_timer(void)
{
	struct itimerval timer;

	memset(&timer, 0, sizeof(timer));
	setitimer(ITIMER_PROF, &timer, NULL);
}

/* Plugin initialization */
static int hotspot_init(void *arg)
{
	(void)arg;

	read_config();

	start_time = time(NULL);
	last_report_time = start_time;

	/* Set up user signal handlers */
	signal(SIGUSR1, user_signal_handler);
	signal(SIGUSR2, user_signal_handler);

	/* Start processor thread first */
	processor_running = 1;
	if (pthread_create(&processor_thread, NULL, processor_thread_func, NULL) != 0) {
		fprintf(stderr, "[hotspot] Failed to create processor thread\n");
		return -1;
	}

	/* Start the profiling timer */
	if (start_profiling_timer() < 0) {
		processor_running = 0;
		pthread_join(processor_thread, NULL);
		return -1;
	}

	enabled = 1;

	fprintf(stderr, "[hotspot] Profiling enabled\n");
	fprintf(stderr, "[hotspot] Sample interval: %d us\n", sample_interval_us);
	fprintf(stderr, "[hotspot] Report interval: %d seconds\n", report_interval);
	fprintf(stderr, "[hotspot] Top functions: %d\n", top_n);
	fprintf(stderr, "[hotspot] SIGUSR1 = generate report, SIGUSR2 = reset stats\n");

	return 0;
}

/* Plugin cleanup */
static void hotspot_fini(void)
{
	/* Stop the timer first */
	stop_profiling_timer();
	enabled = 0;

	/* Stop processor thread */
	processor_running = 0;
	pthread_join(processor_thread, NULL);

	/* Process any remaining samples */
	while (sample_read_idx != sample_write_idx) {
		struct sample_record *rec = &sample_buffer[sample_read_idx];
		process_sample(rec);
		sample_read_idx = (sample_read_idx + 1) % SAMPLE_BUFFER_SIZE;
	}

	/* Generate final report */
	generate_report("Plugin unload");

	/* Clean up */
	reset_stats();

	fprintf(stderr, "[hotspot] Profiling disabled\n");
}

/* Hook and feature tables - no hooks needed for statistical profiling */
struct uftrace_hook uftrace_hooks[] = {};
int uftrace_hooks_count = 0;

struct uftrace_feature uftrace_features[] = {
	{ "hotspot", hotspot_init, hotspot_fini, NULL },
};
int uftrace_features_count = 1;

__attribute__((constructor))
static void plugin_init(void)
{
	hotspot_init(NULL);
}

__attribute__((destructor))
static void plugin_fini(void)
{
	hotspot_fini();
}

