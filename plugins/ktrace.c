/*
 * Kernel Function Trace Plugin for uftrace inject
 *
 * Traces kernel function calls for the target process using Linux ftrace.
 * This plugin configures and reads kernel function_graph traces for the
 * injected process, providing visibility into kernel-space function calls.
 *
 * Requirements:
 *   - Target process must run as root, OR
 *   - tracefs must be accessible to the user
 *
 * Build:
 *   gcc -shared -fPIC -rdynamic -o ktrace.so ktrace.c -ldl -lpthread
 *
 * Usage:
 *   sudo uftrace inject <PID> --lib /path/to/ktrace.so
 *
 * Output:
 *   - /tmp/ktrace_report.txt - Kernel function trace report
 *   - /tmp/ktrace_functions.txt - List of traced kernel functions
 *
 * Environment Variables:
 *   - KTRACE_FILTER: Comma-separated kernel function patterns to trace
 *                    (default: empty = trace all available functions)
 *   - KTRACE_DEPTH: Maximum call depth to trace (default: 5)
 *   - KTRACE_BUFFER_KB: Per-CPU trace buffer size in KB (default: 4096)
 *   - KTRACE_DURATION: Duration in seconds to trace (default: 10, 0=until exit)
 *
 * Signals:
 *   - SIGUSR1: Generate immediate report
 *   - SIGUSR2: Stop tracing and generate final report
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#include <poll.h>

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
#define MAX_CPUS 256
#define MAX_FILTER_LEN 4096
#define DEFAULT_DEPTH 5
#define DEFAULT_BUFFER_KB 4096
#define DEFAULT_DURATION 10
#define READ_BUFFER_SIZE 65536
#define MAX_FUNCTIONS 10000

#ifndef TRACEFS_MAGIC
#define TRACEFS_MAGIC 0x74726163
#endif

/* Tracefs paths */
#define TRACEFS_PATH "/sys/kernel/tracing"
#define OLD_TRACEFS_PATH "/sys/kernel/debug/tracing"

/* Function statistics */
struct kfunc_stats {
    char *name;
    unsigned long count;
    unsigned long total_time_ns;
    unsigned long min_time_ns;
    unsigned long max_time_ns;
    struct kfunc_stats *next;
};

/* Global state */
static char *tracefs_dir = NULL;
static int trace_fds[MAX_CPUS];
static int nr_cpus = 0;
static pthread_t reader_thread;
static volatile int running = 0;
static volatile int enabled = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static FILE *logfile = NULL;
static time_t start_time;

/* Statistics hash table */
#define HASH_SIZE 4096
static struct kfunc_stats *func_table[HASH_SIZE];
static unsigned long total_entries = 0;
static unsigned long total_exits = 0;

/* Configuration */
static int max_depth = DEFAULT_DEPTH;
static int buffer_kb = DEFAULT_BUFFER_KB;
static int duration = DEFAULT_DURATION;
static char filter_str[MAX_FILTER_LEN] = "";

/* Track current call depths per-CPU */
static int current_depth[MAX_CPUS];

/* Forward declarations */
static void generate_report(const char *trigger);
static int ktrace_init(void *arg);
static void ktrace_fini(void);

/* Find tracefs mount point */
static int find_tracefs(void)
{
    struct statfs fs;
    
    if (tracefs_dir)
        return 0;
    
    if (!statfs(TRACEFS_PATH, &fs) && fs.f_type == TRACEFS_MAGIC) {
        tracefs_dir = strdup(TRACEFS_PATH);
        return 0;
    }
    
    if (!statfs(OLD_TRACEFS_PATH, &fs) && fs.f_type == TRACEFS_MAGIC) {
        tracefs_dir = strdup(OLD_TRACEFS_PATH);
        return 0;
    }
    
    fprintf(stderr, "[ktrace] Error: tracefs not found\n");
    return -1;
}

/* Write to tracefs file */
static int write_tracefs(const char *file, const char *val)
{
    char path[512];
    int fd;
    ssize_t len;
    
    snprintf(path, sizeof(path), "%s/%s", tracefs_dir, file);
    fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) {
        fprintf(stderr, "[ktrace] Failed to open %s: %s\n", path, strerror(errno));
        return -1;
    }
    
    len = strlen(val);
    if (write(fd, val, len) != len) {
        fprintf(stderr, "[ktrace] Failed to write to %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }
    
    close(fd);
    return 0;
}

/* Append to tracefs file */
static int append_tracefs(const char *file, const char *val)
{
    char path[512];
    int fd;
    ssize_t len;
    
    snprintf(path, sizeof(path), "%s/%s", tracefs_dir, file);
    fd = open(path, O_WRONLY | O_APPEND);
    if (fd < 0) {
        fprintf(stderr, "[ktrace] Failed to open %s: %s\n", path, strerror(errno));
        return -1;
    }
    
    len = strlen(val);
    if (write(fd, val, len) != len) {
        fprintf(stderr, "[ktrace] Failed to write to %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }
    
    close(fd);
    return 0;
}

/* Hash function for function names */
static unsigned int func_hash(const char *name)
{
    unsigned int h = 0;
    while (*name)
        h = h * 31 + (unsigned char)*name++;
    return h % HASH_SIZE;
}

/* Get or create function stats entry */
static struct kfunc_stats *get_func_stats(const char *name)
{
    unsigned int h = func_hash(name);
    struct kfunc_stats *fs;
    
    for (fs = func_table[h]; fs; fs = fs->next) {
        if (strcmp(fs->name, name) == 0)
            return fs;
    }
    
    /* Create new entry */
    fs = malloc(sizeof(*fs));
    if (!fs)
        return NULL;
    
    memset(fs, 0, sizeof(*fs));
    fs->name = strdup(name);
    fs->min_time_ns = (unsigned long)-1;
    fs->next = func_table[h];
    func_table[h] = fs;
    
    return fs;
}

/* Parse a line from trace_pipe (text format) */
/*
 * Format examples from function_graph tracer:
 *   1137221.778951 |   1) test_kt-372170 |   0.360 us    |    arch_counter_read();
 *   1137221.778953 |   1) test_kt-372170 |   3.720 us    |  } /* mutex_unlock * /
 *   1137221.778954 |   1) test_kt-372170 |               |  /* sys_exit: NR 64 = 1 * /
 *   1137221.778955 |   1) test_kt-372170 |               |  __arm64_sys_close() {
 */
static void parse_trace_line(const char *line)
{
    char funcname[256];
    int is_entry = 0;
    int is_exit = 0;
    unsigned long duration_ns = 0;
    const char *pipe_pos;
    const char *func_start;
    const char *p;
    
    funcname[0] = '\0';
    
    /* Find the last pipe character which precedes the actual content */
    pipe_pos = strrchr(line, '|');
    if (!pipe_pos)
        return;
    
    /* Move past the pipe and whitespace */
    func_start = pipe_pos + 1;
    while (*func_start == ' ' || *func_start == '\t')
        func_start++;
    
    /* Skip comment-only lines (like sys_enter/sys_exit annotations) */
    if (strncmp(func_start, "/*", 2) == 0)
        return;
    
    /* Check for function entry: "funcname() {" */
    if (strstr(func_start, "() {")) {
        is_entry = 1;
        /* Extract function name (everything before "(") */
        p = strchr(func_start, '(');
        if (p && p - func_start < 256 && p - func_start > 0) {
            size_t len = p - func_start;
            strncpy(funcname, func_start, len);
            funcname[len] = '\0';
        }
    }
    /* Check for inline function call: "funcname();" (with duration before) */
    else if (strstr(func_start, "();")) {
        is_entry = 1;
        is_exit = 1;  /* Inline functions are both entry and exit */
        /* Extract function name */
        p = strchr(func_start, '(');
        if (p && p - func_start < 256 && p - func_start > 0) {
            size_t len = p - func_start;
            strncpy(funcname, func_start, len);
            funcname[len] = '\0';
        }
        
        /* Extract duration from before the pipe (format: "0.360 us    |") */
        const char *dur_start = pipe_pos - 1;
        while (dur_start > line && *dur_start == ' ')
            dur_start--;
        while (dur_start > line && *dur_start != '|')
            dur_start--;
        if (*dur_start == '|') {
            dur_start++;
            while (*dur_start == ' ')
                dur_start++;
            char *endptr;
            double d = strtod(dur_start, &endptr);
            if (endptr != dur_start) {
                if (strstr(endptr, "us"))
                    duration_ns = (unsigned long)(d * 1000);
                else if (strstr(endptr, "ms"))
                    duration_ns = (unsigned long)(d * 1000000);
                else if (strstr(endptr, "ns"))
                    duration_ns = (unsigned long)d;
            }
        }
    }
    /* Check for function exit: "} /* funcname * /" */
    else if (func_start[0] == '}') {
        is_exit = 1;
        /* Extract function name from comment */
        const char *comment = strstr(func_start, "/*");
        if (comment) {
            comment += 2;
            while (*comment == ' ')
                comment++;
            /* Find end of function name (space or *) */
            p = comment;
            while (*p && *p != ' ' && *p != '*' && *p != '\n')
                p++;
            if (p - comment < 256 && p - comment > 0) {
                size_t len = p - comment;
                strncpy(funcname, comment, len);
                funcname[len] = '\0';
            }
        }
        
        /* Extract duration from before the last pipe */
        const char *dur_start = pipe_pos - 1;
        while (dur_start > line && *dur_start == ' ')
            dur_start--;
        while (dur_start > line && *dur_start != '|')
            dur_start--;
        if (*dur_start == '|') {
            dur_start++;
            while (*dur_start == ' ')
                dur_start++;
            char *endptr;
            double d = strtod(dur_start, &endptr);
            if (endptr != dur_start) {
                if (strstr(endptr, "us"))
                    duration_ns = (unsigned long)(d * 1000);
                else if (strstr(endptr, "ms"))
                    duration_ns = (unsigned long)(d * 1000000);
                else if (strstr(endptr, "ns"))
                    duration_ns = (unsigned long)d;
            }
        }
    } else {
        return;  /* Unrecognized line format */
    }
    
    /* Skip empty function names */
    if (funcname[0] == '\0')
        return;
    
    pthread_mutex_lock(&lock);
    
    if (is_entry) {
        total_entries++;
        struct kfunc_stats *fs = get_func_stats(funcname);
        if (fs)
            fs->count++;
    }
    
    if (is_exit) {
        total_exits++;
        if (duration_ns > 0) {
            struct kfunc_stats *fs = get_func_stats(funcname);
            if (fs) {
                fs->total_time_ns += duration_ns;
                if (duration_ns < fs->min_time_ns)
                    fs->min_time_ns = duration_ns;
                if (duration_ns > fs->max_time_ns)
                    fs->max_time_ns = duration_ns;
            }
        }
    }
    
    pthread_mutex_unlock(&lock);
}

/* Reader thread - reads from trace_pipe (text format) */
static void *reader_thread_func(void *arg)
{
    char path[512];
    char buffer[READ_BUFFER_SIZE];
    FILE *fp;
    
    (void)arg;
    
    snprintf(path, sizeof(path), "%s/trace_pipe", tracefs_dir);
    fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "[ktrace] Failed to open trace_pipe: %s\n", strerror(errno));
        return NULL;
    }
    
    fprintf(stderr, "[ktrace] Reader thread started\n");
    
    while (running) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            parse_trace_line(buffer);
            
            /* Also log to file */
            if (logfile) {
                fputs(buffer, logfile);
            }
        } else {
            if (feof(fp))
                clearerr(fp);
            usleep(1000);  /* Small delay on EOF */
        }
    }
    
    fclose(fp);
    fprintf(stderr, "[ktrace] Reader thread stopped\n");
    
    return NULL;
}

/* Reset ftrace configuration */
static int reset_tracefs(void)
{
    /* Stop tracing */
    write_tracefs("tracing_on", "0");
    
    /* Reset to nop tracer */
    write_tracefs("current_tracer", "nop");
    
    /* Clear filters */
    write_tracefs("set_ftrace_filter", " ");
    write_tracefs("set_ftrace_pid", " ");
    write_tracefs("set_graph_function", " ");
    write_tracefs("max_graph_depth", "0");
    
    /* Clear events */
    write_tracefs("set_event", " ");
    write_tracefs("set_event_pid", " ");
    
    /* Clear trace buffer */
    write_tracefs("trace", "0");
    
    return 0;
}

/* Default kernel function filters for user-process tracing */
static const char *default_filters[] = {
    /* System calls entry points (most important for user-space) */
    "__x64_sys_*",
    "__arm64_sys_*",
    "ksys_*",
    
    /* VFS layer - file operations */
    "vfs_read",
    "vfs_write",
    "vfs_open",
    "vfs_close",
    "vfs_stat",
    "vfs_fstat",
    "vfs_lseek",
    "vfs_fsync",
    "do_sys_open",
    "do_sys_openat2",
    "do_filp_open",
    "path_openat",
    
    /* Memory management */
    "do_mmap",
    "do_munmap",
    "do_brk_flags",
    "handle_mm_fault",
    "do_page_fault",
    "__do_page_fault",
    "do_anonymous_page",
    "do_wp_page",
    
    /* Process/thread */
    "do_fork",
    "_do_fork",
    "kernel_clone",
    "do_exit",
    "do_execve",
    "do_execveat",
    "__set_current_blocked",
    "do_sigaction",
    "do_signal",
    
    /* Scheduler */
    "schedule",
    "__schedule",
    "wake_up_process",
    "try_to_wake_up",
    "finish_task_switch",
    
    /* Network */
    "sock_sendmsg",
    "sock_recvmsg",
    "__sys_socket",
    "__sys_connect",
    "__sys_accept4",
    "__sys_bind",
    "__sys_listen",
    
    /* I/O */
    "do_select",
    "do_poll",
    "do_epoll_wait",
    "do_epoll_ctl",
    
    /* IPC */
    "do_pipe2",
    "do_futex",
    
    NULL  /* Terminator */
};

/* Default kernel events to enable */
static const char *default_events[] = {
    /* Syscall events */
    "raw_syscalls:sys_enter",
    "raw_syscalls:sys_exit",
    
    /* Scheduler events */
    "sched:sched_switch",
    "sched:sched_wakeup",
    "sched:sched_process_fork",
    "sched:sched_process_exec",
    "sched:sched_process_exit",
    
    /* Signal events */
    "signal:signal_generate",
    "signal:signal_deliver",
    
    /* Page fault events */
    "exceptions:page_fault_user",
    
    NULL  /* Terminator */
};

/* Setup kernel tracing */
static int setup_tracing(void)
{
    char buf[64];
    pid_t pid = getpid();
    int i;
    int filters_added = 0;
    int events_added = 0;
    
    fprintf(stderr, "[ktrace] Setting up kernel tracing for PID %d\n", pid);
    
    /* Reset first */
    reset_tracefs();
    
    /* Set trace clock */
    if (write_tracefs("trace_clock", "mono") < 0) {
        fprintf(stderr, "[ktrace] Warning: failed to set trace clock\n");
    }
    
    /* Set buffer size */
    snprintf(buf, sizeof(buf), "%d", buffer_kb);
    if (write_tracefs("buffer_size_kb", buf) < 0) {
        fprintf(stderr, "[ktrace] Warning: failed to set buffer size\n");
    }
    
    /* Set PID filter */
    snprintf(buf, sizeof(buf), "%d", pid);
    if (append_tracefs("set_ftrace_pid", buf) < 0) {
        fprintf(stderr, "[ktrace] Failed to set PID filter\n");
        return -1;
    }
    
    /* Also set event PID filter (for tracepoints) */
    append_tracefs("set_event_pid", buf);
    
    /* Set depth limit */
    snprintf(buf, sizeof(buf), "%d", max_depth);
    if (write_tracefs("max_graph_depth", buf) < 0) {
        fprintf(stderr, "[ktrace] Warning: failed to set max depth\n");
    }
    
    /* Set function filter if specified by user */
    if (filter_str[0]) {
        char *token, *saveptr;
        char filter_copy[MAX_FILTER_LEN];
        
        strncpy(filter_copy, filter_str, sizeof(filter_copy) - 1);
        filter_copy[sizeof(filter_copy) - 1] = '\0';
        
        token = strtok_r(filter_copy, ",", &saveptr);
        while (token) {
            while (*token == ' ')
                token++;
            if (*token) {
                if (append_tracefs("set_graph_function", token) == 0) {
                    fprintf(stderr, "[ktrace] Added user filter: %s\n", token);
                    filters_added++;
                }
            }
            token = strtok_r(NULL, ",", &saveptr);
        }
    } else {
        /* Use default filters for user-process tracing */
        fprintf(stderr, "[ktrace] Enabling default kernel function filters...\n");
        for (i = 0; default_filters[i] != NULL; i++) {
            if (append_tracefs("set_graph_function", default_filters[i]) == 0) {
                filters_added++;
            }
        }
        fprintf(stderr, "[ktrace] Added %d default function filters\n", filters_added);
    }
    
    /* Enable default kernel events (tracepoints) */
    fprintf(stderr, "[ktrace] Enabling default kernel events...\n");
    for (i = 0; default_events[i] != NULL; i++) {
        if (append_tracefs("set_event", default_events[i]) == 0) {
            events_added++;
        }
    }
    fprintf(stderr, "[ktrace] Enabled %d kernel events\n", events_added);
    
    /* Enable function_graph tracer */
    if (write_tracefs("current_tracer", "function_graph") < 0) {
        fprintf(stderr, "[ktrace] Failed to enable function_graph tracer\n");
        return -1;
    }
    
    /* Enable options */
    write_tracefs("options/function-fork", "1");
    write_tracefs("options/event-fork", "1");
    write_tracefs("options/funcgraph-proc", "1");
    write_tracefs("options/funcgraph-tail", "1");
    write_tracefs("options/funcgraph-abstime", "1");
    
    /* Start tracing */
    if (write_tracefs("tracing_on", "1") < 0) {
        fprintf(stderr, "[ktrace] Failed to enable tracing\n");
        return -1;
    }
    
    fprintf(stderr, "[ktrace] Kernel tracing enabled (%d filters, %d events)\n", 
            filters_added, events_added);
    return 0;
}

/* Stop kernel tracing */
static void stop_tracing(void)
{
    write_tracefs("tracing_on", "0");
    fprintf(stderr, "[ktrace] Kernel tracing disabled\n");
}

/* Comparison for sorting by count */
static int compare_by_count(const void *a, const void *b)
{
    const struct kfunc_stats *fa = *(const struct kfunc_stats **)a;
    const struct kfunc_stats *fb = *(const struct kfunc_stats **)b;
    
    if (fb->count > fa->count)
        return 1;
    if (fb->count < fa->count)
        return -1;
    return 0;
}

/* Generate report */
static void generate_report(const char *trigger)
{
    FILE *f;
    struct kfunc_stats **sorted;
    struct kfunc_stats *fs;
    int count = 0;
    int i;
    time_t now = time(NULL);
    double elapsed = difftime(now, start_time);
    
    /* Count entries */
    pthread_mutex_lock(&lock);
    for (i = 0; i < HASH_SIZE; i++) {
        for (fs = func_table[i]; fs; fs = fs->next) {
            if (fs->count > 0)
                count++;
        }
    }
    
    if (count == 0) {
        pthread_mutex_unlock(&lock);
        fprintf(stderr, "[ktrace] No kernel functions traced yet\n");
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
    for (i = 0; i < HASH_SIZE; i++) {
        for (fs = func_table[i]; fs; fs = fs->next) {
            if (fs->count > 0)
                sorted[count++] = fs;
        }
    }
    pthread_mutex_unlock(&lock);
    
    /* Sort by count */
    qsort(sorted, count, sizeof(*sorted), compare_by_count);
    
    /* Write report */
    f = fopen("/tmp/ktrace_report.txt", "w");
    if (!f) {
        free(sorted);
        return;
    }
    
    fprintf(f, "============================================================\n");
    fprintf(f, "           KERNEL FUNCTION TRACE REPORT\n");
    fprintf(f, "============================================================\n\n");
    fprintf(f, "Trigger:           %s\n", trigger);
    fprintf(f, "Elapsed Time:      %.1f seconds\n", elapsed);
    fprintf(f, "Total Entries:     %lu\n", total_entries);
    fprintf(f, "Total Exits:       %lu\n", total_exits);
    fprintf(f, "Unique Functions:  %d\n", count);
    fprintf(f, "Max Depth:         %d\n", max_depth);
    if (filter_str[0])
        fprintf(f, "Filter:            %s\n", filter_str);
    fprintf(f, "\n");
    
    fprintf(f, "------------------------------------------------------------\n");
    fprintf(f, "TOP 50 KERNEL FUNCTIONS (by call count)\n");
    fprintf(f, "------------------------------------------------------------\n\n");
    
    fprintf(f, "%8s  %12s  %12s  %12s  %s\n", 
            "Rank", "Count", "Total (ns)", "Avg (ns)", "Function");
    fprintf(f, "%8s  %12s  %12s  %12s  %s\n",
            "----", "-----", "----------", "--------", "--------");
    
    for (i = 0; i < count && i < 50; i++) {
        fs = sorted[i];
        unsigned long avg = fs->count > 0 ? fs->total_time_ns / fs->count : 0;
        
        fprintf(f, "%8d  %12lu  %12lu  %12lu  %s\n",
                i + 1, fs->count, fs->total_time_ns, avg,
                fs->name ? fs->name : "(unknown)");
    }
    
    fprintf(f, "\n");
    fprintf(f, "------------------------------------------------------------\n");
    fprintf(f, "Full trace log: /tmp/ktrace_trace.log\n");
    fprintf(f, "------------------------------------------------------------\n");
    
    fclose(f);
    free(sorted);
    
    fprintf(stderr, "[ktrace] Report generated: /tmp/ktrace_report.txt "
            "(%d functions, %lu calls)\n", count, total_entries);
}

/* List available kernel functions */
static void list_available_functions(void)
{
    FILE *fp;
    char path[512];
    char line[256];
    int count = 0;
    
    snprintf(path, sizeof(path), "%s/available_filter_functions", tracefs_dir);
    fp = fopen(path, "r");
    if (!fp)
        return;
    
    FILE *out = fopen("/tmp/ktrace_functions.txt", "w");
    if (!out) {
        fclose(fp);
        return;
    }
    
    fprintf(out, "Available Kernel Functions for Tracing:\n");
    fprintf(out, "========================================\n\n");
    
    while (fgets(line, sizeof(line), fp)) {
        fputs(line, out);
        count++;
        if (count >= MAX_FUNCTIONS) {
            fprintf(out, "\n... (truncated, showing first %d functions)\n", MAX_FUNCTIONS);
            break;
        }
    }
    
    fclose(fp);
    fclose(out);
    
    fprintf(stderr, "[ktrace] Available functions list: /tmp/ktrace_functions.txt (%d functions)\n", count);
}

/* Read configuration from environment */
static void read_config(void)
{
    const char *val;
    
    val = getenv("KTRACE_FILTER");
    if (val) {
        strncpy(filter_str, val, sizeof(filter_str) - 1);
        filter_str[sizeof(filter_str) - 1] = '\0';
    }
    
    val = getenv("KTRACE_DEPTH");
    if (val) {
        max_depth = atoi(val);
        if (max_depth < 1)
            max_depth = 1;
        if (max_depth > 20)
            max_depth = 20;
    }
    
    val = getenv("KTRACE_BUFFER_KB");
    if (val) {
        buffer_kb = atoi(val);
        if (buffer_kb < 128)
            buffer_kb = 128;
        if (buffer_kb > 65536)
            buffer_kb = 65536;
    }
    
    val = getenv("KTRACE_DURATION");
    if (val) {
        duration = atoi(val);
        if (duration < 0)
            duration = 0;
    }
}

/* Signal handlers */
static void signal_handler(int sig)
{
    if (sig == SIGUSR1) {
        generate_report("SIGUSR1 signal");
    } else if (sig == SIGUSR2) {
        running = 0;
        generate_report("SIGUSR2 signal");
    }
}

/* Duration timer thread */
static void *timer_thread_func(void *arg)
{
    int d = *(int *)arg;
    
    sleep(d);
    
    if (running) {
        fprintf(stderr, "[ktrace] Duration timer expired (%d seconds)\n", d);
        running = 0;
    }
    
    return NULL;
}

/* Plugin initialization */
static int ktrace_init(void *arg)
{
    pthread_t timer_thread;
    
    (void)arg;
    
    /* Suppress warnings for unused variables during initialization */
    (void)trace_fds;
    (void)nr_cpus;
    (void)current_depth;
    
    /* Check for root privileges */
    if (geteuid() != 0) {
        fprintf(stderr, "[ktrace] Warning: Not running as root. Kernel tracing may fail.\n");
    }
    
    /* Read configuration */
    read_config();
    
    /* Find tracefs */
    if (find_tracefs() < 0) {
        return -1;
    }
    
    fprintf(stderr, "[ktrace] Using tracefs at: %s\n", tracefs_dir);
    
    /* List available functions for reference */
    list_available_functions();
    
    /* Open log file */
    logfile = fopen("/tmp/ktrace_trace.log", "w");
    if (!logfile) {
        fprintf(stderr, "[ktrace] Warning: Failed to open trace log file\n");
    }
    
    /* Setup signal handlers */
    signal(SIGUSR1, signal_handler);
    signal(SIGUSR2, signal_handler);
    
    start_time = time(NULL);
    
    /* Setup kernel tracing */
    if (setup_tracing() < 0) {
        fprintf(stderr, "[ktrace] Failed to setup kernel tracing\n");
        if (logfile)
            fclose(logfile);
        return -1;
    }
    
    /* Start reader thread */
    running = 1;
    enabled = 1;
    if (pthread_create(&reader_thread, NULL, reader_thread_func, NULL) != 0) {
        fprintf(stderr, "[ktrace] Failed to create reader thread\n");
        stop_tracing();
        reset_tracefs();
        if (logfile)
            fclose(logfile);
        return -1;
    }
    
    /* Start duration timer if set */
    if (duration > 0) {
        pthread_create(&timer_thread, NULL, timer_thread_func, &duration);
        pthread_detach(timer_thread);
    }
    
    fprintf(stderr, "[ktrace] Kernel function tracing enabled\n");
    fprintf(stderr, "[ktrace] Configuration:\n");
    fprintf(stderr, "[ktrace]   Max depth: %d\n", max_depth);
    fprintf(stderr, "[ktrace]   Buffer: %d KB\n", buffer_kb);
    fprintf(stderr, "[ktrace]   Duration: %d seconds (0=unlimited)\n", duration);
    if (filter_str[0])
        fprintf(stderr, "[ktrace]   Filter: %s\n", filter_str);
    fprintf(stderr, "[ktrace] SIGUSR1 = generate report, SIGUSR2 = stop and report\n");
    
    return 0;
}

/* Plugin cleanup */
static void ktrace_fini(void)
{
    /* Suppress warning for enabled */
    (void)enabled;
    
    /* Stop reader thread */
    running = 0;
    pthread_join(reader_thread, NULL);
    
    /* Stop and reset tracing */
    stop_tracing();
    reset_tracefs();
    
    /* Generate final report */
    generate_report("Plugin unload");
    
    /* Cleanup log file */
    if (logfile) {
        fclose(logfile);
        logfile = NULL;
    }
    
    /* Free statistics */
    for (int i = 0; i < HASH_SIZE; i++) {
        struct kfunc_stats *fs = func_table[i];
        while (fs) {
            struct kfunc_stats *next = fs->next;
            if (fs->name)
                free(fs->name);
            free(fs);
            fs = next;
        }
        func_table[i] = NULL;
    }
    
    if (tracefs_dir) {
        free(tracefs_dir);
        tracefs_dir = NULL;
    }
    
    fprintf(stderr, "[ktrace] Kernel function tracing disabled\n");
}

/* Hook and feature tables */
struct uftrace_hook uftrace_hooks[] = {};
int uftrace_hooks_count = 0;

struct uftrace_feature uftrace_features[] = {
    { "ktrace", ktrace_init, ktrace_fini, NULL },
};
int uftrace_features_count = 1;

/* Auto-init on library load */
__attribute__((constructor))
static void plugin_init(void)
{
    ktrace_init(NULL);
}

__attribute__((destructor))
static void plugin_fini(void)
{
    ktrace_fini();
}
