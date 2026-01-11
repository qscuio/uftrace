/*
 * Memory Leak Detection Plugin for uftrace inject (v2)
 * 
 * Improved detection: Tracks allocation growth over time by periodically
 * scanning the allocation database and comparing snapshots. Reports stack
 * traces that show continuous memory growth (likely leaks) vs stable
 * allocations (legitimate long-lived memory).
 *
 * Build:
 *   gcc -shared -fPIC -rdynamic -o memleak.so memleak.c -ldl -lpthread
 *
 * Usage:
 *   uftrace inject <PID> --lib /path/to/memleak.so
 *
 * Output:
 *   - /tmp/memleak.log - real-time allocation log
 *   - /tmp/memleak_growth.txt - periodic growth report (every 10 seconds)
 *   - SIGUSR1 - force immediate growth report
 *   - SIGUSR2 - dump all current allocations
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
#define MAX_STACK_DEPTH 16
#define HASH_TABLE_SIZE 65536
#define SCAN_INTERVAL_SEC 10
#define MAX_SNAPSHOTS 6  /* Keep last N snapshots for trend analysis */
#define GROWTH_THRESHOLD 3  /* Report if growing for N consecutive snapshots */

/* Allocation record - tracks individual allocations */
struct alloc_record {
    void *ptr;
    size_t size;
    void *stack[MAX_STACK_DEPTH];
    int stack_depth;
    time_t alloc_time;
    struct alloc_record *next;
};

/* Stack statistics - groups allocations by call stack */
struct stack_stats {
    void *stack[MAX_STACK_DEPTH];
    int stack_depth;
    
    /* Current state */
    size_t current_bytes;
    size_t current_count;
    
    /* Historical snapshots for trend analysis */
    size_t snapshot_bytes[MAX_SNAPSHOTS];
    size_t snapshot_count[MAX_SNAPSHOTS];
    int snapshot_idx;
    int snapshots_taken;
    
    /* Growth detection */
    int consecutive_growth;
    int reported_as_leak;
    
    struct stack_stats *next;
};

/* Global state */
static struct alloc_record *alloc_table[HASH_TABLE_SIZE];
static struct stack_stats *stack_table[HASH_TABLE_SIZE];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t scanner_thread;
static int scanner_running = 0;
static FILE *logfile = NULL;
static int enabled = 0;
static time_t start_time;

/* Statistics */
static size_t total_allocs = 0;
static size_t total_frees = 0;
static size_t peak_bytes = 0;
static size_t current_bytes = 0;

/* Original function pointers */
static void *(*real_malloc)(size_t) = NULL;
static void (*real_free)(void *) = NULL;

/* Hash functions */
static unsigned int ptr_hash(void *ptr)
{
    unsigned long val = (unsigned long)ptr;
    return (val ^ (val >> 16)) % HASH_TABLE_SIZE;
}

static unsigned int stack_hash(void **stack, int depth)
{
    unsigned long hash = 0;
    int i;
    for (i = 0; i < depth; i++) {
        hash ^= (unsigned long)stack[i];
        hash = (hash << 7) | (hash >> 57);
    }
    return hash % HASH_TABLE_SIZE;
}

static int stack_equal(void **s1, int d1, void **s2, int d2)
{
    if (d1 != d2) return 0;
    return memcmp(s1, s2, d1 * sizeof(void *)) == 0;
}

/* Get or create stack statistics entry */
static struct stack_stats *get_stack_stats(void **stack, int depth)
{
    unsigned int h = stack_hash(stack, depth);
    struct stack_stats *s;

    for (s = stack_table[h]; s; s = s->next) {
        if (stack_equal(s->stack, s->stack_depth, stack, depth))
            return s;
    }

    s = real_malloc(sizeof(*s));
    if (!s) return NULL;
    
    memset(s, 0, sizeof(*s));
    memcpy(s->stack, stack, depth * sizeof(void *));
    s->stack_depth = depth;
    s->next = stack_table[h];
    stack_table[h] = s;

    return s;
}

/* Record allocation */
static void record_alloc(void *ptr, size_t size, void **stack, int depth)
{
    unsigned int h = ptr_hash(ptr);
    struct alloc_record *rec;
    struct stack_stats *stats;

    rec = real_malloc(sizeof(*rec));
    if (!rec) return;

    rec->ptr = ptr;
    rec->size = size;
    memcpy(rec->stack, stack, depth * sizeof(void *));
    rec->stack_depth = depth;
    rec->alloc_time = time(NULL);
    
    pthread_mutex_lock(&lock);
    
    rec->next = alloc_table[h];
    alloc_table[h] = rec;
    
    stats = get_stack_stats(stack, depth);
    if (stats) {
        stats->current_bytes += size;
        stats->current_count++;
    }
    
    total_allocs++;
    current_bytes += size;
    if (current_bytes > peak_bytes)
        peak_bytes = current_bytes;
    
    pthread_mutex_unlock(&lock);
}

/* Remove allocation record */
static struct alloc_record *remove_alloc(void *ptr)
{
    unsigned int h = ptr_hash(ptr);
    struct alloc_record *rec, *prev = NULL;
    struct stack_stats *stats;

    pthread_mutex_lock(&lock);
    
    for (rec = alloc_table[h]; rec; prev = rec, rec = rec->next) {
        if (rec->ptr == ptr) {
            if (prev)
                prev->next = rec->next;
            else
                alloc_table[h] = rec->next;
            
            stats = get_stack_stats(rec->stack, rec->stack_depth);
            if (stats) {
                stats->current_bytes -= rec->size;
                stats->current_count--;
            }
            
            total_frees++;
            current_bytes -= rec->size;
            
            pthread_mutex_unlock(&lock);
            return rec;
        }
    }
    
    pthread_mutex_unlock(&lock);
    return NULL;
}

/* Print call stack */
static void print_stack(FILE *f, void **stack, int depth)
{
    char **symbols = backtrace_symbols(stack, depth);
    int i;
    
    if (symbols) {
        for (i = 0; i < depth; i++)
            fprintf(f, "    #%d %s\n", i, symbols[i]);
        real_free(symbols);
    } else {
        for (i = 0; i < depth; i++)
            fprintf(f, "    #%d %p\n", i, stack[i]);
    }
}

/* Take snapshot and analyze growth */
static void take_snapshot_and_analyze(FILE *report)
{
    struct stack_stats *s;
    int i;
    int leak_count = 0;
    time_t now = time(NULL);
    
    fprintf(report, "\n=== Memory Growth Report (T+%ld sec) ===\n", 
            now - start_time);
    fprintf(report, "Current memory: %zu bytes (%zu allocs)\n",
            current_bytes, total_allocs - total_frees);
    fprintf(report, "Peak memory: %zu bytes\n\n", peak_bytes);

    pthread_mutex_lock(&lock);
    
    /* Update snapshots for all stacks */
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        for (s = stack_table[i]; s; s = s->next) {
            int idx = s->snapshot_idx;
            size_t prev_bytes = 0;
            
            /* Get previous snapshot value */
            if (s->snapshots_taken > 0) {
                int prev_idx = (idx + MAX_SNAPSHOTS - 1) % MAX_SNAPSHOTS;
                prev_bytes = s->snapshot_bytes[prev_idx];
            }
            
            /* Store current snapshot */
            s->snapshot_bytes[idx] = s->current_bytes;
            s->snapshot_count[idx] = s->current_count;
            s->snapshot_idx = (idx + 1) % MAX_SNAPSHOTS;
            if (s->snapshots_taken < MAX_SNAPSHOTS)
                s->snapshots_taken++;
            
            /* Check for growth */
            if (s->current_bytes > prev_bytes && prev_bytes > 0) {
                s->consecutive_growth++;
            } else if (s->current_bytes < prev_bytes) {
                s->consecutive_growth = 0;  /* Reset if shrinking */
            }
            
            /* Report suspected leaks (continuous growth) */
            if (s->consecutive_growth >= GROWTH_THRESHOLD && 
                s->current_bytes > 0 && !s->reported_as_leak) {
                
                leak_count++;
                fprintf(report, "--- SUSPECTED LEAK #%d ---\n", leak_count);
                fprintf(report, "Current: %zu bytes (%zu allocations)\n",
                        s->current_bytes, s->current_count);
                fprintf(report, "Growth: continuous for %d snapshots\n",
                        s->consecutive_growth);
                
                /* Show growth history */
                fprintf(report, "History: ");
                for (int j = 0; j < s->snapshots_taken; j++) {
                    int hi = (s->snapshot_idx - s->snapshots_taken + j + MAX_SNAPSHOTS) % MAX_SNAPSHOTS;
                    fprintf(report, "%zu ", s->snapshot_bytes[hi]);
                }
                fprintf(report, "bytes\n");
                
                fprintf(report, "Allocation call stack:\n");
                print_stack(report, s->stack, s->stack_depth);
                fprintf(report, "\n");
                
                s->reported_as_leak = 1;
            }
        }
    }
    
    pthread_mutex_unlock(&lock);
    
    if (leak_count == 0) {
        fprintf(report, "No new memory leaks detected.\n");
    } else {
        fprintf(report, "\nTotal suspected leaks: %d\n", leak_count);
    }
    
    fprintf(report, "=== End Report ===\n\n");
    fflush(report);
}

/* Dump all current allocations */
static void dump_all_allocations(void)
{
    FILE *f = fopen("/tmp/memleak_dump.txt", "w");
    struct stack_stats *s;
    int i, count = 0;
    
    if (!f) return;
    
    fprintf(f, "=== All Active Allocations ===\n\n");
    
    pthread_mutex_lock(&lock);
    
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        for (s = stack_table[i]; s; s = s->next) {
            if (s->current_count > 0) {
                count++;
                fprintf(f, "--- Allocation Site #%d ---\n", count);
                fprintf(f, "Bytes: %zu, Count: %zu\n", 
                        s->current_bytes, s->current_count);
                fprintf(f, "Consecutive growth snapshots: %d\n",
                        s->consecutive_growth);
                fprintf(f, "Call stack:\n");
                print_stack(f, s->stack, s->stack_depth);
                fprintf(f, "\n");
            }
        }
    }
    
    pthread_mutex_unlock(&lock);
    
    fprintf(f, "Total allocation sites: %d\n", count);
    fclose(f);
    
    fprintf(stderr, "[memleak] Dumped %d allocation sites to /tmp/memleak_dump.txt\n", count);
}

/* Background scanner thread */
static void *scanner_thread_func(void *arg)
{
    FILE *report;
    
    (void)arg;
    
    report = fopen("/tmp/memleak_growth.txt", "w");
    if (!report) {
        fprintf(stderr, "[memleak] Failed to open growth report file\n");
        return NULL;
    }
    
    fprintf(report, "=== Memory Leak Growth Monitor ===\n");
    fprintf(report, "Started at: %s", ctime(&start_time));
    fprintf(report, "Scan interval: %d seconds\n", SCAN_INTERVAL_SEC);
    fprintf(report, "Growth threshold: %d consecutive snapshots\n\n", GROWTH_THRESHOLD);
    fflush(report);
    
    while (scanner_running) {
        sleep(SCAN_INTERVAL_SEC);
        
        if (!scanner_running) break;
        
        take_snapshot_and_analyze(report);
    }
    
    /* Final report */
    fprintf(report, "\n=== FINAL REPORT ===\n");
    take_snapshot_and_analyze(report);
    fclose(report);
    
    return NULL;
}

/* Signal handlers */
static void sig_handler(int sig)
{
    if (sig == SIGUSR1) {
        FILE *f = fopen("/tmp/memleak_growth.txt", "a");
        if (f) {
            fprintf(stderr, "[memleak] Generating growth report...\n");
            take_snapshot_and_analyze(f);
            fclose(f);
        }
    } else if (sig == SIGUSR2) {
        dump_all_allocations();
    }
}

/* Hooked malloc */
void *hooked_malloc(size_t size)
{
    void *ptr;
    void *stack[MAX_STACK_DEPTH];
    int depth;

    if (!real_malloc)
        real_malloc = dlsym(RTLD_NEXT, "malloc");

    ptr = real_malloc(size);

    if (enabled && ptr) {
        depth = backtrace(stack, MAX_STACK_DEPTH);
        record_alloc(ptr, size, stack, depth);
        
        if (logfile) {
            fprintf(logfile, "[+] %p %zu\n", ptr, size);
            fflush(logfile);
        }
    }

    return ptr;
}

/* Hooked free */
void hooked_free(void *ptr)
{
    struct alloc_record *rec;

    if (!real_free)
        real_free = dlsym(RTLD_NEXT, "free");

    if (ptr && enabled) {
        rec = remove_alloc(ptr);
        
        if (logfile) {
            if (rec) {
                fprintf(logfile, "[-] %p %zu\n", ptr, rec->size);
                real_free(rec);
            }
            fflush(logfile);
        }
    }

    real_free(ptr);
}

/* Plugin initialization */
static int memleak_init(void *arg)
{
    (void)arg;

    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_free = dlsym(RTLD_NEXT, "free");

    if (!real_malloc || !real_free) {
        fprintf(stderr, "[memleak] Failed to get real malloc/free\n");
        return -1;
    }

    start_time = time(NULL);
    
    logfile = fopen("/tmp/memleak.log", "w");
    if (!logfile)
        fprintf(stderr, "[memleak] Warning: could not open log file\n");

    signal(SIGUSR1, sig_handler);
    signal(SIGUSR2, sig_handler);

    enabled = 1;
    scanner_running = 1;
    pthread_create(&scanner_thread, NULL, scanner_thread_func, NULL);

    fprintf(stderr, "[memleak] Memory leak detection v2 enabled\n");
    fprintf(stderr, "[memleak] Scanning every %d seconds for growth patterns\n", SCAN_INTERVAL_SEC);
    fprintf(stderr, "[memleak] SIGUSR1 = force report, SIGUSR2 = dump all allocations\n");
    fprintf(stderr, "[memleak] Log: /tmp/memleak.log\n");
    fprintf(stderr, "[memleak] Growth report: /tmp/memleak_growth.txt\n");

    return 0;
}

/* Plugin cleanup */
static void memleak_fini(void)
{
    scanner_running = 0;
    pthread_join(scanner_thread, NULL);
    
    enabled = 0;

    if (logfile) {
        fclose(logfile);
        logfile = NULL;
    }

    fprintf(stderr, "[memleak] Memory leak detection disabled\n");
}

/* Hook and feature tables */
struct uftrace_hook uftrace_hooks[] = {
    { "malloc", hooked_malloc, (void **)&real_malloc },
    { "free", hooked_free, (void **)&real_free },
};
int uftrace_hooks_count = 2;

struct uftrace_feature uftrace_features[] = {
    { "memleak", memleak_init, memleak_fini, NULL },
};
int uftrace_features_count = 1;

__attribute__((constructor))
static void plugin_init(void) { memleak_init(NULL); }

__attribute__((destructor))
static void plugin_fini(void) { memleak_fini(); }
