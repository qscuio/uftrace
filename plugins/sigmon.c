/*
 * Signal Monitor Plugin for uftrace inject
 * 
 * Monitors all signals received by the target process by hooking
 * sigaction() and signal() to wrap signal handlers.
 *
 * Build:
 *   gcc -shared -fPIC -rdynamic -o sigmon.so sigmon.c -ldl -lpthread
 *
 * Usage:
 *   uftrace inject <PID> --lib /path/to/sigmon.so
 *
 * Output:
 *   - /tmp/sigmon.log - Human-readable signal log
 *   - /tmp/sigmon_summary.txt - Summary of all signals received
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>

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
#define MAX_SIGNALS 64

/* Signal statistics */
struct signal_stats {
    unsigned long count;           /* Number of times received */
    struct timespec first_time;    /* First occurrence */
    struct timespec last_time;     /* Last occurrence */
    int has_handler;               /* Whether a handler is installed */
    void *handler;                 /* Original handler address */
};

static struct signal_stats sig_stats[MAX_SIGNALS];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static FILE *logfile = NULL;
static int enabled = 0;
static int initialized = 0;

/* Original function pointers */
static int (*real_sigaction)(int, const struct sigaction *, struct sigaction *) = NULL;
static sighandler_t (*real_signal)(int, sighandler_t) = NULL;

/* Saved original handlers and actions */
static struct sigaction original_actions[MAX_SIGNALS];
static int handler_installed[MAX_SIGNALS];

/* Signal name lookup */
static const char *signal_name(int sig)
{
    static const char *names[] = {
        [SIGHUP]    = "SIGHUP",
        [SIGINT]    = "SIGINT",
        [SIGQUIT]   = "SIGQUIT",
        [SIGILL]    = "SIGILL",
        [SIGTRAP]   = "SIGTRAP",
        [SIGABRT]   = "SIGABRT",
        [SIGBUS]    = "SIGBUS",
        [SIGFPE]    = "SIGFPE",
        [SIGKILL]   = "SIGKILL",
        [SIGUSR1]   = "SIGUSR1",
        [SIGSEGV]   = "SIGSEGV",
        [SIGUSR2]   = "SIGUSR2",
        [SIGPIPE]   = "SIGPIPE",
        [SIGALRM]   = "SIGALRM",
        [SIGTERM]   = "SIGTERM",
        [SIGSTKFLT] = "SIGSTKFLT",
        [SIGCHLD]   = "SIGCHLD",
        [SIGCONT]   = "SIGCONT",
        [SIGSTOP]   = "SIGSTOP",
        [SIGTSTP]   = "SIGTSTP",
        [SIGTTIN]   = "SIGTTIN",
        [SIGTTOU]   = "SIGTTOU",
        [SIGURG]    = "SIGURG",
        [SIGXCPU]   = "SIGXCPU",
        [SIGXFSZ]   = "SIGXFSZ",
        [SIGVTALRM] = "SIGVTALRM",
        [SIGPROF]   = "SIGPROF",
        [SIGWINCH]  = "SIGWINCH",
        [SIGIO]     = "SIGIO",
        [SIGPWR]    = "SIGPWR",
        [SIGSYS]    = "SIGSYS",
    };
    static char buf[32];
    
    if (sig > 0 && sig < MAX_SIGNALS && names[sig])
        return names[sig];
    
    /* Real-time signals */
    if (sig >= SIGRTMIN && sig <= SIGRTMAX) {
        snprintf(buf, sizeof(buf), "SIGRT%d", sig - SIGRTMIN);
        return buf;
    }
    
    snprintf(buf, sizeof(buf), "SIG%d", sig);
    return buf;
}

/* Get timestamp string */
static void get_timestamp(char *buf, size_t len)
{
    struct timespec ts;
    struct tm tm;
    
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    snprintf(buf, len, "%02d:%02d:%02d.%06ld",
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000);
}

/* Signal code to string (for siginfo_t) */
static const char *sigcode_str(int sig, int code)
{
    /* Common codes */
    switch (code) {
    case SI_USER:    return "SI_USER (kill/raise)";
    case SI_KERNEL:  return "SI_KERNEL";
    case SI_QUEUE:   return "SI_QUEUE (sigqueue)";
    case SI_TIMER:   return "SI_TIMER (timer)";
    case SI_MESGQ:   return "SI_MESGQ (mqueue)";
    case SI_ASYNCIO: return "SI_ASYNCIO";
    case SI_SIGIO:   return "SI_SIGIO";
    case SI_TKILL:   return "SI_TKILL (tkill/tgkill)";
    }
    
    /* Signal-specific codes */
    switch (sig) {
    case SIGILL:
        switch (code) {
        case ILL_ILLOPC: return "ILL_ILLOPC (illegal opcode)";
        case ILL_ILLOPN: return "ILL_ILLOPN (illegal operand)";
        case ILL_ILLADR: return "ILL_ILLADR (illegal addressing)";
        case ILL_ILLTRP: return "ILL_ILLTRP (illegal trap)";
        case ILL_PRVOPC: return "ILL_PRVOPC (privileged opcode)";
        case ILL_PRVREG: return "ILL_PRVREG (privileged register)";
        case ILL_COPROC: return "ILL_COPROC (coprocessor error)";
        case ILL_BADSTK: return "ILL_BADSTK (bad stack)";
        }
        break;
    case SIGFPE:
        switch (code) {
        case FPE_INTDIV: return "FPE_INTDIV (integer divide by zero)";
        case FPE_INTOVF: return "FPE_INTOVF (integer overflow)";
        case FPE_FLTDIV: return "FPE_FLTDIV (float divide by zero)";
        case FPE_FLTOVF: return "FPE_FLTOVF (float overflow)";
        case FPE_FLTUND: return "FPE_FLTUND (float underflow)";
        case FPE_FLTRES: return "FPE_FLTRES (float inexact result)";
        case FPE_FLTINV: return "FPE_FLTINV (float invalid operation)";
        case FPE_FLTSUB: return "FPE_FLTSUB (subscript out of range)";
        }
        break;
    case SIGSEGV:
        switch (code) {
        case SEGV_MAPERR: return "SEGV_MAPERR (address not mapped)";
        case SEGV_ACCERR: return "SEGV_ACCERR (invalid permissions)";
        }
        break;
    case SIGBUS:
        switch (code) {
        case BUS_ADRALN: return "BUS_ADRALN (invalid address alignment)";
        case BUS_ADRERR: return "BUS_ADRERR (nonexistent physical address)";
        case BUS_OBJERR: return "BUS_OBJERR (object-specific error)";
        }
        break;
    case SIGCHLD:
        switch (code) {
        case CLD_EXITED:    return "CLD_EXITED (child exited)";
        case CLD_KILLED:    return "CLD_KILLED (child killed)";
        case CLD_DUMPED:    return "CLD_DUMPED (child terminated abnormally)";
        case CLD_TRAPPED:   return "CLD_TRAPPED (traced child trapped)";
        case CLD_STOPPED:   return "CLD_STOPPED (child stopped)";
        case CLD_CONTINUED: return "CLD_CONTINUED (child continued)";
        }
        break;
    case SIGTRAP:
        switch (code) {
        case TRAP_BRKPT: return "TRAP_BRKPT (breakpoint)";
        case TRAP_TRACE: return "TRAP_TRACE (trace trap)";
        }
        break;
    }
    
    static char buf[32];
    snprintf(buf, sizeof(buf), "code=%d", code);
    return buf;
}

/* Log signal event */
static void log_signal(int sig, siginfo_t *info, void *ucontext)
{
    char ts[32];
    (void)ucontext;
    
    if (!logfile || !enabled)
        return;
    
    pthread_mutex_lock(&lock);
    
    get_timestamp(ts, sizeof(ts));
    
    /* Update statistics */
    sig_stats[sig].count++;
    clock_gettime(CLOCK_REALTIME, &sig_stats[sig].last_time);
    if (sig_stats[sig].count == 1)
        sig_stats[sig].first_time = sig_stats[sig].last_time;
    
    fprintf(logfile, "\n[%s] SIGNAL RECEIVED: %s (%d)\n", 
            ts, signal_name(sig), sig);
    fprintf(logfile, "  count:   #%lu\n", sig_stats[sig].count);
    
    if (info) {
        fprintf(logfile, "  si_code: %s\n", sigcode_str(sig, info->si_code));
        
        /* For user-sent signals, show sender info */
        if (info->si_code == SI_USER || info->si_code == SI_QUEUE ||
            info->si_code == SI_TKILL) {
            fprintf(logfile, "  si_pid:  %d (sender PID)\n", info->si_pid);
            fprintf(logfile, "  si_uid:  %d (sender UID)\n", info->si_uid);
        }
        
        /* For timer signals */
        if (info->si_code == SI_TIMER) {
            fprintf(logfile, "  timerid: %d\n", info->si_timerid);
            fprintf(logfile, "  overrun: %d\n", info->si_overrun);
        }
        
        /* For SIGCHLD */
        if (sig == SIGCHLD) {
            fprintf(logfile, "  si_pid:    %d (child PID)\n", info->si_pid);
            fprintf(logfile, "  si_status: %d\n", info->si_status);
        }
        
        /* For SIGSEGV, SIGBUS, SIGILL, SIGFPE - show fault address */
        if (sig == SIGSEGV || sig == SIGBUS || sig == SIGILL || sig == SIGFPE) {
            fprintf(logfile, "  si_addr: %p (fault address)\n", info->si_addr);
        }
        
        /* For SIGIO/SIGPOLL */
        if (sig == SIGIO) {
            fprintf(logfile, "  si_fd:   %d\n", info->si_fd);
            fprintf(logfile, "  si_band: %ld\n", info->si_band);
        }
    }
    
    /* Show thread info */
    fprintf(logfile, "  thread:  %ld (LWP)\n", (long)gettid());
    
    fflush(logfile);
    
    pthread_mutex_unlock(&lock);
}

/* Wrapper signal handler with siginfo */
static void wrapper_handler_sigaction(int sig, siginfo_t *info, void *ucontext)
{
    /* Log the signal first */
    log_signal(sig, info, ucontext);
    
    /* Call original handler if exists */
    if (sig >= 0 && sig < MAX_SIGNALS && handler_installed[sig]) {
        if (original_actions[sig].sa_flags & SA_SIGINFO) {
            /* Original handler uses siginfo */
            if (original_actions[sig].sa_sigaction)
                original_actions[sig].sa_sigaction(sig, info, ucontext);
        } else {
            /* Original handler is simple */
            if (original_actions[sig].sa_handler != SIG_DFL &&
                original_actions[sig].sa_handler != SIG_IGN) {
                original_actions[sig].sa_handler(sig);
            }
        }
    }
}

/* Wrapper signal handler without siginfo */
static void wrapper_handler_simple(int sig)
{
    /* Log the signal */
    log_signal(sig, NULL, NULL);
    
    /* Call original handler if exists */
    if (sig >= 0 && sig < MAX_SIGNALS && handler_installed[sig]) {
        if (original_actions[sig].sa_handler != SIG_DFL &&
            original_actions[sig].sa_handler != SIG_IGN) {
            original_actions[sig].sa_handler(sig);
        }
    }
}

/* Hooked sigaction() */
int hooked_sigaction(int sig, const struct sigaction *act, struct sigaction *oldact)
{
    int ret;
    struct sigaction wrapper_act;
    char ts[32];
    
    if (!real_sigaction)
        real_sigaction = dlsym(RTLD_NEXT, "sigaction");
    
    /* Skip our internal signals or invalid signals */
    if (sig <= 0 || sig >= MAX_SIGNALS || sig == SIGKILL || sig == SIGSTOP) {
        return real_sigaction(sig, act, oldact);
    }
    
    /* If getting old action, return the original one we saved */
    if (!act) {
        if (oldact && handler_installed[sig]) {
            *oldact = original_actions[sig];
            return 0;
        }
        return real_sigaction(sig, act, oldact);
    }
    
    /* Log the sigaction call */
    if (logfile && enabled) {
        get_timestamp(ts, sizeof(ts));
        pthread_mutex_lock(&lock);
        fprintf(logfile, "\n[%s] sigaction(%s, ", ts, signal_name(sig));
        if (act->sa_flags & SA_SIGINFO)
            fprintf(logfile, "handler=%p [SA_SIGINFO]", (void*)act->sa_sigaction);
        else if (act->sa_handler == SIG_DFL)
            fprintf(logfile, "SIG_DFL");
        else if (act->sa_handler == SIG_IGN)
            fprintf(logfile, "SIG_IGN");
        else
            fprintf(logfile, "handler=%p", (void*)act->sa_handler);
        fprintf(logfile, ")\n");
        fflush(logfile);
        pthread_mutex_unlock(&lock);
    }
    
    /* Return previously saved action if requested */
    if (oldact && handler_installed[sig]) {
        *oldact = original_actions[sig];
    } else if (oldact) {
        real_sigaction(sig, NULL, oldact);
    }
    
    /* Save the original action */
    original_actions[sig] = *act;
    handler_installed[sig] = 1;
    sig_stats[sig].has_handler = 1;
    sig_stats[sig].handler = (act->sa_flags & SA_SIGINFO) ?
                             (void*)act->sa_sigaction : (void*)act->sa_handler;
    
    /* Install our wrapper instead */
    memset(&wrapper_act, 0, sizeof(wrapper_act));
    wrapper_act.sa_sigaction = wrapper_handler_sigaction;
    wrapper_act.sa_flags = SA_SIGINFO | (act->sa_flags & ~SA_RESETHAND);
    sigemptyset(&wrapper_act.sa_mask);
    
    ret = real_sigaction(sig, &wrapper_act, NULL);
    
    return ret;
}

/* Hooked signal() */
sighandler_t hooked_signal(int sig, sighandler_t handler)
{
    sighandler_t old_handler;
    struct sigaction act, oldact;
    char ts[32];
    
    if (!real_signal)
        real_signal = dlsym(RTLD_NEXT, "signal");
    
    /* Skip invalid or unblockable signals */
    if (sig <= 0 || sig >= MAX_SIGNALS || sig == SIGKILL || sig == SIGSTOP) {
        return real_signal(sig, handler);
    }
    
    /* Log the signal call */
    if (logfile && enabled) {
        get_timestamp(ts, sizeof(ts));
        pthread_mutex_lock(&lock);
        fprintf(logfile, "\n[%s] signal(%s, ", ts, signal_name(sig));
        if (handler == SIG_DFL)
            fprintf(logfile, "SIG_DFL");
        else if (handler == SIG_IGN)
            fprintf(logfile, "SIG_IGN");
        else
            fprintf(logfile, "handler=%p", (void*)handler);
        fprintf(logfile, ")\n");
        fflush(logfile);
        pthread_mutex_unlock(&lock);
    }
    
    /* Get old handler */
    if (handler_installed[sig]) {
        old_handler = original_actions[sig].sa_handler;
    } else {
        /* Get current handler from system */
        real_sigaction(sig, NULL, &oldact);
        old_handler = oldact.sa_handler;
    }
    
    /* Save as sigaction */
    memset(&act, 0, sizeof(act));
    act.sa_handler = handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;
    
    original_actions[sig] = act;
    handler_installed[sig] = 1;
    sig_stats[sig].has_handler = 1;
    sig_stats[sig].handler = (void*)handler;
    
    /* Install our wrapper */
    memset(&act, 0, sizeof(act));
    act.sa_handler = wrapper_handler_simple;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;
    
    real_sigaction(sig, &act, NULL);
    
    return old_handler;
}

/* Print summary */
static void print_summary(void)
{
    FILE *f = fopen("/tmp/sigmon_summary.txt", "w");
    int i;
    unsigned long total = 0;
    
    if (!f) f = logfile;
    
    fprintf(f, "\n");
    fprintf(f, "╔════════════════════════════════════════════════════════════╗\n");
    fprintf(f, "║            Signal Monitor Summary                          ║\n");
    fprintf(f, "╠════════════════════════════════════════════════════════════╣\n");
    fprintf(f, "║ %-15s │ %10s │ %-8s │ %-15s ║\n", 
            "Signal", "Count", "Handler", "Last Received");
    fprintf(f, "╠════════════════════════════════════════════════════════════╣\n");
    
    for (i = 1; i < MAX_SIGNALS; i++) {
        if (sig_stats[i].count > 0 || sig_stats[i].has_handler) {
            struct tm tm;
            char time_buf[32] = "-";
            
            if (sig_stats[i].count > 0) {
                localtime_r(&sig_stats[i].last_time.tv_sec, &tm);
                snprintf(time_buf, sizeof(time_buf), "%02d:%02d:%02d",
                         tm.tm_hour, tm.tm_min, tm.tm_sec);
            }
            
            fprintf(f, "║ %-15s │ %10lu │ %-8s │ %-15s ║\n",
                    signal_name(i),
                    sig_stats[i].count,
                    sig_stats[i].has_handler ? "Yes" : "No",
                    time_buf);
            
            total += sig_stats[i].count;
        }
    }
    
    fprintf(f, "╠════════════════════════════════════════════════════════════╣\n");
    fprintf(f, "║ Total signals received: %-35lu ║\n", total);
    fprintf(f, "╚════════════════════════════════════════════════════════════╝\n");
    
    if (f != logfile)
        fclose(f);
}

/* Signal handler for our own use */
static void sigmon_handler(int sig)
{
    if (sig == SIGUSR2) {
        print_summary();
        fprintf(stderr, "[sigmon] Summary written to /tmp/sigmon_summary.txt\n");
    }
}

/* Install monitoring on existing handlers - only wrap handlers that are already installed */
static void install_monitors(void)
{
    struct sigaction old;
    int i;
    
    /* List of signals to check for existing handlers */
    int monitor_signals[] = {
        SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT,
        SIGBUS, SIGFPE, SIGUSR1, SIGSEGV, SIGPIPE, SIGALRM,
        SIGTERM, SIGCHLD, SIGCONT, SIGTSTP, SIGTTIN, SIGTTOU,
        SIGURG, SIGXCPU, SIGXFSZ, SIGVTALRM, SIGPROF, SIGWINCH,
        SIGIO, SIGPWR, SIGSYS,
        -1  /* Terminator */
    };
    
    /* For each signal, check if there's already a handler installed */
    for (i = 0; monitor_signals[i] != -1; i++) {
        int sig = monitor_signals[i];
        
        /* Skip unblockable signals */
        if (sig == SIGKILL || sig == SIGSTOP)
            continue;
        
        /* Skip SIGUSR2 which we use ourselves */
        if (sig == SIGUSR2)
            continue;
        
        /* Get current handler - just record it, don't wrap default handlers */
        if (real_sigaction(sig, NULL, &old) == 0) {
            /* Only wrap if there's an actual handler installed */
            if (old.sa_handler != SIG_DFL && old.sa_handler != SIG_IGN) {
                struct sigaction act;
                
                /* Save original */
                original_actions[sig] = old;
                handler_installed[sig] = 1;
                sig_stats[sig].has_handler = 1;
                sig_stats[sig].handler = (old.sa_flags & SA_SIGINFO) ?
                                         (void*)old.sa_sigaction : (void*)old.sa_handler;
                
                /* Install wrapper */
                memset(&act, 0, sizeof(act));
                act.sa_sigaction = wrapper_handler_sigaction;
                act.sa_flags = SA_SIGINFO | SA_RESTART;
                sigemptyset(&act.sa_mask);
                
                real_sigaction(sig, &act, NULL);
                
                if (logfile) {
                    char ts[32];
                    get_timestamp(ts, sizeof(ts));
                    fprintf(logfile, "[%s] Wrapped existing handler for %s\n",
                            ts, signal_name(sig));
                    fflush(logfile);
                }
            }
        }
    }
}

/* Plugin initialization */
static int sigmon_init(void *arg)
{
    (void)arg;
    
    if (initialized)
        return 0;
    initialized = 1;
    
    /* Get real function pointers */
    real_sigaction = dlsym(RTLD_NEXT, "sigaction");
    real_signal = dlsym(RTLD_NEXT, "signal");
    
    /* Initialize statistics */
    memset(sig_stats, 0, sizeof(sig_stats));
    memset(original_actions, 0, sizeof(original_actions));
    memset(handler_installed, 0, sizeof(handler_installed));
    
    /* Open log file */
    logfile = fopen("/tmp/sigmon.log", "a");
    if (!logfile) {
        fprintf(stderr, "[sigmon] Failed to open log file\n");
        return -1;
    }
    
    fprintf(logfile, "\n");
    fprintf(logfile, "═══════════════════════════════════════════════════════════\n");
    fprintf(logfile, "  Signal Monitor Started\n");
    fprintf(logfile, "  PID: %d\n", getpid());
    fprintf(logfile, "═══════════════════════════════════════════════════════════\n");
    fflush(logfile);
    
    enabled = 1;
    
    /* Install our SIGUSR2 handler for summary */
    signal(SIGUSR2, sigmon_handler);
    
    /* Wrap existing signal handlers */
    install_monitors();
    
    fprintf(stderr, "[sigmon] Signal monitoring enabled\n");
    fprintf(stderr, "[sigmon] Log: /tmp/sigmon.log\n");
    fprintf(stderr, "[sigmon] SIGUSR2 = print summary\n");
    
    return 0;
}

/* Plugin cleanup */
static void sigmon_fini(void)
{
    enabled = 0;
    
    print_summary();
    
    if (logfile) {
        fprintf(logfile, "\n═══════════════════════════════════════════════════════════\n");
        fprintf(logfile, "  Signal Monitor Stopped\n");
        fprintf(logfile, "═══════════════════════════════════════════════════════════\n");
        fclose(logfile);
        logfile = NULL;
    }
    
    fprintf(stderr, "[sigmon] Signal monitoring disabled\n");
}

/* Hook table */
struct uftrace_hook uftrace_hooks[] = {
    { "sigaction", hooked_sigaction, (void **)&real_sigaction },
    { "signal", hooked_signal, (void **)&real_signal },
};
int uftrace_hooks_count = 2;

/* Feature table */
struct uftrace_feature uftrace_features[] = {
    { "sigmon", sigmon_init, sigmon_fini, NULL },
};
int uftrace_features_count = 1;

/* Auto-init */
__attribute__((constructor))
static void plugin_init(void) { sigmon_init(NULL); }

__attribute__((destructor))
static void plugin_fini(void) { sigmon_fini(); }
