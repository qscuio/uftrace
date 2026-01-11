/*
 * Socket Monitor Plugin for uftrace inject
 * 
 * Hooks socket system calls (send, recv, read, write, etc.) and logs
 * all network data transmitted and received by the target process.
 *
 * Build:
 *   gcc -shared -fPIC -rdynamic -o sockmon.so sockmon.c -ldl -lpthread
 *
 * Usage:
 *   uftrace inject <PID> --lib /path/to/sockmon.so
 *
 * Output:
 *   - /tmp/sockmon.log - Human-readable log with hex dumps
 *   - /tmp/sockmon_raw/ - Raw data files per fd/direction
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
#define MAX_FDS 1024
#define DUMP_BYTES_PER_LINE 16
#define MAX_DUMP_SIZE 4096  /* Max bytes to dump per call */

/* Track which fds are sockets */
static int socket_fds[MAX_FDS];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static FILE *logfile = NULL;
static int enabled = 0;
static const char *raw_dir = "/tmp/sockmon_raw";

/* Statistics */
static size_t total_bytes_sent = 0;
static size_t total_bytes_recv = 0;
static size_t total_send_calls = 0;
static size_t total_recv_calls = 0;

/* Original function pointers */
static int (*real_socket)(int, int, int) = NULL;
static int (*real_close)(int) = NULL;
static ssize_t (*real_send)(int, const void *, size_t, int) = NULL;
static ssize_t (*real_recv)(int, void *, size_t, int) = NULL;
static ssize_t (*real_sendto)(int, const void *, size_t, int,
                              const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*real_recvfrom)(int, void *, size_t, int,
                                struct sockaddr *, socklen_t *) = NULL;
static ssize_t (*real_read)(int, void *, size_t) = NULL;
static ssize_t (*real_write)(int, const void *, size_t) = NULL;
static ssize_t (*real_sendmsg)(int, const struct msghdr *, int) = NULL;
static ssize_t (*real_recvmsg)(int, struct msghdr *, int) = NULL;
static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*real_accept)(int, struct sockaddr *, socklen_t *) = NULL;

/* Get timestamp string */
static void get_timestamp(char *buf, size_t len)
{
    struct timespec ts;
    struct tm tm;
    
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    snprintf(buf, len, "%02d:%02d:%02d.%03ld",
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000);
}

/* Convert sockaddr to string */
static void sockaddr_to_str(const struct sockaddr *addr, char *buf, size_t len)
{
    if (!addr) {
        snprintf(buf, len, "(null)");
        return;
    }
    
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        snprintf(buf, len, "%s:%d", ip, ntohs(sin->sin_port));
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        snprintf(buf, len, "[%s]:%d", ip, ntohs(sin6->sin6_port));
    } else {
        snprintf(buf, len, "(family=%d)", addr->sa_family);
    }
}

/* Hex dump data to file */
static void hex_dump(FILE *f, const void *data, size_t len, const char *prefix)
{
    const unsigned char *p = data;
    size_t i, j;
    size_t dump_len = (len > MAX_DUMP_SIZE) ? MAX_DUMP_SIZE : len;
    
    for (i = 0; i < dump_len; i += DUMP_BYTES_PER_LINE) {
        fprintf(f, "%s%04zx: ", prefix, i);
        
        /* Hex bytes */
        for (j = 0; j < DUMP_BYTES_PER_LINE; j++) {
            if (i + j < dump_len)
                fprintf(f, "%02x ", p[i + j]);
            else
                fprintf(f, "   ");
            if (j == 7)
                fprintf(f, " ");
        }
        
        /* ASCII */
        fprintf(f, " |");
        for (j = 0; j < DUMP_BYTES_PER_LINE && i + j < dump_len; j++) {
            unsigned char c = p[i + j];
            fprintf(f, "%c", isprint(c) ? c : '.');
        }
        fprintf(f, "|\n");
    }
    
    if (len > MAX_DUMP_SIZE)
        fprintf(f, "%s... (%zu more bytes)\n", prefix, len - MAX_DUMP_SIZE);
}

/* Save raw data to file */
static void save_raw(int fd, const char *direction, const void *data, size_t len)
{
    char path[256];
    FILE *f;
    
    snprintf(path, sizeof(path), "%s/fd%d_%s.bin", raw_dir, fd, direction);
    f = fopen(path, "ab");
    if (f) {
        fwrite(data, 1, len, f);
        fclose(f);
    }
}

/* Log send/recv event */
static void log_event(int fd, const char *func, const char *direction,
                      const void *data, size_t len, const char *addr_str)
{
    char ts[32];
    
    if (!logfile || !enabled)
        return;
    
    pthread_mutex_lock(&lock);
    
    get_timestamp(ts, sizeof(ts));
    
    fprintf(logfile, "\n[%s] %s fd=%d %s bytes=%zu", 
            ts, func, fd, direction, len);
    if (addr_str && addr_str[0])
        fprintf(logfile, " addr=%s", addr_str);
    fprintf(logfile, "\n");
    
    if (data && len > 0) {
        hex_dump(logfile, data, len, "  ");
        save_raw(fd, direction, data, len);
    }
    
    fflush(logfile);
    
    pthread_mutex_unlock(&lock);
}

/* Check if fd is a socket */
static int is_socket_fd(int fd)
{
    int type;
    socklen_t len = sizeof(type);
    
    if (fd < 0 || fd >= MAX_FDS)
        return 0;
    
    /* If we already know it's a socket, return true */
    if (socket_fds[fd])
        return 1;
    
    /* Auto-detect: try getsockopt to see if it's a socket */
    /* This handles sockets created before injection */
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) == 0) {
        /* It's a socket! Mark it for future checks */
        pthread_mutex_lock(&lock);
        socket_fds[fd] = 1;
        pthread_mutex_unlock(&lock);
        return 1;
    }
    
    return 0;
}

/* Mark fd as socket */
static void mark_socket(int fd)
{
    if (fd >= 0 && fd < MAX_FDS) {
        pthread_mutex_lock(&lock);
        socket_fds[fd] = 1;
        pthread_mutex_unlock(&lock);
    }
}

/* Unmark fd */
static void unmark_socket(int fd)
{
    if (fd >= 0 && fd < MAX_FDS) {
        pthread_mutex_lock(&lock);
        socket_fds[fd] = 0;
        pthread_mutex_unlock(&lock);
    }
}

/* Hooked socket() */
int hooked_socket(int domain, int type, int protocol)
{
    int fd;
    
    if (!real_socket)
        real_socket = dlsym(RTLD_NEXT, "socket");
    
    fd = real_socket(domain, type, protocol);
    
    if (fd >= 0 && enabled) {
        mark_socket(fd);
        
        char ts[32];
        get_timestamp(ts, sizeof(ts));
        
        pthread_mutex_lock(&lock);
        fprintf(logfile, "[%s] socket() = %d (domain=%d type=%d proto=%d)\n",
                ts, fd, domain, type, protocol);
        fflush(logfile);
        pthread_mutex_unlock(&lock);
    }
    
    return fd;
}

/* Hooked connect() */
int hooked_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    int ret;
    char addr_str[128] = "";
    
    if (!real_connect)
        real_connect = dlsym(RTLD_NEXT, "connect");
    
    if (addr)
        sockaddr_to_str(addr, addr_str, sizeof(addr_str));
    
    ret = real_connect(fd, addr, addrlen);
    
    if (enabled) {
        mark_socket(fd);
        
        char ts[32];
        get_timestamp(ts, sizeof(ts));
        
        pthread_mutex_lock(&lock);
        fprintf(logfile, "[%s] connect() fd=%d addr=%s ret=%d\n",
                ts, fd, addr_str, ret);
        fflush(logfile);
        pthread_mutex_unlock(&lock);
    }
    
    return ret;
}

/* Hooked accept() */
int hooked_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    int newfd;
    char addr_str[128] = "";
    
    if (!real_accept)
        real_accept = dlsym(RTLD_NEXT, "accept");
    
    newfd = real_accept(fd, addr, addrlen);
    
    if (newfd >= 0 && enabled) {
        mark_socket(newfd);
        
        if (addr)
            sockaddr_to_str(addr, addr_str, sizeof(addr_str));
        
        char ts[32];
        get_timestamp(ts, sizeof(ts));
        
        pthread_mutex_lock(&lock);
        fprintf(logfile, "[%s] accept() fd=%d newfd=%d from=%s\n",
                ts, fd, newfd, addr_str);
        fflush(logfile);
        pthread_mutex_unlock(&lock);
    }
    
    return newfd;
}

/* Hooked close() */
int hooked_close(int fd)
{
    if (!real_close)
        real_close = dlsym(RTLD_NEXT, "close");
    
    if (enabled && is_socket_fd(fd)) {
        char ts[32];
        get_timestamp(ts, sizeof(ts));
        
        pthread_mutex_lock(&lock);
        fprintf(logfile, "[%s] close() fd=%d\n", ts, fd);
        fflush(logfile);
        pthread_mutex_unlock(&lock);
        
        unmark_socket(fd);
    }
    
    return real_close(fd);
}

/* Hooked send() */
ssize_t hooked_send(int fd, const void *buf, size_t len, int flags)
{
    ssize_t ret;
    
    if (!real_send)
        real_send = dlsym(RTLD_NEXT, "send");
    
    ret = real_send(fd, buf, len, flags);
    
    if (ret > 0 && enabled && is_socket_fd(fd)) {
        log_event(fd, "send", "SEND", buf, ret, NULL);
        total_bytes_sent += ret;
        total_send_calls++;
    }
    
    return ret;
}

/* Hooked recv() */
ssize_t hooked_recv(int fd, void *buf, size_t len, int flags)
{
    ssize_t ret;
    
    if (!real_recv)
        real_recv = dlsym(RTLD_NEXT, "recv");
    
    ret = real_recv(fd, buf, len, flags);
    
    if (ret > 0 && enabled && is_socket_fd(fd)) {
        log_event(fd, "recv", "RECV", buf, ret, NULL);
        total_bytes_recv += ret;
        total_recv_calls++;
    }
    
    return ret;
}

/* Hooked sendto() */
ssize_t hooked_sendto(int fd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen)
{
    ssize_t ret;
    char addr_str[128] = "";
    
    if (!real_sendto)
        real_sendto = dlsym(RTLD_NEXT, "sendto");
    
    if (dest_addr)
        sockaddr_to_str(dest_addr, addr_str, sizeof(addr_str));
    
    ret = real_sendto(fd, buf, len, flags, dest_addr, addrlen);
    
    if (ret > 0 && enabled) {
        mark_socket(fd);
        log_event(fd, "sendto", "SEND", buf, ret, addr_str);
        total_bytes_sent += ret;
        total_send_calls++;
    }
    
    return ret;
}

/* Hooked recvfrom() */
ssize_t hooked_recvfrom(int fd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen)
{
    ssize_t ret;
    char addr_str[128] = "";
    
    if (!real_recvfrom)
        real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    
    ret = real_recvfrom(fd, buf, len, flags, src_addr, addrlen);
    
    if (ret > 0 && enabled) {
        mark_socket(fd);
        if (src_addr)
            sockaddr_to_str(src_addr, addr_str, sizeof(addr_str));
        log_event(fd, "recvfrom", "RECV", buf, ret, addr_str);
        total_bytes_recv += ret;
        total_recv_calls++;
    }
    
    return ret;
}

/* Hooked read() - only log if fd is a socket */
ssize_t hooked_read(int fd, void *buf, size_t count)
{
    ssize_t ret;
    
    if (!real_read)
        real_read = dlsym(RTLD_NEXT, "read");
    
    ret = real_read(fd, buf, count);
    
    if (ret > 0 && enabled && is_socket_fd(fd)) {
        log_event(fd, "read", "RECV", buf, ret, NULL);
        total_bytes_recv += ret;
        total_recv_calls++;
    }
    
    return ret;
}

/* Hooked write() - only log if fd is a socket */
ssize_t hooked_write(int fd, const void *buf, size_t count)
{
    ssize_t ret;
    
    if (!real_write)
        real_write = dlsym(RTLD_NEXT, "write");
    
    ret = real_write(fd, buf, count);
    
    if (ret > 0 && enabled && is_socket_fd(fd)) {
        log_event(fd, "write", "SEND", buf, ret, NULL);
        total_bytes_sent += ret;
        total_send_calls++;
    }
    
    return ret;
}

/* Print summary */
static void print_summary(void)
{
    FILE *f = fopen("/tmp/sockmon_summary.txt", "w");
    if (!f) f = logfile;
    
    fprintf(f, "\n=== Socket Monitor Summary ===\n");
    fprintf(f, "Total bytes sent: %zu\n", total_bytes_sent);
    fprintf(f, "Total bytes received: %zu\n", total_bytes_recv);
    fprintf(f, "Total send calls: %zu\n", total_send_calls);
    fprintf(f, "Total recv calls: %zu\n", total_recv_calls);
    fprintf(f, "Log file: /tmp/sockmon.log\n");
    fprintf(f, "Raw data: %s/\n", raw_dir);
    fprintf(f, "==============================\n");
    
    if (f != logfile)
        fclose(f);
}

/* Signal handler */
static void sig_handler(int sig)
{
    if (sig == SIGUSR1) {
        print_summary();
        fprintf(stderr, "[sockmon] Summary written to /tmp/sockmon_summary.txt\n");
    }
}

/* Plugin initialization */
static int initialized = 0;

static int sockmon_init(void *arg)
{
    (void)arg;
    
    /* Prevent double initialization */
    if (initialized)
        return 0;
    initialized = 1;
    
    /* Get real function pointers */
    real_socket = dlsym(RTLD_NEXT, "socket");
    real_close = dlsym(RTLD_NEXT, "close");
    real_send = dlsym(RTLD_NEXT, "send");
    real_recv = dlsym(RTLD_NEXT, "recv");
    real_sendto = dlsym(RTLD_NEXT, "sendto");
    real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    real_read = dlsym(RTLD_NEXT, "read");
    real_write = dlsym(RTLD_NEXT, "write");
    real_connect = dlsym(RTLD_NEXT, "connect");
    real_accept = dlsym(RTLD_NEXT, "accept");
    
    /* Create raw data directory */
    mkdir(raw_dir, 0755);
    
    /* Open log file in append mode to preserve existing data */
    logfile = fopen("/tmp/sockmon.log", "a");
    if (!logfile) {
        fprintf(stderr, "[sockmon] Failed to open log file\n");
        return -1;
    }
    
    fprintf(logfile, "=== Socket Monitor Started ===\n");
    fprintf(logfile, "PID: %d\n\n", getpid());
    fflush(logfile);
    
    signal(SIGUSR1, sig_handler);
    
    enabled = 1;
    
    fprintf(stderr, "[sockmon] Socket monitoring enabled\n");
    fprintf(stderr, "[sockmon] Log: /tmp/sockmon.log\n");
    fprintf(stderr, "[sockmon] Raw data: %s/\n", raw_dir);
    fprintf(stderr, "[sockmon] SIGUSR1 = print summary\n");
    
    return 0;
}

/* Plugin cleanup */
static void sockmon_fini(void)
{
    enabled = 0;
    
    print_summary();
    
    if (logfile) {
        fclose(logfile);
        logfile = NULL;
    }
    
    fprintf(stderr, "[sockmon] Socket monitoring disabled\n");
}

/* Hook table */
struct uftrace_hook uftrace_hooks[] = {
    { "socket", hooked_socket, (void **)&real_socket },
    { "close", hooked_close, (void **)&real_close },
    { "connect", hooked_connect, (void **)&real_connect },
    { "accept", hooked_accept, (void **)&real_accept },
    { "send", hooked_send, (void **)&real_send },
    { "recv", hooked_recv, (void **)&real_recv },
    { "sendto", hooked_sendto, (void **)&real_sendto },
    { "recvfrom", hooked_recvfrom, (void **)&real_recvfrom },
    { "read", hooked_read, (void **)&real_read },
    { "write", hooked_write, (void **)&real_write },
};
int uftrace_hooks_count = 10;

/* Feature table */
struct uftrace_feature uftrace_features[] = {
    { "sockmon", sockmon_init, sockmon_fini, NULL },
};
int uftrace_features_count = 1;

/* Auto-init */
__attribute__((constructor))
static void plugin_init(void) { sockmon_init(NULL); }

__attribute__((destructor))
static void plugin_fini(void) { sockmon_fini(); }
