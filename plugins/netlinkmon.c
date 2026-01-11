/*
 * Netlink Monitor Plugin for uftrace inject
 * 
 * Hooks netlink socket operations (sendto, sendmsg, recvfrom, recvmsg)
 * and parses/dumps netlink messages with type and attribute information.
 *
 * Build:
 *   gcc -shared -fPIC -rdynamic -o netlinkmon.so netlinkmon.c -ldl -lpthread
 *
 * Usage:
 *   uftrace inject <PID> --lib /path/to/netlinkmon.so
 *
 * Output:
 *   - /tmp/netlinkmon.log - Human-readable netlink message dump
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
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdint.h>
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
#define MAX_DUMP_SIZE 4096

/* Track netlink sockets */
static int netlink_fds[MAX_FDS];
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static FILE *logfile = NULL;
static int enabled = 0;
static int initialized = 0;

/* Statistics */
static size_t total_messages_sent = 0;
static size_t total_messages_recv = 0;
static size_t total_bytes_sent = 0;
static size_t total_bytes_recv = 0;

/* Original function pointers */
static int (*real_socket)(int, int, int) = NULL;
static int (*real_close)(int) = NULL;
static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*real_sendto)(int, const void *, size_t, int,
                              const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*real_recvfrom)(int, void *, size_t, int,
                                struct sockaddr *, socklen_t *) = NULL;
static ssize_t (*real_send)(int, const void *, size_t, int) = NULL;
static ssize_t (*real_recv)(int, void *, size_t, int) = NULL;
static ssize_t (*real_sendmsg)(int, const struct msghdr *, int) = NULL;
static ssize_t (*real_recvmsg)(int, struct msghdr *, int) = NULL;

/* Get timestamp */
static void get_timestamp(char *buf, size_t len)
{
    struct timespec ts;
    struct tm tm;
    
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    snprintf(buf, len, "%02d:%02d:%02d.%03ld",
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000);
}

/* Netlink message type to string */
static const char *nlmsg_type_str(uint16_t type)
{
    switch (type) {
    case NLMSG_NOOP:     return "NLMSG_NOOP";
    case NLMSG_ERROR:    return "NLMSG_ERROR";
    case NLMSG_DONE:     return "NLMSG_DONE";
    case NLMSG_OVERRUN:  return "NLMSG_OVERRUN";
    
    /* RTM messages */
    case RTM_NEWLINK:    return "RTM_NEWLINK";
    case RTM_DELLINK:    return "RTM_DELLINK";
    case RTM_GETLINK:    return "RTM_GETLINK";
    case RTM_SETLINK:    return "RTM_SETLINK";
    case RTM_NEWADDR:    return "RTM_NEWADDR";
    case RTM_DELADDR:    return "RTM_DELADDR";
    case RTM_GETADDR:    return "RTM_GETADDR";
    case RTM_NEWROUTE:   return "RTM_NEWROUTE";
    case RTM_DELROUTE:   return "RTM_DELROUTE";
    case RTM_GETROUTE:   return "RTM_GETROUTE";
    case RTM_NEWNEIGH:   return "RTM_NEWNEIGH";
    case RTM_DELNEIGH:   return "RTM_DELNEIGH";
    case RTM_GETNEIGH:   return "RTM_GETNEIGH";
    case RTM_NEWRULE:    return "RTM_NEWRULE";
    case RTM_DELRULE:    return "RTM_DELRULE";
    case RTM_GETRULE:    return "RTM_GETRULE";
    case RTM_NEWQDISC:   return "RTM_NEWQDISC";
    case RTM_DELQDISC:   return "RTM_DELQDISC";
    case RTM_GETQDISC:   return "RTM_GETQDISC";
    default:
        return NULL;
    }
}

/* Netlink flags to string */
static void nlmsg_flags_str(uint16_t flags, char *buf, size_t len)
{
    buf[0] = '\0';
    
    if (flags & NLM_F_REQUEST)  strncat(buf, "REQUEST|", len - strlen(buf) - 1);
    if (flags & NLM_F_MULTI)    strncat(buf, "MULTI|", len - strlen(buf) - 1);
    if (flags & NLM_F_ACK)      strncat(buf, "ACK|", len - strlen(buf) - 1);
    if (flags & NLM_F_ECHO)     strncat(buf, "ECHO|", len - strlen(buf) - 1);
    if (flags & NLM_F_DUMP)     strncat(buf, "DUMP|", len - strlen(buf) - 1);
    if (flags & NLM_F_ROOT)     strncat(buf, "ROOT|", len - strlen(buf) - 1);
    if (flags & NLM_F_MATCH)    strncat(buf, "MATCH|", len - strlen(buf) - 1);
    if (flags & NLM_F_ATOMIC)   strncat(buf, "ATOMIC|", len - strlen(buf) - 1);
    if (flags & NLM_F_REPLACE)  strncat(buf, "REPLACE|", len - strlen(buf) - 1);
    if (flags & NLM_F_EXCL)     strncat(buf, "EXCL|", len - strlen(buf) - 1);
    if (flags & NLM_F_CREATE)   strncat(buf, "CREATE|", len - strlen(buf) - 1);
    if (flags & NLM_F_APPEND)   strncat(buf, "APPEND|", len - strlen(buf) - 1);
    
    /* Remove trailing | */
    size_t l = strlen(buf);
    if (l > 0 && buf[l-1] == '|')
        buf[l-1] = '\0';
    
    if (buf[0] == '\0')
        snprintf(buf, len, "0x%x", flags);
}

/* Hex dump */
static void hex_dump(FILE *f, const void *data, size_t len, const char *prefix)
{
    const unsigned char *p = data;
    size_t i, j;
    size_t dump_len = (len > 64) ? 64 : len;  /* Limit hex dump */
    
    for (i = 0; i < dump_len; i += 16) {
        fprintf(f, "%s%04zx: ", prefix, i);
        for (j = 0; j < 16; j++) {
            if (i + j < dump_len)
                fprintf(f, "%02x ", p[i + j]);
            else
                fprintf(f, "   ");
            if (j == 7) fprintf(f, " ");
        }
        fprintf(f, " |");
        for (j = 0; j < 16 && i + j < dump_len; j++) {
            unsigned char c = p[i + j];
            fprintf(f, "%c", (c >= 32 && c < 127) ? c : '.');
        }
        fprintf(f, "|\n");
    }
    if (len > dump_len)
        fprintf(f, "%s... (%zu more bytes)\n", prefix, len - dump_len);
}

/* Parse and dump netlink message */
static void dump_netlink_message(FILE *f, const void *data, size_t len, 
                                  const char *direction, int fd)
{
    const struct nlmsghdr *nlh = data;
    char ts[32];
    char flags_str[256];
    
    get_timestamp(ts, sizeof(ts));
    
    /* Validate message */
    if (len < sizeof(struct nlmsghdr)) {
        fprintf(f, "\n[%s] NETLINK %s fd=%d len=%zu (too short)\n", 
                ts, direction, fd, len);
        hex_dump(f, data, len, "  ");
        return;
    }
    
    /* Parse all messages in the buffer */
    size_t remaining = len;
    int msg_num = 0;
    
    while (NLMSG_OK(nlh, remaining)) {
        msg_num++;
        const char *type_name = nlmsg_type_str(nlh->nlmsg_type);
        nlmsg_flags_str(nlh->nlmsg_flags, flags_str, sizeof(flags_str));
        
        fprintf(f, "\n[%s] NETLINK %s fd=%d msg#%d\n", ts, direction, fd, msg_num);
        fprintf(f, "  nlmsg_len:   %u\n", nlh->nlmsg_len);
        
        if (type_name)
            fprintf(f, "  nlmsg_type:  %s (%u)\n", type_name, nlh->nlmsg_type);
        else
            fprintf(f, "  nlmsg_type:  %u\n", nlh->nlmsg_type);
        
        fprintf(f, "  nlmsg_flags: %s\n", flags_str);
        fprintf(f, "  nlmsg_seq:   %u\n", nlh->nlmsg_seq);
        fprintf(f, "  nlmsg_pid:   %u\n", nlh->nlmsg_pid);
        
        /* Dump payload */
        size_t payload_len = NLMSG_PAYLOAD(nlh, 0);
        if (payload_len > 0) {
            fprintf(f, "  payload (%zu bytes):\n", payload_len);
            hex_dump(f, NLMSG_DATA(nlh), payload_len, "    ");
        }
        
        /* Handle error message */
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = NLMSG_DATA(nlh);
            fprintf(f, "  error: %d (%s)\n", err->error, strerror(-err->error));
        }
        
        nlh = NLMSG_NEXT(nlh, remaining);
    }
    
    fflush(f);
}

/* Check if fd is a netlink socket */
static int is_netlink_fd(int fd)
{
    int domain;
    socklen_t len = sizeof(domain);
    
    if (fd < 0 || fd >= MAX_FDS)
        return 0;
    
    if (netlink_fds[fd])
        return 1;
    
    /* Auto-detect netlink socket */
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &len) == 0) {
        if (domain == AF_NETLINK) {
            pthread_mutex_lock(&lock);
            netlink_fds[fd] = 1;
            pthread_mutex_unlock(&lock);
            return 1;
        }
    }
    
    return 0;
}

/* Hooked socket() */
int hooked_socket(int domain, int type, int protocol)
{
    int fd;
    
    if (!real_socket)
        real_socket = dlsym(RTLD_NEXT, "socket");
    
    fd = real_socket(domain, type, protocol);
    
    fprintf(stderr, "DEBUG: hooked_socket domain=%d type=%d proto=%d fd=%d\n", domain, type, protocol);

    if (fd >= 0 && enabled && domain == AF_NETLINK) {
        pthread_mutex_lock(&lock);
        if (fd < MAX_FDS)
            netlink_fds[fd] = 1;
        pthread_mutex_unlock(&lock);
        
        char ts[32];
        get_timestamp(ts, sizeof(ts));
        
        const char *proto_name;
        switch (protocol) {
        case NETLINK_ROUTE:      proto_name = "NETLINK_ROUTE"; break;
        case NETLINK_UNUSED:     proto_name = "NETLINK_UNUSED"; break;
        case NETLINK_USERSOCK:   proto_name = "NETLINK_USERSOCK"; break;
        case NETLINK_FIREWALL:   proto_name = "NETLINK_FIREWALL"; break;
        case NETLINK_SOCK_DIAG:  proto_name = "NETLINK_SOCK_DIAG"; break;
        case NETLINK_NFLOG:      proto_name = "NETLINK_NFLOG"; break;
        case NETLINK_XFRM:       proto_name = "NETLINK_XFRM"; break;
        case NETLINK_SELINUX:    proto_name = "NETLINK_SELINUX"; break;
        case NETLINK_ISCSI:      proto_name = "NETLINK_ISCSI"; break;
        case NETLINK_AUDIT:      proto_name = "NETLINK_AUDIT"; break;
        case NETLINK_FIB_LOOKUP: proto_name = "NETLINK_FIB_LOOKUP"; break;
        case NETLINK_CONNECTOR:  proto_name = "NETLINK_CONNECTOR"; break;
        case NETLINK_NETFILTER:  proto_name = "NETLINK_NETFILTER"; break;
        case NETLINK_IP6_FW:     proto_name = "NETLINK_IP6_FW"; break;
        case NETLINK_DNRTMSG:    proto_name = "NETLINK_DNRTMSG"; break;
        case NETLINK_KOBJECT_UEVENT: proto_name = "NETLINK_KOBJECT_UEVENT"; break;
        case NETLINK_GENERIC:    proto_name = "NETLINK_GENERIC"; break;
        case NETLINK_CRYPTO:     proto_name = "NETLINK_CRYPTO"; break;
        default:                 proto_name = "UNKNOWN"; break;
        }
        
        pthread_mutex_lock(&lock);
        fprintf(logfile, "\n[%s] socket(AF_NETLINK, type=%d, %s) = %d\n",
                ts, type, proto_name, fd);
        fflush(logfile);
        pthread_mutex_unlock(&lock);
    }
    
    return fd;
}

/* Hooked bind() */
int hooked_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    int ret;
    
    if (!real_bind)
        real_bind = dlsym(RTLD_NEXT, "bind");
    
    ret = real_bind(fd, addr, addrlen);
    
    if (enabled && is_netlink_fd(fd) && addr->sa_family == AF_NETLINK) {
        struct sockaddr_nl *nladdr = (struct sockaddr_nl *)addr;
        char ts[32];
        get_timestamp(ts, sizeof(ts));
        
        pthread_mutex_lock(&lock);
        fprintf(logfile, "[%s] bind(fd=%d, nl_pid=%u, nl_groups=0x%x) = %d\n",
                ts, fd, nladdr->nl_pid, nladdr->nl_groups, ret);
        fflush(logfile);
        pthread_mutex_unlock(&lock);
    }
    
    return ret;
}

/* Hooked close() */
int hooked_close(int fd)
{
    if (!real_close)
        real_close = dlsym(RTLD_NEXT, "close");
    
    if (enabled && is_netlink_fd(fd)) {
        char ts[32];
        get_timestamp(ts, sizeof(ts));
        
        pthread_mutex_lock(&lock);
        fprintf(logfile, "[%s] close(fd=%d) netlink socket\n", ts, fd);
        fflush(logfile);
        if (fd >= 0 && fd < MAX_FDS)
            netlink_fds[fd] = 0;
        pthread_mutex_unlock(&lock);
    }
    
    return real_close(fd);
}

/* Hooked sendto() */
ssize_t hooked_sendto(int fd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen)
{
    ssize_t ret;
    
    if (!real_sendto)
        real_sendto = dlsym(RTLD_NEXT, "sendto");
    
    ret = real_sendto(fd, buf, len, flags, dest_addr, addrlen);
    
    /* Debug print */
    fprintf(stderr, "DEBUG: hooked_sendto fd=%d ret=%zd\n", fd, ret);

    /* Always log and try to parse as netlink */
    if (ret > 0 && enabled) {
        pthread_mutex_lock(&lock);
        dump_netlink_message(logfile, buf, ret, "SEND", fd);
        total_messages_sent++;
        total_bytes_sent += ret;
        pthread_mutex_unlock(&lock);
    }
    
    return ret;
}

/* Hooked send() */
ssize_t hooked_send(int fd, const void *buf, size_t len, int flags)
{
    ssize_t ret;
    
    if (!real_send)
        real_send = dlsym(RTLD_NEXT, "send");
    
    ret = real_send(fd, buf, len, flags);
    
    if (ret > 0 && enabled) {
        pthread_mutex_lock(&lock);
        dump_netlink_message(logfile, buf, ret, "SEND", fd);
        total_messages_sent++;
        total_bytes_sent += ret;
        pthread_mutex_unlock(&lock);
    }
    
    return ret;
}

/* Hooked recvfrom() */
ssize_t hooked_recvfrom(int fd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen)
{
    ssize_t ret;
    
    if (!real_recvfrom)
        real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    
    ret = real_recvfrom(fd, buf, len, flags, src_addr, addrlen);

    /* Debug print */
    fprintf(stderr, "DEBUG: hooked_recvfrom fd=%d ret=%zd\n", fd, ret);
    
    /* Always log and try to parse as netlink */
    if (ret > 0 && enabled) {
        pthread_mutex_lock(&lock);
        dump_netlink_message(logfile, buf, ret, "RECV", fd);
        total_messages_recv++;
        total_bytes_recv += ret;
        pthread_mutex_unlock(&lock);
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
    
    if (ret > 0 && enabled) {
        pthread_mutex_lock(&lock);
        dump_netlink_message(logfile, buf, ret, "RECV", fd);
        total_messages_recv++;
        total_bytes_recv += ret;
        pthread_mutex_unlock(&lock);
    }
    
    return ret;
}

/* Hooked sendmsg() */
ssize_t hooked_sendmsg(int fd, const struct msghdr *msg, int flags)
{
    ssize_t ret;
    
    if (!real_sendmsg)
        real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    
    ret = real_sendmsg(fd, msg, flags);
    
    if (ret > 0 && enabled && is_netlink_fd(fd) && msg->msg_iov && msg->msg_iovlen > 0) {
        pthread_mutex_lock(&lock);
        /* Dump first iovec */
        dump_netlink_message(logfile, msg->msg_iov[0].iov_base, 
                            msg->msg_iov[0].iov_len, "SEND", fd);
        total_messages_sent++;
        total_bytes_sent += ret;
        pthread_mutex_unlock(&lock);
    }
    
    return ret;
}

/* Hooked recvmsg() */
ssize_t hooked_recvmsg(int fd, struct msghdr *msg, int flags)
{
    ssize_t ret;
    
    if (!real_recvmsg)
        real_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    
    ret = real_recvmsg(fd, msg, flags);
    
    if (ret > 0 && enabled && is_netlink_fd(fd) && msg->msg_iov && msg->msg_iovlen > 0) {
        pthread_mutex_lock(&lock);
        dump_netlink_message(logfile, msg->msg_iov[0].iov_base,
                            msg->msg_iov[0].iov_len, "RECV", fd);
        total_messages_recv++;
        total_bytes_recv += ret;
        pthread_mutex_unlock(&lock);
    }
    
    return ret;
}

/* Print summary */
static void print_summary(void)
{
    FILE *f = fopen("/tmp/netlinkmon_summary.txt", "w");
    if (!f) f = logfile;
    
    fprintf(f, "\n=== Netlink Monitor Summary ===\n");
    fprintf(f, "Messages sent: %zu\n", total_messages_sent);
    fprintf(f, "Messages received: %zu\n", total_messages_recv);
    fprintf(f, "Bytes sent: %zu\n", total_bytes_sent);
    fprintf(f, "Bytes received: %zu\n", total_bytes_recv);
    fprintf(f, "===============================\n");
    
    if (f != logfile)
        fclose(f);
}

/* Signal handler */
static void sig_handler(int sig)
{
    if (sig == SIGUSR1) {
        print_summary();
        fprintf(stderr, "[netlinkmon] Summary written\n");
    }
}

/* Plugin initialization */
static int netlinkmon_init(void *arg)
{
    (void)arg;
    
    if (initialized)
        return 0;
    initialized = 1;
    
    real_socket = dlsym(RTLD_NEXT, "socket");
    real_close = dlsym(RTLD_NEXT, "close");
    real_bind = dlsym(RTLD_NEXT, "bind");
    real_sendto = dlsym(RTLD_NEXT, "sendto");
    real_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    real_send = dlsym(RTLD_NEXT, "send");
    real_recv = dlsym(RTLD_NEXT, "recv");
    real_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    real_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    
    logfile = fopen("/tmp/netlinkmon.log", "a");
    if (!logfile) {
        fprintf(stderr, "[netlinkmon] Failed to open log file\n");
        return -1;
    }
    
    fprintf(logfile, "=== Netlink Monitor Started ===\n");
    fprintf(logfile, "PID: %d\n", getpid());
    fflush(logfile);
    
    signal(SIGUSR1, sig_handler);
    
    enabled = 1;
    
    fprintf(stderr, "[netlinkmon] Netlink monitoring enabled\n");
    fprintf(stderr, "[netlinkmon] Log: /tmp/netlinkmon.log\n");
    fprintf(stderr, "[netlinkmon] SIGUSR1 = print summary\n");
    
    return 0;
}

/* Plugin cleanup */
static void netlinkmon_fini(void)
{
    enabled = 0;
    print_summary();
    
    if (logfile) {
        fclose(logfile);
        logfile = NULL;
    }
    
    fprintf(stderr, "[netlinkmon] Netlink monitoring disabled\n");
}

/* Hook table */
struct uftrace_hook uftrace_hooks[] = {
    { "socket", hooked_socket, (void **)&real_socket },
    { "close", hooked_close, (void **)&real_close },
    { "bind", hooked_bind, (void **)&real_bind },
    { "sendto", hooked_sendto, (void **)&real_sendto },
    { "recvfrom", hooked_recvfrom, (void **)&real_recvfrom },
    { "send", hooked_send, (void **)&real_send },
    { "recv", hooked_recv, (void **)&real_recv },
    { "sendmsg", hooked_sendmsg, (void **)&real_sendmsg },
    { "recvmsg", hooked_recvmsg, (void **)&real_recvmsg },
};
int uftrace_hooks_count = 9;

/* Feature table */
struct uftrace_feature uftrace_features[] = {
    { "netlinkmon", netlinkmon_init, netlinkmon_fini, NULL },
};
int uftrace_features_count = 1;

/* Auto-init */
__attribute__((constructor))
static void plugin_init(void) { netlinkmon_init(NULL); }

__attribute__((destructor))
static void plugin_fini(void) { netlinkmon_fini(); }
