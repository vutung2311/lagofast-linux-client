#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

/*
 * LD_PRELOAD socket interposer for Wine/Proton games.
 *
 * Hot-path design: socket options are sticky, so per-packet work is reduced to
 * a single relaxed byte load once a socket has been configured. The cache is
 * indexed by fd and invalidated whenever an fd is (re)created or closed, so a
 * reused fd number never inherits a stale "configured" flag.
 *
 * Wine's ntdll sends datagrams through sendmsg(), not sendto(), so both are
 * intercepted.
 */

typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
typedef ssize_t (*sendto_fn)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef ssize_t (*sendmsg_fn)(int, const struct msghdr *, int);
typedef int (*setsockopt_fn)(int, int, int, const void *, socklen_t);
typedef int (*socket_fn)(int, int, int);
typedef int (*close_fn)(int);
typedef int (*dup2_fn)(int, int);
typedef int (*dup3_fn)(int, int, int);

static connect_fn real_connect;
static sendto_fn real_sendto;
static sendmsg_fn real_sendmsg;
static setsockopt_fn real_setsockopt;
static socket_fn real_socket;
static close_fn real_close;
static dup2_fn real_dup2;
static dup3_fn real_dup3;

static const char *g_device = "lagofast0";
static socklen_t g_device_len = sizeof("lagofast0");

#define FD_CACHE_SIZE 65536
#define FD_UDP_CONFIGURED 0x1
static unsigned char g_fd_state[FD_CACHE_SIZE];

#define RESOLVE(var, type, name) \
    do { if (!(var)) (var) = (type)dlsym(RTLD_NEXT, name); } while (0)

static void resolve_all(void) {
    RESOLVE(real_connect, connect_fn, "connect");
    RESOLVE(real_sendto, sendto_fn, "sendto");
    RESOLVE(real_sendmsg, sendmsg_fn, "sendmsg");
    RESOLVE(real_setsockopt, setsockopt_fn, "setsockopt");
    RESOLVE(real_socket, socket_fn, "socket");
    RESOLVE(real_close, close_fn, "close");
    RESOLVE(real_dup2, dup2_fn, "dup2");
    RESOLVE(real_dup3, dup3_fn, "dup3");
}

__attribute__((constructor))
static void lagofast_bind_init(void) {
    resolve_all();
    const char *dev = getenv("LAGOFAST_DEVICE");
    if (dev && dev[0]) {
        g_device = dev;
        g_device_len = (socklen_t)(strlen(dev) + 1);
    }
}

static inline int fd_state_get(int fd) {
    if (fd < 0 || fd >= FD_CACHE_SIZE) return 0;
    return __atomic_load_n(&g_fd_state[fd], __ATOMIC_RELAXED);
}

static inline void fd_state_set(int fd, unsigned char v) {
    if (fd < 0 || fd >= FD_CACHE_SIZE) return;
    __atomic_store_n(&g_fd_state[fd], v, __ATOMIC_RELAXED);
}

static inline int is_loopback(uint32_t ip) { return (ip >> 24) == 127; }

static inline int is_local_lan(uint32_t ip) {
    return ((ip >> 16) == 0xc0a8) || ((ip >> 24) == 10);
}

static inline int is_game_subnet(uint32_t ip) {
    return ((ip & 0xfff00000) == 0x08d00000) || // 8.208.0.0/12 (Alibaba SG/HK)
           ((ip & 0xffff0000) == 0x2f540000) || // 47.84.0.0/16 (NetEase SG)
           ((ip & 0xffff0000) == 0x2fed0000) || // 47.237.0.0/16
           ((ip & 0xfffe0000) == 0x2f4c0000);   // 47.76.0.0/15 (47.76-47.77)
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    if (!real_setsockopt) resolve_all();
    if (level == IPPROTO_TCP) {
        if (optname == TCP_CONGESTION) {
            return real_setsockopt(sockfd, level, optname, "bbr", 4);
        }
        if (optname == TCP_NODELAY || optname == TCP_QUICKACK) {
            int one = 1;
            return real_setsockopt(sockfd, level, optname, &one, sizeof(one));
        }
    }
    return real_setsockopt(sockfd, level, optname, optval, optlen);
}

int socket(int domain, int type, int protocol) {
    if (!real_socket) resolve_all();
    int fd = real_socket(domain, type, protocol);
    fd_state_set(fd, 0);
    return fd;
}

int close(int fd) {
    if (!real_close) resolve_all();
    fd_state_set(fd, 0);
    return real_close(fd);
}

int dup2(int oldfd, int newfd) {
    if (!real_dup2) resolve_all();
    int ret = real_dup2(oldfd, newfd);
    if (ret >= 0) fd_state_set(ret, fd_state_get(oldfd));
    return ret;
}

int dup3(int oldfd, int newfd, int flags) {
    if (!real_dup3) resolve_all();
    int ret = real_dup3(oldfd, newfd, flags);
    if (ret >= 0) fd_state_set(ret, fd_state_get(oldfd));
    return ret;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!real_connect) resolve_all();
    if (addr && addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        uint32_t ip = ntohl(sin->sin_addr.s_addr);
        uint16_t port = ntohs(sin->sin_port);

        if (!is_loopback(ip) && !is_local_lan(ip)) {
            int one = 1;
            /* TCP_NODELAY doubles as a cheap stream-socket probe: on UDP it fails
             * with ENOPROTOOPT and the remaining TCP-only options are skipped. */
            if (real_setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0) {
                real_setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
                real_setsockopt(sockfd, IPPROTO_TCP, TCP_CONGESTION, "bbr", 4);
            }

            int is_web_port = (port == 80 || port == 443 || port == 8080 || port == 8443 || port == 8000);
            if (!is_web_port || is_game_subnet(ip)) {
                real_setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, g_device, g_device_len);
            }
        }
    }
    return real_connect(sockfd, addr, addrlen);
}

/* Configure an unconnected UDP socket the first time it sends to a remote
 * (non-local, non-DNS) destination. Subsequent packets cost one byte load. */
static inline void maybe_configure_udp(int sockfd, const struct sockaddr *dest, socklen_t addrlen) {
    if (fd_state_get(sockfd) & FD_UDP_CONFIGURED) return;
    if (!dest || dest->sa_family != AF_INET || addrlen < sizeof(struct sockaddr_in)) return;

    const struct sockaddr_in *sin = (const struct sockaddr_in *)dest;
    uint32_t ip = ntohl(sin->sin_addr.s_addr);
    uint16_t port = ntohs(sin->sin_port);
    if (is_loopback(ip) || is_local_lan(ip) || port == 53) return;

    real_setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, g_device, g_device_len);
    int bufsize = 4 * 1024 * 1024;
    real_setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    bufsize = 2 * 1024 * 1024;
    real_setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    fd_state_set(sockfd, FD_UDP_CONFIGURED);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    if (!real_sendto) resolve_all();
    maybe_configure_udp(sockfd, dest_addr, addrlen);
    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    if (!real_sendmsg) resolve_all();
    if (msg) {
        maybe_configure_udp(sockfd, (const struct sockaddr *)msg->msg_name, msg->msg_namelen);
    }
    return real_sendmsg(sockfd, msg, flags);
}
