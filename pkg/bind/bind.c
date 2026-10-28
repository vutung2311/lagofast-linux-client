#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

static int (*real_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static ssize_t (*real_sendto)(int sockfd, const void *buf, size_t len, int flags,
                              const struct sockaddr *dest_addr, socklen_t addrlen) = NULL;
static int (*real_setsockopt)(int sockfd, int level, int optname, const void *optval, socklen_t optlen) = NULL;

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    if (!real_setsockopt) {
        real_setsockopt = (int (*)(int, int, int, const void *, socklen_t))dlsym(RTLD_NEXT, "setsockopt");
    }
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

static const char *get_device(void) {
    const char *dev = getenv("LAGOFAST_DEVICE");
    if (dev && dev[0]) {
        return dev;
    }
    return "lagofast0";
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!real_connect) {
        real_connect = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "connect");
    }
    if (addr && addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        uint32_t ip = ntohl(sin->sin_addr.s_addr);
        uint16_t port = ntohs(sin->sin_port);

        int is_loopback = ((ip >> 24) == 127);
        int is_local_lan = ((ip >> 16) == 0xc0a8) || ((ip >> 24) == 10);
        int is_web_port = (port == 80 || port == 443 || port == 8080 || port == 8443 || port == 8000);

        int is_game_subnet = ((ip & 0xfff00000) == 0x08d00000) || // 8.208.0.0/12 (Alibaba SG/HK)
                             ((ip & 0xffff0000) == 0x2f540000) || // 47.84.0.0/16 (NetEase SG)
                             ((ip & 0xffff0000) == 0x2fed0000) || // 47.237.0.0/16
                             ((ip & 0xfffe0000) == 0x2f4c0000);   // 47.76.0.0/15 (47.76-47.77)

        if (!is_loopback && !is_local_lan) {
            int one = 1;
            setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
            setsockopt(sockfd, IPPROTO_TCP, TCP_CONGESTION, "bbr", 4);

            if (!is_web_port || is_game_subnet) {
                const char *dev = get_device();
                setsockopt(sockfd, SOL_SOCKET, 25 /* SO_BINDTODEVICE */, dev, strlen(dev) + 1);
            }
        }
    }
    return real_connect(sockfd, addr, addrlen);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    if (!real_sendto) {
        real_sendto = (ssize_t (*)(int, const void *, size_t, int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "sendto");
    }
    if (dest_addr && dest_addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)dest_addr;
        uint32_t ip = ntohl(sin->sin_addr.s_addr);
        uint16_t port = ntohs(sin->sin_port);

        int is_loopback = ((ip >> 24) == 127);
        int is_local_lan = ((ip >> 16) == 0xc0a8) || ((ip >> 24) == 10);
        int is_dns = (port == 53);

        if (!is_loopback && !is_local_lan && !is_dns) {
            const char *dev = get_device();
            setsockopt(sockfd, SOL_SOCKET, 25 /* SO_BINDTODEVICE */, dev, strlen(dev) + 1);

            int bufsize = 4 * 1024 * 1024;
            setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
            bufsize = 2 * 1024 * 1024;
            setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        }
    }
    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}
