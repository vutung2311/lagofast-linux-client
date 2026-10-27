
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

static int (*real_socket)(int domain, int type, int protocol) = NULL;
static int (*real_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;

static const char *tun_name = "lagofast0";

__attribute__((constructor))
static void init_lagofast_bind(void) {
    real_socket = (int (*)(int, int, int))dlsym(RTLD_NEXT, "socket");
    real_connect = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "connect");
    const char *env_dev = getenv("LAGOFAST_DEVICE");
    if (env_dev && env_dev[0]) {
        tun_name = env_dev;
    }
}

int socket(int domain, int type, int protocol) {
    if (!real_socket) {
        real_socket = (int (*)(int, int, int))dlsym(RTLD_NEXT, "socket");
    }
    int fd = real_socket(domain, type, protocol);
    if (fd >= 0 && (domain == AF_INET || domain == AF_INET6)) {
        int sock_type = type & 0xf;
        if (sock_type == SOCK_STREAM || sock_type == SOCK_DGRAM) {
            setsockopt(fd, SOL_SOCKET, 25 /* SO_BINDTODEVICE */, tun_name, strlen(tun_name) + 1);
        }
    }
    return fd;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!real_connect) {
        real_connect = (int (*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "connect");
    }
    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        uint32_t ip = ntohl(sin->sin_addr.s_addr);
        if ((ip >> 24) != 127) {
            setsockopt(sockfd, SOL_SOCKET, 25 /* SO_BINDTODEVICE */, tun_name, strlen(tun_name) + 1);
        }
    }
    return real_connect(sockfd, addr, addrlen);
}
