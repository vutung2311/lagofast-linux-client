#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <pthread.h>

int __android_log_write(int prio, const char *tag, const char *text) {
    return fprintf(stderr, "[%s] %s\n", tag ? tag : "LAGO", text ? text : "");
}

int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[%s] ", tag ? tag : "LAGO");
    int ret = vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    return ret;
}

void __assert2(const char* file, int line, const char* function, const char* expr) {
    fprintf(stderr, "Assertion failed: %s (%s:%d in %s)\n", expr, file, line, function);
    abort();
}

int* __errno(void) {
    return __errno_location();
}

int* __get_h_errno(void) {
    return __h_errno_location();
}

void android_set_abort_message(const char* msg) {
    if (msg) fprintf(stderr, "[ABORT] %s\n", msg);
}

int __system_property_get(const char* name, char* value) {
    if (value) value[0] = '\0';
    return 0;
}

size_t __strlen_chk(const char *s, size_t s_len) {
    return strlen(s);
}

char* __strchr_chk(const char *p, int ch, size_t s_len) {
    return (char*)strchr(p, ch);
}

char* __strrchr_chk(const char *p, int ch, size_t s_len) {
    return (char*)strrchr(p, ch);
}

char* __strncpy_chk2(char *dst, const char *src, size_t n, size_t dst_len, size_t src_len) {
    return strncpy(dst, src, n);
}

void *__memcpy_chk(void *dest, const void *src, size_t len, size_t destlen) {
    if (len > destlen) {
        fprintf(stderr, "[__memcpy_chk] buffer overflow detected: len=%zu > destlen=%zu\n", len, destlen);
        abort();
    }
    return memcpy(dest, src, len);
}

// Modern NPTL pthread_cond redirection
int qy_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
    static int (*real)(pthread_cond_t *, const pthread_condattr_t *) = NULL;
    if (!real) real = (int (*)(pthread_cond_t *, const pthread_condattr_t *))dlvsym(RTLD_DEFAULT, "pthread_cond_init", "GLIBC_2.3.2");
    return real(cond, attr);
}

int qy_cond_destroy(pthread_cond_t *cond) {
    static int (*real)(pthread_cond_t *) = NULL;
    if (!real) real = (int (*)(pthread_cond_t *))dlvsym(RTLD_DEFAULT, "pthread_cond_destroy", "GLIBC_2.3.2");
    return real(cond);
}

int qy_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    static int (*real)(pthread_cond_t *, pthread_mutex_t *) = NULL;
    if (!real) real = (int (*)(pthread_cond_t *, pthread_mutex_t *))dlvsym(RTLD_DEFAULT, "pthread_cond_wait", "GLIBC_2.3.2");
    return real(cond, mutex);
}

int qy_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime) {
    static int (*real)(pthread_cond_t *, pthread_mutex_t *, const struct timespec *) = NULL;
    if (!real) real = (int (*)(pthread_cond_t *, pthread_mutex_t *, const struct timespec *))dlvsym(RTLD_DEFAULT, "pthread_cond_timedwait", "GLIBC_2.3.2");
    return real(cond, mutex, abstime);
}

int qy_cond_signal(pthread_cond_t *cond) {
    static int (*real)(pthread_cond_t *) = NULL;
    if (!real) real = (int (*)(pthread_cond_t *))dlvsym(RTLD_DEFAULT, "pthread_cond_signal", "GLIBC_2.3.2");
    return real(cond);
}

int qy_cond_broadcast(pthread_cond_t *cond) {
    static int (*real)(pthread_cond_t *) = NULL;
    if (!real) real = (int (*)(pthread_cond_t *))dlvsym(RTLD_DEFAULT, "pthread_cond_broadcast", "GLIBC_2.3.2");
    return real(cond);
}

int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) __attribute__((weak, alias("qy_cond_init")));
int pthread_cond_destroy(pthread_cond_t *cond) __attribute__((weak, alias("qy_cond_destroy")));
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) __attribute__((weak, alias("qy_cond_wait")));
int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime) __attribute__((weak, alias("qy_cond_timedwait")));
int pthread_cond_signal(pthread_cond_t *cond) __attribute__((weak, alias("qy_cond_signal")));
int pthread_cond_broadcast(pthread_cond_t *cond) __attribute__((weak, alias("qy_cond_broadcast")));

// Bionic addrinfo layout translation:
// In Bionic: ai_canonname (offset 24), ai_addr (offset 32).
// In Glibc:  ai_addr (offset 24), ai_canonname (offset 32).
struct bionic_addrinfo {
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    socklen_t ai_addrlen;
    char *ai_canonname;
    struct sockaddr *ai_addr;
    struct bionic_addrinfo *ai_next;
};

void qy_freeaddrinfo(struct bionic_addrinfo *res) {
    while (res) {
        struct bionic_addrinfo *next = res->ai_next;
        if (res->ai_canonname) free(res->ai_canonname);
        if (res->ai_addr) free(res->ai_addr);
        free(res);
        res = next;
    }
}

int qy_getaddrinfo(const char *node, const char *service,
                   const struct bionic_addrinfo *hints,
                   struct bionic_addrinfo **res) {
    if (!res) return EAI_NONAME;
    *res = NULL;

    struct addrinfo glibc_hints;
    struct addrinfo *p_glibc_hints = NULL;

    if (hints) {
        memset(&glibc_hints, 0, sizeof(glibc_hints));
        glibc_hints.ai_flags = hints->ai_flags;
        glibc_hints.ai_family = hints->ai_family;
        glibc_hints.ai_socktype = hints->ai_socktype;
        glibc_hints.ai_protocol = hints->ai_protocol;
        glibc_hints.ai_addrlen = hints->ai_addrlen;
        p_glibc_hints = &glibc_hints;
    }

    struct addrinfo *gres = NULL;
    int ret = getaddrinfo(node, service, p_glibc_hints, &gres);
    if (ret != 0) return ret;

    struct bionic_addrinfo *head = NULL;
    struct bionic_addrinfo **tail = &head;

    for (struct addrinfo *curr = gres; curr != NULL; curr = curr->ai_next) {
        struct bionic_addrinfo *bnode = (struct bionic_addrinfo *)calloc(1, sizeof(struct bionic_addrinfo));
        if (!bnode) {
            qy_freeaddrinfo(head);
            freeaddrinfo(gres);
            return EAI_MEMORY;
        }

        bnode->ai_flags = curr->ai_flags;
        bnode->ai_family = curr->ai_family;
        bnode->ai_socktype = curr->ai_socktype;
        bnode->ai_protocol = curr->ai_protocol;
        bnode->ai_addrlen = curr->ai_addrlen;

        if (curr->ai_canonname) {
            bnode->ai_canonname = strdup(curr->ai_canonname);
        }
        if (curr->ai_addr && curr->ai_addrlen > 0) {
            bnode->ai_addr = (struct sockaddr *)malloc(curr->ai_addrlen);
            if (bnode->ai_addr) {
                memcpy(bnode->ai_addr, curr->ai_addr, curr->ai_addrlen);
            }
        }

        *tail = bnode;
        tail = &bnode->ai_next;
    }

    freeaddrinfo(gres);
    *res = head;
    return 0;
}

// Bionic ctype table
static char bionic_ctype_table[257];
const char* _ctype_ = bionic_ctype_table;

struct __sFILE {
    char __private[152];
} __attribute__((aligned(8)));

struct __sFILE __sF[3];

static inline FILE* translate_file(FILE* fp) {
    if (fp == (FILE*)&__sF[0]) return stdin;
    if (fp == (FILE*)&__sF[1]) return stdout;
    if (fp == (FILE*)&__sF[2]) return stderr;
    return fp;
}

int fflush(FILE *stream) {
    static int (*real_fflush)(FILE *) = NULL;
    if (!real_fflush) {
        real_fflush = (int (*)(FILE *))dlvsym(RTLD_DEFAULT, "fflush", "GLIBC_2.2.5");
        if (!real_fflush) real_fflush = dlsym(RTLD_NEXT, "fflush");
    }
    if (!real_fflush) return 0;
    if (!stream) return real_fflush(NULL);
    return real_fflush(translate_file(stream));
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*real_fwrite)(const void *, size_t, size_t, FILE *) = NULL;
    if (!real_fwrite) {
        real_fwrite = (size_t (*)(const void *, size_t, size_t, FILE *))dlvsym(RTLD_DEFAULT, "fwrite", "GLIBC_2.2.5");
        if (!real_fwrite) real_fwrite = dlsym(RTLD_NEXT, "fwrite");
    }
    if (!real_fwrite) return 0;
    return real_fwrite(ptr, size, nmemb, translate_file(stream));
}

int fputs(const char *s, FILE *stream) {
    static int (*real_fputs)(const char *, FILE *) = NULL;
    if (!real_fputs) {
        real_fputs = (int (*)(const char *, FILE *))dlvsym(RTLD_DEFAULT, "fputs", "GLIBC_2.2.5");
        if (!real_fputs) real_fputs = dlsym(RTLD_NEXT, "fputs");
    }
    if (!real_fputs) return 0;
    return real_fputs(s, translate_file(stream));
}

int fputc(int c, FILE *stream) {
    static int (*real_fputc)(int, FILE *) = NULL;
    if (!real_fputc) {
        real_fputc = (int (*)(int, FILE *))dlvsym(RTLD_DEFAULT, "fputc", "GLIBC_2.2.5");
        if (!real_fputc) real_fputc = dlsym(RTLD_NEXT, "fputc");
    }
    if (!real_fputc) return 0;
    return real_fputc(c, translate_file(stream));
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*real_fread)(void *, size_t, size_t, FILE *) = NULL;
    if (!real_fread) {
        real_fread = (size_t (*)(void *, size_t, size_t, FILE *))dlvsym(RTLD_DEFAULT, "fread", "GLIBC_2.2.5");
        if (!real_fread) real_fread = dlsym(RTLD_NEXT, "fread");
    }
    if (!real_fread) return 0;
    return real_fread(ptr, size, nmemb, translate_file(stream));
}

int fclose(FILE *stream) {
    static int (*real_fclose)(FILE *) = NULL;
    if (!real_fclose) {
        real_fclose = (int (*)(FILE *))dlvsym(RTLD_DEFAULT, "fclose", "GLIBC_2.2.5");
        if (!real_fclose) real_fclose = dlsym(RTLD_NEXT, "fclose");
    }
    if (!real_fclose) return 0;
    FILE *t = translate_file(stream);
    if (t == stdin || t == stdout || t == stderr) return 0;
    return real_fclose(t);
}

int fprintf(FILE *stream, const char *fmt, ...) {
    static int (*real_vfprintf)(FILE *, const char *, va_list) = NULL;
    if (!real_vfprintf) {
        real_vfprintf = (int (*)(FILE *, const char *, va_list))dlvsym(RTLD_DEFAULT, "vfprintf", "GLIBC_2.2.5");
        if (!real_vfprintf) real_vfprintf = dlsym(RTLD_NEXT, "vfprintf");
    }
    if (!real_vfprintf) return 0;
    va_list ap;
    va_start(ap, fmt);
    int ret = real_vfprintf(translate_file(stream), fmt, ap);
    va_end(ap);
    return ret;
}

int vfprintf(FILE *stream, const char *fmt, va_list ap) {
    static int (*real_vfprintf)(FILE *, const char *, va_list) = NULL;
    if (!real_vfprintf) {
        real_vfprintf = (int (*)(FILE *, const char *, va_list))dlvsym(RTLD_DEFAULT, "vfprintf", "GLIBC_2.2.5");
        if (!real_vfprintf) real_vfprintf = dlsym(RTLD_NEXT, "vfprintf");
    }
    if (!real_vfprintf) return 0;
    return real_vfprintf(translate_file(stream), fmt, ap);
}

__attribute__((constructor))
static void init_bionic_compat(void) {
    bionic_ctype_table[0] = 0; // for EOF (-1)
    for (int i = 0; i < 256; i++) {
        char val = 0;
        if (isupper(i)) val |= 0x01;
        if (islower(i)) val |= 0x02;
        if (isdigit(i)) val |= 0x04;
        if (isspace(i)) val |= 0x08;
        if (ispunct(i)) val |= 0x10;
        if (iscntrl(i)) val |= 0x20;
        if (isxdigit(i)) val |= 0x40;
        if (i == ' ')   val |= 0x80;
        bionic_ctype_table[i + 1] = val;
    }
}

// Safe implementation of qyproxy::isIp(std::string) to avoid C++ exception unwind crashes
bool _ZN7qyproxy4isIpENSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE(void* ndk_str) {
    if (!ndk_str) return false;
    unsigned char* b = (unsigned char*)ndk_str;
    const char* s = (b[0] & 1) == 0 ? (const char*)(b + 1) : *((const char**)(b + 16));
    if (!s || !s[0]) return false;

    struct in_addr a4;
    if (inet_pton(AF_INET, s, &a4) == 1) return true;
    struct in6_addr a6;
    if (inet_pton(AF_INET6, s, &a6) == 1) return true;
    return false;
}
