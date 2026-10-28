#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
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

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res) {
    static int (*real_gai)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;
    if (!real_gai) real_gai = dlsym(RTLD_NEXT, "getaddrinfo");

    struct addrinfo glibc_hints;
    const struct addrinfo *p_hints = hints;
    if (hints) {
        memcpy(&glibc_hints, hints, sizeof(struct addrinfo));
        void* tmp = *(void**)((char*)&glibc_hints + 24);
        *(void**)((char*)&glibc_hints + 24) = *(void**)((char*)&glibc_hints + 32);
        *(void**)((char*)&glibc_hints + 32) = tmp;
        p_hints = &glibc_hints;
    }

    int ret = real_gai(node, service, p_hints, res);
    if (ret == 0 && res && *res) {
        for (struct addrinfo *p = *res; p != NULL; p = p->ai_next) {
            void* tmp = *(void**)((char*)p + 24);
            *(void**)((char*)p + 24) = *(void**)((char*)p + 32);
            *(void**)((char*)p + 32) = tmp;
        }
    }
    return ret;
}

void freeaddrinfo(struct addrinfo *res) {
    static void (*real_fai)(struct addrinfo *) = NULL;
    if (!real_fai) real_fai = dlsym(RTLD_NEXT, "freeaddrinfo");

    if (res) {
        for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
            void* tmp = *(void**)((char*)p + 24);
            *(void**)((char*)p + 24) = *(void**)((char*)p + 32);
            *(void**)((char*)p + 32) = tmp;
        }
    }
    real_fai(res);
}

int handshake_set_product_line(void* h, const char* pl) {
    static int (*real_fn)(void*, const char*) = NULL;
    if (!real_fn) real_fn = dlsym(RTLD_NEXT, "handshake_set_product_line");
    return real_fn(h, pl);
}

int handshake_set_client_version(void* h, const char* ver) {
    static int (*real_fn)(void*, const char*) = NULL;
    if (!real_fn) real_fn = dlsym(RTLD_NEXT, "handshake_set_client_version");
    return real_fn(h, ver);
}

int handshake_set_authentication(void* h, unsigned short authType, const char* username, const char* password) {
    static int (*real_fn)(void*, unsigned short, const char*, const char*) = NULL;
    if (!real_fn) real_fn = dlsym(RTLD_NEXT, "handshake_set_authentication");
    return real_fn(h, authType, username, password);
}

int handshake_get_errno(void* h) {
    static int (*real_fn)(void*) = NULL;
    if (!real_fn) real_fn = dlsym(RTLD_NEXT, "handshake_get_errno");
    return real_fn(h);
}

const char* handshake_get_strerror(void* h) {
    static const char* (*real_fn)(void*) = NULL;
    if (!real_fn) real_fn = dlsym(RTLD_NEXT, "handshake_get_strerror");
    return real_fn(h);
}

unsigned int handshake_get_heartbeat_interval(void* h) {
    static unsigned int (*real_fn)(void*) = NULL;
    if (!real_fn) real_fn = dlsym(RTLD_NEXT, "handshake_get_heartbeat_interval");
    return real_fn(h);
}

void handshake_log(void* ctx, int level, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[HANDSHAKE_LOG %d] ", level);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

int libhandshake_MD5_Update(void* ctx, const void* data, unsigned int len) {
    static int (*real_fn)(void*, const void*, unsigned int) = NULL;
    if (!real_fn) real_fn = dlsym(RTLD_NEXT, "libhandshake_MD5_Update");
    return real_fn(ctx, data, len);
}

int libhandshake_MD5_Final(void* ctx, unsigned char* digest) {
    static int (*real_fn)(void*, unsigned char*) = NULL;
    if (!real_fn) real_fn = dlsym(RTLD_NEXT, "libhandshake_MD5_Final");
    return real_fn(ctx, digest);
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
    if (!real_fflush) real_fflush = dlsym(RTLD_NEXT, "fflush");
    return real_fflush(translate_file(stream));
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*real_fwrite)(const void *, size_t, size_t, FILE *) = NULL;
    if (!real_fwrite) real_fwrite = dlsym(RTLD_NEXT, "fwrite");
    return real_fwrite(ptr, size, nmemb, translate_file(stream));
}

int fputs(const char *s, FILE *stream) {
    static int (*real_fputs)(const char *, FILE *) = NULL;
    if (!real_fputs) real_fputs = dlsym(RTLD_NEXT, "fputs");
    return real_fputs(s, translate_file(stream));
}

int fputc(int c, FILE *stream) {
    static int (*real_fputc)(int, FILE *) = NULL;
    if (!real_fputc) real_fputc = dlsym(RTLD_NEXT, "fputc");
    return real_fputc(c, translate_file(stream));
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*real_fread)(void *, size_t, size_t, FILE *) = NULL;
    if (!real_fread) real_fread = dlsym(RTLD_NEXT, "fread");
    return real_fread(ptr, size, nmemb, translate_file(stream));
}

int fclose(FILE *stream) {
    static int (*real_fclose)(FILE *) = NULL;
    if (!real_fclose) real_fclose = dlsym(RTLD_NEXT, "fclose");
    FILE *t = translate_file(stream);
    if (t == stdin || t == stdout || t == stderr) return 0;
    return real_fclose(t);
}

int fprintf(FILE *stream, const char *fmt, ...) {
    static int (*real_vfprintf)(FILE *, const char *, va_list) = NULL;
    if (!real_vfprintf) real_vfprintf = dlsym(RTLD_NEXT, "vfprintf");
    va_list ap;
    va_start(ap, fmt);
    int ret = real_vfprintf(translate_file(stream), fmt, ap);
    va_end(ap);
    return ret;
}

int vfprintf(FILE *stream, const char *fmt, va_list ap) {
    static int (*real_vfprintf)(FILE *, const char *, va_list) = NULL;
    if (!real_vfprintf) real_vfprintf = dlsym(RTLD_NEXT, "vfprintf");
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
