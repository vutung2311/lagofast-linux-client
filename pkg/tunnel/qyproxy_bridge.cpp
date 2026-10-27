#include "qyproxy_bridge.h"

#include <iostream>
#include <string>
#include <vector>
#include <mutex>
#include <cstring>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/stat.h>

struct ndk_string {
    void* p[3];
};

typedef void (*str_init_t)(ndk_string*, const char*, size_t);
typedef void (*str_free_t)(ndk_string*);
typedef void (*ctor_t)(void*);
typedef void (*initial_t)(void*, ndk_string*);
typedef bool (*start_t)(void*, void*, ndk_string*, ndk_string*);
typedef void (*stop_t)(void*, ndk_string*);

static std::mutex g_mutex;
static bool g_initialized = false;
static int g_running = 0;
static int g_tun_fd = -1;
static std::string g_last_error;

static void* g_h_log = NULL;
static void* g_h_proxy = NULL;
static void* g_h_qy = NULL;

static str_init_t g_str_init = NULL;
static str_free_t g_str_free = NULL;
static ctor_t g_ctor = NULL;
static initial_t g_fn_initial = NULL;
static start_t g_fn_start = NULL;
static stop_t g_fn_stop = NULL;

static void* g_client = NULL;
static void* g_vtable[64];

static void make_ndk_str(ndk_string* out, const char* s) {
    memset(out, 0, sizeof(*out));
    if (g_str_init && s) {
        g_str_init(out, s, strlen(s));
    }
}

static void free_ndk_str(ndk_string* s) {
    if (g_str_free && s) {
        g_str_free(s);
    }
}

static const char* ndk_c_str(ndk_string* s) {
    if (!s) return "";
    unsigned char* b = (unsigned char*)s;
    if ((b[0] & 1) == 0) {
        return (const char*)(b + 1);
    } else {
        return (const char*)(s->p[2]);
    }
}

static bool my_tun_true(void* self, void* a1, void* a2, void* a3, void* a4, void* a5) {
    return true;
}

static int my_tun_establish(void* self) {
    std::cout << "[QYPROXY] Native tun_builder_establish returning TUN fd: " << g_tun_fd << std::endl;
    return g_tun_fd;
}

static void my_event_cb(void* self, void* event) {
    std::cout << "[QYPROXY] Native event callback received" << std::endl;
}

static bool my_socket_protect(void* self, int fd, bool is_ipv6) {
    return true;
}

static bool my_log_hook(void* self, ndk_string* log_msg) {
    const char* msg = ndk_c_str(log_msg);
    if (msg && msg[0]) {
        std::cout << "[QY_LOG] " << msg << std::endl;
    }
    return true;
}

static long dummy_virtual_fn(void* self, void* a1, void* a2, void* a3) {
    return 1;
}

static bool file_exists(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

int qyproxy_init(const char* lib_dir) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_initialized) {
        return 0;
    }

    std::vector<std::string> search_dirs;
    if (lib_dir && strlen(lib_dir) > 0) {
        search_dirs.push_back(lib_dir);
    }
    const char* env_dir = getenv("LAGOFAST_LIB_DIR");
    if (env_dir && strlen(env_dir) > 0) {
        search_dirs.push_back(env_dir);
    }
    search_dirs.push_back("/usr/local/lib/lagofast");
    search_dirs.push_back("/tmp/patch_test");
    search_dirs.push_back("./compat_test");
    search_dirs.push_back("./extracted_libs");

    std::string found_log, found_proxy, found_qy;

    for (const auto& dir : search_dirs) {
        std::string p_log = dir + "/liblog.so";
        std::string p_proxy = dir + "/libproxy.so";
        std::string p_qy = dir + "/libqyproxy-lib.so";

        if (found_log.empty() && file_exists(p_log)) found_log = p_log;
        if (found_proxy.empty() && file_exists(p_proxy)) found_proxy = p_proxy;
        if (found_qy.empty() && file_exists(p_qy)) found_qy = p_qy;
    }

    if (found_log.empty()) {
        g_last_error = "liblog.so not found in candidate paths";
        return -1;
    }
    if (found_proxy.empty()) {
        g_last_error = "libproxy.so not found in candidate paths";
        return -2;
    }
    if (found_qy.empty()) {
        g_last_error = "libqyproxy-lib.so not found in candidate paths";
        return -3;
    }

    g_h_log = dlopen(found_log.c_str(), RTLD_NOW | RTLD_GLOBAL);
    if (!g_h_log) {
        g_last_error = std::string("dlopen liblog failed: ") + dlerror();
        return -4;
    }

    g_h_proxy = dlopen(found_proxy.c_str(), RTLD_NOW | RTLD_GLOBAL);
    if (!g_h_proxy) {
        g_last_error = std::string("dlopen libproxy failed: ") + dlerror();
        return -5;
    }

    g_h_qy = dlopen(found_qy.c_str(), RTLD_NOW | RTLD_GLOBAL);
    if (!g_h_qy) {
        g_last_error = std::string("dlopen libqyproxy-lib failed: ") + dlerror();
        return -6;
    }

    g_str_init = (str_init_t)dlsym(g_h_proxy, "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm");
    g_str_free = (str_free_t)dlsym(g_h_proxy, "_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev");

    if (!g_str_init || !g_str_free) {
        g_last_error = "Failed to resolve ndk_string functions in libproxy.so";
        return -7;
    }

    Dl_info info;
    void* sym_new = dlsym(g_h_qy, "Java_net_qyproxy_vpn_QyproxyCliJNI_new_1QyProxyClient");
    if (!sym_new || !dladdr(sym_new, &info)) {
        g_last_error = "Failed to locate libqyproxy-lib base address";
        return -8;
    }

    char* qy_base = (char*)info.dli_fbase;
    g_ctor = (ctor_t)(qy_base + 0x3dab0);
    g_fn_initial = (initial_t)(qy_base + 0x42070);
    g_fn_start = (start_t)(qy_base + 0x45370);

    g_client = calloc(1, 168);
    if (!g_client) {
        g_last_error = "Failed to allocate memory for QyProxyClient";
        return -9;
    }

    g_ctor(g_client);

    void** orig_vtable = *(void***)g_client;
    memcpy(g_vtable, orig_vtable, 64 * sizeof(void*));

    void* pure_virt = dlsym(RTLD_DEFAULT, "__cxa_pure_virtual");
    for (int i = 0; i < 64; i++) {
        if (g_vtable[i] == pure_virt) {
            g_vtable[i] = (void*)&dummy_virtual_fn;
        }
    }

    for (int i = 0; i <= 18; i++) {
        g_vtable[i] = (void*)&my_tun_true;
    }
    g_vtable[19] = (void*)&my_tun_establish;
    g_fn_stop = (stop_t)orig_vtable[26];
    g_vtable[27] = (void*)&my_event_cb;
    g_vtable[28] = (void*)&my_socket_protect;
    g_vtable[31] = (void*)&my_log_hook;

    *(void***)g_client = g_vtable;

    ndk_string tag_str;
    make_ndk_str(&tag_str, "QyProxy");
    g_fn_initial(g_client, &tag_str);
    free_ndk_str(&tag_str);

    g_initialized = true;
    return 0;
}

int qyproxy_start(const char* config_json, int tun_fd) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_initialized) {
        int err = qyproxy_init(NULL);
        if (err != 0) return err;
    }

    if (!config_json || tun_fd < 0) {
        g_last_error = "Invalid arguments to qyproxy_start";
        return -10;
    }

    g_tun_fd = tun_fd;

    ndk_string cfg_str;
    make_ndk_str(&cfg_str, config_json);

    ndk_string tag_str;
    make_ndk_str(&tag_str, "QyProxy");

    bool ok = g_fn_start(g_client, NULL, &cfg_str, &tag_str);

    free_ndk_str(&cfg_str);
    free_ndk_str(&tag_str);

    if (!ok) {
        g_last_error = "QyProxyClient::start returned false";
        return -11;
    }

    g_running = 1;
    return 0;
}

void qyproxy_stop(void) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_initialized || !g_running) {
        return;
    }

    if (g_client && g_fn_stop) {
        ndk_string stop_reason;
        make_ndk_str(&stop_reason, "user_stop");
        g_fn_stop(g_client, &stop_reason);
        free_ndk_str(&stop_reason);
    }

    g_running = 0;
}

int qyproxy_is_running(void) {
    return g_running;
}

const char* qyproxy_last_error(void) {
    return g_last_error.c_str();
}
