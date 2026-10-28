#ifndef QYPROXY_BRIDGE_H
#define QYPROXY_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

// Set the physical interface to bind protected tunnel sockets (e.g. "wlan0", "eth0").
void qyproxy_set_bind_interface(const char* iface);

// Initialize the QyProxy native bridge by loading liblog.so, libproxy.so, libqyproxy-lib.so.
// If lib_dir is NULL or empty, default locations will be searched.
// Returns 0 on success, or non-zero error code.
int qyproxy_init(const char* lib_dir);

// Start the QyProxy client tunnel with the specified JSON configuration and TUN file descriptor.
// Returns 0 on success, or non-zero error code.
int qyproxy_start(const char* config_json, int tun_fd);

// Stop the QyProxy client tunnel and release resources.
void qyproxy_stop(void);

// Returns 1 if running and connected, 0 otherwise.
int qyproxy_is_running(void);

// Get last error message (if any)
const char* qyproxy_last_error(void);

#ifdef __cplusplus
}
#endif

#endif // QYPROXY_BRIDGE_H
