package tunnel

/*
#cgo CXXFLAGS: -std=c++14 -O2 -Wall
#cgo LDFLAGS: -ldl -lstdc++
#include "qyproxy_bridge.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

type Engine struct {
	mu sync.Mutex
}

var DefaultEngine = &Engine{}

func (e *Engine) SetBindInterface(iface string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	cIface := C.CString(iface)
	defer C.free(unsafe.Pointer(cIface))
	C.qyproxy_set_bind_interface(cIface)
}

func (e *Engine) Init(libDir string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	var cLibDir *C.char
	if libDir != "" {
		cLibDir = C.CString(libDir)
		defer C.free(unsafe.Pointer(cLibDir))
	}

	ret := C.qyproxy_init(cLibDir)
	if ret != 0 {
		errMsg := C.GoString(C.qyproxy_last_error())
		return fmt.Errorf("qyproxy_init failed (code %d): %s", int(ret), errMsg)
	}
	return nil
}

func (e *Engine) Start(configJSON string, tunFd int) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if configJSON == "" {
		return errors.New("empty configJSON")
	}
	if tunFd < 0 {
		return errors.New("invalid tunFd")
	}

	cConfig := C.CString(configJSON)
	defer C.free(unsafe.Pointer(cConfig))

	ret := C.qyproxy_start(cConfig, C.int(tunFd))
	if ret != 0 {
		errMsg := C.GoString(C.qyproxy_last_error())
		return fmt.Errorf("qyproxy_start failed (code %d): %s", int(ret), errMsg)
	}
	return nil
}

func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()

	C.qyproxy_stop()
}

func (e *Engine) IsRunning() bool {
	return C.qyproxy_is_running() != 0
}
