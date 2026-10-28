package tunnel

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	DefaultTunName = "lagofast0"
	DefaultMTU     = 1400
)

type ifreq struct {
	Name [unix.IFNAMSIZ]byte
	Data [24]byte
}

type Device struct {
	Name string
	File *os.File
	MTU  int
}

// OpenTun creates and opens a Linux TUN interface
func OpenTun(name string, mtu int) (*Device, error) {
	if name == "" {
		name = DefaultTunName
	}
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %w", err)
	}

	var req ifreq
	copy(req.Name[:], []byte(name))
	flags := (*uint16)(unsafe.Pointer(&req.Data[0]))
	*flags = unix.IFF_TUN | unix.IFF_NO_PI

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF failed: %w", errno)
	}

	actualName := string(bytesTrimRight(req.Name[:]))
	dev := &Device{
		Name: actualName,
		File: os.NewFile(uintptr(fd), actualName),
		MTU:  mtu,
	}

	// Optimize transmit queue length for lower packet drop under gaming bursts
	_ = dev.SetTxQueueLen(1000)

	return dev, nil
}

// SetTxQueueLen sets the transmission queue length on the TUN interface
func (d *Device) SetTxQueueLen(qlen int) error {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(s)

	var req ifreq
	copy(req.Name[:], []byte(d.Name))
	q := (*int32)(unsafe.Pointer(&req.Data[0]))
	*q = int32(qlen)

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(s),
		uintptr(unix.SIOCSIFTXQLEN),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		return fmt.Errorf("ioctl SIOCSIFTXQLEN failed: %w", errno)
	}
	return nil
}

// SetIP configures the IPv4 address on the TUN interface
func (d *Device) SetIP(ip net.IP, mask net.IPMask) error {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(s)

	var req ifreq
	copy(req.Name[:], []byte(d.Name))

	// Set IP address (ifr_addr begins immediately at offset 16)
	sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(&req.Data[0]))
	sa.Family = unix.AF_INET
	copy(sa.Addr[:], ip.To4())

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(s),
		uintptr(unix.SIOCSIFADDR),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 && errno != syscall.EEXIST {
		return fmt.Errorf("ioctl SIOCSIFADDR failed: %w", errno)
	}

	// Set Netmask
	if len(mask) == 4 {
		saMask := (*unix.RawSockaddrInet4)(unsafe.Pointer(&req.Data[0]))
		saMask.Family = unix.AF_INET
		copy(saMask.Addr[:], mask)
		unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(s),
			uintptr(unix.SIOCSIFNETMASK),
			uintptr(unsafe.Pointer(&req)),
		)
	}

	// Bring interface UP
	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(s),
		uintptr(unix.SIOCGIFFLAGS),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno == 0 {
		ifrFlags := (*uint16)(unsafe.Pointer(&req.Data[0]))
		*ifrFlags |= unix.IFF_UP | unix.IFF_RUNNING
		unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(s),
			unix.SIOCSIFFLAGS,
			uintptr(unsafe.Pointer(&req)),
		)
	}

	return nil
}

func (d *Device) Close() error {
	if d.File != nil {
		return d.File.Close()
	}
	return nil
}

func bytesTrimRight(b []byte) []byte {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] != 0 {
			return b[:i+1]
		}
	}
	return nil
}
