package tunnel

import (
	"net"
	"os"
	"testing"
)

func TestBytesTrimRight(t *testing.T) {
	input := []byte{'l', 'a', 'g', 'o', '0', 0, 0, 0}
	trimmed := bytesTrimRight(input)
	if string(trimmed) != "lago0" {
		t.Errorf("Expected 'lago0', got '%s'", string(trimmed))
	}
}

func TestOpenTun_Permissions(t *testing.T) {
	dev, err := OpenTun("lagotest0", DefaultMTU)
	if err != nil {
		if os.IsPermission(err) || os.Geteuid() != 0 {
			t.Logf("Expected permission error when non-root: %v", err)
			return
		}
		t.Fatalf("Unexpected error opening TUN: %v", err)
	}
	defer dev.Close()

	if dev.Name != "lagotest0" {
		t.Errorf("Expected device name lagotest0, got %s", dev.Name)
	}
}

// Regression: OpenTun used to record the MTU without applying it, leaving the
// interface at the kernel default. Run as root, or unprivileged via
// `unshare -rn go test ./pkg/tunnel`.
func TestOpenTun_AppliesMTU(t *testing.T) {
	dev, err := OpenTun("lagomtu0", 1280)
	if err != nil {
		t.Skipf("cannot create TUN here: %v", err)
	}
	defer dev.Close()

	iface, err := net.InterfaceByName(dev.Name)
	if err != nil {
		t.Fatalf("InterfaceByName: %v", err)
	}
	if iface.MTU != 1280 || dev.MTU != 1280 {
		t.Fatalf("expected MTU 1280, kernel=%d struct=%d", iface.MTU, dev.MTU)
	}
}
