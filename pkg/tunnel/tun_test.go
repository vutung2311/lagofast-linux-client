package tunnel

import (
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
	dev, err := OpenTun("lagotest0", 1400)
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
