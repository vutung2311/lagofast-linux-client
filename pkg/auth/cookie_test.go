package auth

import (
	"testing"
)

func TestDeriveKeyAndDecrypt(t *testing.T) {
	secret := GetChromeSecret()
	if secret == "" {
		t.Skip("No Chrome secret found on system")
	}

	key := DeriveKey(secret)
	if len(key) != 16 {
		t.Fatalf("expected key length 16, got %d", len(key))
	}

	// Read existing _ga or cid cookie
	val, err := ReadLagofastCookie("cid")
	if err != nil {
		t.Logf("cookie cid lookup result: %v", err)
	} else {
		t.Logf("Successfully read and decrypted cid: %s", val)
		if val != "1" {
			t.Errorf("expected cid '1', got '%s'", val)
		}
	}
}
