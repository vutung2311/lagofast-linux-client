package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"testing"
)

// encryptLikeChromium builds a v11 cookie payload the way Chromium on Linux does.
func encryptLikeChromium(t *testing.T, secret, host, value string, metaVersion int) []byte {
	t.Helper()
	plain := []byte(value)
	if metaVersion >= 24 {
		sum := sha256.Sum256([]byte(host))
		plain = append(sum[:], plain...)
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	plain = append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
	block, err := aes.NewCipher(DeriveKey(secret))
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, bytes.Repeat([]byte(" "), aes.BlockSize)).CryptBlocks(out, plain)
	return out
}

func TestDecryptWithKey(t *testing.T) {
	const host, token = ".lagofast.com", "202610abcdef0123456789"
	for _, mv := range []int{23, 24} {
		enc := encryptLikeChromium(t, "right-secret", host, token, mv)

		if got, ok := decryptWithKey(enc, DeriveKey("right-secret"), host, mv); !ok || got != token {
			t.Errorf("meta %d: right key: got %q ok=%v, want %q", mv, got, ok, token)
		}
		// The old code returned garbage here instead of failing.
		if got, ok := decryptWithKey(enc, DeriveKey("wrong-secret"), host, mv); ok {
			t.Errorf("meta %d: wrong key accepted, decrypted to %q", mv, got)
		}
	}

	// Schema 24 value must not decrypt under a different host (hash check).
	enc := encryptLikeChromium(t, "s", host, token, 24)
	if _, ok := decryptWithKey(enc, DeriveKey("s"), "www.other.com", 24); ok {
		t.Error("host hash mismatch was accepted")
	}
	// Schema 23 value must not lose its first 32 bytes (old code always stripped them).
	long := "0123456789012345678901234567890123456789-tail"
	enc = encryptLikeChromium(t, "s", host, long, 23)
	if got, ok := decryptWithKey(enc, DeriveKey("s"), host, 23); !ok || got != long {
		t.Errorf("meta 23 long value: got %q ok=%v", got, ok)
	}
}

func TestMatchProfiles(t *testing.T) {
	chrome, chromium := &browserDefs[0], &browserDefs[1]
	ps := []BrowserProfile{
		{def: chrome, Dir: "Default", DisplayName: "Tung@Local", Email: "me@example.com"},
		{def: chrome, Dir: "Profile 1", DisplayName: "Work", Email: "me@work.example"},
		{def: chromium, Dir: "Default", DisplayName: "Work"},
	}
	cases := map[string][]string{
		"chrome:Profile 1": {"chrome:Profile 1"},
		"CHROME:default":   {"chrome:Default"},
		"chrome":           {"chrome:Default", "chrome:Profile 1"},
		"me@example.com":   {"chrome:Default"},
		"Work":             {"chrome:Profile 1", "chromium:Default"},
		"nope":             nil,
	}
	for in, want := range cases {
		var got []string
		for _, p := range MatchProfiles(ps, in) {
			got = append(got, p.ID())
		}
		if len(got) != len(want) {
			t.Errorf("%q: got %v want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%q: got %v want %v", in, got, want)
			}
		}
	}

}
