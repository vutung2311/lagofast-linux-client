package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// LoginCookieName is the cookie lagofast.com sets after a successful sign-in.
const LoginCookieName = "Login-Credential"

// DeriveKey derives the 16-byte AES-CBC key using Chromium's Linux PBKDF2 parameters (iterations=1)
func DeriveKey(password string) []byte {
	salt := []byte("saltysalt\x00\x00\x00\x01")
	h := hmac.New(sha1.New, []byte(password))
	h.Write(salt)
	return h.Sum(nil)[:16]
}

var (
	secretMu    sync.Mutex
	secretCache = map[[2]string]string{}
)

// lookupSecret reads a browser "Safe Storage" secret from the Secret Service, falling
// back to KWallet (Chromium on KDE stores it there by default).
func lookupSecret(server, user string) string {
	secretMu.Lock()
	defer secretMu.Unlock()
	k := [2]string{server, user}
	if v, ok := secretCache[k]; ok {
		return v
	}
	v := ""
	if out, err := exec.Command("secret-tool", "lookup", "server", server, "user", user).Output(); err == nil {
		v = string(bytes.TrimSpace(out))
	}
	if v == "" {
		if out, err := exec.Command("kwallet-query", "-r", user, "-f", server, "kdewallet").Output(); err == nil {
			v = string(bytes.TrimSpace(out))
			if strings.HasPrefix(v, "Failed") {
				v = ""
			}
		}
	}
	secretCache[k] = v
	return v
}

// candidateKeys returns the AES keys to try for a cookie of the given version prefix.
func (p *BrowserProfile) candidateKeys(prefix string) [][]byte {
	var keys [][]byte
	peanuts := DeriveKey("peanuts")
	if prefix == "v10" {
		keys = append(keys, peanuts)
	}
	for _, kr := range p.def.Keyrings {
		if s := lookupSecret(kr[0], kr[1]); s != "" {
			keys = append(keys, DeriveKey(s))
		}
	}
	if prefix != "v10" {
		keys = append(keys, peanuts)
	}
	return keys
}

// decryptWithKey decrypts one Chromium cookie payload (without the vNN prefix) and
// checks that the result is really plaintext. AES-CBC with a wrong key does not fail;
// it produces garbage, so padding and (for DB schema >= 24) the SHA-256 of the host
// that Chromium prepends are both verified.
func decryptWithKey(ciphertext, key []byte, host string, metaVersion int) (string, bool) {
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return "", false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, bytes.Repeat([]byte(" "), aes.BlockSize)).CryptBlocks(out, ciphertext)

	pad := int(out[len(out)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(out) {
		return "", false
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			return "", false
		}
	}
	out = out[:len(out)-pad]

	if metaVersion >= 24 {
		sum := sha256.Sum256([]byte(host))
		if len(out) < len(sum) || !bytes.Equal(out[:len(sum)], sum[:]) {
			return "", false
		}
		out = out[len(sum):]
	}
	if !utf8.Valid(out) {
		return "", false
	}
	return string(out), true
}

func (p *BrowserProfile) decrypt(enc []byte, host string, metaVersion int) (string, error) {
	if len(enc) < 3 {
		return "", errors.New("encrypted cookie too short")
	}
	prefix := string(enc[:3])
	if prefix != "v10" && prefix != "v11" {
		return "", fmt.Errorf("unsupported cookie encryption %q", prefix)
	}
	for _, key := range p.candidateKeys(prefix) {
		if v, ok := decryptWithKey(enc[3:], key, host, metaVersion); ok {
			return v, nil
		}
	}
	return "", fmt.Errorf("could not decrypt %s cookie with any known %s key (is the keyring unlocked?)", prefix, p.def.Name)
}

// Cookie is one decrypted lagofast.com cookie.
type Cookie struct {
	Host, Name, Value string
	Created           time.Time
	LastAccess        time.Time
}

// chromeTime converts Chromium's microseconds-since-1601 to time.Time.
func chromeTime(s string) time.Time {
	us, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || us == 0 {
		return time.Time{}
	}
	return time.UnixMicro(us - 11644473600*1000000)
}

// snapshotDB copies the cookie DB (and its rollback journal) so we never contend for
// the running browser's lock and always read a consistent state.
func snapshotDB(src string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "lagofast-cookies-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	dst := dir + "/Cookies"
	for _, suffix := range []string{"", "-journal", "-wal"} {
		if err := copyFile(src+suffix, dst+suffix); err != nil {
			if suffix == "" {
				cleanup()
				return "", nil, err
			}
		}
	}
	return dst, cleanup, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func sqliteQuery(db, query string) ([][]string, error) {
	out, err := exec.Command("sqlite3", "-batch", "-noheader", "-separator", "\t", db, query).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("sqlite3: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("sqlite3: %w", err)
	}
	var rows [][]string
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line != "" {
			rows = append(rows, strings.Split(line, "\t"))
		}
	}
	return rows, nil
}

// ReadLagofastCookies returns this profile's lagofast.com cookies, newest first.
// An empty name returns all of them.
func (p *BrowserProfile) ReadLagofastCookies(name string) ([]Cookie, error) {
	db, cleanup, err := snapshotDB(p.CookiePath())
	if err != nil {
		return nil, err
	}
	defer cleanup()

	metaVersion := 0
	if rows, err := sqliteQuery(db, "SELECT value FROM meta WHERE key='version';"); err == nil && len(rows) > 0 {
		metaVersion, _ = strconv.Atoi(rows[0][0])
	}

	q := "SELECT host_key, name, hex(encrypted_value), hex(value), creation_utc, last_access_utc FROM cookies " +
		"WHERE (host_key = 'lagofast.com' OR host_key LIKE '%.lagofast.com')"
	if name != "" {
		q += " AND name = '" + strings.ReplaceAll(name, "'", "''") + "'"
	}
	q += " ORDER BY creation_utc DESC;"
	rows, err := sqliteQuery(db, q)
	if err != nil {
		return nil, err
	}

	var cookies []Cookie
	var lastErr error
	for _, r := range rows {
		if len(r) < 6 {
			continue
		}
		c := Cookie{Host: r[0], Name: r[1], Created: chromeTime(r[4]), LastAccess: chromeTime(r[5])}
		if plain, _ := hex.DecodeString(r[3]); len(plain) > 0 {
			c.Value = string(plain)
		} else if enc, _ := hex.DecodeString(r[2]); len(enc) > 0 {
			v, err := p.decrypt(enc, c.Host, metaVersion)
			if err != nil {
				lastErr = err
				continue
			}
			c.Value = v
		}
		cookies = append(cookies, c)
	}
	if len(cookies) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return cookies, nil
}

// ReadLoginCredential returns the profile's Login-Credential cookie, or "" if absent.
func (p *BrowserProfile) ReadLoginCredential() (string, error) {
	cookies, err := p.ReadLagofastCookies(LoginCookieName)
	if err != nil {
		return "", err
	}
	for _, c := range cookies {
		if c.Value != "" {
			return c.Value, nil
		}
	}
	return "", nil
}
