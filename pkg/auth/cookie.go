package auth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DeriveKey derives the 16-byte AES-CBC key using Chromium's Linux PBKDF2 parameters (iterations=1)
func DeriveKey(password string) []byte {
	salt := []byte("saltysalt\x00\x00\x00\x01")
	h := hmac.New(sha1.New, []byte(password))
	h.Write(salt)
	return h.Sum(nil)[:16]
}

// GetChromeSecret retrieves the Chrome Safe Storage secret from desktop Secret Service
func GetChromeSecret() string {
	candidates := []struct {
		server string
		user   string
	}{
		{"Chrome Keys", "Chrome Safe Storage"},
		{"Chromium Keys", "Chromium Safe Storage"},
		{"Brave Keys", "Brave Safe Storage"},
	}

	for _, c := range candidates {
		cmd := exec.Command("secret-tool", "lookup", "server", c.server, "user", c.user)
		out, err := cmd.Output()
		if err == nil && len(bytes.TrimSpace(out)) > 0 {
			return string(bytes.TrimSpace(out))
		}
	}

	// Fallback to Chromium hardcoded Linux secret
	return "peanuts"
}

// DecryptCookie decrypts a hex-encoded cookie value from Chromium SQLite database
func DecryptCookie(encHex string, key []byte) (string, error) {
	encHex = strings.TrimSpace(encHex)
	if len(encHex) == 0 {
		return "", fmt.Errorf("empty encrypted cookie")
	}

	data, err := hex.DecodeString(encHex)
	if err != nil {
		return "", fmt.Errorf("failed to hex-decode cookie: %w", err)
	}

	// Must start with v10 or v11
	if len(data) < 3 {
		return "", fmt.Errorf("encrypted cookie too short")
	}

	ciphertext := data[3:]
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext length %d not a multiple of AES block size", len(ciphertext))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("cipher initialization error: %w", err)
	}

	iv := bytes.Repeat([]byte(" "), aes.BlockSize)
	mode := cipher.NewCBCDecrypter(block, iv)

	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	// Strip PKCS7 padding
	if len(decrypted) == 0 {
		return "", fmt.Errorf("empty decrypted payload")
	}
	padLen := int(decrypted[len(decrypted)-1])
	if padLen > 0 && padLen <= aes.BlockSize {
		decrypted = decrypted[:len(decrypted)-padLen]
	}

	// Modern Linux Chromium (v11) prepends a 32-byte header before the plaintext cookie value
	if len(decrypted) > 32 {
		return string(decrypted[32:]), nil
	}

	return string(decrypted), nil
}

// GetCookieDBPaths returns potential SQLite cookie file locations
func GetCookieDBPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	return []string{
		filepath.Join(home, ".config", "google-chrome", "Default", "Cookies"),
		filepath.Join(home, ".config", "google-chrome", "Profile 1", "Cookies"),
		filepath.Join(home, ".config", "chromium", "Default", "Cookies"),
		filepath.Join(home, ".config", "BraveSoftware", "Brave-Browser", "Default", "Cookies"),
		filepath.Join(home, ".config", "microsoft-edge", "Default", "Cookies"),
	}
}

// ReadLagofastCookie attempts to read and decrypt the Login-Credential cookie
func ReadLagofastCookie(cookieName string) (string, error) {
	if cookieName == "" {
		cookieName = "Login-Credential"
	}

	secret := GetChromeSecret()
	key := DeriveKey(secret)

	var lastErr error
	for _, dbPath := range GetCookieDBPaths() {
		if _, err := os.Stat(dbPath); err != nil {
			continue
		}

		// Copy database to a temporary location to prevent SQLite lock contention with running browser
		tmpDB := fmt.Sprintf("/tmp/lagofast_cookie_%d.db", time.Now().UnixNano())
		input, err := os.ReadFile(dbPath)
		if err != nil {
			lastErr = err
			continue
		}
		if err := os.WriteFile(tmpDB, input, 0600); err != nil {
			lastErr = err
			continue
		}
		defer os.Remove(tmpDB)

		query := fmt.Sprintf("SELECT hex(encrypted_value) FROM cookies WHERE host_key LIKE '%%lagofast.com' AND name = '%s' ORDER BY creation_utc DESC LIMIT 1;", cookieName)
		cmd := exec.Command("sqlite3", "-batch", "-noheader", tmpDB, query)
		out, err := cmd.Output()
		if err != nil {
			lastErr = err
			continue
		}

		hexVal := strings.TrimSpace(string(out))
		if hexVal == "" {
			continue
		}

		val, err := DecryptCookie(hexVal, key)
		if err == nil && val != "" {
			return val, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("cookie %s not found in browser database", cookieName)
}

// WatchForLoginCookie polls the browser cookie database until Login-Credential appears
func WatchForLoginCookie(ctx context.Context, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
			token, err := ReadLagofastCookie("Login-Credential")
			if err == nil && len(token) > 0 {
				return token, nil
			}
			if time.Now().After(deadline) {
				return "", fmt.Errorf("timed out waiting for login in browser")
			}
		}
	}
}

// LaunchBrowserWindow opens the LagoFast sign-in page in an app-mode window or default browser
func LaunchBrowserWindow(url string) (*exec.Cmd, error) {
	// Try opening with Chrome in app window mode (looks identical to native desktop client)
	for _, bin := range []string{"google-chrome-stable", "google-chrome", "chromium", "brave"} {
		if path, err := exec.LookPath(bin); err == nil {
			cmd := exec.Command(path, fmt.Sprintf("--app=%s", url))
			if err := cmd.Start(); err == nil {
				return cmd, nil
			}
		}
	}

	// Fallback to xdg-open
	cmd := exec.Command("xdg-open", url)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// CloseAuthWindow attempts to close the login window across Wayland/KDE and X11
func CloseAuthWindow() {
	// 1. If running KDE Plasma / KWin (Wayland or X11)
	script := `for (var i = 0; i < workspace.windowList().length; i++) {
		var w = workspace.windowList()[i];
		if (w.caption && (w.caption.indexOf("LagoFast") !== -1 || w.caption.indexOf("Sign in") !== -1)) {
			w.closeWindow();
		}
	}`
	tmpScript := fmt.Sprintf("/tmp/lagofast_close_%d.js", time.Now().UnixNano())
	if err := os.WriteFile(tmpScript, []byte(script), 0600); err == nil {
		defer os.Remove(tmpScript)
		_ = exec.Command("qdbus", "org.kde.KWin", "/Scripting", "unloadScript", "close_lagofast").Run()
		_ = exec.Command("qdbus", "org.kde.KWin", "/Scripting", "loadScript", tmpScript, "close_lagofast").Run()
		_ = exec.Command("qdbus", "org.kde.KWin", "/Scripting", "start").Run()
	}

	// 2. If running X11 or XWayland, try xdotool
	if xdotool, err := exec.LookPath("xdotool"); err == nil {
		out, err := exec.Command(xdotool, "search", "--name", "LagoFast").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				id := strings.TrimSpace(line)
				if id != "" {
					_ = exec.Command(xdotool, "windowclose", id).Run()
				}
			}
		}
	}
}
