package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/lagofast/lagofast-vpn/pkg/model"
)

const (
	GoogleClientID = "191210733397-cnfhehfl7ife3c22u7n37ljo50m0q3bj.apps.googleusercontent.com"
)

const loginHTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>LagoFast Linux Client - Google Sign-In</title>
  <script src="https://accounts.google.com/gsi/client" async defer></script>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; background: #0f1117; color: #fff; margin: 0; }
    .card { background: #1a1d26; padding: 40px; border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.6); text-align: center; max-width: 400px; width: 90%; }
    h2 { margin-top: 0; color: #4e73df; font-weight: 600; }
    p { color: #a0aec0; margin-bottom: 24px; font-size: 14px; }
  </style>
</head>
<body>
  <div class="card" id="main">
    <h2>LagoFast Linux Client</h2>
    <p>Sign in with your Google account to authorize the Linux client:</p>
    <div id="g_id_onload"
         data-client_id="` + GoogleClientID + `"
         data-callback="handleCredentialResponse"
         data-auto_prompt="false">
    </div>
    <div class="g_id_signin" data-type="standard" data-size="large" data-theme="filled_blue"></div>
  </div>
  <script>
    function handleCredentialResponse(response) {
      document.getElementById('main').innerHTML = "<h2>Authorizing...</h2><p>Exchanging tokens with LagoFast...</p>";
      fetch('/callback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: response.credential })
      }).then(r => r.json()).then(data => {
        if (data.success) {
          document.getElementById('main').innerHTML = "<h2 style='color:#10b981'>Authorization Successful!</h2><p>You can close this tab and return to your terminal.</p>";
        } else {
          document.getElementById('main').innerHTML = "<h2 style='color:#ef4444'>Login Failed</h2><p>" + (data.error || 'Unknown error') + "</p>";
        }
      }).catch(err => {
        document.getElementById('main').innerHTML = "<h2 style='color:#ef4444'>Network Error</h2><p>" + err.message + "</p>";
      });
    }
  </script>
</body>
</html>`

// StartGoogleOAuthFlow starts a local web server to capture Google Sign-In
func (c *Client) StartGoogleOAuthFlow(port int) (*model.UserSession, error) {
	if port <= 0 {
		port = 8085
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	serverURL := fmt.Sprintf("http://%s/login", addr)

	resultChan := make(chan *model.UserSession, 1)
	errChan := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(loginHTML))
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			Credential string `json:"credential"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		session, err := c.LoginWithGoogle(payload.Credential)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"error":   err.Error(),
			})
			errChan <- err
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
		})
		resultChan <- session
	})

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("oauth server error: %w", err)
		}
	}()

	fmt.Printf("\nOpening browser for Google Sign-In...\n")
	fmt.Printf("If your browser doesn't open automatically, visit:\n  %s\n\n", serverURL)

	openBrowser(serverURL)

	// Wait for callback or timeout (2 minutes)
	select {
	case session := <-resultChan:
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		server.Shutdown(ctx)
		return session, nil
	case err := <-errChan:
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		server.Shutdown(ctx)
		return nil, err
	case <-time.After(2 * time.Minute):
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		server.Shutdown(ctx)
		return nil, fmt.Errorf("google login timed out (2 minutes)")
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	}
	if cmd != nil {
		_ = cmd.Start()
	}
}
