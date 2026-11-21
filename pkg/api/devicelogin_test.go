package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewLoginState(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		s, err := NewLoginState()
		if err != nil {
			t.Fatal(err)
		}
		if len(s) != stateLength {
			t.Fatalf("len %d, want %d", len(s), stateLength)
		}
		if strings.Trim(s, stateAlphabet) != "" {
			t.Fatalf("state %q has characters outside the alphabet", s)
		}
		if seen[s] {
			t.Fatalf("duplicate state %q", s)
		}
		seen[s] = true
	}
}

func TestGoogleLoginURL(t *testing.T) {
	got := GoogleLoginURL("", "abc_-XYZ09")
	if want := "https://h5win.lagofast.com/google/login?token=abc_-XYZ09"; got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestParseStateResponse(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    StateResult
		wantErr bool
	}{
		// Verbatim from cbs.lagofast.com for a state nobody has signed in with.
		{"observed pending", `{"state_validated": 0, "login_credential": "", "open_id": "", "is_bind": 0, "new_resgit": 0}`, StateResult{}, false},
		{"int validated", `{"state_validated": 1, "login_credential": "CRED", "open_id": "x", "is_bind": 1, "new_resgit": 0}`,
			StateResult{Validated: true, LoginCredential: "CRED"}, false},
		{"bad flag", `{"state_validated": 2}`, StateResult{}, true},
		{"flat pending", `{"state_validated":false}`, StateResult{}, false},
		{"flat pending empty", `{}`, StateResult{}, false},
		{"flat validated", `{"state_validated":true,"login_credential":"CRED","new_resgit":true}`,
			StateResult{Validated: true, LoginCredential: "CRED", NewRegistration: true}, false},
		{"wrapped validated", `{"success":true,"result":{"state_validated":true,"login_credential":"CRED"}}`,
			StateResult{Validated: true, LoginCredential: "CRED"}, false},
		{"wrapped pending", `{"success":true,"result":{"state_validated":false}}`, StateResult{}, false},
		{"wrapped failure", `{"success":false,"error_msg":"bad state"}`, StateResult{}, true},
		{"error body", `{"error_code":400,"error_msg":"invalid"}`, StateResult{}, true},
		{"validated without credential", `{"state_validated":true}`, StateResult{}, true},
		{"not json", `<html>`, StateResult{}, true},
	}
	for _, c := range cases {
		got, err := ParseStateResponse([]byte(c.body))
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", c.name, err, c.wantErr)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
		}
	}
}

// fakeBackend serves validate_state from a script of responses and a member/detail
// that accepts only the credential "CRED".
type fakeBackend struct {
	t        *testing.T
	state    string
	script   []func(w http.ResponseWriter) // one per poll; the last repeats
	polls    atomic.Int32
	detailOK atomic.Bool
}

func (f *fakeBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case googleValidateStateAPI:
		if r.Method != http.MethodPost {
			f.t.Errorf("validate_state method %s", r.Method)
		}
		if h := r.Header.Get("Login-Credential"); h != "" {
			f.t.Errorf("validate_state leaked saved token %q", h)
		}
		if r.Header.Get("Useragent") == "" {
			f.t.Error("validate_state missing Useragent header")
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["state"] != f.state {
			f.t.Errorf("polled state %q, want %q", body["state"], f.state)
		}
		n := int(f.polls.Add(1)) - 1
		if n >= len(f.script) {
			n = len(f.script) - 1
		}
		f.script[n](w)
	case "/api/common_bll/v1/member/detail":
		if r.Header.Get("Login-Credential") != "CRED" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error_code":401,"error_msg":"Login credential expired"}`))
			return
		}
		f.detailOK.Store(true)
		_, _ = w.Write([]byte(`{"uid":"U123","member_name":"me@example.com","email":"me@example.com"}`))
	default:
		f.t.Errorf("unexpected request %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func reply(status int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func newFake(t *testing.T, script ...func(http.ResponseWriter)) (*fakeBackend, *Client) {
	f := &fakeBackend{t: t, state: "STATE-1", script: script}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL)
	c.SetToken("OLD-SAVED-TOKEN", "OLDUID") // must never be sent to validate_state
	return f, c
}

func TestPollGoogleLoginSuccess(t *testing.T) {
	f, c := newFake(t,
		reply(200, `{"state_validated": 0, "login_credential": "", "open_id": "", "is_bind": 0, "new_resgit": 0}`),
		reply(503, `upstream busy`), // transient: keep polling
		reply(200, `{"state_validated":false}`),
		reply(200, `{"state_validated": 1, "login_credential": "CRED", "is_bind": 1, "new_resgit": 0}`),
	)
	var pending []error
	sess, err := c.PollGoogleLogin(context.Background(), f.state, PollOptions{
		Interval:  time.Millisecond,
		OnPending: func(_ int, e error) { pending = append(pending, e) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.polls.Load(); got != 4 {
		t.Errorf("polls = %d, want 4", got)
	}
	if len(pending) != 3 || pending[0] != nil || pending[1] == nil || pending[2] != nil {
		t.Errorf("OnPending calls = %v, want [nil, transient, nil]", pending)
	}
	if !f.detailOK.Load() {
		t.Error("credential was not checked with member/detail")
	}
	if sess.Token != "CRED" || sess.UID != "U123" || sess.Account != "me@example.com" {
		t.Errorf("session = %+v", sess)
	}
	if !sess.Verified || sess.VerifiedAt == 0 || sess.LoginMethod != "google-device" {
		t.Errorf("session not marked verified: %+v", sess)
	}
	// The backend reported neither, so neither may be invented.
	if sess.IsVIP || sess.ExpireTime != 0 {
		t.Errorf("fabricated VIP/expiry: %+v", sess)
	}
}

func TestPollGoogleLoginRejectedState(t *testing.T) {
	f, c := newFake(t, reply(400, `{"error_code":400,"error_msg":"invalid state"}`))
	_, err := c.PollGoogleLogin(context.Background(), f.state, PollOptions{Interval: time.Millisecond})
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 400 {
		t.Fatalf("err = %v, want HTTP 400", err)
	}
	if got := f.polls.Load(); got != 1 {
		t.Errorf("polls = %d, want 1 (4xx must stop polling)", got)
	}
}

func TestPollGoogleLoginCredentialRejected(t *testing.T) {
	f, c := newFake(t, reply(200, `{"state_validated":true,"login_credential":"NOT-CRED"}`))
	_, err := c.PollGoogleLogin(context.Background(), f.state, PollOptions{Interval: time.Millisecond})
	if err == nil || !IsUnauthorized(err) {
		t.Fatalf("err = %v, want unauthorized from member/detail", err)
	}
}

func TestPollGoogleLoginTimeoutAndCancel(t *testing.T) {
	f, c := newFake(t, reply(200, `{"state_validated":false}`))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := c.PollGoogleLogin(ctx, f.state, PollOptions{Interval: 5 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}
	if f.polls.Load() < 2 {
		t.Errorf("polls = %d, want several before timeout", f.polls.Load())
	}

	ctx, cancel = context.WithCancel(context.Background())
	cancel() // like Ctrl+C before the first poll
	before := f.polls.Load()
	_, err = c.PollGoogleLogin(ctx, f.state, PollOptions{Interval: time.Hour})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want canceled", err)
	}
	if f.polls.Load() > before+1 {
		t.Error("kept polling after cancel")
	}
}

func TestPollGoogleLoginStopsOnGarbage(t *testing.T) {
	f, c := newFake(t, reply(200, `<html>maintenance</html>`))
	_, err := c.PollGoogleLogin(context.Background(), f.state, PollOptions{Interval: time.Millisecond})
	if !errors.Is(err, errProtocol) {
		t.Fatalf("err = %v, want protocol error", err)
	}
	if got := f.polls.Load(); got != 1 {
		t.Errorf("polls = %d, want 1 (unparseable responses must not be retried)", got)
	}
}
