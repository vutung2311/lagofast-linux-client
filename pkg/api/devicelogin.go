package api

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lagofast/lagofast-vpn/pkg/model"
)

// Device-style Google sign-in, as used by www.lagofast.com when it cannot show the
// in-page Google button:
//
//  1. The client generates a random state token.
//  2. The user opens https://h5win.lagofast.com/google/login?token=<state> in any
//     browser, on any device. That page runs Google's OAuth code flow with
//     state=<state> and redirect_uri pointing at LagoFast's own login_callback,
//     so the server binds the Google sign-in to the state. Nothing redirects back
//     to this machine.
//  3. The client polls validate_state until it reports state_validated together
//     with a login_credential.

const (
	DefaultLoginPortal     = "https://h5win.lagofast.com"
	googleValidateStateAPI = "/api/third_party_login/v2/member/google/validate_state"

	// State alphabet and length used by the LagoFast website (64 symbols, so a
	// random byte masked to 6 bits picks one uniformly).
	stateAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	stateLength   = 32
)

// NewLoginState returns a fresh, unguessable sign-in state token (192 bits).
func NewLoginState() (string, error) {
	buf := make([]byte, stateLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate login state: %w", err)
	}
	for i, b := range buf {
		buf[i] = stateAlphabet[b&63]
	}
	return string(buf), nil
}

// GoogleLoginURL is the page the user opens to sign in for the given state.
func GoogleLoginURL(portal, state string) string {
	if portal == "" {
		portal = DefaultLoginPortal
	}
	return portal + "/google/login?token=" + url.QueryEscape(state)
}

// StateResult is the parsed validate_state response.
type StateResult struct {
	Validated       bool
	LoginCredential string
	NewRegistration bool
}

// flexBool decodes the API's integer flags (0/1, as validate_state actually sends
// them) as well as JSON booleans and their string forms.
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	switch strings.Trim(string(data), `"`) {
	case "1", "true":
		*b = true
	case "0", "false", "", "null":
		*b = false
	default:
		return fmt.Errorf("not a boolean flag: %s", data)
	}
	return nil
}

// ParseStateResponse accepts the flat body the API returns, observed as
// {"state_validated":0,"login_credential":"","open_id":"","is_bind":0,"new_resgit":0},
// and the {"success":…, "result":{…}} envelope the web client's wrapper exposes.
func ParseStateResponse(body []byte) (StateResult, error) {
	type inner struct {
		StateValidated  flexBool `json:"state_validated"`
		LoginCredential string   `json:"login_credential"`
		NewRegistration flexBool `json:"new_resgit"` // sic, as spelled by the API
	}
	var raw struct {
		inner
		Success   *bool  `json:"success"`
		Result    *inner `json:"result"`
		ErrorCode int    `json:"error_code"`
		ErrorMsg  string `json:"error_msg"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return StateResult{}, fmt.Errorf("%w: validate_state: %v", errProtocol, err)
	}
	if raw.ErrorCode != 0 || (raw.Success != nil && !*raw.Success) {
		return StateResult{}, fmt.Errorf("%w: validate_state rejected (code %d): %s", errProtocol, raw.ErrorCode, raw.ErrorMsg)
	}
	in := raw.inner
	if raw.Result != nil {
		in = *raw.Result
	}
	res := StateResult{Validated: bool(in.StateValidated), LoginCredential: in.LoginCredential, NewRegistration: bool(in.NewRegistration)}
	if res.Validated && res.LoginCredential == "" {
		return StateResult{}, fmt.Errorf("%w: validate_state reported success without a login_credential", errProtocol)
	}
	return res, nil
}

// ValidateGoogleState asks LagoFast whether a sign-in has completed for state.
// It never sends the saved session token.
func (c *Client) ValidateGoogleState(state string) (StateResult, error) {
	body, err := c.doRequestAuth(http.MethodPost, googleValidateStateAPI, nil, map[string]string{"state": state}, false)
	if err != nil {
		return StateResult{}, err
	}
	return ParseStateResponse(body)
}

// PollOptions controls PollGoogleLogin.
type PollOptions struct {
	Interval time.Duration // between polls; default 3s
	// OnPending, if set, is called after each poll that is still waiting, with
	// the number of polls so far and the last transient error (or nil).
	OnPending func(polls int, transient error)
}

// errProtocol marks a response we could not understand. Retrying would only spin
// until the timeout, so it stops polling.
var errProtocol = errors.New("unexpected response from LagoFast")

// isTransient reports errors worth retrying: network failures, 5xx and 429.
// Any other 4xx means the state was rejected and polling cannot succeed.
func isTransient(err error) bool {
	if errors.Is(err, errProtocol) {
		return false
	}
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status >= 500 || he.Status == http.StatusTooManyRequests
	}
	return true
}

// PollGoogleLogin polls validate_state until the sign-in for state completes, ctx is
// done, or the server rejects the state. On success the returned credential is
// checked with member/detail, so the session (UID, account, email) comes from the
// backend. Fields the backend does not report (e.g. VIP, expiry) stay zero.
func (c *Client) PollGoogleLogin(ctx context.Context, state string, opts PollOptions) (*model.UserSession, error) {
	interval := opts.Interval
	if interval <= 0 {
		interval = 3 * time.Second
	}
	timer := time.NewTimer(0) // first poll immediately
	defer timer.Stop()

	for polls := 1; ; polls++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}

		res, err := c.ValidateGoogleState(state)
		switch {
		case err != nil && !isTransient(err):
			return nil, err
		case err == nil && res.Validated:
			sess, verr := c.LoginWithToken(res.LoginCredential)
			if verr != nil {
				return nil, fmt.Errorf("sign-in completed but the credential did not validate: %w", verr)
			}
			sess.Verified = true
			sess.VerifiedAt = time.Now().Unix()
			sess.LoginMethod = "google-device"
			return sess, nil
		}
		if opts.OnPending != nil {
			opts.OnPending(polls, err)
		}
		timer.Reset(interval)
	}
}
