package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// browserDef describes a Chromium-family browser installed the standard Linux way.
type browserDef struct {
	ID        string
	Name      string
	ConfigDir string // relative to ~/.config
	// Keyring entries holding the "Safe Storage" secret, as (server/folder, user/entry).
	// Each browser has its own secret; using the wrong one silently yields garbage.
	Keyrings [][2]string
}

var browserDefs = []browserDef{
	{"chrome", "Google Chrome", "google-chrome",
		[][2]string{{"Chrome Keys", "Chrome Safe Storage"}}},
	{"chromium", "Chromium", "chromium",
		[][2]string{{"Chromium Keys", "Chromium Safe Storage"}}},
	{"thorium", "Thorium", "thorium",
		[][2]string{{"Thorium Keys", "Thorium Safe Storage"}, {"Chromium Keys", "Chromium Safe Storage"}}},
	{"brave", "Brave", filepath.Join("BraveSoftware", "Brave-Browser"),
		[][2]string{{"Brave Keys", "Brave Safe Storage"}}},
	{"vivaldi", "Vivaldi", "vivaldi",
		[][2]string{{"Vivaldi Keys", "Vivaldi Safe Storage"}, {"Chromium Keys", "Chromium Safe Storage"}}},
	{"edge", "Microsoft Edge", "microsoft-edge",
		[][2]string{{"Microsoft Edge Keys", "Microsoft Edge Safe Storage"}}},
}

// BrowserProfile is one profile directory of one Chromium-family browser.
type BrowserProfile struct {
	def         *browserDef
	UserDataDir string // e.g. ~/.config/google-chrome
	Dir         string // profile directory name, e.g. "Default", "Profile 1"
	DisplayName string // name shown in the browser's profile picker
	Email       string // signed-in Google account, if any
}

// ID is a stable identifier like "chrome:Profile 1", accepted by --browser and stored in the session.
func (p *BrowserProfile) ID() string { return p.def.ID + ":" + p.Dir }

// Label is a human-readable description of the profile.
func (p *BrowserProfile) Label() string {
	s := fmt.Sprintf("%s, profile %q", p.def.Name, p.DisplayName)
	if p.Email != "" {
		s += " <" + p.Email + ">"
	}
	return s
}

// CookiePath returns the profile's cookie database.
func (p *BrowserProfile) CookiePath() string {
	base := filepath.Join(p.UserDataDir, p.Dir)
	for _, c := range []string{filepath.Join(base, "Cookies"), filepath.Join(base, "Network", "Cookies")} {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return filepath.Join(base, "Cookies")
}

// DiscoverProfiles lists every Chromium-family browser profile with a cookie database.
func DiscoverProfiles() []BrowserProfile {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var out []BrowserProfile
	for i := range browserDefs {
		def := &browserDefs[i]
		root := filepath.Join(home, ".config", def.ConfigDir)
		if _, err := os.Stat(root); err != nil {
			continue
		}
		var ls struct {
			Profile struct {
				InfoCache map[string]struct {
					Name     string `json:"name"`
					UserName string `json:"user_name"`
				} `json:"info_cache"`
			} `json:"profile"`
		}
		if data, err := os.ReadFile(filepath.Join(root, "Local State")); err == nil {
			_ = json.Unmarshal(data, &ls)
		}
		dirs := map[string]bool{}
		for d := range ls.Profile.InfoCache {
			dirs[d] = true
		}
		// Profiles missing from Local State (or no Local State at all).
		if matches, _ := filepath.Glob(filepath.Join(root, "*", "Cookies")); matches != nil {
			for _, m := range matches {
				dirs[filepath.Base(filepath.Dir(m))] = true
			}
		}

		names := make([]string, 0, len(dirs))
		for d := range dirs {
			if d == "Guest Profile" || d == "System Profile" || strings.HasSuffix(d, ".old") {
				continue
			}
			names = append(names, d)
		}
		sort.Slice(names, func(a, b int) bool {
			// "Default" first, then "Profile N" in numeric-ish order.
			if (names[a] == "Default") != (names[b] == "Default") {
				return names[a] == "Default"
			}
			if len(names[a]) != len(names[b]) {
				return len(names[a]) < len(names[b])
			}
			return names[a] < names[b]
		})

		for _, d := range names {
			p := BrowserProfile{def: def, UserDataDir: root, Dir: d}
			if _, err := os.Stat(p.CookiePath()); err != nil {
				continue
			}
			info := ls.Profile.InfoCache[d]
			p.DisplayName = info.Name
			if p.DisplayName == "" {
				p.DisplayName = d
			}
			p.Email = info.UserName
			out = append(out, p)
		}
	}
	return out
}

// MatchProfiles returns the profiles that a user-supplied --browser value refers to.
// Accepted forms: "chrome:Profile 1" (ID), "chrome" (browser), a profile display
// name ("Tung@Local"), a profile directory ("Profile 1") or a signed-in email.
func MatchProfiles(profiles []BrowserProfile, pref string) []BrowserProfile {
	pref = strings.TrimSpace(pref)
	if pref == "" {
		return nil
	}
	var browser, rest string
	if i := strings.Index(pref, ":"); i > 0 {
		browser, rest = pref[:i], pref[i+1:]
	}
	var out []BrowserProfile
	for _, p := range profiles {
		switch {
		case browser != "":
			if strings.EqualFold(p.def.ID, browser) && profileNameMatches(p, rest) {
				out = append(out, p)
			}
		case strings.EqualFold(p.def.ID, pref), profileNameMatches(p, pref):
			out = append(out, p)
		}
	}
	return out
}

func profileNameMatches(p BrowserProfile, s string) bool {
	return strings.EqualFold(p.Dir, s) || strings.EqualFold(p.DisplayName, s) ||
		(p.Email != "" && strings.EqualFold(p.Email, s))
}
