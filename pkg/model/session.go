package model

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	ConfigDirName   = ".config/lagofast"
	SessionFileName = "session.json"
	GlobalConfigDir = "/etc/lagofast"
)

func GetConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" || home == "/root" {
		os.MkdirAll(GlobalConfigDir, 0755)
		return filepath.Join(GlobalConfigDir, SessionFileName)
	}
	dir := filepath.Join(home, ConfigDirName)
	os.MkdirAll(dir, 0700)
	return filepath.Join(dir, SessionFileName)
}

func readSessionFromFile(path string) (*UserSession, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var session UserSession
	err = json.Unmarshal(data, &session)
	if err != nil {
		return nil, err
	}
	if session.Token == "" {
		return nil, os.ErrNotExist
	}
	return &session, nil
}

func tryReadSession(path string) *UserSession {
	session, err := readSessionFromFile(path)
	if err != nil {
		return nil
	}
	return session
}

func LoadSession() (*UserSession, error) {
	home, _ := os.UserHomeDir()
	if home != "" {
		if session := tryReadSession(filepath.Join(home, ConfigDirName, SessionFileName)); session != nil {
			return session, nil
		}
	}

	var candidates []string
	if su := os.Getenv("SUDO_USER"); su != "" {
		candidates = append(candidates, su)
	}
	if u := os.Getenv("USER"); u != "" {
		candidates = append(candidates, u)
	}
	if entries, err := os.ReadDir("/home"); err != nil {
		entries = nil
	} else {
		for _, e := range entries {
			if e.IsDir() {
				candidates = append(candidates, e.Name())
			}
		}
	}

	for _, sudoUser := range candidates {
		if sudoUser == "" || sudoUser == "root" {
			continue
		}
		userPath := filepath.Join("/home", sudoUser, ConfigDirName, SessionFileName)
		if session := tryReadSession(userPath); session != nil {
			return session, nil
		}
	}

	if session := tryReadSession(filepath.Join(GlobalConfigDir, SessionFileName)); session != nil {
		return session, nil
	}

	return nil, os.ErrNotExist
}

func SaveSession(session *UserSession) error {
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(GetConfigPath(), data, 0600)
}
