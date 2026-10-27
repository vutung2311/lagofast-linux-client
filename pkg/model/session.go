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

func LoadSession() (*UserSession, error) {
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		userPath := filepath.Join(home, ConfigDirName, SessionFileName)
		session, err := readSessionFromFile(userPath)
		if err == nil {
			return session, nil
		}
	}

	candidates := []string{os.Getenv("SUDO_USER"), os.Getenv("USER"), "tung"}
	for _, sudoUser := range candidates {
		if sudoUser == "" || sudoUser == "root" {
			continue
		}
		userPath := filepath.Join("/home", sudoUser, ConfigDirName, SessionFileName)
		session, err := readSessionFromFile(userPath)
		if err == nil {
			return session, nil
		}
	}

	globalPath := filepath.Join(GlobalConfigDir, SessionFileName)
	session, err := readSessionFromFile(globalPath)
	if err == nil {
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
