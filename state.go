package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// StateDir is the default location for windroute runtime state. It lives in
// /run so it disappears on reboot, which matches nftables rule lifetime. It can
// be overridden with WINDROUTE_STATE_DIR (useful for tests).
const defaultStateDir = "/run/windroute"

func stateDir() string {
	if v := os.Getenv("WINDROUTE_STATE_DIR"); v != "" {
		return v
	}
	return defaultStateDir
}

const (
	stateFile = "state.json"
	pidFile   = "proxy.pid"
	logFile   = "proxy.log"
)

// State describes a running windroute instance. It is written to disk so that
// stop/status work across invocations and after a crash.
type State struct {
	Proxy     string `json:"proxy"`
	Listen    string `json:"listen"`
	Port      int    `json:"port"`
	Cgroup    string `json:"cgroup"`
	Level     int    `json:"level"`
	Table     string `json:"table"`
	PID       int    `json:"pid"`
	LogFile   string `json:"log_file"`
	StartedAt string `json:"started_at"`
	Connected string `json:"connected,omitempty"`
}

func statePath() string { return filepath.Join(stateDir(), stateFile) }

func LogPath() string { return filepath.Join(stateDir(), logFile) }

// SaveState writes the state file, creating the state directory if needed.
func SaveState(s *State) error {
	if err := os.MkdirAll(stateDir(), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(statePath(), b, 0o644)
}

// LoadState reads the state file. It returns (nil, nil) when no instance is
// recorded.
func LoadState() (*State, error) {
	b, err := os.ReadFile(statePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ClearState removes the state file. Missing files are not an error.
func ClearState() error {
	err := os.Remove(statePath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func now() string { return time.Now().Format(time.RFC3339) }
