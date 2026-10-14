// Package state persists windroute's runtime state so that stop and status work
// across invocations and after a crash.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// defaultDir lives in /run so state disappears on reboot, which matches
// nftables rule lifetime. It can be overridden with WINDROUTE_STATE_DIR.
const defaultDir = "/run/windroute"

const (
	stateFile = "state.json"
	logFile   = "proxy.log"
)

// Dir returns the runtime state directory.
func Dir() string {
	if v := os.Getenv("WINDROUTE_STATE_DIR"); v != "" {
		return v
	}
	return defaultDir
}

// LogFile returns the path of the proxy log file.
func LogFile() string { return filepath.Join(Dir(), logFile) }

func statePath() string { return filepath.Join(Dir(), stateFile) }

// State describes a running windroute instance.
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

// Save writes the state file, creating the state directory if needed.
func Save(s *State) error {
	if err := os.MkdirAll(Dir(), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(statePath(), b, 0o644)
}

// Load reads the state file. It returns (nil, nil) when no instance is
// recorded.
func Load() (*State, error) {
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

// Clear removes the state file. Missing files are not an error.
func Clear() error {
	err := os.Remove(statePath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Now returns the current time in RFC3339 form.
func Now() string { return time.Now().Format(time.RFC3339) }
