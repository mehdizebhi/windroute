// Package util holds small helpers shared across windroute packages.
package util

import (
	"bytes"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// RunOut runs a command and returns its combined output as a string.
func RunOut(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// Run runs a command, discarding its output.
func Run(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// Have reports whether an executable exists in PATH.
func Have(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// StatUID returns the owning username for a FileInfo, falling back to the
// numeric uid when the name cannot be resolved.
func StatUID(fi os.FileInfo) (string, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(st.Uid), 10))
	if err != nil {
		return strconv.FormatUint(uint64(st.Uid), 10), true
	}
	return u.Username, true
}

// IsRoot reports whether the current process runs as root.
func IsRoot() bool { return os.Geteuid() == 0 }
