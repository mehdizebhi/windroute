package main

import (
	"bytes"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// runOut runs a command and returns its combined output as a string.
func runOut(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// run is runOut discarding the output.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

// have reports whether an executable exists in PATH.
func have(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// statUID returns the owning username for a FileInfo, or "?" when unknown.
func statUID(fi os.FileInfo) (string, bool) {
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

func isRoot() bool { return os.Geteuid() == 0 }
