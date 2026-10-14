package cli

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"text/tabwriter"

	"windroute/internal/state"
	"windroute/internal/util"
)

func requireRoot() error {
	if !util.IsRoot() {
		return errors.New("this command needs root; run it with sudo")
	}
	return nil
}

func processAlive(pid int) bool {
	return pid > 0 && syscall.Kill(pid, 0) == nil
}

func tailLog(n int) string {
	b, err := os.ReadFile(state.LogFile())
	if err != nil {
		return "(no log)"
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func newTabWriter() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
}
