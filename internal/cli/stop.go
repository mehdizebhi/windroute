package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"syscall"
	"time"

	"windroute/internal/nft"
	"windroute/internal/state"
)

func cmdStop(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	_ = fs.Bool("quiet", false, "suppress output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}

	var problems []string

	if err := nft.Remove(); err != nil {
		problems = append(problems, err.Error())
	} else {
		fmt.Println("nftables: windroute rules removed")
	}

	st, _ := state.Load()
	if st != nil {
		if st.PID > 0 && processAlive(st.PID) {
			if err := stopProxy(st.PID); err != nil {
				problems = append(problems, err.Error())
			} else {
				fmt.Printf("proxy: stopped (pid %d)\n", st.PID)
			}
		}
	} else {
		fmt.Println("proxy: no running instance recorded")
	}
	_ = state.Clear()

	if len(problems) > 0 {
		return fmt.Errorf("stop completed with issues: %s", strings.Join(problems, "; "))
	}
	fmt.Println("windroute stopped")
	return nil
}

func stopProxy(pid int) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	for i := 0; i < 20; i++ {
		if !processAlive(pid) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return syscall.Kill(pid, syscall.SIGKILL)
}
