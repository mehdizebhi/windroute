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

	actions, problems := teardown()
	for _, a := range actions {
		fmt.Println(a)
	}
	if len(problems) > 0 {
		return fmt.Errorf("stop completed with issues: %s", strings.Join(problems, "; "))
	}
	fmt.Println("windroute stopped")
	return nil
}

// teardown removes windroute's nftables rules, stops the redirect proxy and
// clears the runtime state. It returns human readable actions and any problems,
// so both "stop" and "uninstall" share exactly the same cleanup path.
func teardown() (actions, problems []string) {
	if err := nft.Remove(); err != nil {
		problems = append(problems, err.Error())
	} else {
		actions = append(actions, "nftables: windroute rules removed")
	}

	st, _ := state.Load()
	if st != nil && st.PID > 0 && processAlive(st.PID) {
		if err := stopProxy(st.PID); err != nil {
			problems = append(problems, err.Error())
		} else {
			actions = append(actions, fmt.Sprintf("proxy: stopped (pid %d)", st.PID))
		}
	} else {
		actions = append(actions, "proxy: no running instance recorded")
	}
	_ = state.Clear()
	return actions, problems
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
