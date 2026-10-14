package cli

import (
	"flag"
	"fmt"

	"windroute/internal/nft"
	"windroute/internal/state"
	"windroute/internal/util"
)

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := state.Load()
	if err != nil {
		return err
	}
	if st == nil {
		fmt.Println("windroute is not running (no state in " + state.Dir() + ")")
		if nft.Exists() {
			fmt.Printf("warning: an nftables table '%s' still exists; run 'sudo windroute stop'\n", nft.Ref())
		}
		return nil
	}

	alive := processAlive(st.PID)
	fmt.Printf("windroute: %s\n", statusWord(alive))
	fmt.Printf("  started        : %s\n", st.StartedAt)
	fmt.Printf("  local redirect : %s\n", st.Listen)
	fmt.Printf("  upstream proxy : %s\n", st.Proxy)
	fmt.Printf("  intercept      : cgroup %q (level %d)\n", st.Cgroup, st.Level)
	fmt.Printf("  proxy pid      : %d (%s)\n", st.PID, aliveWord(alive))

	if !alive {
		fmt.Println("  warning: recorded proxy process is gone; state is stale, run 'windroute stop'")
	}
	if nft.Exists() {
		fmt.Println("  nftables       : active")
	} else if util.IsRoot() {
		fmt.Println("  nftables       : missing")
	} else {
		fmt.Println("  nftables       : unknown (run as root to check)")
	}
	return nil
}

func statusWord(ok bool) string {
	if ok {
		return "running"
	}
	return "stopped (stale state)"
}

func aliveWord(ok bool) string {
	if ok {
		return "alive"
	}
	return "dead"
}
