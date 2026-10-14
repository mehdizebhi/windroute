package cli

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"windroute/internal/detect"
	"windroute/internal/nft"
	"windroute/internal/proxy"
	"windroute/internal/state"
	"windroute/internal/util"
)

func cmdStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	proxyURL := fs.String("proxy", "", "upstream proxy URL (socks5:// or http://) [required]")
	port := fs.Int("port", 10800, "local redirect port")
	listenIP := fs.String("listen", "127.0.0.1", "local listen address")
	cgroupFlag := fs.String("cgroup", "", "cgroup to intercept (default: auto-detect)")
	connectProto := fs.String("connect", "", "after start, run 'windscribe-cli connect <protocol>' (e.g. wstunnel, tcp)")
	location := fs.String("location", "", "location to pass to windscribe-cli connect")
	noRules := fs.Bool("no-rules", false, "start only the proxy; do not install nftables rules")
	excludeFlag := fs.String("exclude", "", "extra comma separated CIDRs to exclude from redirection")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireRoot(); err != nil {
		return err
	}
	if *proxyURL == "" {
		return errors.New("--proxy is required, e.g. --proxy socks5://127.0.0.1:10808")
	}
	p, err := proxy.Parse(*proxyURL)
	if err != nil {
		return err
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("invalid --port %d", *port)
	}

	cgroup := detect.NormCgroup(*cgroupFlag)
	if cgroup == "" {
		cgroup, err = detect.DetectCgroup()
		if err != nil {
			return err
		}
	}
	level := detect.CgroupLevel(cgroup)

	// Refuse to start twice.
	if st, _ := state.Load(); st != nil && processAlive(st.PID) {
		return fmt.Errorf("windroute is already running (pid %d); run 'windroute stop' first", st.PID)
	}
	_ = nft.Remove()

	listen := net.JoinHostPort(*listenIP, strconv.Itoa(*port))

	excludes := append([]string{}, nft.DefaultExcludes...)
	if s := strings.TrimSpace(*excludeFlag); s != "" {
		for _, e := range strings.Split(s, ",") {
			if e = strings.TrimSpace(e); e != "" {
				excludes = append(excludes, e)
			}
		}
	}

	if err := os.MkdirAll(state.Dir(), 0o755); err != nil {
		return err
	}

	pid, err := spawnProxy(listen, p.Raw)
	if err != nil {
		return err
	}

	st := &state.State{
		Proxy:     p.Raw,
		Listen:    listen,
		Port:      *port,
		Cgroup:    cgroup,
		Level:     level,
		Table:     nft.Ref(),
		PID:       pid,
		LogFile:   state.LogFile(),
		StartedAt: state.Now(),
	}

	if !*noRules {
		if err := nft.Apply(nft.BuildRuleset(cgroup, level, *port, excludes)); err != nil {
			_ = stopProxy(pid)
			return err
		}
	}

	if err := state.Save(st); err != nil {
		return err
	}

	fmt.Printf("windroute started\n")
	fmt.Printf("  local redirect : %s\n", listen)
	fmt.Printf("  upstream proxy : %s\n", p.Raw)
	if *noRules {
		fmt.Printf("  nftables       : skipped (--no-rules)\n")
	} else {
		fmt.Printf("  intercept      : cgroup %q (level %d), IPv4 TCP\n", cgroup, level)
	}
	fmt.Printf("  proxy pid      : %d  (log: %s)\n", pid, state.LogFile())

	if *connectProto != "" {
		if isUDPProtocol(*connectProto) {
			fmt.Printf("\nwarning: protocol %q is UDP based and will NOT be intercepted by windroute.\n", *connectProto)
			fmt.Printf("         use a TCP protocol instead: tcp, wstunnel or stealth.\n")
		}
		fmt.Printf("\nconnecting Windscribe with protocol %q ...\n", *connectProto)
		if err := windscribeConnect(*connectProto, *location); err != nil {
			return fmt.Errorf("windscribe connect failed: %w", err)
		}
	} else {
		fmt.Printf("\nNow connect Windscribe over a TCP protocol, e.g.:\n")
		fmt.Printf("  windscribe-cli connect wstunnel\n")
	}
	return nil
}

func spawnProxy(listen, proxyURL string) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	lf, err := os.OpenFile(state.LogFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 0, err
	}
	defer lf.Close()

	cmd := exec.Command(exe, "__serve", "--listen", listen, "--proxy", proxyURL)
	cmd.Stdout = lf
	cmd.Stderr = lf
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	_ = cmd.Process.Release()

	if err := waitForListen(listen, pid, 5*time.Second); err != nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		return 0, fmt.Errorf("%w\n--- proxy log ---\n%s", err, tailLog(15))
	}
	return pid, nil
}

func waitForListen(addr string, pid int, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return errors.New("proxy process exited during startup")
		}
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("proxy did not start listening on %s in time", addr)
}

// isUDPProtocol reports whether a Windscribe protocol carries its transport
// over UDP (and therefore cannot be intercepted by this TCP-only version).
func isUDPProtocol(p string) bool {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "wireguard", "udp", "ikev2":
		return true
	}
	return false
}

func windscribeConnect(proto, location string) error {
	if !util.Have("windscribe-cli") {
		return errors.New("windscribe-cli not found in PATH")
	}
	a := []string{"connect"}
	if location != "" {
		a = append(a, location)
	}
	if proto != "" {
		a = append(a, proto)
	}
	cmd := exec.Command("windscribe-cli", a...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
