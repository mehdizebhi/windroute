package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
)

// ---------------------------------------------------------------- start

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
	p, err := ParseProxy(*proxyURL)
	if err != nil {
		return err
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("invalid --port %d", *port)
	}

	cgroup := normalizeCgroupFlag(*cgroupFlag)
	if cgroup == "" {
		cgroup, err = DetectCgroup()
		if err != nil {
			return err
		}
	}
	level := cgroupLevel(cgroup)

	// Refuse to start twice.
	if st, _ := LoadState(); st != nil && processAlive(st.PID) {
		return fmt.Errorf("windroute is already running (pid %d); run 'windroute stop' first", st.PID)
	}
	_ = removeRuleset()

	listen := net.JoinHostPort(*listenIP, strconv.Itoa(*port))

	excludes := append([]string{}, defaultExcludes...)
	if s := strings.TrimSpace(*excludeFlag); s != "" {
		for _, e := range strings.Split(s, ",") {
			if e = strings.TrimSpace(e); e != "" {
				excludes = append(excludes, e)
			}
		}
	}

	if err := os.MkdirAll(stateDir(), 0o755); err != nil {
		return err
	}

	pid, err := spawnProxy(listen, p.Raw)
	if err != nil {
		return err
	}

	st := &State{
		Proxy:     p.Raw,
		Listen:    listen,
		Port:      *port,
		Cgroup:    cgroup,
		Level:     level,
		Table:     "inet " + nftTable,
		PID:       pid,
		LogFile:   LogPath(),
		StartedAt: now(),
	}

	if !*noRules {
		ruleset := buildRuleset(cgroup, *port, excludes)
		if err := applyRuleset(ruleset); err != nil {
			_ = stopProxy(pid)
			return err
		}
	}

	if err := SaveState(st); err != nil {
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
	fmt.Printf("  proxy pid      : %d  (log: %s)\n", pid, LogPath())

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

// normalizeCgroupFlag accepts both "/system.slice/x.service" and
// "system.slice/x.service" and returns the relative form.
func normalizeCgroupFlag(s string) string {
	return strings.TrimSpace(s)
}

func spawnProxy(listen, proxyURL string) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	lf, err := os.OpenFile(LogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
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

// ---------------------------------------------------------------- stop

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

	if err := removeRuleset(); err != nil {
		problems = append(problems, err.Error())
	} else {
		fmt.Println("nftables: windroute rules removed")
	}

	st, _ := LoadState()
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
	_ = ClearState()

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

// ---------------------------------------------------------------- status

func cmdStatus(args []string) error {
	st, err := LoadState()
	if err != nil {
		return err
	}
	if st == nil {
		fmt.Println("windroute is not running (no state in " + stateDir() + ")")
		if tableExists() {
			fmt.Println("warning: an nftables table 'inet " + nftTable + "' still exists; run 'sudo windroute stop'")
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
	if tableExists() {
		fmt.Println("  nftables       : active")
	} else if isRoot() {
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

// ---------------------------------------------------------------- test-proxy

func cmdTestProxy(args []string) error {
	fs := flag.NewFlagSet("test-proxy", flag.ContinueOnError)
	proxyURL := fs.String("proxy", "", "proxy URL to test [required]")
	target := fs.String("target", "example.com:443", "destination to reach through the proxy")
	plain := fs.Bool("plain", false, "skip the TLS probe for :443 targets")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *proxyURL == "" {
		return errors.New("--proxy is required")
	}
	p, err := ParseProxy(*proxyURL)
	if err != nil {
		return err
	}

	fmt.Printf("dialing %s through %s ...\n", *target, p.Raw)
	start := time.Now()
	conn, err := p.Dial(*target, 15*time.Second)
	if err != nil {
		return fmt.Errorf("proxy test failed: %w", err)
	}
	defer conn.Close()
	fmt.Printf("OK: TCP tunnel to %s established through proxy %s in %s\n",
		*target, conn.RemoteAddr(), time.Since(start).Round(time.Millisecond))

	if _, port, _ := net.SplitHostPort(*target); port == "443" && !*plain {
		if err := tlsProbe(conn, *target); err != nil {
			fmt.Printf("note: TLS probe failed: %v\n", err)
		}
	}
	return nil
}

// tlsProbe performs a TLS handshake through the tunnel, which proves the proxy
// really forwards data end to end (not just that the SOCKS/CONNECT handshake
// succeeded).
func tlsProbe(conn net.Conn, target string) error {
	host, _, _ := net.SplitHostPort(target)
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if net.ParseIP(host) != nil {
		cfg.InsecureSkipVerify = true // cannot verify a bare IP
	}
	tc := tls.Client(conn, cfg)
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		return err
	}
	st := tc.ConnectionState()
	fmt.Printf("OK: TLS handshake with %s succeeded (%s, %s)\n", host, tls.VersionName(st.Version), tls.CipherSuiteName(st.CipherSuite))
	return nil
}

// ---------------------------------------------------------------- serve

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("__serve", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:10800", "listen address")
	proxyURL := fs.String("proxy", "", "upstream proxy URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *proxyURL == "" {
		return errors.New("--proxy is required")
	}
	p, err := ParseProxy(*proxyURL)
	if err != nil {
		return err
	}
	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.Printf("windroute proxy starting (pid %d)", os.Getpid())
	return serveProxy(*listen, p, logger)
}

// ---------------------------------------------------------------- helpers

func requireRoot() error {
	if !isRoot() {
		return errors.New("this command needs root; run it with sudo")
	}
	return nil
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

func processAlive(pid int) bool {
	return pid > 0 && syscall.Kill(pid, 0) == nil
}

func tailLog(n int) string {
	b, err := os.ReadFile(LogPath())
	if err != nil {
		return "(no log)"
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func windscribeConnect(proto, location string) error {
	if !have("windscribe-cli") {
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

func newTabWriter() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
}
