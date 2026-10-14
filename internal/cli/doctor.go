package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"windroute/internal/detect"
	"windroute/internal/nft"
	"windroute/internal/proxy"
	"windroute/internal/state"
	"windroute/internal/util"
)

type checkResult struct {
	name   string
	status string // ok, warn, fail
	detail string
}

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	proxyURL := fs.String("proxy", "", "also test this proxy URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var results []checkResult
	add := func(name, status, detail string) {
		results = append(results, checkResult{name, status, detail})
	}

	// root
	if util.IsRoot() {
		add("privileges", "ok", "running as root")
	} else {
		add("privileges", "warn", "not root; 'start' and 'stop' need sudo")
	}

	// nftables
	if util.Have("nft") {
		v, _ := util.RunOut("nft", "--version")
		add("nftables", "ok", strings.TrimSpace(v))
	} else {
		add("nftables", "fail", "'nft' not found in PATH (install nftables)")
	}

	// cgroup v2
	if fi, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil && fi != nil {
		add("cgroup v2", "ok", "/sys/fs/cgroup is a cgroup2 mount")
	} else {
		add("cgroup v2", "fail", "cgroup v2 not detected; the cgroup matcher will not work")
	}

	// Windscribe installed
	if util.Have("windscribe-cli") || dirExists("/opt/windscribe") {
		add("windscribe", "ok", "Windscribe installation found")
	} else {
		add("windscribe", "fail", "Windscribe not found (install the desktop app)")
	}

	// helper service / cgroup
	if cg, err := detect.DetectCgroup(); err == nil {
		add("intercept cgroup", "ok", fmt.Sprintf("%s (level %d)", cg, detect.CgroupLevel(cg)))
	} else {
		add("intercept cgroup", "warn", err.Error())
	}

	// helper systemd unit
	if util.Have("systemctl") {
		out, _ := util.RunOut("systemctl", "is-active", "windscribe-helper.service")
		switch strings.TrimSpace(out) {
		case "active":
			add("helper service", "ok", "windscribe-helper.service is active")
		case "inactive", "failed", "":
			add("helper service", "warn", "windscribe-helper.service is not active; start the Windscribe app")
		default:
			add("helper service", "warn", "could not determine helper state: "+strings.TrimSpace(out))
		}
	}

	// Windscribe connection state
	if util.Have("windscribe-cli") {
		if st := windscribeStatusText(); st != "" {
			add("windscribe status", "ok", st)
		} else {
			add("windscribe status", "warn", "could not read status")
		}
	}

	// stale state / leftover rules
	if st, _ := state.Load(); st != nil && processAlive(st.PID) {
		add("existing instance", "warn", fmt.Sprintf("windroute is already running (pid %d)", st.PID))
	}
	if nft.Exists() {
		add("nftables table", "warn", fmt.Sprintf("table '%s' already exists", nft.Ref()))
	} else if util.IsRoot() {
		add("nftables table", "ok", "no leftover '"+nft.Ref()+"' table")
	}

	// proxy reachability
	if strings.TrimSpace(*proxyURL) != "" {
		p, err := proxy.Parse(*proxyURL)
		if err != nil {
			add("proxy", "fail", err.Error())
		} else {
			start := time.Now()
			conn, err := p.Dial("example.com:443", 10*time.Second)
			if err != nil {
				add("proxy", "fail", fmt.Sprintf("%s: %v", p.Addr, err))
			} else {
				conn.Close()
				add("proxy", "ok", fmt.Sprintf("%s reachable in %s", p.Addr, time.Since(start).Round(time.Millisecond)))
			}
		}
	}

	// --- report ---------------------------------------------------------------
	fmt.Println("windroute doctor")
	fmt.Println()
	worst := "ok"
	for _, r := range results {
		mark := "ok  "
		switch r.status {
		case "warn":
			mark = "WARN"
			if worst == "ok" {
				worst = "warn"
			}
		case "fail":
			mark = "FAIL"
			worst = "fail"
		}
		fmt.Printf("  [%s] %-18s %s\n", mark, r.name, r.detail)
	}
	fmt.Println()
	switch worst {
	case "ok":
		fmt.Println("Everything looks good. Example:")
		fmt.Println("  sudo windroute start --proxy socks5://127.0.0.1:10808 --connect wstunnel")
	case "warn":
		fmt.Println("Some warnings above, but windroute will probably work.")
	default:
		fmt.Println("Fix the FAIL items above before running 'windroute start'.")
	}
	return nil
}

func windscribeStatusText() string {
	out, err := util.RunOut("windscribe-cli", "status")
	if err != nil && out == "" {
		return ""
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "{") {
			continue
		}
		lines = append(lines, l)
	}
	return strings.Join(lines, " | ")
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}
