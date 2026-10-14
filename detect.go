package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Proc is a minimal view of a process we care about.
type Proc struct {
	PID     int
	User    string
	Comm    string
	Cmdline string
	Cgroup  string // path relative to the cgroup2 root, e.g. /system.slice/x.service
}

// vpnTransportBinaries are the helper-spawned daemons that carry the actual
// VPN transport. They are the ones we want to intercept.
var vpnTransportBinaries = map[string]bool{
	"windscribeopenvpn":   true,
	"windscribewstunnel":  true,
	"windscribeamneziawg": true,
	"windscribectrld":     true,
}

// scanProcs reads /proc and returns all processes we can see.
func scanProcs() []Proc {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var procs []Proc
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p := Proc{PID: pid}
		raw, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		p.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
		p.Comm = readComm(e.Name())
		p.Cgroup = readCgroup(e.Name())
		p.User = readUser(e.Name())
		if p.Cmdline != "" || p.Comm != "" {
			procs = append(procs, p)
		}
	}
	return procs
}

func readComm(pidDir string) string {
	b, err := os.ReadFile(filepath.Join("/proc", pidDir, "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readCgroup(pidDir string) string {
	b, err := os.ReadFile(filepath.Join("/proc", pidDir, "cgroup"))
	if err != nil {
		return ""
	}
	// format: "0::/system.slice/windscribe-helper.service"
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			return parts[2]
		}
	}
	return ""
}

func readUser(pidDir string) string {
	st, err := os.Stat(filepath.Join("/proc", pidDir))
	if err != nil {
		return ""
	}
	uid := "?"
	if sys, ok := statUID(st); ok {
		uid = sys
	}
	return uid
}

func baseName(s string) string {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// isWindscribe reports whether a process belongs to Windscribe.
func isWindscribe(p Proc) bool {
	return strings.Contains(p.Cmdline, "windscribe") ||
		strings.Contains(p.Cgroup, "windscribe")
}

// isHelper reports whether the process is Windscribe's root helper.
func isHelper(p Proc) bool {
	return baseName(p.Cmdline) == "helper" && strings.Contains(p.Cmdline, "windscribe")
}

// isVPNTransport reports whether a process is a helper-spawned VPN daemon.
func isVPNTransport(p Proc) bool {
	return vpnTransportBinaries[baseName(p.Cmdline)]
}

// normCgroup converts an absolute cgroup path into the relative form used by
// nftables' "socket cgroupv2 level N" matcher.
func normCgroup(c string) string {
	return strings.Trim(c, "/")
}

func cgroupLevel(c string) int {
	c = normCgroup(c)
	if c == "" {
		return 0
	}
	return len(strings.Split(c, "/"))
}

// DetectCgroup finds the cgroup that carries Windscribe's VPN transport.
// It prefers a live VPN daemon, then falls back to the helper service.
func DetectCgroup() (string, error) {
	procs := scanProcs()
	for _, p := range procs {
		if isVPNTransport(p) && p.Cgroup != "" {
			return normCgroup(p.Cgroup), nil
		}
	}
	for _, p := range procs {
		if isHelper(p) && p.Cgroup != "" {
			return normCgroup(p.Cgroup), nil
		}
	}
	// Last resort: the default systemd unit path.
	def := "system.slice/windscribe-helper.service"
	if _, err := os.Stat("/sys/fs/cgroup/" + def); err == nil {
		return def, nil
	}
	return "", errors.New("could not find the Windscribe helper cgroup (is the Windscribe app running?)")
}

// Sock is an established TCP socket associated with a process.
type Sock struct {
	Local   string
	Peer    string
	Process string
	PID     int
}

var ssPidRE = regexp.MustCompile(`pid=(\d+)`)
var ssNameRE = regexp.MustCompile(`\("([^"]+)"`)

// listSockets runs "ss -tnp" and parses the established TCP sockets. Requires
// root to see sockets owned by other users; without root the process column is
// empty.
func listSockets() []Sock {
	out, err := runOut("ss", "-tnp", "state", "established")
	if err != nil {
		return nil
	}
	return parseSS(out)
}

func parseSS(out string) []Sock {
	var socks []Sock
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "State") || strings.HasPrefix(line, "Netid") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		s := Sock{Local: f[3], Peer: f[4]}
		proc := strings.Join(f[5:], " ")
		s.Process = proc
		if m := ssNameRE.FindStringSubmatch(proc); m != nil {
			s.Process = m[1]
		}
		if m := ssPidRE.FindStringSubmatch(proc); m != nil {
			s.PID, _ = strconv.Atoi(m[1])
		}
		socks = append(socks, s)
	}
	return socks
}
