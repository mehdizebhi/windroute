// Package detect finds Windscribe processes, the cgroup that carries the VPN
// transport, and the sockets involved.
package detect

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"windroute/internal/util"
)

// Proc is a minimal view of a process we care about.
type Proc struct {
	PID     int
	User    string
	Comm    string
	Cmdline string
	Cgroup  string // path relative to the cgroup2 root, e.g. /system.slice/x.service
}

// vpnTransportBinaries are the helper-spawned daemons that carry the actual VPN
// transport. They are the ones we want to intercept.
var vpnTransportBinaries = map[string]bool{
	"windscribeopenvpn":   true,
	"windscribewstunnel":  true,
	"windscribeamneziawg": true,
	"windscribectrld":     true,
}

// Scan reads /proc and returns all processes we can see.
func Scan() []Proc {
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
	if sys, ok := util.StatUID(st); ok {
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

// IsWindscribe reports whether a process belongs to Windscribe.
func IsWindscribe(p Proc) bool {
	return strings.Contains(p.Cmdline, "windscribe") ||
		strings.Contains(p.Cgroup, "windscribe")
}

// isHelper reports whether the process is Windscribe's root helper.
func isHelper(p Proc) bool {
	return baseName(p.Cmdline) == "helper" && strings.Contains(p.Cmdline, "windscribe")
}

// IsVPNTransport reports whether a process is a helper-spawned VPN daemon.
func IsVPNTransport(p Proc) bool {
	return vpnTransportBinaries[baseName(p.Cmdline)]
}

// Label returns a short display name for a process.
func Label(p Proc) string {
	if p.Comm != "" {
		return p.Comm
	}
	return baseName(p.Cmdline)
}

// NormCgroup converts an absolute cgroup path into the relative form used by
// nftables' "socket cgroupv2 level N" matcher.
func NormCgroup(c string) string {
	return strings.Trim(c, "/")
}

// CgroupLevel returns the number of path components in a cgroup path, which is
// the "level" nftables needs for a given cgroup.
func CgroupLevel(c string) int {
	c = NormCgroup(c)
	if c == "" {
		return 0
	}
	return len(strings.Split(c, "/"))
}

// DetectCgroup finds the cgroup that carries Windscribe's VPN transport. It
// prefers a live VPN daemon, then falls back to the helper service.
func DetectCgroup() (string, error) {
	procs := Scan()
	for _, p := range procs {
		if IsVPNTransport(p) && p.Cgroup != "" {
			return NormCgroup(p.Cgroup), nil
		}
	}
	for _, p := range procs {
		if isHelper(p) && p.Cgroup != "" {
			return NormCgroup(p.Cgroup), nil
		}
	}
	// Last resort: the default systemd unit path.
	def := "system.slice/windscribe-helper.service"
	if _, err := os.Stat("/sys/fs/cgroup/" + def); err == nil {
		return def, nil
	}
	return "", errors.New("could not find the Windscribe helper cgroup (is the Windscribe app running?)")
}

// Sock is a TCP socket associated with a process.
type Sock struct {
	Local   string
	Peer    string
	Process string
	PID     int
}

var (
	ssPidRE  = regexp.MustCompile(`pid=(\d+)`)
	ssNameRE = regexp.MustCompile(`\("([^"]+)"`)
)

// ListSockets returns established TCP sockets. Requires root to see sockets
// owned by other users; without root the process column is empty.
func ListSockets() []Sock {
	out, err := util.RunOut("ss", "-tnp", "state", "established")
	if err != nil {
		return nil
	}
	return parseSS(out)
}

// ListListeners returns listening TCP sockets.
func ListListeners() []Sock {
	out, err := util.RunOut("ss", "-tlnp")
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
