// Package nft installs and removes the single nftables table windroute owns.
package nft

import (
	"fmt"
	"os/exec"
	"strings"

	"windroute/internal/util"
)

// Table is the dedicated nftables table windroute owns. Removing this one table
// undoes everything windroute changed, which keeps "stop" reliable.
const Table = "windroute"

// Ref returns the fully qualified table name, e.g. "inet windroute".
func Ref() string { return "inet " + Table }

// DefaultExcludes are destinations we never redirect: loopback (Windscribe's
// GUI <-> helper control channel) and non-routable / link-local ranges.
var DefaultExcludes = []string{
	"127.0.0.0/8",
	"169.254.0.0/16",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"224.0.0.0/4",
	"240.0.0.0/4",
}

// BuildRuleset renders the nftables rules that redirect only the Windscribe
// transport cgroup's IPv4 TCP traffic to the local windroute proxy.
//
// Matching on the cgroup (rather than a uid or a destination IP) has two
// benefits:
//   - it targets exactly the helper-spawned VPN daemon, and
//   - windroute's own process is outside that cgroup, so the connection to the
//     upstream proxy can never be redirected back into windroute (no loop).
//
// level is the number of path components in cgroup (see detect.CgroupLevel).
func BuildRuleset(cgroup string, level, port int, excludes []string) string {
	match := fmt.Sprintf("meta nfproto ipv4 meta l4proto tcp socket cgroupv2 level %d %q", level, cgroup)

	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", Table)
	b.WriteString("\tchain output {\n")
	b.WriteString("\t\ttype nat hook output priority -100; policy accept;\n")
	if len(excludes) > 0 {
		fmt.Fprintf(&b, "\t\t%s ip daddr { %s } return\n", match, strings.Join(excludes, ", "))
	}
	fmt.Fprintf(&b, "\t\t%s redirect to :%d\n", match, port)
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String()
}

// Apply replaces windroute's table with ruleset.
func Apply(ruleset string) error {
	// Drop any previous table so re-running start is idempotent.
	_ = util.Run("nft", "delete", "table", "inet", Table)

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Remove deletes windroute's table. It is safe to call when no table exists.
func Remove() error {
	out, err := util.RunOut("nft", "delete", "table", "inet", Table)
	if err != nil {
		if strings.Contains(out, "No such file") || strings.Contains(out, "does not exist") || strings.Contains(out, "not found") {
			return nil
		}
		return fmt.Errorf("nft delete failed: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// Exists reports whether windroute's table is currently installed.
func Exists() bool {
	return util.Run("nft", "list", "table", "inet", Table) == nil
}
