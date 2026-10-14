package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// nftTable is the dedicated nftables table windroute owns. Removing this one
// table undoes everything windroute changed, which keeps "stop" reliable.
const nftTable = "windroute"

// defaultExcludes are destinations we never redirect: loopback (Windscribe's
// GUI <-> helper control channel) and non-routable / link-local ranges.
var defaultExcludes = []string{
	"127.0.0.0/8",
	"169.254.0.0/16",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"224.0.0.0/4",
	"240.0.0.0/4",
}

// buildRuleset renders the nftables rules that redirect only the Windscribe
// transport cgroup's IPv4 TCP traffic to the local windroute proxy.
//
// Matching on the cgroup (rather than a uid or a destination IP) has two
// benefits:
//   - it targets exactly the helper-spawned VPN daemon, and
//   - windroute's own process is outside that cgroup, so the connection to the
//     upstream proxy can never be redirected back into windroute (no loop).
func buildRuleset(cgroup string, port int, excludes []string) string {
	level := cgroupLevel(cgroup)
	match := fmt.Sprintf("meta nfproto ipv4 meta l4proto tcp socket cgroupv2 level %d %q", level, cgroup)

	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
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

// applyRuleset replaces windroute's table with ruleset.
func applyRuleset(ruleset string) error {
	// Drop any previous table so re-running start is idempotent.
	_ = run("nft", "delete", "table", "inet", nftTable)

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// removeRuleset deletes windroute's table. It is safe to call when no table
// exists.
func removeRuleset() error {
	out, err := runOut("nft", "delete", "table", "inet", nftTable)
	if err != nil {
		s := out
		if strings.Contains(s, "No such file") || strings.Contains(s, "does not exist") || strings.Contains(s, "not found") {
			return nil
		}
		return fmt.Errorf("nft delete failed: %v: %s", err, strings.TrimSpace(s))
	}
	return nil
}

func tableExists() bool {
	return run("nft", "list", "table", "inet", nftTable) == nil
}

func dumpRuleset() string {
	out, _ := runOut("nft", "list", "table", "inet", nftTable)
	return strings.TrimSpace(out)
}
