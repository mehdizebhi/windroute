package cli

import (
	"flag"
	"fmt"
	"strings"

	"windroute/internal/detect"
	"windroute/internal/nft"
)

// cmdInspect shows what windroute sees on this machine: Windscribe's processes,
// the sockets carrying the VPN transport, and the interception plan.
func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	showRules := fs.Bool("rules", true, "print the nftables ruleset that would be applied")
	port := fs.Int("port", 10800, "local redirect port used for the plan")
	if err := fs.Parse(args); err != nil {
		return err
	}

	procs := detect.Scan()

	// --- Windscribe processes -------------------------------------------------
	fmt.Println("Windscribe processes")
	tw := newTabWriter()
	fmt.Fprintln(tw, "  PID\tUSER\tPROCESS\tCGROUP")
	found := 0
	for _, p := range procs {
		if !detect.IsWindscribe(p) {
			continue
		}
		found++
		fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\n", p.PID, p.User, detect.Label(p), p.Cgroup)
	}
	if found == 0 {
		fmt.Println("  (none found - is the Windscribe app running?)")
	} else {
		tw.Flush()
	}
	fmt.Println()

	// --- VPN transport daemons ------------------------------------------------
	fmt.Println("VPN transport daemons")
	var transports []detect.Proc
	for _, p := range procs {
		if detect.IsVPNTransport(p) {
			transports = append(transports, p)
		}
	}
	if len(transports) == 0 {
		fmt.Println("  (none running - connect Windscribe to observe the transport)")
	} else {
		tw = newTabWriter()
		fmt.Fprintln(tw, "  PID\tUSER\tPROCESS\tCGROUP")
		for _, p := range transports {
			fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\n", p.PID, p.User, detect.Label(p), p.Cgroup)
		}
		tw.Flush()
	}
	fmt.Println()

	// --- Transport sockets ----------------------------------------------------
	fmt.Println("Established TCP sockets owned by Windscribe")
	wsPIDs := map[int]bool{}
	for _, p := range procs {
		if detect.IsWindscribe(p) {
			wsPIDs[p.PID] = true
		}
	}
	tw = newTabWriter()
	fmt.Fprintln(tw, "  LOCAL\tPEER\tPROCESS")
	n := 0
	for _, s := range detect.ListSockets() {
		if !wsPIDs[s.PID] && !strings.Contains(strings.ToLower(s.Process), "windscribe") {
			continue
		}
		n++
		fmt.Fprintf(tw, "  %s\t%s\t%s(%d)\n", s.Local, s.Peer, s.Process, s.PID)
	}
	if n == 0 {
		fmt.Println("  (none - Windscribe is not connected, or run windroute as root to see other users' sockets)")
	} else {
		tw.Flush()
	}
	fmt.Println()

	// --- Local listeners ------------------------------------------------------
	fmt.Println("Local listeners (possible upstream proxies)")
	tw = newTabWriter()
	fmt.Fprintln(tw, "  ADDRESS\tPROCESS")
	for _, s := range detect.ListListeners() {
		fmt.Fprintf(tw, "  %s\t%s(%d)\n", s.Local, s.Process, s.PID)
	}
	tw.Flush()
	fmt.Println()

	// --- Interception plan ----------------------------------------------------
	cgroup, err := detect.DetectCgroup()
	fmt.Println("Interception plan")
	if err != nil {
		fmt.Printf("  cgroup : UNKNOWN (%v)\n", err)
	} else {
		fmt.Printf("  match cgroup : %s (level %d)\n", cgroup, detect.CgroupLevel(cgroup))
	}
	fmt.Printf("  redirect     : IPv4 TCP -> 127.0.0.1:%d\n", *port)
	fmt.Printf("  excludes     : %s\n", strings.Join(nft.DefaultExcludes, ", "))
	fmt.Println("  note         : Windscribe must use a TCP protocol (tcp / wstunnel / stealth);")
	fmt.Println("                 UDP (wireguard / udp) is not intercepted by this version.")

	if *showRules && err == nil {
		fmt.Println()
		fmt.Println("nftables ruleset that would be applied")
		fmt.Println(indent(nft.BuildRuleset(cgroup, detect.CgroupLevel(cgroup), *port, nft.DefaultExcludes), "  "))
	}
	return nil
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
}
