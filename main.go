// windroute routes the Windscribe Desktop GUI VPN transport through an
// existing HTTP or SOCKS5 proxy without creating a second VPN or a TUN device.
package main

import (
	"fmt"
	"os"
)

const version = "0.1.0"

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage(os.Stderr)
		os.Exit(2)
	}

	cmd, rest := args[0], args[1:]

	var err error
	switch cmd {
	case "start":
		err = cmdStart(rest)
	case "stop":
		err = cmdStop(rest)
	case "status":
		err = cmdStatus(rest)
	case "inspect":
		err = cmdInspect(rest)
	case "doctor":
		err = cmdDoctor(rest)
	case "test-proxy", "test":
		err = cmdTestProxy(rest)
	case "__serve":
		err = cmdServe(rest)
	case "version", "--version", "-v":
		fmt.Printf("windroute %s\n", version)
	case "help", "--help", "-h":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "windroute: unknown command %q\n\n", cmd)
		usage(os.Stderr)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "windroute: error: %v\n", err)
		os.Exit(1)
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `windroute - route Windscribe's VPN transport through a SOCKS5/HTTP proxy

USAGE
  windroute <command> [flags]

COMMANDS
  start        Start the local redirect proxy and install nftables rules
  stop         Remove nftables rules and stop the proxy
  status       Show whether windroute is running
  inspect      Show Windscribe processes, endpoints and the interception plan
  doctor       Check the system for everything windroute needs
  test-proxy   Verify that a proxy can reach a target
  version      Print version

QUICK START
  # 1. make sure your proxy is running, e.g. xray on 127.0.0.1:10808
  windroute test-proxy --proxy socks5://127.0.0.1:10808
  # 2. start routing (needs root)
  sudo windroute start --proxy socks5://127.0.0.1:10808 --connect wstunnel
  # 3. when done
  sudo windroute stop

NOTES
  - Windscribe must use a TCP based protocol (tcp / wstunnel / stealth).
    UDP (wireguard, udp) is NOT supported by this version.
  - Only traffic belonging to Windscribe's helper cgroup is redirected, so
    the proxy connection itself is never re-routed back into windroute.
`)
}
