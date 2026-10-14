// Command windroute routes the Windscribe Desktop GUI VPN transport through an
// existing HTTP or SOCKS5 proxy without creating a second VPN or a TUN device.
package main

import (
	"os"

	"windroute/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
