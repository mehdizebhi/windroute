package cli

import (
	"errors"
	"flag"
	"log"
	"os"

	"windroute/internal/proxy"
)

// cmdServe is the internal entry point that runs the redirect proxy as a child
// process. It is not meant to be invoked by users directly.
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
	p, err := proxy.Parse(*proxyURL)
	if err != nil {
		return err
	}
	logger := log.New(os.Stdout, "", log.LstdFlags)
	logger.Printf("windroute proxy starting (pid %d)", os.Getpid())
	return proxy.Serve(*listen, p, logger)
}
