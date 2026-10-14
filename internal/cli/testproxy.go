package cli

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"time"

	"windroute/internal/proxy"
)

func cmdTestProxy(args []string) error {
	fs := flag.NewFlagSet("test-proxy", flag.ContinueOnError)
	proxyURL := fs.String("proxy", "", "proxy URL to test [required]")
	target := fs.String("target", "example.com:443", "destination to reach through the proxy")
	plain := fs.Bool("plain", false, "skip the TLS probe for :443 targets")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *proxyURL == "" {
		return fmt.Errorf("--proxy is required")
	}
	p, err := proxy.Parse(*proxyURL)
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
