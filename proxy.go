package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

// soOriginalDst is the socket option that recovers the pre-NAT destination of a
// connection that nftables redirected to us (REDIRECT target).
const soOriginalDst = 80

// proxyStats tracks what the local redirect proxy is doing.
type proxyStats struct {
	accepted atomic.Int64
	failed   atomic.Int64
	active   atomic.Int64
}

// serveProxy listens on listen and forwards every accepted connection to the
// original destination through the upstream proxy. It blocks until the
// listener is closed.
func serveProxy(listen string, p *Proxy, logger *log.Logger) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	logger.Printf("listening on %s -> proxy %s", listen, p.Raw)

	var stats proxyStats

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		go func() {
			stats.accepted.Add(1)
			stats.active.Add(1)
			defer stats.active.Add(-1)
			if err := handleConn(conn, p, logger); err != nil {
				stats.failed.Add(1)
				logger.Printf("connection error: %v", err)
			}
		}()
	}
}

func handleConn(client net.Conn, p *Proxy, logger *log.Logger) error {
	defer client.Close()

	tcp, ok := client.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("unexpected connection type %T", client)
	}
	target, err := originalDst(tcp)
	if err != nil {
		return fmt.Errorf("cannot recover original destination: %w", err)
	}

	upstream, err := p.Dial(target, 15*time.Second)
	if err != nil {
		return fmt.Errorf("%s: %w", target, err)
	}
	defer upstream.Close()

	logger.Printf("redirect %s -> proxy -> %s", client.RemoteAddr(), target)

	errc := make(chan error, 2)
	go func() { _, e := io.Copy(upstream, client); errc <- e }()
	go func() { _, e := io.Copy(client, upstream); errc <- e }()
	<-errc

	// Give the other direction a moment to flush before closing both ends.
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = upstream.SetDeadline(time.Now().Add(2 * time.Second))
	return nil
}

// originalDst reads SO_ORIGINAL_DST from a redirected IPv4 connection and
// returns "ip:port".
//
// This is the standard transparent-proxy trick: nftables' REDIRECT changes the
// destination to loopback and conntrack stores the original tuple, which the
// kernel exposes through this option.
func originalDst(c *net.TCPConn) (string, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return "", err
	}
	var (
		target string
		serr   error
	)
	cerr := raw.Control(func(fd uintptr) {
		mreq, e := syscall.GetsockoptIPv6Mreq(int(fd), syscall.SOL_IP, soOriginalDst)
		if e != nil {
			serr = e
			return
		}
		// struct sockaddr_in bytes: [0:2] family, [2:4] port (network order),
		// [4:8] IPv4 address.
		ip := net.IPv4(mreq.Multiaddr[4], mreq.Multiaddr[5], mreq.Multiaddr[6], mreq.Multiaddr[7])
		port := int(mreq.Multiaddr[2])<<8 | int(mreq.Multiaddr[3])
		target = net.JoinHostPort(ip.String(), strconv.Itoa(port))
	})
	if cerr != nil {
		return "", cerr
	}
	if serr != nil {
		return "", serr
	}
	if target == "" {
		return "", fmt.Errorf("empty original destination")
	}
	return target, nil
}
