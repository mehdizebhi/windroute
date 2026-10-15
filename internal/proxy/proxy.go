package proxy

import (
	"errors"
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

const (
	// dialTimeout bounds the handshake with the upstream proxy.
	dialTimeout = 15 * time.Second
	// maxConcurrent caps simultaneously handled connections. It is a safety
	// valve: if anything ever tries to loop back into us, windroute degrades to
	// dropping connections instead of spinning forever.
	maxConcurrent = 1024
	// halfCloseGrace is how long the remaining direction may keep draining
	// after the first direction of a tunnel has finished.
	halfCloseGrace = 60 * time.Second
)

// active counts connections currently being handled.
var active atomic.Int64

// Serve listens on listen and forwards every accepted connection to the
// original destination through the upstream proxy. It blocks until the
// listener is closed.
func Serve(listen string, p *Proxy, logger *log.Logger) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	logger.Printf("listening on %s -> proxy %s", listen, p.Raw)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		if active.Load() >= maxConcurrent {
			logger.Printf("dropping %s: too many concurrent connections (%d)", conn.RemoteAddr(), maxConcurrent)
			conn.Close()
			continue
		}
		active.Add(1)
		go func() {
			defer active.Add(-1)
			if err := handleConn(conn, p, listen, logger); err != nil {
				logger.Printf("connection error: %v", err)
			}
		}()
	}
}

func handleConn(client net.Conn, p *Proxy, listen string, logger *log.Logger) error {
	defer client.Close()
	start := time.Now()

	tcp, ok := client.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("unexpected connection type %T", client)
	}
	target, err := originalDst(tcp)
	if err != nil {
		// A plain (non-redirected) connection has no conntrack original
		// destination. That is not an error, it just is not ours to proxy.
		if errors.Is(err, syscall.ENOENT) {
			logger.Printf("ignored %s: not a redirected connection", client.RemoteAddr())
			return nil
		}
		return fmt.Errorf("cannot recover original destination: %w", err)
	}

	// Refuse anything that would loop back into windroute. Redirected traffic
	// never targets loopback (the nftables rules exclude it), so such a
	// connection is either our own startup probe or a stray local client.
	// Proxying it would recurse forever.
	if reason, loop := selfLoop(target, listen); loop {
		logger.Printf("ignored %s -> %s: %s", client.RemoteAddr(), target, reason)
		return nil
	}

	upstream, err := p.Dial(target, dialTimeout)
	if err != nil {
		return fmt.Errorf("%s: %w", target, err)
	}
	defer upstream.Close()

	logger.Printf("redirect %s -> proxy -> %s", client.RemoteAddr(), target)

	sent, recv := relay(client, upstream)

	logger.Printf("closed %s -> %s in %s (%s up, %s down)",
		client.RemoteAddr(), target, time.Since(start).Round(time.Millisecond), human(sent), human(recv))
	return nil
}

// selfLoop reports whether forwarding to target would loop back into windroute.
func selfLoop(target, listen string) (string, bool) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", false
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return "loopback destination", true
	}
	lhost, lport, err := net.SplitHostPort(listen)
	if err != nil {
		return "", false
	}
	if port == lport {
		lip := net.ParseIP(lhost)
		if lip == nil || lip.IsUnspecified() || host == lhost {
			return "destination is windroute's own listen address", true
		}
	}
	return "", false
}

// relay copies data in both directions. When one direction ends it half-closes
// the peer so the other direction can still drain, and returns the byte counts.
func relay(client, upstream net.Conn) (sent, recv int64) {
	var sentN, recvN atomic.Int64
	done := make(chan struct{}, 2)

	go func() {
		n, _ := io.Copy(upstream, client)
		sentN.Store(n)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(client, upstream)
		recvN.Store(n)
		closeWrite(client)
		done <- struct{}{}
	}()

	<-done
	// Let the other direction keep draining, but not indefinitely.
	deadline := time.Now().Add(halfCloseGrace)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	<-done

	return sentN.Load(), recvN.Load()
}

type closeWriter interface{ CloseWrite() error }

func closeWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
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

// human formats a byte count compactly for logs.
func human(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + "B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
