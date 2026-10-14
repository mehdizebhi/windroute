package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Proxy is a parsed upstream proxy URL.
type Proxy struct {
	Raw  string
	URL  *url.URL
	Addr string // host:port of the proxy itself
}

// Parse validates a proxy URL such as:
//
//	socks5://127.0.0.1:10808
//	socks5h://user:pass@127.0.0.1:1080
//	http://127.0.0.1:10809
//	https://user:pass@proxy.example:8443
func Parse(raw string) (*Proxy, error) {
	if raw == "" {
		return nil, errors.New("empty proxy URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h", "http", "https":
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use socks5://, http:// or https://)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("proxy URL %q has no host", raw)
	}
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "socks5", "socks5h":
			port = "1080"
		default:
			port = "8080"
		}
	}
	return &Proxy{Raw: raw, URL: u, Addr: net.JoinHostPort(host, port)}, nil
}

// Dial opens a connection to target ("host:port") through the proxy.
func (p *Proxy) Dial(target string, timeout time.Duration) (net.Conn, error) {
	switch strings.ToLower(p.URL.Scheme) {
	case "socks5", "socks5h":
		return p.dialSOCKS5(target, timeout)
	default:
		return p.dialHTTPConnect(target, timeout)
	}
}

func (p *Proxy) dialSOCKS5(target string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", p.Addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", p.Addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	methods := []byte{0x00} // no auth
	var user, pass string
	if p.URL.User != nil {
		user = p.URL.User.Username()
		pass, _ = p.URL.User.Password()
		methods = append(methods, 0x02) // username/password
	}

	greet := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greet); err != nil {
		conn.Close()
		return nil, err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, err
	}
	if reply[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("socks5: bad version %d", reply[0])
	}
	switch reply[1] {
	case 0x00:
		// no auth
	case 0x02:
		if err := socks5Auth(conn, user, pass); err != nil {
			conn.Close()
			return nil, err
		}
	case 0xFF:
		conn.Close()
		return nil, errors.New("socks5: no acceptable authentication method")
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5: unsupported auth method 0x%02x", reply[1])
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("bad target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		conn.Close()
		return nil, fmt.Errorf("bad target port %q", portStr)
	}

	req := []byte{0x05, 0x01, 0x00} // VER CMD=CONNECT RSV
	ip := net.ParseIP(host)
	switch {
	case ip == nil:
		if len(host) > 255 {
			conn.Close()
			return nil, errors.New("socks5: hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	case ip.To4() != nil:
		req = append(req, 0x01)
		req = append(req, ip.To4()...)
	default:
		req = append(req, 0x04)
		req = append(req, ip.To16()...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		conn.Close()
		return nil, err
	}
	if head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: connect failed: %s", socks5Err(head[1]))
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			conn.Close()
			return nil, err
		}
		skip = int(l[0])
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5: bad address type 0x%02x", head[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(skip)+2); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func socks5Auth(conn net.Conn, user, pass string) error {
	if len(user) > 255 || len(pass) > 255 {
		return errors.New("socks5: credentials too long")
	}
	buf := []byte{0x01, byte(len(user))}
	buf = append(buf, user...)
	buf = append(buf, byte(len(pass)))
	buf = append(buf, pass...)
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return errors.New("socks5: authentication failed")
	}
	return nil
}

func socks5Err(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown error 0x%02x", code)
	}
}

func (p *Proxy) dialHTTPConnect(target string, timeout time.Duration) (net.Conn, error) {
	var conn net.Conn
	var err error
	if strings.EqualFold(p.URL.Scheme, "https") {
		d := &net.Dialer{Timeout: timeout}
		conn, err = tls.DialWithDialer(d, "tcp", p.Addr, &tls.Config{
			ServerName: p.URL.Hostname(),
			MinVersion: tls.VersionTLS12,
		})
	} else {
		conn, err = net.DialTimeout("tcp", p.Addr, timeout)
	}
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", p.Addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var req strings.Builder
	fmt.Fprintf(&req, "CONNECT %s HTTP/1.1\r\n", target)
	fmt.Fprintf(&req, "Host: %s\r\n", target)
	if p.URL.User != nil {
		pass, _ := p.URL.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(p.URL.User.Username() + ":" + pass))
		fmt.Fprintf(&req, "Proxy-Authorization: Basic %s\r\n", cred)
	}
	req.WriteString("\r\n")

	if _, err := io.WriteString(conn, req.String()); err != nil {
		conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("http proxy response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("http proxy refused CONNECT: %s", resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})

	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// bufferedConn preserves bytes that were read into a bufio.Reader after the
// CONNECT response but before the tunnel started.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// CloseWrite lets relay half-close the tunnel without dropping buffered reads.
func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}
