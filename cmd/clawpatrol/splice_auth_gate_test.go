package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// loopbackDialer dials 127.0.0.1:port whatever address it is asked for:
// the edge a spliced name resolves to. dials counts the attempts.
type loopbackDialer struct {
	port  int
	dials *atomic.Int32
}

func (d loopbackDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d loopbackDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	d.dials.Add(1)
	var nd net.Dialer
	return nd.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(d.port)))
}

// loopbackResolver resolves every name to 127.0.0.1.
type loopbackResolver struct{}

func (loopbackResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

// splice443 runs Gateway.handle for one agent connection on port 443
// under the default unknown_host = "passthrough": no endpoint claims any
// name, so a TLS connection with an SNI is spliced, and the splice dial
// lands on r's upstream. It returns the agent end, a channel closed when
// handle returns, and the splice dial count.
func (r *relayGateRig) splice443(t *testing.T) (net.Conn, <-chan struct{}, *atomic.Int32) {
	t.Helper()
	dials := &atomic.Int32{}
	r.g.resolver = loopbackResolver{}
	r.g.dialer = loopbackDialer{port: r.port, dials: dials}
	agent, gw := net.Pipe()
	r.g.onboard.knownDeviceIPs[peerIP(gw)] = true
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.g.handle(gw, "", 443)
	}()
	t.Cleanup(func() { _ = agent.Close() })
	return agent, done, dials
}

func (r *relayGateRig) spliceStart(t *testing.T) (net.Conn, <-chan struct{}) {
	t.Helper()
	agent, done, _ := r.splice443(t)
	return agent, done
}

// D-R4-10 (A), C1: on 443 passthrough a server_name list that puts a
// decoy entry before the auth host is refused by the strict parser, with
// zero bytes upstream. peekSNI reads the first entry, so before the fix
// the decoy was spliced and an edge serving both names completed the
// handshake as the auth host.
func TestSpliceGatesMixedSNIList(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []sniEntry
	}{
		{"other type first", []sniEntry{{1, "example.com"}, {0, "auth.openai.com"}}},
		{"two host_names", []sniEntry{{0, "example.com"}, {0, "auth.openai.com"}}},
	} {
		r := newRelayGateRig(t, "")
		agent, done, _ := r.splice443(t)
		m := helloMsg(sniExt(tc.entries...))
		go func() {
			_, _ = agent.Write(append([]byte{0x16, 0x03, 0x01, byte(len(m) >> 8), byte(len(m))}, m...))
			time.AfterFunc(300*time.Millisecond, func() { _ = agent.Close() })
		}()
		if b := r.upstreamBytes(t); len(b) != 0 {
			t.Fatalf("%s: upstream received %d byte(s); a mixed server_name list must never be spliced", tc.name, len(b))
		}
		waitDone(t, done)
		if ev := awaitRelayEvent(t, r.sink); ev.Mode != "auth-gate" || ev.Action != "deny" || !strings.Contains(ev.Reason, "443 passthrough") {
			t.Fatalf("%s: event = %+v, want an auth-gate deny on 443 passthrough", tc.name, ev)
		}
	}
}

// D-R4-10 (A), C1: on 443 passthrough ClientHello 2 after a
// HelloRetryRequest is gated as on a relay. A ClientHello 2 that changes
// the SNI (to an auth host, to another name, or to none) never reaches
// the upstream.
func TestSpliceGatesAuthSNIAfterHelloRetry(t *testing.T) {
	for _, tc := range []struct{ sni1, sni2 string }{
		{"example.com", "auth.openai.com"},
		{"example.com", "console.anthropic.com"},
		{"example.com", "example.org"},
		{"example.com", ""},
	} {
		r := newRelayGateRig(t, "")
		r.serveHRR(t)
		hello1, _, done := helloRetryVia(t, r.spliceStart, tc.sni1, tc.sni2)
		waitDone(t, done)
		if b := r.upstreamBytes(t); !bytes.Equal(b, hello1) {
			t.Fatalf("%q -> %q: upstream got %d byte(s), want ClientHello 1 only (%d); ClientHello 2 must not be spliced", tc.sni1, tc.sni2, len(b), len(hello1))
		}
		ev := awaitRelayEvent(t, r.sink)
		if ev.Mode != "auth-gate" || ev.Action != "deny" || !strings.Contains(ev.Reason, "HelloRetryRequest") || !strings.Contains(ev.Reason, "443 passthrough") {
			t.Fatalf("%q -> %q: event = %+v, want an auth-gate deny after the HelloRetryRequest on 443 passthrough", tc.sni1, tc.sni2, ev)
		}
	}
}

// countConn counts the bytes a server read and wrote, and keeps what it
// wrote.
type countConn struct {
	net.Conn
	mu      sync.Mutex
	in, out int64
	wrote   []byte
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.mu.Lock()
	c.in += int64(n)
	c.mu.Unlock()
	return n, err
}

func (c *countConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.mu.Lock()
	c.out += int64(n)
	c.wrote = append(c.wrote, b[:n]...)
	c.mu.Unlock()
	return n, err
}

func selfSignedCert(t *testing.T, name string) tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// D-R4-10 (A) keeps DEV-24's allowance on 443: a real TLS 1.3 handshake
// to a host with no auth rule, through a HelloRetryRequest (the server
// takes P-256 only, the client's key share is X25519), is spliced end to
// end, and the splice event counts every byte both ways.
func TestSpliceRelaysTLS13HelloRetry(t *testing.T) {
	r := newRelayGateRig(t, "")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	r.port = ln.Addr().(*net.TCPAddr).Port
	cert := selfSignedCert(t, "example.com")
	srvDone := make(chan *countConn, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			srvDone <- nil
			return
		}
		cc := &countConn{Conn: raw}
		defer func() { _ = raw.Close(); srvDone <- cc }()
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		tc := tls.Server(cc, &tls.Config{
			Certificates:     []tls.Certificate{cert},
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.CurveP256},
		})
		if err := tc.Handshake(); err != nil {
			return
		}
		buf := make([]byte, 64)
		n, _ := tc.Read(buf)
		_, _ = tc.Write(append([]byte("echo:"), buf[:n]...))
		_, _ = io.Copy(io.Discard, tc)
	}()
	agent, done, _ := r.splice443(t)
	_ = agent.SetDeadline(time.Now().Add(5 * time.Second))
	cli := tls.Client(agent, &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.CurveP256},
	})
	if err := cli.Handshake(); err != nil {
		t.Fatalf("handshake through the splice: %v", err)
	}
	if _, err := cli.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len("echo:ping"))
	if _, err := io.ReadFull(cli, got); err != nil || string(got) != "echo:ping" {
		t.Fatalf("read %q, %v; want echo:ping", got, err)
	}
	_ = agent.Close()
	waitDone(t, done)
	var cc *countConn
	select {
	case cc = <-srvDone:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never finished")
	}
	if cc == nil {
		t.Fatal("upstream never accepted")
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if !bytes.Contains(cc.wrote, rfc8446HRRRandom) {
		t.Fatal("the upstream sent no HelloRetryRequest; the test no longer covers the HRR watch")
	}
	ev := awaitRelayEvent(t, r.sink)
	if ev.Mode != "splice" || ev.Action != "allow" || ev.Out != cc.in || ev.In != cc.out {
		t.Fatalf("event = %+v, want a splice allow with Out = %d and In = %d", ev, cc.in, cc.out)
	}
}

// D-R4-10 (A): the splice event's byte counts stay whole when the gate
// writes ClientHello 1 upstream itself and forwards the HelloRetryRequest
// to the agent itself (out += sent, in += pre).
func TestSpliceCountsGateForwardedBytes(t *testing.T) {
	r := newRelayGateRig(t, "")
	r.serveHRR(t)
	hello1, rest, done := helloRetryVia(t, r.spliceStart, "example.com", "example.com")
	want := append(append([]byte{}, hello1...), rest...)
	if b := r.upstreamBytes(t); !bytes.Equal(b, want) {
		t.Fatalf("upstream got %d byte(s), want both ClientHellos (%d)", len(b), len(want))
	}
	waitDone(t, done)
	ev := awaitRelayEvent(t, r.sink)
	if ev.Mode != "splice" || ev.Action != "allow" || ev.Out != int64(len(want)) || ev.In != int64(len(hrrRecord())) {
		t.Fatalf("event = %+v, want a splice allow with Out = %d and In = %d", ev, len(want), len(hrrRecord()))
	}
}

// A ClientHello with no SNI on 443 is handled as before the fix: with no
// destination address to fall back on it is never spliced (handle needs
// a name to dial), and the gate records nothing.
func TestSpliceNoSNIUnchanged(t *testing.T) {
	hello := captureClientHello(t, "")
	r := newRelayGateRig(t, "")
	agent, done, dials := r.splice443(t)
	go func() { _, _ = agent.Write(hello) }()
	waitDone(t, done)
	if n := dials.Load(); n != 0 {
		t.Fatalf("no-SNI hello on 443 dialed upstream %d time(s); want the pre-fix behavior (never spliced)", n)
	}
	recent, _, cancel := r.sink.RecentAndSubscribe()
	cancel()
	for _, ev := range recent {
		if ev.Mode == "auth-gate" {
			t.Fatalf("no-SNI hello produced an auth-gate event %+v", ev)
		}
	}
}
