package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/agentprovider"
	"github.com/denoland/clawpatrol/internal/config"
)

// relayGateRig is a gateway whose wgRelay may dial loopback, plus one
// upstream connection that reports every byte it received before the
// relay closed it.
type relayGateRig struct {
	g    *Gateway
	sink *Sink
	port int
	got  chan []byte
}

func newRelayGateRig(t *testing.T, banner string) *relayGateRig {
	t.Helper()
	sink, err := NewSink(nil, 16)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	g, _ := relayDialTestGateway(t, &tableResolver{}, true)
	g.sink = sink
	g.onboard = newOnboardRegistry()
	// 127.0.0.1 is refused under "public"; declare it, as
	// TestWgRelayAllowsPublicDestination does.
	g.policy.Store(&config.CompiledPolicy{RelayAllowCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	r := &relayGateRig{g: g, sink: sink, port: ln.Addr().(*net.TCPAddr).Port, got: make(chan []byte, 1)}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		if banner != "" {
			_, _ = c.Write([]byte(banner))
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		b, _ := io.ReadAll(c)
		r.got <- b
	}()
	return r
}

// relay runs wgRelay for one agent connection on a non-443 port. It
// returns the agent end and a channel closed when wgRelay returns.
func (r *relayGateRig) relay(t *testing.T) (net.Conn, <-chan struct{}) {
	t.Helper()
	agent, gw := net.Pipe()
	r.g.onboard.knownDeviceIPs[peerIP(gw)] = true
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.g.wgRelay(gw, "127.0.0.1", r.port)
	}()
	t.Cleanup(func() { _ = agent.Close() })
	return agent, done
}

func (r *relayGateRig) upstreamBytes(t *testing.T) []byte {
	t.Helper()
	select {
	case b := <-r.got:
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never finished")
		return nil
	}
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("wgRelay did not return")
	}
}

// D3: a ClientHello naming a provider auth host on a non-443 relay is
// refused, and not one agent byte reaches the upstream.
func TestWgRelayGatesAuthSNI(t *testing.T) {
	r := newRelayGateRig(t, "")
	agent, done := r.relay(t)
	go func() {
		_ = tls.Client(agent, &tls.Config{ServerName: "auth.openai.com", InsecureSkipVerify: true}).Handshake()
	}()
	waitDone(t, done)
	if b := r.upstreamBytes(t); len(b) != 0 {
		t.Fatalf("upstream received %d byte(s); an auth-host ClientHello must never be forwarded", len(b))
	}
	ev := awaitRelayEvent(t, r.sink)
	if ev.Mode != "auth-gate" || ev.Action != "deny" || !strings.Contains(ev.Reason, "auth.openai.com") {
		t.Fatalf("event = %+v, want an auth-gate deny naming the SNI", ev)
	}
}

// Other TLS on a non-443 relay is forwarded byte for byte, ClientHello
// first.
func TestWgRelayForwardsOtherTLS(t *testing.T) {
	r := newRelayGateRig(t, "")
	agent, done := r.relay(t)
	go func() {
		_ = tls.Client(agent, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true}).Handshake()
	}()
	time.AfterFunc(300*time.Millisecond, func() { _ = agent.Close() })
	if b := r.upstreamBytes(t); len(b) < 5 || b[0] != 0x16 {
		t.Fatalf("upstream got %q, want the agent's ClientHello", b)
	}
	waitDone(t, done)
}

// A server-first protocol (SSH, SMTP) gets its banner before the agent
// has sent anything: the peek never waits on the agent to forward the
// upstream's first bytes.
func TestWgRelayServerFirstNotDelayed(t *testing.T) {
	r := newRelayGateRig(t, "SSH-2.0-upstream\r\n")
	agent, done := r.relay(t)
	_ = agent.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := agent.Read(buf)
	if err != nil || string(buf[:n]) != "SSH-2.0-upstream\r\n" {
		t.Fatalf("agent read %q, %v; the upstream banner must reach the agent before it speaks", buf[:n], err)
	}
	if _, err := agent.Write([]byte("SSH-2.0-agent\r\n")); err != nil {
		t.Fatalf("agent write: %v", err)
	}
	_ = agent.Close()
	if b := r.upstreamBytes(t); string(b) != "SSH-2.0-agent\r\n" {
		t.Fatalf("upstream got %q, want the agent's reply", b)
	}
	waitDone(t, done)
}

// captureClientHello returns the first TLS record a Go client writes for
// sni: a whole ClientHello in one record.
func captureClientHello(t *testing.T, sni string) []byte {
	t.Helper()
	cli, srv := net.Pipe()
	defer func() { _ = srv.Close(); _ = cli.Close() }()
	go func() {
		_ = tls.Client(cli, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake()
	}()
	_ = srv.SetReadDeadline(time.Now().Add(3 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(srv, hdr); err != nil {
		t.Fatalf("read ClientHello header: %v", err)
	}
	rec := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(srv, rec); err != nil {
		t.Fatalf("read ClientHello: %v", err)
	}
	return append(hdr, rec...)
}

// fragmentRecord re-splits one TLS handshake record into records of at
// most size payload bytes each, as openssl -max_send_frag does.
func fragmentRecord(rec []byte, size int) []byte {
	var out []byte
	for p := rec[5:]; len(p) > 0; {
		n := min(size, len(p))
		out = append(out, rec[0], rec[1], rec[2], byte(n>>8), byte(n))
		out = append(out, p[:n]...)
		p = p[n:]
	}
	return out
}

// S101: an auth-host ClientHello split across TLS records is reassembled
// and refused; the single-record peek alone would have relayed it.
func TestWgRelayGatesFragmentedClientHello(t *testing.T) {
	rec := captureClientHello(t, "auth.openai.com")
	if len(rec) < 3*64 {
		t.Fatalf("ClientHello is %d bytes; too short to split into three records", len(rec))
	}
	r := newRelayGateRig(t, "")
	agent, done := r.relay(t)
	go func() { _, _ = agent.Write(fragmentRecord(rec, 64)) }()
	waitDone(t, done)
	if b := r.upstreamBytes(t); len(b) != 0 {
		t.Fatalf("upstream received %d byte(s); a fragmented auth-host ClientHello must never be forwarded", len(b))
	}
	ev := awaitRelayEvent(t, r.sink)
	if ev.Mode != "auth-gate" || ev.Action != "deny" || !strings.Contains(ev.Reason, "auth.openai.com") {
		t.Fatalf("event = %+v, want an auth-gate deny naming the SNI", ev)
	}
}

// R2-D8: a relay sees no paths, so TLS whose SNI is the host of any
// AuthPaths rule is refused on a non-443 relay, whole or fragmented, with
// zero bytes upstream.
func TestWgRelayGatesAuthPathHostSNI(t *testing.T) {
	legs := []struct {
		name string
		frag int // 0 = one record
	}{{"whole", 0}, {"fragmented", 64}}
	for _, sni := range []string{"platform.claude.com", "claude.com", "claude.ai", "api.anthropic.com"} {
		for _, leg := range legs {
			t.Run(sni+"/"+leg.name, func(t *testing.T) {
				hello := captureClientHello(t, sni)
				if leg.frag > 0 {
					hello = fragmentRecord(hello, leg.frag)
				}
				r := newRelayGateRig(t, "")
				agent, done := r.relay(t)
				go func() { _, _ = agent.Write(hello) }()
				waitDone(t, done)
				if b := r.upstreamBytes(t); len(b) != 0 {
					t.Fatalf("upstream received %d byte(s); TLS to an AuthPaths host must never be relayed", len(b))
				}
				ev := awaitRelayEvent(t, r.sink)
				if ev.Mode != "auth-gate" || ev.Action != "deny" || !strings.Contains(ev.Reason, "SNI "+sni) {
					t.Fatalf("event = %+v, want an auth-gate deny naming SNI %s", ev, sni)
				}
			})
		}
	}
}

// R2-D8 refuses AuthPaths rule hosts only: a provider host with no rule
// (chatgpt.com, a codex API host) is still relayed byte for byte.
func TestWgRelayForwardsProviderHostWithoutAuthPaths(t *testing.T) {
	if agentprovider.HasAuthPaths("chatgpt.com") || agentprovider.AuthProvider("chatgpt.com") != nil {
		t.Fatal("chatgpt.com gained an auth rule; pick a provider host without one")
	}
	hello := captureClientHello(t, "chatgpt.com")
	r := newRelayGateRig(t, "")
	agent, done := r.relay(t)
	go func() {
		_, _ = agent.Write(hello)
		time.AfterFunc(300*time.Millisecond, func() { _ = agent.Close() })
	}()
	if b := r.upstreamBytes(t); string(b) != string(hello) {
		t.Fatalf("upstream got %d byte(s), want the agent's %d ClientHello bytes unchanged", len(b), len(hello))
	}
	waitDone(t, done)
}

// A fragmented ClientHello for any other host is forwarded byte for
// byte, records and all.
func TestWgRelayForwardsFragmentedOtherTLS(t *testing.T) {
	frag := fragmentRecord(captureClientHello(t, "example.com"), 64)
	r := newRelayGateRig(t, "")
	agent, done := r.relay(t)
	go func() {
		_, _ = agent.Write(frag)
		time.AfterFunc(300*time.Millisecond, func() { _ = agent.Close() })
	}()
	if b := r.upstreamBytes(t); string(b) != string(frag) {
		t.Fatalf("upstream got %d byte(s), want the agent's %d fragmented ClientHello bytes unchanged", len(b), len(frag))
	}
	waitDone(t, done)
}

// S101: a TLS handshake the gate cannot parse is refused (fail closed),
// with zero bytes upstream.
func TestWgRelayRefusesUnparsableHello(t *testing.T) {
	r := newRelayGateRig(t, "")
	agent, done := r.relay(t)
	bad := append([]byte{0x16, 0x03, 0x01, 0x00, 0x30}, make([]byte, 0x30)...) // handshake type 0, not ClientHello
	go func() { _, _ = agent.Write(bad) }()
	waitDone(t, done)
	if b := r.upstreamBytes(t); len(b) != 0 {
		t.Fatalf("upstream received %d byte(s) of an unparsable handshake", len(b))
	}
	ev := awaitRelayEvent(t, r.sink)
	if ev.Mode != "auth-gate" || ev.Action != "deny" || !strings.Contains(ev.Reason, "unparsable") {
		t.Fatalf("event = %+v, want an auth-gate deny for an unparsable ClientHello", ev)
	}
}

// F105: a handshake record that breaks off mid-read closes the relay with
// zero bytes upstream.
func TestWgRelayTruncatedHelloClosed(t *testing.T) {
	r := newRelayGateRig(t, "")
	agent, done := r.relay(t)
	go func() {
		_, _ = agent.Write(append([]byte{0x16, 0x03, 0x01, 0x02, 0x00}, make([]byte, 10)...)) // declares 512, sends 10
		_ = agent.Close()
	}()
	waitDone(t, done)
	if b := r.upstreamBytes(t); len(b) != 0 {
		t.Fatalf("upstream received %d byte(s) of a truncated handshake", len(b))
	}
}

// A first byte of 0x16 without a TLS record version after it is not TLS
// and is relayed unchanged.
func TestWgRelayForwardsNonTLSLeading0x16(t *testing.T) {
	msg := []byte("\x16\x00not-tls-payload")
	r := newRelayGateRig(t, "")
	agent, done := r.relay(t)
	go func() {
		_, _ = agent.Write(msg)
		time.AfterFunc(300*time.Millisecond, func() { _ = agent.Close() })
	}()
	if b := r.upstreamBytes(t); string(b) != string(msg) {
		t.Fatalf("upstream got %q, want %q", b, msg)
	}
	waitDone(t, done)
}

type sniEntry struct {
	typ  byte
	name string
}

// sniExt builds a server_name extension holding entries.
func sniExt(entries ...sniEntry) []byte {
	var list []byte
	for _, e := range entries {
		list = append(list, e.typ, byte(len(e.name)>>8), byte(len(e.name)))
		list = append(list, e.name...)
	}
	body := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	return append([]byte{0x00, 0x00, byte(len(body) >> 8), byte(len(body))}, body...)
}

// helloMsg builds a minimal ClientHello handshake message carrying exts.
func helloMsg(exts ...[]byte) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // one cipher suite
	body = append(body, 0x01, 0x00)             // null compression
	var all []byte
	for _, e := range exts {
		all = append(all, e...)
	}
	body = append(body, byte(len(all)>>8), byte(len(all)))
	body = append(body, all...)
	return append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

// R2-03: one server_name extension, one host_name entry, hostname bytes.
func TestClientHelloSNIStrict(t *testing.T) {
	alpn := []byte{0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2'}
	cases := []struct {
		name    string
		msg     []byte
		want    string
		wantErr bool
	}{
		{"one host_name", helloMsg(sniExt(sniEntry{0, "auth.openai.com"})), "auth.openai.com", false},
		{"other type first", helloMsg(sniExt(sniEntry{1, "example.com"}, sniEntry{0, "auth.openai.com"})), "", true},
		{"other type only", helloMsg(sniExt(sniEntry{1, "auth.openai.com"})), "", true},
		{"two host_names", helloMsg(sniExt(sniEntry{0, "example.com"}, sniEntry{0, "auth.openai.com"})), "", true},
		{"two extensions", helloMsg(sniExt(sniEntry{0, "example.com"}), sniExt(sniEntry{0, "auth.openai.com"})), "", true},
		{"NUL in name", helloMsg(sniExt(sniEntry{0, "auth.openai.com\x00"})), "", true},
		{"space in name", helloMsg(sniExt(sniEntry{0, "auth.openai.com x"})), "", true},
		{"empty list", helloMsg(sniExt()), "", true},
		{"no server_name", helloMsg(alpn), "", false},
	}
	for _, tc := range cases {
		got, err := clientHelloSNI(tc.msg)
		if tc.wantErr {
			if err == nil || errors.Is(err, errNoSNI) {
				t.Errorf("%s: clientHelloSNI = %q, %v; want a refusal error", tc.name, got, err)
			}
			continue
		}
		if tc.want == "" {
			if !errors.Is(err, errNoSNI) {
				t.Errorf("%s: err = %v, want errNoSNI", tc.name, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: clientHelloSNI = %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
}

// R2-03 end to end: a mixed server_name list naming an auth host second
// is refused with zero bytes upstream.
func TestWgRelayGatesMixedSNIList(t *testing.T) {
	r := newRelayGateRig(t, "")
	agent, done := r.relay(t)
	m := helloMsg(sniExt(sniEntry{1, "example.com"}, sniEntry{0, "auth.openai.com"}))
	go func() { _, _ = agent.Write(append([]byte{0x16, 0x03, 0x01, byte(len(m) >> 8), byte(len(m))}, m...)) }()
	waitDone(t, done)
	if b := r.upstreamBytes(t); len(b) != 0 {
		t.Fatalf("upstream received %d byte(s); a mixed server_name list must be refused", len(b))
	}
	if ev := awaitRelayEvent(t, r.sink); ev.Mode != "auth-gate" || ev.Action != "deny" {
		t.Fatalf("event = %+v, want an auth-gate deny", ev)
	}
}

// After the hand-off the upstream's reply reaches the agent: the gate
// clears the read deadline it used to stop its copier (R2-06a). A non-TLS
// opening hands off at once; a TLS one hands off after the gate forwarded
// ClientHello 1 and read the first bytes of the reply.
func TestWgRelayUpstreamReplyAfterHello(t *testing.T) {
	for _, tc := range []struct {
		name    string
		opening []byte
	}{
		{"non-TLS opening", []byte("PING-from-agent\r\n")},
		{"TLS ClientHello", captureClientHello(t, "example.com")},
	} {
		r := newRelayGateRig(t, "")
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			hdr := make([]byte, 5)
			_, _ = io.ReadFull(c, hdr) // the agent has spoken
			time.Sleep(200 * time.Millisecond)
			_, _ = c.Write([]byte("upstream-reply"))
			_, _ = io.Copy(io.Discard, c)
		}()
		r.port = ln.Addr().(*net.TCPAddr).Port
		agent, done := r.relay(t)
		go func() { _, _ = agent.Write(tc.opening) }()
		_ = agent.SetReadDeadline(time.Now().Add(3 * time.Second))
		got := make([]byte, len("upstream-reply"))
		if _, err := io.ReadFull(agent, got); err != nil || string(got) != "upstream-reply" {
			t.Fatalf("%s: agent read %q, %v; the upstream reply after the hand-off must reach the agent", tc.name, got, err)
		}
		_ = agent.Close()
		waitDone(t, done)
	}
}

// A continuation record of a fragmented auth-host ClientHello with an
// odd record version or a non-handshake type is never relayed: Go's
// server accepts any version below 0x1000 before the hello is parsed
// (R2-06b, M29, M27).
func TestWgRelayGatesOddContinuationRecords(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sni    string
		edit   func(rec2 []byte)
		reason string // "" = any deny
	}{
		{"continuation version 00 00", "auth.openai.com", func(rec2 []byte) { rec2[1], rec2[2] = 0x00, 0x00 }, ""},
		{"continuation type 0x17", "auth.openai.com", func(rec2 []byte) { rec2[0] = 0x17 }, ""},
		// Fix round 1, m2: the rows above are denied on their SNI whether or
		// not the continuation checks run. These two name a host the gate
		// lets through, so only the continuation checks refuse them: a
		// continuation version of 0x10 or more (M29) and a continuation
		// record that is not a handshake record (M27).
		{"continuation version 10 00, ungated SNI", "example.com", func(rec2 []byte) { rec2[1], rec2[2] = 0x10, 0x00 }, "bad record version in a continuation record"},
		{"continuation type 0x17, ungated SNI", "example.com", func(rec2 []byte) { rec2[0] = 0x17 }, "non-handshake record"},
	} {
		r := newRelayGateRig(t, "")
		agent, done := r.relay(t)
		frags := fragmentRecord(captureClientHello(t, tc.sni), 100)
		tc.edit(frags[5+100:]) // the second record's header
		go func() { _, _ = agent.Write(frags) }()
		waitDone(t, done)
		if b := r.upstreamBytes(t); len(b) != 0 {
			t.Fatalf("%s: upstream received %d byte(s), want 0", tc.name, len(b))
		}
		if ev := awaitRelayEvent(t, r.sink); ev.Mode != "auth-gate" || ev.Action != "deny" || !strings.Contains(ev.Reason, tc.reason) {
			t.Fatalf("%s: event = %+v, want an auth-gate deny (reason containing %q)", tc.name, ev, tc.reason)
		}
	}
}

// A ClientHello that dribbles in is cut off at the peek timeout with
// zero bytes upstream (R2-06c, M26).
func TestWgRelaySlowHelloTimesOut(t *testing.T) {
	saved := relayPeekTimeout
	relayPeekTimeout = 500 * time.Millisecond
	defer func() { relayPeekTimeout = saved }()
	r := newRelayGateRig(t, "")
	agent, done := r.relay(t)
	hello := captureClientHello(t, "example.com")
	go func() {
		for _, b := range hello {
			if _, err := agent.Write([]byte{b}); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("wgRelay still running; the peek must time out")
	}
	if b := r.upstreamBytes(t); len(b) != 0 {
		t.Fatalf("upstream received %d byte(s), want 0", len(b))
	}
}

// A ClientHello whose records add up to more than 64 KiB is refused,
// whatever its SNI (R2-06d, M25).
func TestWgRelayRefusesOversizedHello(t *testing.T) {
	protos := make([]string, 60)
	for i := range protos {
		protos[i] = strings.Repeat(string(rune('a'+i%26)), 200)
	}
	cli, srv := net.Pipe()
	go func() {
		_ = tls.Client(cli, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true, NextProtos: protos}).Handshake()
	}()
	_ = srv.SetReadDeadline(time.Now().Add(3 * time.Second))
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(srv, hdr); err != nil {
		t.Fatalf("read hello header: %v", err)
	}
	rec := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(srv, rec); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	_ = srv.Close()
	_ = cli.Close()
	big := fragmentRecord(append(hdr, rec...), 1) // ~12 KB hello in 1-byte records: ~72 KB on the wire
	r := newRelayGateRig(t, "")
	agent, done := r.relay(t)
	go func() { _, _ = agent.Write(big) }()
	waitDone(t, done)
	if b := r.upstreamBytes(t); len(b) != 0 {
		t.Fatalf("upstream received %d byte(s), want 0", len(b))
	}
	if ev := awaitRelayEvent(t, r.sink); ev.Mode != "auth-gate" || ev.Action != "deny" || !strings.Contains(ev.Reason, "64 KiB") {
		t.Fatalf("event = %+v, want an auth-gate deny for a hello over 64 KiB", ev)
	}
}

// rfc8446HRRRandom is the ServerHello.random that marks a
// HelloRetryRequest (RFC 8446 §4.1.3). Spelled out here rather than taken
// from relay_auth_gate.go, so a wrong constant there fails the tests.
var rfc8446HRRRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// hrrRecord is a minimal HelloRetryRequest record: a ServerHello whose
// random is the HRR constant. The gate reads only the first 38 bytes of
// the handshake message.
func hrrRecord() []byte {
	body := append([]byte{0x03, 0x03}, rfc8446HRRRandom...)
	body = append(body, 0x00, 0x13, 0x01, 0x00, 0x00, 0x00) // session id, cipher suite, compression, no extensions
	msg := append([]byte{0x02, 0x00, 0x00, byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x03, 0x00, byte(len(msg))}, msg...)
}

// serveHRR points r at an upstream that answers the agent's first TLS
// record with a HelloRetryRequest, then reports every byte it received,
// ClientHello 1 included, once the relay closes. Call it before r.relay.
func (r *relayGateRig) serveHRR(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	r.port = ln.Addr().(*net.TCPAddr).Port
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(c, hdr); err != nil {
			r.got <- nil
			return
		}
		rec := make([]byte, int(hdr[3])<<8|int(hdr[4]))
		_, _ = io.ReadFull(c, rec)
		_, _ = c.Write(hrrRecord())
		rest, _ := io.ReadAll(c)
		r.got <- append(append(hdr, rec...), rest...)
	}()
}

// helloRetry drives one agent through a HelloRetryRequest on r, as a TLS
// 1.3 client does: ClientHello 1 naming sni1, then (after it reads the
// HRR) a CCS record and ClientHello 2 naming sni2. It returns ClientHello
// 1, the CCS plus ClientHello 2, and wgRelay's done channel.
func helloRetry(t *testing.T, r *relayGateRig, sni1, sni2 string) ([]byte, []byte, <-chan struct{}) {
	t.Helper()
	hello1 := captureClientHello(t, sni1)
	rest := append([]byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}, captureClientHello(t, sni2)...)
	agent, done := r.relay(t)
	go func() { _, _ = agent.Write(hello1) }()
	_ = agent.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(hrrRecord()))
	if _, err := io.ReadFull(agent, got); err != nil || !bytes.Equal(got, hrrRecord()) {
		t.Fatalf("agent read %x, %v; want the upstream's HelloRetryRequest", got, err)
	}
	go func() {
		_, _ = agent.Write(rest)
		time.AfterFunc(300*time.Millisecond, func() { _ = agent.Close() })
	}()
	return hello1, rest, done
}

// R2-01, D-R4-6 (A): after a HelloRetryRequest, ClientHello 2 is gated
// too. A ClientHello 2 that changes the SNI (to an auth host, an
// AuthPaths host, or any other name) never reaches the upstream.
func TestWgRelayGatesAuthSNIAfterHelloRetry(t *testing.T) {
	for _, tc := range []struct{ sni1, sni2 string }{
		{"example.com", "auth.openai.com"},
		{"", "platform.claude.com"},
		{"example.com", "example.org"},
	} {
		r := newRelayGateRig(t, "")
		r.serveHRR(t)
		hello1, _, done := helloRetry(t, r, tc.sni1, tc.sni2)
		waitDone(t, done)
		if b := r.upstreamBytes(t); !bytes.Equal(b, hello1) {
			t.Fatalf("%q -> %q: upstream got %d byte(s), want ClientHello 1 only (%d); ClientHello 2 must not be relayed", tc.sni1, tc.sni2, len(b), len(hello1))
		}
		ev := awaitRelayEvent(t, r.sink)
		if ev.Mode != "auth-gate" || ev.Action != "deny" || !strings.Contains(ev.Reason, "HelloRetryRequest") {
			t.Fatalf("%q -> %q: event = %+v, want an auth-gate deny after the HelloRetryRequest", tc.sni1, tc.sni2, ev)
		}
	}
}

// DEV-24 allowances survive the HRR check: no SNI, or the same ungated
// SNI, in both ClientHellos is relayed byte for byte (the CCS before
// ClientHello 2 is skipped, not refused), and the relay event counts
// every agent byte (D-R4-6 (A)).
func TestWgRelayHRRKeepsNoSNIAndOtherSNI(t *testing.T) {
	for _, sni := range []string{"", "example.com"} {
		r := newRelayGateRig(t, "")
		r.serveHRR(t)
		hello1, rest, done := helloRetry(t, r, sni, sni)
		want := append(append([]byte{}, hello1...), rest...)
		if b := r.upstreamBytes(t); !bytes.Equal(b, want) {
			t.Fatalf("SNI %q: upstream got %d byte(s), want both ClientHellos (%d)", sni, len(b), len(want))
		}
		waitDone(t, done)
		ev := awaitRelayEvent(t, r.sink)
		if ev.Mode != "relay" || ev.Action != "allow" || ev.Out != int64(len(want)) {
			t.Fatalf("SNI %q: event = %+v, want a relay allow with Out = %d", sni, ev, len(want))
		}
	}
}

// R2-02, D-R4-6 (A): Go's TLS server skips a leading warning alert, so an
// alert-prefixed auth-host ClientHello is parsed and refused, not relayed
// as non-TLS.
func TestWgRelayGatesAlertPrefixedHello(t *testing.T) {
	for _, sni := range []string{"auth.openai.com", "platform.claude.com"} {
		msg := append([]byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x01, 0x5a}, captureClientHello(t, sni)...)
		r := newRelayGateRig(t, "")
		agent, done := r.relay(t)
		go func() { _, _ = agent.Write(msg) }()
		waitDone(t, done)
		if b := r.upstreamBytes(t); len(b) != 0 {
			t.Fatalf("%s: upstream received %d byte(s) of an alert-prefixed ClientHello", sni, len(b))
		}
		if ev := awaitRelayEvent(t, r.sink); ev.Mode != "auth-gate" || ev.Action != "deny" || !strings.Contains(ev.Reason, "SNI "+sni) {
			t.Fatalf("%s: event = %+v, want an auth-gate deny naming the SNI", sni, ev)
		}
	}
}

// R2-02, D-R4-6 (A): Go accepts any first-record version below 0x1000,
// so an auth-host ClientHello with record version 00 00, 0f 00 or 02 00
// is parsed and refused.
func TestWgRelayGatesOddRecordVersionHello(t *testing.T) {
	for _, tc := range []struct {
		sni    string
		v0, v1 byte
	}{
		{"auth.openai.com", 0x00, 0x00},
		{"auth.openai.com", 0x0f, 0x00},
		{"platform.claude.com", 0x02, 0x00},
	} {
		hello := captureClientHello(t, tc.sni)
		hello[1], hello[2] = tc.v0, tc.v1
		r := newRelayGateRig(t, "")
		agent, done := r.relay(t)
		go func() { _, _ = agent.Write(hello) }()
		waitDone(t, done)
		if b := r.upstreamBytes(t); len(b) != 0 {
			t.Fatalf("%s version %02x %02x: upstream received %d byte(s), want 0", tc.sni, tc.v0, tc.v1, len(b))
		}
		if ev := awaitRelayEvent(t, r.sink); ev.Mode != "auth-gate" || ev.Action != "deny" {
			t.Fatalf("%s version %02x %02x: event = %+v, want an auth-gate deny", tc.sni, tc.v0, tc.v1, ev)
		}
	}
}

// DEV-24 boundary: a first record with version byte 0x10 or more is one
// Go's server rejects (and OpenSSL needs 0x03xx), so it is not TLS and is
// relayed unchanged, whatever it seems to name.
func TestWgRelayForwardsRecordVersionGoRejects(t *testing.T) {
	hello := captureClientHello(t, "auth.openai.com")
	hello[1], hello[2] = 0x10, 0x00
	r := newRelayGateRig(t, "")
	agent, done := r.relay(t)
	go func() {
		_, _ = agent.Write(hello)
		time.AfterFunc(300*time.Millisecond, func() { _ = agent.Close() })
	}()
	if b := r.upstreamBytes(t); !bytes.Equal(b, hello) {
		t.Fatalf("upstream got %d byte(s), want the agent's %d bytes unchanged", len(b), len(hello))
	}
	waitDone(t, done)
}

// D-R4-6 (A): the gate writes ClientHello 1 upstream itself, and the
// relay event's Out still counts it (tx += sent). The upstream here never
// answers, so the agent's close must end the gate's wait for it.
func TestWgRelayCountsGateForwardedBytes(t *testing.T) {
	hello := captureClientHello(t, "example.com")
	r := newRelayGateRig(t, "")
	agent, done := r.relay(t)
	start := time.Now()
	go func() {
		_, _ = agent.Write(hello)
		time.AfterFunc(300*time.Millisecond, func() { _ = agent.Close() })
	}()
	if b := r.upstreamBytes(t); !bytes.Equal(b, hello) {
		t.Fatalf("upstream got %d byte(s), want the agent's %d ClientHello bytes", len(b), len(hello))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("relay ended %v after start; the agent's close must end the wait on a silent upstream", d)
	}
	waitDone(t, done)
	if ev := awaitRelayEvent(t, r.sink); ev.Mode != "relay" || ev.Out != int64(len(hello)) {
		t.Fatalf("event = %+v, want a relay event with Out = %d", ev, len(hello))
	}
}
