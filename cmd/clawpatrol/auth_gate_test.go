package main

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// gatewayConn opens one agent connection into Gateway.handle exactly as
// an agent would: TLS ClientHello with SNI=host. closeFn closes the raw
// pipe first (see inspectUnknownSend) and waits for handle to return.
func gatewayConn(t *testing.T, g *Gateway, host string) (*tls.Conn, *bufio.Reader, func()) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	g.onboard.profileByIP[peerIP(serverConn)] = "default"
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handle(serverConn, "", 443)
	}()
	if err := clientConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: host, NextProtos: []string{"http/1.1"}})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	closeFn := func() {
		_ = clientConn.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("handle did not return")
		}
	}
	return clientTLS, bufio.NewReader(clientTLS), closeFn
}

// gatewayRoundTrip writes one request on an open gateway connection and
// reads its response in full, leaving the connection open.
func gatewayRoundTrip(t *testing.T, tc *tls.Conn, br *bufio.Reader, host, method, path string, header http.Header, body string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest(method, "https://"+host+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if err := req.Write(tc); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read response body: %v", err) // a framing break must fail the test (R3-07)
	}
	return resp.StatusCode, resp.Header, string(b)
}

// gatewaySend drives one request through Gateway.handle on a fresh
// connection.
func gatewaySend(t *testing.T, g *Gateway, host, method, path string, header http.Header, body string) (int, http.Header, string) {
	t.Helper()
	tc, br, closeFn := gatewayConn(t, g, host)
	defer closeFn()
	return gatewayRoundTrip(t, tc, br, host, method, path, header, body)
}

const authGateHCL = `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

defaults { unknown_host = "inspect" }

endpoint "https" "unknown" { hosts = [] }

rule "allow-all" {
  endpoint  = https.unknown
  condition = "true"
  verdict   = "allow"
}

profile "default" { credentials = [] }
`

func TestAuthGateDeniesAndNeverDials(t *testing.T) {
	h := newCredentialMatchHarness(t, authGateHCL, "unknown")
	for _, host := range []string{"auth.openai.com", "console.anthropic.com"} {
		status, hdr, body := gatewaySend(t, h.gateway, host, http.MethodPost, "/oauth/token", nil, "grant_type=refresh_token")
		if status != http.StatusForbidden {
			t.Fatalf("%s: status %d body %q, want 403", host, status, body)
		}
		if !strings.Contains(body, "managed by clawpatrol") {
			t.Fatalf("%s: body %q", host, body)
		}
		if hdr.Get("Set-Cookie") != "" || hdr.Get("Alt-Svc") != "" {
			t.Fatalf("%s: auth-bearing headers leaked: %v", host, hdr)
		}
		if got, _ := h.dialedAddr.Load().(string); got != "" {
			t.Fatalf("%s: gateway dialed upstream %q; auth hosts must never be forwarded", host, got)
		}
	}
}

func TestAuthGateHostNormalization(t *testing.T) {
	h := newCredentialMatchHarness(t, authGateHCL, "unknown")
	for _, host := range []string{"Auth.OpenAI.com", "AUTH.OPENAI.COM"} {
		if status, _, _ := gatewaySend(t, h.gateway, host, http.MethodGet, "/", nil, ""); status != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403", host, status)
		}
	}
	if got, _ := h.dialedAddr.Load().(string); got != "" {
		t.Fatalf("dialed %q", got)
	}
	// Go's TLS client strips a trailing dot before writing SNI, so the
	// trailing-dot form cannot be sent through gatewaySend. Pin it at the
	// lookup handle() calls on the raw SNI instead.
	for _, raw := range []string{"Auth.OpenAI.com.", "AUTH.OPENAI.COM.", "auth.openai.com:443"} {
		if p := agentprovider.AuthProvider(raw); p == nil || p.ID != "codex" {
			t.Fatalf("AuthProvider(%q) = %v, want codex", raw, p)
		}
	}
}

// A stub's own response passes through the same header stripping as the
// MITM path: a stub can never hand the agent a cookie or an Alt-Svc hint.
func TestAuthGateStripsStubAuthHeaders(t *testing.T) {
	restore := agentprovider.Swap(append(agentprovider.All(), &agentprovider.Provider{
		ID: "gatetest", DisplayName: "Gate Test", AuthHosts: []string{"auth.gate.test"},
		Stubs: []agentprovider.AuthStub{{
			Host: "auth.gate.test", Method: http.MethodGet, PathSuffix: "/stub",
			Respond: func(req *http.Request, _ agentprovider.PublicMaterial) *http.Response {
				r := plainResponse(req, http.StatusOK, "ok")
				r.Header.Set("Set-Cookie", "session=leak")
				r.Header.Set("Alt-Svc", `h3=":443"`)
				return r
			},
		}},
	}))
	defer restore()
	h := newCredentialMatchHarness(t, authGateHCL, "unknown")
	status, hdr, _ := gatewaySend(t, h.gateway, "auth.gate.test", http.MethodGet, "/stub", nil, "")
	if status != http.StatusOK || hdr.Get("Set-Cookie") != "" || hdr.Get("Alt-Svc") != "" {
		t.Fatalf("stub response status %d headers %v; want 200 with Set-Cookie and Alt-Svc stripped", status, hdr)
	}
}

// Spec §8.2: the first gated request per agent carries the dashboard
// hint; later ones do not.
func TestAuthGateLoginHintOncePerAgent(t *testing.T) {
	h := newCredentialMatchHarness(t, authGateHCL, "unknown")
	for range 2 {
		_, _, _ = gatewaySend(t, h.gateway, "auth.openai.com", http.MethodPost, "/oauth/token", nil, "")
	}
	// Sink.drain moves events into the recent ring asynchronously.
	// recentSnapshot needs s.mu held; RecentAndSubscribe takes it (F3:
	// calling recentSnapshot directly is a data race under -race).
	var gated, hints int
	deadline := time.Now().Add(3 * time.Second)
	for {
		gated, hints = 0, 0
		recent, _, cancel := h.gateway.sink.RecentAndSubscribe()
		cancel()
		for _, ev := range recent {
			if ev.Mode != "auth-gate" {
				continue
			}
			gated++
			if strings.Contains(ev.Reason, "Codex login now happens in the dashboard") {
				hints++
			}
		}
		if gated >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if gated != 2 || hints != 1 {
		t.Fatalf("gated events = %d, login hints = %d; want 2 events and exactly 1 hint", gated, hints)
	}
}

func TestAuthGateCodexTaskRegisterStub(t *testing.T) {
	h := newCredentialMatchHarness(t, authGateHCL, "unknown")
	status, _, body := gatewaySend(t, h.gateway, "auth.openai.com", http.MethodPost,
		"/api/accounts/v1/agent/clawpatrol-codex/task/register", nil, "{}")
	if status != http.StatusOK || !strings.Contains(body, `"task_id":"clawpatrol-task"`) {
		t.Fatalf("synthetic register = %d %q, want 200 task_id", status, body)
	}
	status, _, _ = gatewaySend(t, h.gateway, "auth.openai.com", http.MethodPost,
		"/api/accounts/v1/agent/real-runtime/task/register", nil, "{}")
	if status != http.StatusForbidden {
		t.Fatalf("foreign runtime register = %d, want 403", status)
	}
	// The stub answers only POST and only the exact suffix.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/accounts/v1/agent/clawpatrol-codex/task/register"},
		{http.MethodPost, "/api/accounts/v1/agent/clawpatrol-codex/task/register/x"},
	} {
		if status, _, _ := gatewaySend(t, h.gateway, "auth.openai.com", tc.method, tc.path, nil, "{}"); status != http.StatusForbidden {
			t.Fatalf("%s %s = %d, want 403", tc.method, tc.path, status)
		}
	}
	if got, _ := h.dialedAddr.Load().(string); got != "" {
		t.Fatalf("dialed %q", got)
	}
}

// Spec §8.2: the hint is once per (agent, provider), and only on a
// deny, never on a stub answer.
func TestAuthGateLoginHintPerAgentAndDenyOnly(t *testing.T) {
	h := newCredentialMatchHarness(t, authGateHCL, "unknown")
	p := agentprovider.AuthProvider("auth.openai.com")
	req := httptest.NewRequest(http.MethodPost, "https://auth.openai.com/oauth/token", nil)
	send := func(agent, action string) {
		resp := plainResponse(req, http.StatusForbidden, "x")
		defer func() { _ = resp.Body.Close() }() // writeAuthGateAnswer closes it too; a second close is a no-op
		_ = h.gateway.writeAuthGateAnswer(io.Discard, req, "auth.openai.com", agent, p,
			resp, action, "auth host gated (codex)")
	}
	send("10.55.0.3", "synth") // a stub answer: no hint, and it must not use up the agent's hint
	send("10.55.0.2", "deny")
	send("10.55.0.3", "deny")
	send("10.55.0.2", "deny")
	var hints []string
	deadline := time.Now().Add(3 * time.Second)
	for {
		hints = hints[:0]
		n := 0
		recent, _, cancel := h.gateway.sink.RecentAndSubscribe()
		cancel()
		for _, ev := range recent {
			if ev.Mode != "auth-gate" {
				continue
			}
			n++
			if strings.Contains(ev.Reason, "login now happens in the dashboard") {
				hints = append(hints, ev.Action+"@"+ev.AgentIP)
			}
		}
		if n >= 4 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	slices.Sort(hints)
	if want := []string{"deny@10.55.0.2", "deny@10.55.0.3"}; !slices.Equal(hints, want) {
		t.Fatalf("hinted events = %v, want %v (one per agent, deny only)", hints, want)
	}
}
