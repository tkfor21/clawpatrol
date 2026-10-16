package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

// claudeHostsHCL claims Claude's path-gated hosts with an endpoint that
// has a bound credential, so a request that slipped past the path gate
// would resolve a credential and be forwarded with it.
const claudeHostsHCL = `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "https" "claudehosts" { hosts = ["platform.claude.com", "claude.com", "claude.ai", "api.anthropic.com"] }

credential "bearer_token" "tok" { endpoint = https.claudehosts }

rule "allow-all" {
  endpoint  = https.claudehosts
  condition = "true"
  verdict   = "allow"
}

profile "default" { credentials = [bearer_token.tok] }
`

// D1/D2: login paths on hosts the agent otherwise uses get 403 from the
// MITM loop and are never dialed, in every spelling an upstream would
// normalize, even with a credential bound to the host. The event check
// ties the gate to its place before credential resolution: a gated
// request emits exactly one auth-gate event, no mitm event, and no
// credential (round-2 F106).
func TestAuthPathGateDeniesLoginPaths(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_TOK", "real-secret-value-0123456789abcdef")
	hdr := http.Header{"Authorization": {"Bearer placeholder"}}
	cases := []struct{ host, method, path string }{
		{"platform.claude.com", http.MethodPost, "/v1/oauth/token"},
		{"platform.claude.com", http.MethodGet, "/oauth/authorize?client_id=x"},
		{"platform.claude.com", http.MethodGet, "/V1/OAuth/token"},
		{"platform.claude.com", http.MethodGet, "/docs/../oauth/authorize"},
		{"platform.claude.com", http.MethodGet, "//oauth/authorize"},
		// Percent-encoded spellings (F106, S109): the gate matches the
		// decoded, cleaned path.
		{"platform.claude.com", http.MethodPost, "/v1/oauth%2Ftoken"},
		{"platform.claude.com", http.MethodPost, "/v1/%6Fauth/token"},
		{"platform.claude.com", http.MethodPost, "/v1%2F..%2Foauth/token"},
		{"platform.claude.com", http.MethodGet, "/x/%2e%2e/oauth/authorize"},
		{"claude.com", http.MethodGet, "/cai/oauth/authorize"},
		{"api.anthropic.com", http.MethodPost, "/api/oauth/claude_cli/create_api_key"},
		{"api.anthropic.com", http.MethodPost, "/api/oauth/claude_cli/create_api_key/"},
		{"api.anthropic.com", http.MethodPost, "/api/oauth/claude_cli/%63reate_api_key"},
		// Alias hosts of the same handlers (S105, S106).
		{"platform.claude.com", http.MethodPost, "/api/oauth/claude_cli/create_api_key"},
		{"api.anthropic.com", http.MethodPost, "/v1/oauth/token"},
		{"claude.ai", http.MethodPost, "/v1/oauth/token"},
		{"claude.ai", http.MethodGet, "/oauth/authorize"},
		// create_api_key on claude.ai and claude.com (X-01, round 4; D2).
		{"claude.ai", http.MethodPost, "/api/oauth/claude_cli/create_api_key"},
		{"claude.com", http.MethodPost, "/api/oauth/claude_cli/create_api_key"},
	}
	for _, tc := range cases {
		h := newCredentialMatchHarness(t, claudeHostsHCL, "claudehosts")
		events, cancelEvents := h.gateway.sink.Subscribe()
		before := mitmCredentialResolutions.Load()
		status, _, body := gatewaySend(t, h.gateway, tc.host, tc.method, tc.path, hdr, "{}")
		if status != http.StatusForbidden || !strings.Contains(body, "managed by clawpatrol") {
			t.Errorf("%s %s%s: status %d body %q, want the gate's 403", tc.method, tc.host, tc.path, status, body)
		}
		if got, _ := h.dialedAddr.Load().(string); got != "" {
			t.Errorf("%s %s%s: gateway dialed upstream %q; a gated path must never be forwarded", tc.method, tc.host, tc.path, got)
		}
		if n := mitmCredentialResolutions.Load() - before; n != 0 {
			t.Errorf("%s %s%s: %d credential resolution(s) ran for a gated path; the gate must answer first", tc.method, tc.host, tc.path, n)
		}
		gates := 0
		for _, ev := range collectEvents(events, 300*time.Millisecond) {
			// Pins only that the auth-gate event carries no credential; the
			// counter above pins the gate's place before resolution (R2-05).
			if ev.Credential != "" {
				t.Errorf("%s %s%s: event %q carries credential %q", tc.method, tc.host, tc.path, ev.Mode, ev.Credential)
			}
			switch ev.Mode {
			case "auth-gate":
				gates++
			case "mitm":
				t.Errorf("%s %s%s: a mitm event was emitted; the request went past the path gate", tc.method, tc.host, tc.path)
			}
		}
		if gates != 1 {
			t.Errorf("%s %s%s: %d auth-gate event(s), want exactly 1", tc.method, tc.host, tc.path, gates)
		}
		cancelEvents()
	}
}

// collectEvents drains events for d and returns what arrived.
func collectEvents(events <-chan eventPacket, d time.Duration) []Event {
	var out []Event
	timeout := time.After(d)
	for {
		select {
		case pkt, ok := <-events:
			if !ok {
				return out
			}
			out = append(out, pkt.ev)
		case <-timeout:
			return out
		}
	}
}

// Path parameters (";x") are not stripped: a path-blind upstream treats
// "/v1/oauth;x/token" as a different path (live: 404), so it is
// forwarded. Pinned so a change either way is deliberate (F106).
func TestAuthPathGateForwardsPathParameter(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_TOK", "real-secret-value-0123456789abcdef")
	h := newCredentialMatchHarness(t, claudeHostsHCL, "claudehosts")
	status, _, _ := gatewaySend(t, h.gateway, "platform.claude.com", http.MethodGet, "/v1/oauth;x/token", http.Header{"Authorization": {"Bearer placeholder"}}, "")
	if got, _ := h.dialedAddr.Load().(string); status != http.StatusOK || got == "" {
		t.Fatalf("GET /v1/oauth;x/token = %d (dialed %q); want it forwarded", status, got)
	}
}

// The gate is path-scoped: other paths on the same hosts, including the
// agent's own inference and docs, are still forwarded.
func TestAuthPathGateForwardsOtherPaths(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_TOK", "real-secret-value-0123456789abcdef")
	hdr := http.Header{"Authorization": {"Bearer placeholder"}}
	for _, tc := range []struct{ host, path string }{
		{"platform.claude.com", "/llms.txt"},
		{"platform.claude.com", "/docs/en/api/messages"},
		{"platform.claude.com", "/oauthx"},
		{"claude.com", "/docs/llms.txt"},
		{"api.anthropic.com", "/api/oauth/profile"},
		{"claude.ai", "/api/oauth/profile"}, // X-01: the create_api_key rows are exact
	} {
		h := newCredentialMatchHarness(t, claudeHostsHCL, "claudehosts")
		before := mitmCredentialResolutions.Load()
		status, _, body := gatewaySend(t, h.gateway, tc.host, http.MethodGet, tc.path, hdr, "")
		if status != http.StatusOK || body != "upstream-ok" {
			t.Errorf("GET %s%s: status %d body %q, want it forwarded", tc.host, tc.path, status, body)
		}
		if got, _ := h.dialedAddr.Load().(string); got == "" {
			t.Errorf("GET %s%s was not dialed", tc.host, tc.path)
		}
		if mitmCredentialResolutions.Load() == before {
			t.Errorf("GET %s%s: no credential resolution counted; the counter is not wired", tc.host, tc.path)
		}
	}
}

// TestAuthPathGatePassthroughSplices pins the documented D1 scope the
// user kept (R2-D1): under unknown_host = "passthrough", an unclaimed
// platform.claude.com is spliced to its upstream and never reaches the
// path gate. Path rules apply only to connections the gateway already
// inspects; operators claim the Claude login hosts to gate them (round-2
// F104).
func TestAuthPathGatePassthroughSplices(t *testing.T) {
	// The allow-all rule on https.unknown is valid only under "inspect"
	// (compile.go), so the passthrough policy disables it.
	hcl := strings.Replace(authGateHCL, `unknown_host = "inspect"`, `unknown_host = "passthrough"`, 1)
	hcl = strings.Replace(hcl, `verdict   = "allow"`, "verdict   = \"allow\"\n  disabled  = true", 1)
	h := newCredentialMatchHarness(t, hcl, "unknown")
	dialer := &recordingDialer{}
	resolver := &tableResolver{answers: [][]netip.Addr{addrs(t, "203.0.113.10")}}
	h.gateway.dialer, h.gateway.resolver = dialer, resolver
	serverConn, clientConn := net.Pipe()
	h.gateway.onboard.profileByIP[peerIP(serverConn)] = "default"
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.gateway.handle(serverConn, "", 443)
	}()
	_ = clientConn.SetDeadline(time.Now().Add(3 * time.Second))
	// The handshake fails: recordingDialer refuses the splice dial.
	_ = tls.Client(clientConn, &tls.Config{ServerName: "platform.claude.com", InsecureSkipVerify: true}).Handshake()
	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handle did not return")
	}
	// The splice path (g.splice -> dialRelayHost, main.go:1992, :2438)
	// resolves the host and may dial it; either proves the connection was
	// spliced rather than gated.
	if resolver.calls == 0 && len(dialer.asked) == 0 {
		t.Fatalf("platform.claude.com was neither resolved nor dialed by the splice path under passthrough; R2-D1 keeps path rules off spliced connections, so a change here needs a new user decision")
	}
	if got, _ := h.dialedAddr.Load().(string); got != "" {
		t.Fatalf("MITM transport dialed %q; a spliced connection never enters the MITM loop", got)
	}
}

// Claude Code's first-run connectivity check (preflight_endpoint) is a
// bare GET /v1/oauth/hello on the token host and needs a 200 (#18). The
// gate answers it locally, so nothing under the gated /v1/oauth/ tree is
// ever forwarded, while every other method and the token path stay 403.
func TestAuthPathGateAnswersClaudePreflightLocally(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_TOK", "real-secret-value-0123456789abcdef")
	cases := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/v1/oauth/hello", http.StatusOK},
		{http.MethodGet, "/V1/OAuth/hello", http.StatusOK},
		{http.MethodGet, "/v1/oauth/hello/", http.StatusOK},
		{http.MethodPost, "/v1/oauth/hello", http.StatusForbidden},
		{http.MethodGet, "/v1/oauth/hello/x", http.StatusForbidden},
		{http.MethodPost, "/v1/oauth/token", http.StatusForbidden},
	}
	for _, tc := range cases {
		h := newCredentialMatchHarness(t, claudeHostsHCL, "claudehosts")
		status, _, body := gatewaySend(t, h.gateway, "platform.claude.com", tc.method, tc.path, nil, "")
		if status != tc.want {
			t.Errorf("%s platform.claude.com%s: status %d body %q, want %d", tc.method, tc.path, status, body, tc.want)
		}
		if strings.Contains(body, "real-secret-value") {
			t.Errorf("%s %s: the answer carries the held secret", tc.method, tc.path)
		}
		if got, _ := h.dialedAddr.Load().(string); got != "" {
			t.Errorf("%s %s: gateway dialed upstream %q; the gated tree must never be forwarded", tc.method, tc.path, got)
		}
	}
}

// A request-target with no leading "/" (a "scheme:path" opaque form, or
// a bare relative path) leaves req.URL.Path empty, so every path-based
// gate would miss it while the upstream might still route it. The MITM
// loop refuses anything but a "/path" target before any gate runs, and
// never dials upstream for it. Absolute-form targets still work.
func TestMITMRefusesNonOriginTargets(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_TOK", "real-secret-value-0123456789abcdef")
	for _, target := range []string{
		"http:v1/oauth/token",
		"https:v1/oauth/token",
		"x:v1/oauth/token",
		"*",
		// Go's parser rejects a bare relative path and the loop closes
		// the connection; that is a refusal too.
		"v1/oauth/token",
	} {
		h := newCredentialMatchHarness(t, claudeHostsHCL, "claudehosts")
		tc, br, closeFn := gatewayConn(t, h.gateway, "platform.claude.com")
		raw := "POST " + target + " HTTP/1.1\r\nHost: platform.claude.com\r\nAuthorization: Bearer placeholder\r\nContent-Length: 2\r\n\r\n{}"
		if _, err := io.WriteString(tc, raw); err != nil {
			t.Fatal(err)
		}
		status := 0
		if resp, err := http.ReadResponse(br, nil); err == nil {
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			status = resp.StatusCode
		}
		closeFn()
		if status != http.StatusBadRequest && status != 0 {
			t.Errorf("%q: status %d, want 400 or a closed connection", target, status)
		}
		if got, _ := h.dialedAddr.Load().(string); got != "" {
			t.Errorf("%q: gateway dialed upstream %q; a non-origin target must never be forwarded", target, got)
		}
	}
	// Absolute-form is a normal path once parsed, and still forwards.
	h := newCredentialMatchHarness(t, claudeHostsHCL, "claudehosts")
	tc, br, closeFn := gatewayConn(t, h.gateway, "platform.claude.com")
	defer closeFn()
	if _, err := io.WriteString(tc, "GET https://platform.claude.com/llms.txt HTTP/1.1\r\nHost: platform.claude.com\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("absolute-form GET /llms.txt: status %d, want 200", resp.StatusCode)
	}
}

// A path rule's answer goes through the same header stripping as the
// host gate, and its stub (when declared) answers instead of the 403.
func TestAuthPathGateStubAndHeaderStrip(t *testing.T) {
	restore := agentprovider.Swap(append(agentprovider.All(), &agentprovider.Provider{
		ID: "pathtest", DisplayName: "Path Test", APIHosts: []string{"api.pathtest.test"},
		AuthPaths: []agentprovider.AuthPath{{
			Host: "api.pathtest.test", Path: "/login/", Match: agentprovider.PathPrefix,
			Respond: func(req *http.Request, _ agentprovider.PublicMaterial) *http.Response {
				r := plainResponse(req, http.StatusOK, "stubbed")
				r.Header.Set("Set-Cookie", "session=leak")
				return r
			},
		}},
	}))
	defer restore()
	h := newCredentialMatchHarness(t, authGateHCL, "unknown")
	status, hdr, body := gatewaySend(t, h.gateway, "api.pathtest.test", http.MethodGet, "/login/start", nil, "")
	if status != http.StatusOK || body != "stubbed" || hdr.Get("Set-Cookie") != "" {
		t.Fatalf("stub answer = %d %q %v; want 200 stubbed with Set-Cookie stripped", status, body, hdr)
	}
	if got, _ := h.dialedAddr.Load().(string); got != "" {
		t.Fatalf("dialed %q", got)
	}
}

// DEV-21: the path gate answers and closes, so a pipelined request, or
// the tail of a gated body past the 1 MiB drain, is never parsed as a
// next request and never forwarded (R2-04).
func TestAuthPathGateClosesConnection(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_TOK", "real-secret-value-0123456789abcdef")
	const smuggled = "GET /llms.txt HTTP/1.1\r\nHost: platform.claude.com\r\n\r\n"
	for _, tc := range []struct{ name, body, after string }{
		{"pipelined request", "{}", smuggled},
		{"body tail past the 1 MiB drain", strings.Repeat("x", 1<<20) + smuggled, ""},
	} {
		h := newCredentialMatchHarness(t, claudeHostsHCL, "claudehosts")
		conn, br, closeFn := gatewayConn(t, h.gateway, "platform.claude.com")
		raw := fmt.Sprintf("POST /v1/oauth/token HTTP/1.1\r\nHost: platform.claude.com\r\nAuthorization: Bearer placeholder\r\nContent-Length: %d\r\n\r\n", len(tc.body)) + tc.body + tc.after
		go func() { _, _ = io.WriteString(conn, raw) }() // may block on the unread tail; the close ends it
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("%s: read first answer: %v", tc.name, err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || !resp.Close {
			t.Errorf("%s: first answer %d close=%v, want 403 with Connection: close", tc.name, resp.StatusCode, resp.Close)
		}
		if resp2, err := http.ReadResponse(br, nil); err == nil {
			_ = resp2.Body.Close()
			t.Errorf("%s: a second answer arrived; the gated connection must be closed", tc.name)
		}
		if got, _ := h.dialedAddr.Load().(string); got != "" {
			t.Errorf("%s: dialed %q; nothing after a gated request may be forwarded", tc.name, got)
		}
		closeFn()
	}
}
