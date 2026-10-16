package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/plugins/credentials"
	"golang.org/x/oauth2"
)

// The gateway's OAuth bearer in these tests. Synthetic; assertions only
// report whether it appeared.
const oauthSecret = "sk-ant-oat01-REAL-OAUTH-0123456789abcdef"

const sessionTokenHCL = `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "https" "anthropic" { hosts = ["api.anthropic.com"] }

credential "anthropic_oauth_subscription" "claude" {
  endpoint = https.anthropic
%s}

rule "allow-all" {
  endpoint  = https.anthropic
  condition = "true"
  verdict   = "allow"
}

profile "default" { credentials = [anthropic_oauth_subscription.claude] }
`

// workerTokenFor is the worker token the fake upstream issues for a
// session. Its shape passes validSessionToken.
func workerTokenFor(session string) string { return realWorkerToken + "." + session }

type seenRequest struct {
	method, path, rawPath, auth, acceptEncoding string
}

// fakeRemoteControl is a fake api.anthropic.com for the remote-control
// flow. /bridge answers bridgeBody (default: a well-formed grant); a
// worker path answers 200 only for the session's real worker token;
// anything else answers 200.
type fakeRemoteControl struct {
	mu         sync.Mutex
	seen       []seenRequest
	bridgeBody func(session string) (status int, hdr http.Header, body string)
}

func (f *fakeRemoteControl) requests() []seenRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seenRequest(nil), f.seen...)
}

func (f *fakeRemoteControl) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	f.mu.Lock()
	f.seen = append(f.seen, seenRequest{r.Method, r.URL.Path, r.URL.RawPath, r.Header.Get("Authorization"), r.Header.Get("Accept-Encoding")})
	bridge := f.bridgeBody
	f.mu.Unlock()
	segs := strings.Split(strings.TrimPrefix(path.Clean(r.URL.Path), "/"), "/")
	switch {
	case len(segs) == 5 && segs[0] == "v1" && segs[1] == "code" && segs[2] == "sessions" && strings.EqualFold(segs[4], "bridge"):
		status, hdr, body := 200, http.Header{}, fmt.Sprintf(`{"api_base_url":"https://api.anthropic.com","worker_jwt":%q,"expires_in":3600,"worker_epoch":7}`, workerTokenFor(segs[3]))
		if bridge != nil {
			status, hdr, body = bridge(segs[3])
		}
		for k, vs := range hdr {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	case len(segs) >= 5 && segs[0] == "v1" && segs[1] == "code" && segs[2] == "sessions" && segs[4] == "worker":
		if r.Header.Get("Authorization") == "Bearer "+workerTokenFor(segs[3]) {
			_, _ = io.WriteString(w, "worker-ok")
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "bad worker token")
	default:
		_, _ = io.WriteString(w, "ok")
	}
}

type sessionTokenRig struct {
	h        *credentialMatchHarness
	upstream *fakeRemoteControl
}

func newSessionTokenRig(t *testing.T, credExtra string) *sessionTokenRig {
	t.Helper()
	t.Setenv("CLAWPATROL_SECRET_CLAUDE", oauthSecret)
	up := &fakeRemoteControl{}
	h := newCredentialMatchHarnessWith(t, fmt.Sprintf(sessionTokenHCL, credExtra), "anthropic", up)
	return &sessionTokenRig{h: h, upstream: up}
}

// addrConn gives a net.Pipe end a chosen remote address, so tests can
// act as distinct agent devices.
type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }

// agentConn opens one agent connection from ip with SNI api.anthropic.com.
func (r *sessionTokenRig) agentConn(t *testing.T, ip string) (*tls.Conn, *bufio.Reader, func()) {
	t.Helper()
	g := r.h.gateway
	serverConn, clientConn := net.Pipe()
	sc := addrConn{serverConn, &net.TCPAddr{IP: net.ParseIP(ip), Port: 41000}}
	g.onboard.mu.Lock()
	g.onboard.profileByIP[ip] = "default"
	g.onboard.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.handle(sc, "", 443)
	}()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	tc := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: "api.anthropic.com", NextProtos: []string{"http/1.1"}})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return tc, bufio.NewReader(tc), func() {
		_ = clientConn.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("handle did not return")
		}
	}
}

func (r *sessionTokenRig) send(t *testing.T, ip, method, p, bearer string) (int, http.Header, string) {
	t.Helper()
	tc, br, closeFn := r.agentConn(t, ip)
	defer closeFn()
	hdr := http.Header{}
	if bearer != "" {
		hdr.Set("Authorization", "Bearer "+bearer)
	}
	return gatewayRoundTrip(t, tc, br, "api.anthropic.com", method, p, hdr, "{}")
}

// bridge runs the issue step and returns the placeholder the agent got.
func (r *sessionTokenRig) bridge(t *testing.T, ip, session string) string {
	t.Helper()
	status, hdr, body := r.send(t, ip, http.MethodPost, "/v1/code/sessions/"+session+"/bridge", "sk-ant-oat01-clawpatrol-placeholder-do-not-use")
	if status != 200 {
		t.Fatalf("bridge %s: status %d body %q", session, status, body)
	}
	assertNoToken(t, "bridge response", body, hdr)
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("bridge body not JSON: %v", err)
	}
	ph, _ := m["worker_jwt"].(string)
	if !strings.HasPrefix(ph, sessionTokenPlaceholderPrefix) {
		t.Fatalf("worker_jwt is not a placeholder")
	}
	if m["api_base_url"] != "https://api.anthropic.com" || m["expires_in"] != float64(3600) || m["worker_epoch"] != float64(7) {
		t.Fatalf("other bridge fields changed: %v", m)
	}
	return ph
}

func assertNoToken(t *testing.T, what, body string, hdr http.Header) {
	t.Helper()
	all := body
	for k, vs := range hdr {
		all += "\n" + k + ": " + strings.Join(vs, ",")
	}
	if strings.Contains(all, realWorkerToken) {
		t.Fatalf("%s: the agent received a real worker token", what)
	}
	if strings.Contains(all, oauthSecret) {
		t.Fatalf("%s: the agent received the gateway's OAuth secret", what)
	}
}

// lastSeen returns the last upstream request for a path.
func (r *sessionTokenRig) lastSeen(t *testing.T, p string) seenRequest {
	t.Helper()
	reqs := r.upstream.requests()
	for i := len(reqs) - 1; i >= 0; i-- {
		if reqs[i].path == p {
			return reqs[i]
		}
	}
	t.Fatalf("upstream never saw %s", p)
	return seenRequest{}
}

const agentA, agentB = "10.55.0.2", "10.55.0.3"

// --- opt-in --------------------------------------------------------------

func TestRemoteControlCredentialAttribute(t *testing.T) {
	for _, tc := range []struct {
		extra string
		want  bool
	}{
		{"", false},
		{"  remote_control = false\n", false},
		{"  remote_control = true\n", true},
	} {
		gw, diags := config.LoadBytes([]byte(fmt.Sprintf(sessionTokenHCL, tc.extra)), "t.hcl")
		if diags.HasErrors() {
			t.Fatalf("%q: %v", tc.extra, diags)
		}
		check := func(gw *config.Gateway, when string) {
			t.Helper()
			var body *credentials.AnthropicOAuthSubscription
			for _, c := range gw.Policy.Credentials {
				if b, ok := c.Body.(*credentials.AnthropicOAuthSubscription); ok {
					body = b
				}
			}
			if body == nil {
				t.Fatalf("%s: no anthropic credential", when)
			}
			if body.RemoteControl != tc.want || body.SessionTokensEnabled() != tc.want {
				t.Fatalf("%s %q: remote_control = %v, want %v", when, tc.extra, body.RemoteControl, tc.want)
			}
		}
		check(gw, "load")
		out, err := config.Emit(gw)
		if err != nil {
			t.Fatal(err)
		}
		gw2, diags := config.LoadBytes(out, "emitted.hcl")
		if diags.HasErrors() {
			t.Fatalf("reload: %v", diags)
		}
		check(gw2, "emit round-trip")
	}
}

// Off (the default): the gateway answers the issue path itself with
// 403, in every spelling an upstream could route there, so no worker
// token is ever minted with the gateway's credential.
func TestSessionTokenOffRefusesIssue(t *testing.T) {
	for _, extra := range []string{"", "  remote_control = false\n"} {
		r := newSessionTokenRig(t, extra)
		for _, p := range []string{
			"/v1/code/sessions/cse_1/bridge",
			"/v1/code/sessions/cse_1/bridge/",
			"//v1/code/sessions/cse_1/bridge",
			"/v1/code/sessions/cse_1/./bridge",
			"/V1/Code/Sessions/cse_1/Bridge",
			"/v1/code/sessions/cse_1/%62ridge",
			"/v1/code/sessions/cse_1/bridge;x=1",
			"/v1/code/sessions/a.b/bridge",
			"/v1/code/sessions/cse_1/bridge?x=1",
		} {
			for _, m := range []string{http.MethodPost, http.MethodGet, http.MethodPut} {
				status, hdr, body := r.send(t, agentA, m, p, "sk-ant-oat01-clawpatrol-placeholder-do-not-use")
				if status != http.StatusForbidden || !strings.Contains(body, "remote_control") {
					t.Errorf("off %q %s %s: status %d body %q, want the gateway's 403", extra, m, p, status, body)
				}
				assertNoToken(t, "off issue", body, hdr)
			}
		}
		for _, s := range r.upstream.requests() {
			if strings.Contains(strings.ToLower(s.path), "bridge") {
				t.Errorf("off: upstream saw %s %s; the issue path must never be forwarded", s.method, s.path)
			}
		}
	}
}

// Off: worker paths get today's OAuth injection, whatever bearer the
// agent sends, so a worker token the agent obtained elsewhere is useless
// through the gateway.
func TestSessionTokenOffWorkerGetsOAuth(t *testing.T) {
	r := newSessionTokenRig(t, "")
	for _, bearer := range []string{workerTokenFor("cse_1"), sessionTokenPlaceholderPrefix + strings.Repeat("a", 32), "anything"} {
		status, _, _ := r.send(t, agentA, http.MethodGet, "/v1/code/sessions/cse_1/worker", bearer)
		if status != http.StatusForbidden {
			t.Errorf("off, bearer %.12q…: status %d, want upstream's 403", bearer, status)
		}
		if got := r.lastSeen(t, "/v1/code/sessions/cse_1/worker").auth; got != "Bearer "+oauthSecret {
			t.Errorf("off: upstream got a non-OAuth bearer on a worker path")
		}
	}
}

// --- on --------------------------------------------------------------------

func TestSessionTokenOnSwapsAndInjects(t *testing.T) {
	r := newSessionTokenRig(t, "  remote_control = true\n")
	events, cancel := r.h.gateway.sink.Subscribe()
	defer cancel()

	ph := r.bridge(t, agentA, "cse_1")
	seen := r.lastSeen(t, "/v1/code/sessions/cse_1/bridge")
	if seen.auth != "Bearer "+oauthSecret {
		t.Fatal("bridge did not reach upstream with the gateway's OAuth bearer")
	}
	if seen.acceptEncoding != "identity" {
		t.Fatalf("bridge Accept-Encoding = %q, want identity", seen.acceptEncoding)
	}

	for _, c := range []struct{ method, p string }{
		{http.MethodGet, "/v1/code/sessions/cse_1/worker"},
		{http.MethodPut, "/v1/code/sessions/cse_1/worker"},
		{http.MethodPost, "/v1/code/sessions/cse_1/worker/events"},
		{http.MethodPost, "/v1/code/sessions/cse_1/worker/heartbeat"},
		{http.MethodPost, "/v1/code/sessions/cse_1/worker/events/delivery"},
	} {
		status, hdr, body := r.send(t, agentA, c.method, c.p, ph)
		if status != 200 || body != "worker-ok" {
			t.Errorf("%s %s with the placeholder: status %d body %q, want worker-ok", c.method, c.p, status, body)
		}
		assertNoToken(t, c.p, body, hdr)
		if got := r.lastSeen(t, c.p).auth; got != "Bearer "+workerTokenFor("cse_1") {
			t.Errorf("%s: upstream did not get the real worker token", c.p)
		}
	}
	// Other session paths keep OAuth injection.
	r.send(t, agentA, http.MethodPost, "/v1/code/sessions/cse_1/client/presence", ph)
	if got := r.lastSeen(t, "/v1/code/sessions/cse_1/client/presence").auth; got != "Bearer "+oauthSecret {
		t.Error("presence did not get OAuth injection")
	}

	// Nothing stored for the dashboard holds the real worker token.
	for _, ev := range collectEvents(events, 300*time.Millisecond) {
		b, _ := json.Marshal(ev)
		if strings.Contains(string(b), realWorkerToken) {
			t.Fatalf("stored event %s %s holds the real worker token", ev.Method, ev.Path)
		}
		if strings.Contains(string(b), oauthSecret) {
			t.Fatalf("stored event %s %s holds the OAuth secret", ev.Method, ev.Path)
		}
	}
}

// A placeholder resolves only for the session, device, path family and
// lifetime it was issued for. Every miss gets OAuth injection, so the
// upstream refuses it and the real worker token never leaves.
func TestSessionTokenOnScoping(t *testing.T) {
	r := newSessionTokenRig(t, "  remote_control = true\n")
	ph := r.bridge(t, agentA, "cse_1")
	r.bridge(t, agentA, "cse_2")

	misses := []struct {
		name, ip, method, p, bearer string
	}{
		{"other session", agentA, http.MethodGet, "/v1/code/sessions/cse_2/worker", ph},
		{"other device", agentB, http.MethodGet, "/v1/code/sessions/cse_1/worker", ph},
		{"forged placeholder", agentA, http.MethodGet, "/v1/code/sessions/cse_1/worker", sessionTokenPlaceholderPrefix + strings.Repeat("0", 32)},
		{"agent sends the real token", agentA, http.MethodGet, "/v1/code/sessions/cse_1/worker", workerTokenFor("cse_1")},
		{"lowercase scheme", agentA, http.MethodGet, "/v1/code/sessions/cse_1/worker", ""},
		{"trailing slash", agentA, http.MethodGet, "/v1/code/sessions/cse_1/worker/", ph},
		{"dot segment", agentA, http.MethodGet, "/v1/code/sessions/cse_1/x/../worker", ph},
		{"escaped path", agentA, http.MethodGet, "/v1/code/sessions/cse_1/%77orker", ph},
		{"case", agentA, http.MethodGet, "/v1/code/sessions/cse_1/Worker", ph},
		{"escape to another path", agentA, http.MethodGet, "/v1/code/sessions/cse_1/worker/../../../../api/oauth/profile", ph},
		{"non-worker path", agentA, http.MethodGet, "/api/oauth/profile", ph},
		{"messages", agentA, http.MethodPost, "/v1/messages", ph},
	}
	for _, m := range misses {
		tc, br, closeFn := r.agentConn(t, m.ip)
		hdr := http.Header{}
		switch {
		case m.name == "lowercase scheme":
			hdr.Set("Authorization", "bearer "+ph)
		case m.bearer != "":
			hdr.Set("Authorization", "Bearer "+m.bearer)
		}
		_, rh, body := gatewayRoundTrip(t, tc, br, "api.anthropic.com", m.method, m.p, hdr, "{}")
		closeFn()
		assertNoToken(t, m.name, body, rh)
		reqs := r.upstream.requests()
		last := reqs[len(reqs)-1]
		if strings.Contains(last.auth, realWorkerToken) {
			t.Errorf("%s: upstream got a real worker token", m.name)
		}
	}
	// Two Authorization headers are ambiguous: no put-back.
	{
		tc, br, closeFn := r.agentConn(t, agentA)
		hdr := http.Header{"Authorization": {"Bearer " + ph, "Bearer other"}}
		_, rh, body := gatewayRoundTrip(t, tc, br, "api.anthropic.com", http.MethodGet, "/v1/code/sessions/cse_1/worker", hdr, "{}")
		closeFn()
		assertNoToken(t, "two auth headers", body, rh)
		if got := r.lastSeen(t, "/v1/code/sessions/cse_1/worker").auth; got != "Bearer "+oauthSecret {
			t.Error("two Authorization headers: upstream did not get plain OAuth injection")
		}
	}
	// The placeholder still works where it belongs.
	if status, _, body := r.send(t, agentA, http.MethodGet, "/v1/code/sessions/cse_1/worker", ph); status != 200 || body != "worker-ok" {
		t.Fatalf("scoped use failed: %d %q", status, body)
	}
}

func TestSessionTokenOnExpiry(t *testing.T) {
	r := newSessionTokenRig(t, "  remote_control = true\n")
	now := time.Now()
	store := r.h.gateway.sessionTokenStore()
	store.mu.Lock()
	store.now = func() time.Time { return now }
	store.mu.Unlock()
	ph := r.bridge(t, agentA, "cse_1")
	store.mu.Lock()
	now = now.Add(3601 * time.Second)
	store.mu.Unlock()
	status, _, _ := r.send(t, agentA, http.MethodGet, "/v1/code/sessions/cse_1/worker", ph)
	if status != http.StatusForbidden || r.lastSeen(t, "/v1/code/sessions/cse_1/worker").auth != "Bearer "+oauthSecret {
		t.Fatalf("expired placeholder: status %d; want OAuth injection and upstream's 403", status)
	}
}

// On: any issue response the gateway can't rewrite safely is answered
// with 502 and never forwarded; the agent gets no token.
func TestSessionTokenOnIssueFailsClosed(t *testing.T) {
	tok := func(s string) string { return workerTokenFor(s) }
	cases := []struct {
		name   string
		bridge func(s string) (int, http.Header, string)
	}{
		{"gzip", func(s string) (int, http.Header, string) {
			return 200, http.Header{"Content-Encoding": {"gzip"}}, `{"worker_jwt":"` + tok(s) + `","expires_in":60}`
		}},
		{"not json", func(s string) (int, http.Header, string) { return 200, nil, "worker_jwt=" + tok(s) }},
		{"duplicate key", func(s string) (int, http.Header, string) {
			return 200, nil, `{"worker_jwt":"` + tok(s) + `","worker_jwt":"` + tok(s) + `x","expires_in":60}`
		}},
		{"no ttl", func(s string) (int, http.Header, string) { return 200, nil, `{"worker_jwt":"` + tok(s) + `"}` }},
		{"header echo", func(s string) (int, http.Header, string) {
			return 200, http.Header{"X-Echo": {tok(s)}}, `{"worker_jwt":"` + tok(s) + `","expires_in":60}`
		}},
		{"error naming the field", func(s string) (int, http.Header, string) {
			return 401, nil, `{"error":{"worker_jwt":"` + tok(s) + `"}}`
		}},
		{"oversized", func(s string) (int, http.Header, string) {
			return 200, nil, `{"worker_jwt":"` + tok(s) + `","expires_in":60,"pad":"` + strings.Repeat("x", sessionTokenMaxBody) + `"}`
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newSessionTokenRig(t, "  remote_control = true\n")
			r.upstream.bridgeBody = c.bridge
			status, hdr, body := r.send(t, agentA, http.MethodPost, "/v1/code/sessions/cse_1/bridge", "sk-ant-oat01-clawpatrol-placeholder-do-not-use")
			if status != http.StatusBadGateway {
				t.Fatalf("status %d, want 502", status)
			}
			assertNoToken(t, c.name, body, hdr)
			if n := r.h.gateway.sessionTokenStore().size(); n != 0 {
				t.Fatalf("%d placeholder(s) issued for a refused response", n)
			}
		})
	}
}

// On: an issue response with no token (an error, a conflict) passes
// through unchanged.
func TestSessionTokenOnIssuePassesThroughErrors(t *testing.T) {
	r := newSessionTokenRig(t, "  remote_control = true\n")
	r.upstream.bridgeBody = func(string) (int, http.Header, string) {
		return 409, nil, `{"error":{"type":"conflict","expected_epoch":3,"actual_epoch":4}}`
	}
	status, _, body := r.send(t, agentA, http.MethodPost, "/v1/code/sessions/cse_1/bridge", "x")
	if status != 409 || !jsonEqual(t, body, `{"error":{"type":"conflict","expected_epoch":3,"actual_epoch":4}}`) {
		t.Fatalf("conflict: %d %q", status, body)
	}
}

// On, but the issue request names no plain session id: refused, since
// a placeholder could not be bound to a session.
func TestSessionTokenOnIssueWithoutSessionID(t *testing.T) {
	r := newSessionTokenRig(t, "  remote_control = true\n")
	for _, p := range []string{"/v1/code/sessions/a.b/bridge", "/v1/code/sessions/a%2Fb/bridge"} {
		status, hdr, body := r.send(t, agentA, http.MethodPost, p, "x")
		if status != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", p, status)
		}
		assertNoToken(t, p, body, hdr)
	}
	for _, s := range r.upstream.requests() {
		if strings.Contains(strings.ToLower(s.path), "bridge") {
			t.Errorf("upstream saw %s", s.path)
		}
	}
}

// A WebSocket upgrade on the issue path can't be rewritten: refused.
func TestSessionTokenIssueRefusesWebSocket(t *testing.T) {
	r := newSessionTokenRig(t, "  remote_control = true\n")
	tc, br, closeFn := r.agentConn(t, agentA)
	defer closeFn()
	hdr := http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Sec-Websocket-Version": {"13"}, "Sec-Websocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="}}
	status, _, _ := gatewayRoundTrip(t, tc, br, "api.anthropic.com", http.MethodGet, "/v1/code/sessions/cse_1/bridge", hdr, "")
	if status != http.StatusForbidden {
		t.Fatalf("ws upgrade on the issue path: status %d, want 403", status)
	}
}

// Review #25 I1/I2 end to end: on, any /bridge 200 whose token appears
// anywhere but the one top-level field, in any spelling, is refused.
func TestSessionTokenOnIssueRefusesTokenElsewhere(t *testing.T) {
	bodies := map[string]func(s string) string{
		"unicode-escaped echo": func(s string) string {
			tok := workerTokenFor(s)
			return fmt.Sprintf(`{"api_base_url":"https://api.anthropic.com","worker_jwt":%q,"expires_in":3600,"worker_epoch":7,"mcp_config":{"debug":"\u00%x%s"}}`, tok, tok[0], tok[1:])
		},
		"camel": func(s string) string { return fmt.Sprintf(`{"workerJwt":%q,"expires_in":3600}`, workerTokenFor(s)) },
		"upper": func(s string) string { return fmt.Sprintf(`{"WORKER_JWT":%q,"expires_in":3600}`, workerTokenFor(s)) },
		"nested": func(s string) string {
			return fmt.Sprintf(`{"worker":{"jwt":%q},"expires_in":3600}`, workerTokenFor(s))
		},
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			r := newSessionTokenRig(t, "  remote_control = true\n")
			r.upstream.bridgeBody = func(s string) (int, http.Header, string) { return 200, nil, body(s) }
			status, hdr, got := r.send(t, agentA, http.MethodPost, "/v1/code/sessions/abc/bridge", "sk-ant-oat01-clawpatrol-placeholder-do-not-use")
			if status != http.StatusBadGateway {
				t.Errorf("status %d, want 502", status)
			}
			assertNoToken(t, name, got, hdr)
			var m any
			if json.Unmarshal([]byte(got), &m) == nil && strings.Contains(fmt.Sprint(m), realWorkerToken) {
				t.Errorf("the agent decodes a real worker token")
			}
		})
	}
}

// Review #25 round 2 (N4): an OAuth refresh changes the access token
// but not who the credential is; live remote-control sessions survive.
func TestSessionTokenSurvivesTokenRefresh(t *testing.T) {
	r := newSessionTokenRig(t, "  remote_control = true\n")
	ph := r.bridge(t, agentA, "cse_1")
	t.Setenv("CLAWPATROL_SECRET_CLAUDE", oauthSecret+"-refreshed")
	if status, _, body := r.send(t, agentA, http.MethodGet, "/v1/code/sessions/cse_1/worker", ph); status != 200 || body != "worker-ok" {
		t.Fatalf("after a refresh: %d %q, want worker-ok", status, body)
	}
}

// Reconnecting or clearing the credential retires its placeholders.
func TestSessionTokenDroppedOnCredentialChange(t *testing.T) {
	r := newSessionTokenRig(t, "  remote_control = true\n")
	ph := r.bridge(t, agentA, "cse_1")
	r.h.gateway.sessionTokenStore().dropCredential("other")
	if status, _, _ := r.send(t, agentA, http.MethodGet, "/v1/code/sessions/cse_1/worker", ph); status != 200 {
		t.Fatalf("dropping another credential retired this one: %d", status)
	}
	r.h.gateway.sessionTokenStore().dropCredential("claude")
	status, _, _ := r.send(t, agentA, http.MethodGet, "/v1/code/sessions/cse_1/worker", ph)
	if status != http.StatusForbidden || strings.Contains(r.lastSeen(t, "/v1/code/sessions/cse_1/worker").auth, realWorkerToken) {
		t.Fatalf("after a credential change: %d; the old token must not be put back", status)
	}
}

// A reload keeps placeholders of credentials still opted in and drops
// the rest, so turning remote_control off and on can't revive them.
func TestSessionTokenReloadPrunesOptedOut(t *testing.T) {
	r := newSessionTokenRig(t, "  remote_control = true\n")
	ph := r.bridge(t, agentA, "cse_1")
	load := func(extra string) *config.CompiledPolicy {
		gw, diags := config.LoadBytes([]byte(fmt.Sprintf(sessionTokenHCL, extra)), "t.hcl")
		if diags.HasErrors() {
			t.Fatal(diags)
		}
		p, err := config.Compile(gw)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	r.h.gateway.pruneSessionTokens(load("  remote_control = true\n"))
	if n := r.h.gateway.sessionTokenStore().size(); n != 1 {
		t.Fatalf("reload with remote_control still on dropped placeholders (%d left)", n)
	}
	if status, _, _ := r.send(t, agentA, http.MethodGet, "/v1/code/sessions/cse_1/worker", ph); status != 200 {
		t.Fatalf("placeholder broke across an unrelated reload: %d", status)
	}
	r.h.gateway.pruneSessionTokens(load(""))
	if n := r.h.gateway.sessionTokenStore().size(); n != 0 {
		t.Fatalf("reload with remote_control off kept %d placeholder(s)", n)
	}
}

// The OAuth registry reports connects, reconnects and revokes, which is
// what retires placeholders (wired in the gateway at startup).
func TestOAuthRegistryReportsCredentialChanges(t *testing.T) {
	reg, err := NewOAuthRegistry(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	reg.Register("claude", OAuthIntegration{OAuth: config.OAuthConfig{ClientID: "c", TokenURL: "https://example.invalid/token"}})
	var got []string
	reg.onCredentialChange = func(id string) {
		got = append(got, id)
		// The hook must run after the change is stored, so nothing
		// issued in between can outlive it (commit review: ordering).
		if tok, _ := reg.Token(id); len(got) == 1 && tok != "a" {
			t.Errorf("connect hook ran before the new token was stored")
		}
		if len(got) == 2 && reg.Status(id).Connected {
			t.Errorf("revoke hook ran before the credential was removed")
		}
	}
	if err := reg.Set(context.Background(), "claude", &oauth2.Token{AccessToken: "a", RefreshToken: "r", Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	reg.Revoke("claude")
	if strings.Join(got, ",") != "claude,claude" {
		t.Fatalf("changes reported: %v, want claude twice (set, revoke)", got)
	}
}

// Review #25 C1: an opaque request-target names no path for any gate to
// read; it is refused before forwarding, whatever remote_control is.
func TestSessionTokenOpaqueTargetRefused(t *testing.T) {
	for _, extra := range []string{"", "  remote_control = true\n"} {
		for _, target := range []string{"http:v1/code/sessions/abc/bridge", "https:v1/code/sessions/abc/bridge", "x:v1/code/sessions/abc/worker"} {
			r := newSessionTokenRig(t, extra)
			tc, br, closeFn := r.agentConn(t, agentA)
			raw := "POST " + target + " HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer sk-ant-oat01-clawpatrol-placeholder-do-not-use\r\nContent-Length: 2\r\n\r\n{}"
			if _, err := io.WriteString(tc, raw); err != nil {
				t.Fatal(err)
			}
			status := 0
			if resp, err := http.ReadResponse(br, nil); err == nil {
				b, _ := io.ReadAll(resp.Body)
				assertNoToken(t, target, string(b), resp.Header)
				status = resp.StatusCode
			}
			closeFn()
			if status != http.StatusBadRequest && status != http.StatusForbidden {
				t.Errorf("%q %q: status %d, want a refusal", extra, target, status)
			}
			if got, _ := r.h.dialedAddr.Load().(string); got != "" {
				t.Errorf("%q %q: gateway dialed upstream", extra, target)
			}
		}
	}
}

// The real reload path prunes: a config written with remote_control off
// retires the placeholders; one still on keeps them.
func TestSessionTokenReloadFromFilePrunes(t *testing.T) {
	r := newSessionTokenRig(t, "  remote_control = true\n")
	r.bridge(t, agentA, "cse_1")
	path := filepath.Join(t.TempDir(), "gateway.hcl")
	write := func(extra string) {
		if err := os.WriteFile(path, []byte(fmt.Sprintf(sessionTokenHCL, extra)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("  remote_control = true\n")
	if err := r.h.gateway.reloadConfigFromFileLocked(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if n := r.h.gateway.sessionTokenStore().size(); n != 1 {
		t.Fatalf("reload with remote_control on left %d placeholder(s), want 1", n)
	}
	write("")
	if err := r.h.gateway.reloadConfigFromFileLocked(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if n := r.h.gateway.sessionTokenStore().size(); n != 0 {
		t.Fatalf("reload with remote_control off left %d placeholder(s)", n)
	}
}

// The startup wiring: a connect or revoke in the OAuth registry retires
// that credential's placeholders.
func TestWireSessionTokenHooks(t *testing.T) {
	g := &Gateway{}
	reg, err := NewOAuthRegistry(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	reg.Register("claude", OAuthIntegration{OAuth: config.OAuthConfig{ClientID: "c", TokenURL: "https://example.invalid/token"}})
	g.wireSessionTokenHooks(reg)
	own := sessionTokenOwner{agent: agentA, profile: "default", credential: "claude", host: "api.anthropic.com"}
	issue := func() {
		if _, err := g.sessionTokenStore().issue(own, "cse_1", realWorkerToken, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	issue()
	if err := reg.Set(context.Background(), "claude", &oauth2.Token{AccessToken: "a", RefreshToken: "r", Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if n := g.sessionTokenStore().size(); n != 0 {
		t.Fatalf("connect left %d placeholder(s)", n)
	}
	issue()
	reg.Revoke("claude")
	if n := g.sessionTokenStore().size(); n != 0 {
		t.Fatalf("revoke left %d placeholder(s)", n)
	}
}

// Review #25 round 3: a credential change while /bridge is in flight
// wins; the late response is refused and nothing is issued.
func TestSessionTokenCredentialChangeDuringIssue(t *testing.T) {
	r := newSessionTokenRig(t, "  remote_control = true\n")
	r.upstream.bridgeBody = func(s string) (int, http.Header, string) {
		r.h.gateway.sessionTokenStore().dropCredential("claude")
		return 200, nil, fmt.Sprintf(`{"worker_jwt":%q,"expires_in":3600,"api_base_url":"https://api.anthropic.com","worker_epoch":7}`, workerTokenFor(s))
	}
	status, hdr, body := r.send(t, agentA, http.MethodPost, "/v1/code/sessions/cse_1/bridge", "x")
	if status != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", status)
	}
	assertNoToken(t, "in-flight change", body, hdr)
	if n := r.h.gateway.sessionTokenStore().size(); n != 0 {
		t.Fatalf("%d placeholder(s) issued after the credential changed", n)
	}
}

// Review #25 R4-1 end to end: a huge crafted header on /bridge is
// refused fast instead of burning CPU in the token scan.
func TestSessionTokenIssueHugeHeaderRefusedFast(t *testing.T) {
	r := newSessionTokenRig(t, "  remote_control = true\n")
	big := alnum(1 << 20)
	for range 3 {
		big = base64.StdEncoding.EncodeToString([]byte(big))[:1<<20]
	}
	r.upstream.bridgeBody = func(s string) (int, http.Header, string) {
		return 200, http.Header{"X-Big": {big}}, fmt.Sprintf(`{"worker_jwt":%q,"expires_in":3600}`, workerTokenFor(s))
	}
	start := time.Now()
	status, hdr, body := r.send(t, agentA, http.MethodPost, "/v1/code/sessions/cse_1/bridge", "x")
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("took %v", d)
	}
	if status != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", status)
	}
	assertNoToken(t, "huge header", body, hdr)
}

// Review #25 R4-m3: the epoch is taken when the request arrives, so a
// credential change any time after that (a HITL wait included) refuses
// the issue.
func TestSessionTokenChangeAfterArrivalRefused(t *testing.T) {
	r := newSessionTokenRig(t, "  remote_control = true\n")
	sessionTokenAfterReadHook = func() { r.h.gateway.sessionTokenStore().dropCredential("claude") }
	t.Cleanup(func() { sessionTokenAfterReadHook = nil })
	status, hdr, body := r.send(t, agentA, http.MethodPost, "/v1/code/sessions/cse_1/bridge", "x")
	if status != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", status)
	}
	assertNoToken(t, "change after arrival", body, hdr)
	if n := r.h.gateway.sessionTokenStore().size(); n != 0 {
		t.Fatalf("%d placeholder(s) issued", n)
	}
}
