package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
)

// ADAPTER: Task 6 rewires this to the registry.
func lockAgentType(host string) string { return detectAgentTypeFromHost(host) }

// ADAPTER: Task 5 rewires this to llmRouteFor.
func lockTrack(g *Gateway, host, path string, req, resp []byte, hint string) {
	g.trackLLMUsage(nil, trackKindFor(host), host, path, req, resp, hint, time.Time{})
}

// ADAPTER: Task 6 rewires needsBrowserTLS internally; the call stays.
func lockBrowserTLS(host string) bool { return needsBrowserTLS(host) }

// ADAPTER: Task 5 rewires this to sessionHintFor(host, h).
func lockSessionHint(_ string, h http.Header) string {
	v := h.Get("Session_id")
	if v == "" {
		v = h.Get("Session-Id")
	}
	return v
}

// ADAPTER: Task 5 rewires this to wsTurnRoute (ws.go).
func lockWSObserves(host, _ string) bool { return trackKindFor(host) == "codex_ws_usage" }

func TestLockAgentTypeFromHost(t *testing.T) {
	cases := map[string]string{
		"api.anthropic.com":          "claude",
		"statsig.anthropic.com":      "claude",
		"anthropic.com":              "claude",
		"claude.ai":                  "claude",
		"www.claude.ai":              "claude",
		"claude.com":                 "claude",
		"chatgpt.com":                "codex",
		"backend-api.chatgpt.com":    "codex",
		"files.oaiusercontent.com":   "codex",
		"cdn.openai.com":             "codex",
		"openai.com":                 "codex",
		"api.openai.com":             "codex",  // CHANGES IN TASK 6 → "openai-sdk"
		"auth.openai.com":            "codex",  // CHANGES IN TASK 6 → "" (auth host; gated in Task 9)
		"console.anthropic.com":      "claude", // CHANGES IN TASK 6 → "" (auth host; gated in Task 9)
		"evilanthropic.com":          "claude", // CHANGES IN TASK 6 → "" (bare-suffix lookalike)
		"evilchatgpt.com":            "codex",  // CHANGES IN TASK 6 → "" (bare-suffix lookalike)
		"example.com":                "",
		"anthropic.com.evil.example": "",
	}
	for host, want := range cases {
		if got := lockAgentType(host); got != want {
			t.Errorf("agent type for %q = %q, want %q", host, got, want)
		}
	}
}

func lockGateway(t *testing.T) *Gateway {
	t.Helper()
	gw, diags := config.LoadBytes([]byte(`
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
`), "lock.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	g := &Gateway{}
	g.cfg.Store(gw)
	g.agents = NewAgentRegistry()
	// trackLLMUsage(nil conn) resolves agent IP "" — seed that agent.
	g.agents.agents[""] = &Agent{}
	return g
}

type lockSession struct {
	typ, id, model string
	in, out        int64
}

func onlySession(t *testing.T, g *Gateway) *lockSession {
	t.Helper()
	return onlySessionAt(t, g, "")
}

// onlySessionAt reads the one session recorded for agent key ip.
func onlySessionAt(t *testing.T, g *Gateway, ip string) *lockSession {
	t.Helper()
	ss := g.agents.agents[ip].Sessions
	if len(ss) == 0 {
		return nil
	}
	if len(ss) != 1 {
		t.Fatalf("got %d sessions, want 1", len(ss))
	}
	s := ss[0]
	return &lockSession{typ: s.Type, id: s.ID, model: s.Model, in: s.TokensIn, out: s.TokensOut}
}

func TestLockLLMUsageRouting(t *testing.T) {
	cases := []struct {
		name, host, path, hint string
		req, resp              string
		want                   *lockSession // nil = no session recorded
	}{
		{
			name: "claude messages", host: "api.anthropic.com", path: "/v1/messages",
			req:  `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hello claude"}]}`,
			resp: `{"model":"claude-sonnet-4","usage":{"input_tokens":3,"output_tokens":5}}`,
			want: &lockSession{typ: "claude", model: "claude-sonnet-4", in: 3, out: 5},
		},
		{
			name: "claude non-model path", host: "api.anthropic.com", path: "/v1/messages/count_tokens",
			req: `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"x"}]}`, resp: `{}`,
		},
		{
			// Claude Code packs its session id in metadata.user_id, and the
			// session model is the request's, not the response's dated echo.
			name: "claude metadata session id", host: "api.anthropic.com", path: "/v1/messages",
			req:  `{"model":"claude-sonnet-4","metadata":{"user_id":"{\"device_id\":\"d1\",\"session_id\":\"sess-claude-1\"}"},"messages":[{"role":"user","content":"hello claude"}]}`,
			resp: `{"model":"claude-sonnet-4-20250514","usage":{"input_tokens":3,"output_tokens":5}}`,
			want: &lockSession{typ: "claude", id: "s_" + shortHash("sess-claude-1"), model: "claude-sonnet-4", in: 3, out: 5},
		},
		{
			name: "claude hint without metadata", host: "api.anthropic.com", path: "/v1/messages", hint: "h-claude",
			req:  `{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hello claude"}]}`,
			resp: `{"model":"claude-sonnet-4","usage":{"input_tokens":3,"output_tokens":5}}`,
			want: &lockSession{typ: "claude", id: shortHash("hello claude"), model: "claude-sonnet-4", in: 3, out: 5}, // CHANGES IN TASK 5 → id shortHash("h-claude")
		},
		{
			name: "openai chat", host: "api.openai.com", path: "/v1/chat/completions",
			req:  `{"model":"gpt-5","messages":[{"role":"user","content":"hello openai"}]}`,
			resp: `{"model":"gpt-5","usage":{"prompt_tokens":2,"completion_tokens":4}}`,
			want: &lockSession{typ: "codex", model: "gpt-5", in: 2, out: 4}, // CHANGES IN TASK 5 → typ "openai-sdk"
		},
		{
			name: "openai chat with hint", host: "api.openai.com", path: "/v1/chat/completions", hint: "h-openai",
			req:  `{"model":"gpt-5","messages":[{"role":"user","content":"hello openai"}]}`,
			resp: `{"model":"gpt-5","usage":{"prompt_tokens":2,"completion_tokens":4}}`,
			want: &lockSession{typ: "codex", id: shortHash("hello openai"), model: "gpt-5", in: 2, out: 4}, // CHANGES IN TASK 5 → typ "openai-sdk", id shortHash("h-openai")
		},
		{
			name: "codex responses", host: "chatgpt.com", path: "/backend-api/codex/responses", hint: "sess-1",
			req: `{"model":"gpt-5-codex","input":[{"role":"user","content":[{"type":"input_text","text":"hello codex"}]}]}`,
			resp: "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n" +
				"data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-5-codex\",\"usage\":{\"input_tokens\":7,\"output_tokens\":9}}}\n\n",
			want: &lockSession{typ: "codex", id: shortHash("sess-1"), model: "gpt-5-codex", in: 7, out: 9},
		},
		{
			// No Session_id: the session keys on the FIRST user message, so
			// it stays stable as the conversation grows.
			name: "codex responses first-title fallback", host: "chatgpt.com", path: "/backend-api/codex/responses",
			req: `{"model":"gpt-5-codex","input":[{"role":"user","content":[{"type":"input_text","text":"first codex msg"}]},` +
				`{"role":"user","content":[{"type":"input_text","text":"second codex msg"}]}]}`,
			resp: "data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-5-codex\",\"usage\":{\"input_tokens\":7,\"output_tokens\":9}}}\n\n",
			want: &lockSession{typ: "codex", id: shortHash("first codex msg"), model: "gpt-5-codex", in: 7, out: 9},
		},
		{
			// trackKindFor matches the bare suffix "chatgpt.com" today.
			name: "lookalike chatgpt host", host: "evilchatgpt.com", path: "/backend-api/codex/responses",
			req:  `{"model":"gpt-5-codex","input":[{"role":"user","content":[{"type":"input_text","text":"x"}]}]}`,
			resp: "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n",
			want: &lockSession{typ: "codex", model: "gpt-5-codex"}, // CHANGES IN TASK 5 → nil (not a registry host)
		},
		{
			// An openai turn with no model, title or usage records nothing,
			// even with a session hint.
			name: "openai empty turn", host: "api.openai.com", path: "/v1/chat/completions", hint: "h-empty",
			req: `{}`, resp: `{}`,
		},
		{
			name: "untracked host", host: "example.com", path: "/v1/messages",
			req: `{"model":"m","messages":[{"role":"user","content":"x"}]}`, resp: `{}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := lockGateway(t)
			lockTrack(g, tc.host, tc.path, []byte(tc.req), []byte(tc.resp), tc.hint)
			got := onlySession(t, g)
			if (got == nil) != (tc.want == nil) {
				t.Fatalf("session = %+v, want %+v", got, tc.want)
			}
			if got == nil {
				return
			}
			if got.typ != tc.want.typ || got.model != tc.want.model {
				t.Fatalf("session = %+v, want type %q model %q", got, tc.want.typ, tc.want.model)
			}
			if got.in != tc.want.in || got.out != tc.want.out {
				t.Fatalf("tokens = %d/%d, want %d/%d", got.in, got.out, tc.want.in, tc.want.out)
			}
			if tc.want.id != "" && got.id != tc.want.id {
				t.Fatalf("session id = %q, want %q", got.id, tc.want.id)
			}
			if got.id == "" {
				t.Fatal("session id is empty")
			}
		})
	}
}

func TestLockBrowserTLS(t *testing.T) {
	for host, want := range map[string]bool{
		"chatgpt.com":             true,
		"backend-api.chatgpt.com": true,
		"api.openai.com":          true,
		"cdn.openai.com":          true,
		"openai.com":              true,
		"auth.openai.com":         true, // CHANGES IN TASK 6 → false (auth hosts are gated, never dialed for agents)
		"evilchatgpt.com":         false,
		"example.com":             false,
		"api.anthropic.com":       false,
	} {
		if got := lockBrowserTLS(host); got != want {
			t.Errorf("needsBrowserTLS(%q) = %v, want %v", host, got, want)
		}
	}
}

// Session_id keys sessions only on hosts whose provider declares
// SessionHeaders (Task 5 narrows the base "every host" read).
func TestLockSessionHint(t *testing.T) {
	for _, tc := range []struct{ host, name, want string }{
		{"chatgpt.com", "Session_id", "s1"},
		{"chatgpt.com", "Session-Id", "s1"},
		{"api.anthropic.com", "Session_id", "s1"}, // CHANGES IN TASK 5 → ""
		{"api.openai.com", "Session_id", "s1"},    // CHANGES IN TASK 5 → ""
		{"example.com", "Session_id", "s1"},       // CHANGES IN TASK 5 → ""
	} {
		h := http.Header{}
		h.Set(tc.name, "s1")
		if got := lockSessionHint(tc.host, h); got != tc.want {
			t.Errorf("session hint for %s %s = %q, want %q", tc.host, tc.name, got, tc.want)
		}
	}
}

// Which WS upgrades feed the Codex turn observer.
func TestLockWSObserver(t *testing.T) {
	for _, tc := range []struct {
		host, path string
		want       bool
	}{
		{"chatgpt.com", "/backend-api/codex/responses", true},
		{"chatgpt.com", "/backend-api/other", true}, // CHANGES IN TASK 5 → false (path-gated by the WireCodexWS route)
		{"api.openai.com", "/v1/responses", false},
		{"api.anthropic.com", "/v1/messages", false},
	} {
		if got := lockWSObserves(tc.host, tc.path); got != tc.want {
			t.Errorf("WS observer for %s%s = %v, want %v", tc.host, tc.path, got, tc.want)
		}
	}
}

// The GenAI span's gen_ai.provider.name per route.
func TestLockGenAIProviderName(t *testing.T) {
	cases := []struct{ host, path, req, resp, want string }{
		{"api.anthropic.com", "/v1/messages",
			`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`,
			`{"model":"claude-sonnet-4","usage":{"input_tokens":3,"output_tokens":5}}`, "anthropic"},
		{"api.openai.com", "/v1/chat/completions",
			`{"model":"gpt-5","messages":[{"role":"user","content":"hi"}]}`,
			`{"model":"gpt-5","usage":{"prompt_tokens":2,"completion_tokens":4}}`, "openai"},
		{"chatgpt.com", "/backend-api/codex/responses",
			`{"model":"gpt-5-codex","input":[{"role":"user","content":[{"type":"input_text","text":"hi"}]}]}`,
			"data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-5-codex\",\"usage\":{\"input_tokens\":7,\"output_tokens\":9}}}\n\n", "openai"},
	}
	for _, tc := range cases {
		sr, tp := newRecordingTracer(t)
		prev := genaiTracer
		genaiTracer = tp.Tracer("test")
		g := newGenAIGateway(t, false)
		g.agents = NewAgentRegistry()
		g.agents.agents[""] = &Agent{}
		lockTrack(g, tc.host, tc.path, []byte(tc.req), []byte(tc.resp), "")
		genaiTracer = prev
		spans := sr.Ended()
		if len(spans) != 1 {
			t.Fatalf("%s: %d spans, want 1", tc.host, len(spans))
		}
		if got := attrMap(spans[0].Attributes())["gen_ai.provider.name"].AsString(); got != tc.want {
			t.Errorf("%s: gen_ai.provider.name = %q, want %q", tc.host, got, tc.want)
		}
	}
}

// The splice path creates a session only for providers that key
// sessions by header (codex today).
func TestLockSpliceSession(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"chatgpt.com", true},
		{"api.openai.com", true}, // CHANGES IN TASK 6 → false (openai-sdk declares no SessionHeaders)
		{"api.anthropic.com", false},
		{"example.com", false},
	} {
		r := NewAgentRegistry()
		r.trackUA("10.55.0.9:1234", tc.host, "", 0, 0)
		got := len(r.agents["10.55.0.9"].Sessions) > 0
		if got != tc.want {
			t.Errorf("splice to %s created a session = %v, want %v", tc.host, got, tc.want)
		}
	}
}

const lockAnthropicHCL = `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
endpoint "https" "anthropic" { hosts = ["api.anthropic.com"] }
rule "allow-all" {
  endpoint  = https.anthropic
  condition = "true"
  verdict   = "allow"
}
profile "default" { credentials = [] }
`

// Usage is recorded only from 200 responses; a 429 carrying a usage
// body leaves the pre-created session at zero tokens.
func TestLockLLMUsageOnly200(t *testing.T) {
	for _, tc := range []struct {
		status  int
		in, out int64
	}{{http.StatusOK, 3, 5}, {http.StatusTooManyRequests, 0, 0}} {
		h := newCredentialMatchHarness(t, lockAnthropicHCL, "anthropic")
		up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(`{"model":"claude-sonnet-4","usage":{"input_tokens":3,"output_tokens":5}}`))
		}))
		t.Cleanup(up.Close)
		h.gateway.transports.Store(h.endpoint, &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, up.Listener.Addr().String())
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		})
		h.gateway.agents = NewAgentRegistry()
		serverConn, clientConn := net.Pipe()
		// agentIPFor keys a net.Pipe conn on its RemoteAddr ("pipe").
		pipeIP := h.gateway.agentIPFor(serverConn)
		h.gateway.agents.agents[pipeIP] = &Agent{}
		done := make(chan struct{})
		go func() { defer close(done); h.gateway.mitmHTTPS(serverConn, "api.anthropic.com", h.endpoint) }()
		ct := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: "api.anthropic.com"})
		req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages",
			strings.NewReader(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hello claude"}]}`))
		req.Header.Set("Content-Type", "application/json")
		if err := req.Write(ct); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(ct), req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		_ = ct.Close()
		<-done
		s := onlySessionAt(t, h.gateway, pipeIP)
		if s == nil || s.in != tc.in || s.out != tc.out {
			t.Errorf("status %d: session %+v, want tokens %d/%d", tc.status, s, tc.in, tc.out)
		}
	}
}

const lockCodexHCL = `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
endpoint "https" "codex" { hosts = ["chatgpt.com"] }
rule "allow-all" {
  endpoint  = https.codex
  condition = "true"
  verdict   = "allow"
}
profile "default" { credentials = [] }
`

// TestLockMITMCodexSessionHeader drives a codex turn through the real
// mitmHTTPS loop and pins how the gateway reads the Session_id /
// Session-Id request header: exactly one session (the pre-created and
// final ones share an id), typed codex, keyed on the header when set
// and on the first user message otherwise.
func TestLockMITMCodexSessionHeader(t *testing.T) {
	const reqBody = `{"model":"gpt-5-codex","input":[{"role":"user","content":[{"type":"input_text","text":"hello codex"}]}]}`
	const sse = "data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-5-codex\",\"usage\":{\"input_tokens\":7,\"output_tokens\":9}}}\n\n"
	for _, tc := range []struct{ name, header, wantID string }{
		{"Session_id", "Session_id", shortHash("sess-1")},
		{"Session-Id", "Session-Id", shortHash("sess-1")},
		{"no header", "", shortHash("hello codex")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCredentialMatchHarness(t, lockCodexHCL, "codex")
			up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(sse))
			}))
			t.Cleanup(up.Close)
			h.gateway.transports.Store(h.endpoint, &http.Transport{
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, network, up.Listener.Addr().String())
				},
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			})
			h.gateway.agents = NewAgentRegistry()
			serverConn, clientConn := net.Pipe()
			pipeIP := h.gateway.agentIPFor(serverConn)
			h.gateway.agents.agents[pipeIP] = &Agent{}
			done := make(chan struct{})
			go func() { defer close(done); h.gateway.mitmHTTPS(serverConn, "chatgpt.com", h.endpoint) }()
			ct := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: "chatgpt.com"})
			req, _ := http.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", strings.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")
			if tc.header != "" {
				req.Header.Set(tc.header, "sess-1")
			}
			if err := req.Write(ct); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(ct), req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			_ = ct.Close()
			<-done
			s := onlySessionAt(t, h.gateway, pipeIP)
			if s == nil {
				t.Fatal("no session recorded")
			}
			if s.typ != "codex" || s.id != tc.wantID || s.in != 7 || s.out != 9 {
				t.Errorf("session %+v, want type codex id %q tokens 7/9", s, tc.wantID)
			}
		})
	}
}
