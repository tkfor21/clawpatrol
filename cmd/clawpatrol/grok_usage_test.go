package main

import (
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
)

// PLACEHOLDER BODIES. No successful Grok Build /v1/responses exchange has
// been captured yet: the live checks ran with no grok_oauth credential
// bound, so every inference call got a 401. These bodies are synthetic,
// shaped like the documented OpenAI Responses API (an SSE stream ending
// in response.completed, whose usage object carries input_tokens,
// output_tokens, their details objects and total_tokens). Replace them
// with a real, redacted capture once a Grok account is connected through
// the dashboard; keep the structure and usage fields exactly as captured.
// Until then these tests pin provider routing (session type "grok",
// gen_ai.provider.name "x_ai") and the Responses usage shape, not xAI's
// real field names.
var (
	grokTestRequest = []byte(`{"model":"grok-code-fast-1","stream":true,"input":[{"role":"user","content":[{"type":"input_text","text":"hello grok"}]}]}`)
	grokTestStream  = []byte("event: response.created\n" +
		"data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\",\"model\":\"grok-code-fast-1\",\"status\":\"in_progress\"}}\n\n" +
		"event: response.output_text.delta\n" +
		"data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n" +
		"event: response.completed\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"model\":\"grok-code-fast-1\",\"status\":\"completed\"," +
		"\"usage\":{\"input_tokens\":7,\"input_tokens_details\":{\"cached_tokens\":2},\"output_tokens\":11,\"output_tokens_details\":{\"reasoning_tokens\":3},\"total_tokens\":18}}}\n\n")
	grokTestJSON = []byte(`{"id":"resp_2","object":"response","model":"grok-code-fast-1","status":"completed",` +
		`"usage":{"input_tokens":5,"input_tokens_details":{"cached_tokens":0},"output_tokens":9,"output_tokens_details":{"reasoning_tokens":0},"total_tokens":14}}`)
)

// TestGrokUsageTracking checks that a Grok Build turn on the CLI chat
// proxy is recorded as a "grok" session keyed by x-grok-session-id, with
// the token counts from the Responses usage object, for both a streamed
// and a non-streamed response.
func TestGrokUsageTracking(t *testing.T) {
	cases := []struct {
		name    string
		resp    []byte
		in, out int64
	}{
		{"sse", grokTestStream, 7, 11},
		{"json", grokTestJSON, 5, 9},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := lockGateway(t)
			g.trackLLMUsage(nil, mustRoute(t, "cli-chat-proxy.grok.com", "/v1/responses"), "cli-chat-proxy.grok.com", grokTestRequest, c.resp, "grok-sess-1", time.Time{})
			s := onlySession(t, g)
			if s == nil || s.typ != "grok" || s.id != shortHash("grok-sess-1") {
				t.Fatalf("session = %+v, want type grok keyed by x-grok-session-id", s)
			}
			if s.model != "grok-code-fast-1" {
				t.Errorf("model = %q, want grok-code-fast-1", s.model)
			}
			if s.in != c.in || s.out != c.out {
				t.Fatalf("tokens = %d/%d, want %d/%d", s.in, s.out, c.in, c.out)
			}
		})
	}
}

// TestGrokGenAISpan checks that a Grok Build turn emits one GenAI span
// naming xAI as the provider (OTel semconv gen_ai.provider.name "x_ai"),
// with the model and token counts of the turn. lockGateway has no
// genai_telemetry block, so this builds its own gateway.
func TestGrokGenAISpan(t *testing.T) {
	sr, tp := newRecordingTracer(t)
	prev := genaiTracer
	genaiTracer = tp.Tracer("test")
	defer func() { genaiTracer = prev }()

	gw, diags := config.LoadBytes([]byte(`
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
  genai_telemetry {}
}
`), "base.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	g := &Gateway{}
	g.cfg.Store(gw)
	g.agents = NewAgentRegistry()

	g.trackLLMUsage(nil, mustRoute(t, "cli-chat-proxy.grok.com", "/v1/responses"), "cli-chat-proxy.grok.com", grokTestRequest, grokTestStream, "grok-sess-1", time.Time{})

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	m := attrMap(spans[0].Attributes())
	if got := m["gen_ai.provider.name"].AsString(); got != "x_ai" {
		t.Errorf("gen_ai.provider.name = %q, want x_ai", got)
	}
	if got := m["gen_ai.request.model"].AsString(); got != "grok-code-fast-1" {
		t.Errorf("gen_ai.request.model = %q, want grok-code-fast-1", got)
	}
	if got := m["gen_ai.usage.input_tokens"].AsInt64(); got != 7 {
		t.Errorf("gen_ai.usage.input_tokens = %d, want 7", got)
	}
	if got := m["gen_ai.usage.output_tokens"].AsInt64(); got != 11 {
		t.Errorf("gen_ai.usage.output_tokens = %d, want 11", got)
	}
}
