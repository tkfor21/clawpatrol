package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
)

// grokCapturedStream is a faithful excerpt of a real Grok Build
// /v1/responses exchange on cli-chat-proxy.grok.com: grok 1.0.50, model
// grok-4.7-build, captured through the gateway on 2026-10-16 (source:
// cli-chat-proxy-v1-responses.complete-with-usage.sse.txt, 123,966 bytes,
// checked for JWT, key and bearer shapes). It keeps, byte for byte and in
// the captured order, the opening keepalive comment, response.created,
// the one response.output_text.delta, the ": xai-usage" SSE comment xAI
// sends after it, and the complete response.completed event with its real
// usage object. Only the in_progress, output_item, content_part and
// output_text.done events between them are dropped; no value is edited.
// The usage object carries xAI-specific fields (num_sources_used,
// num_server_side_tools_used, cost_in_usd_ticks, context_details) next to
// the standard Responses ones.
const grokCapturedStream = "testdata/grok-responses-usage.sse"

// grokCaptured reads the capture excerpt.
func grokCaptured(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(grokCapturedStream)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// grokDerivedJSON is the non-streamed form of the same response. No
// non-streamed Grok Build body has been captured (grok streams), so this
// is DERIVED: the "response" object of the captured response.completed
// event, which is what the Responses API returns as a non-streamed body.
func grokDerivedJSON(t *testing.T, stream []byte) []byte {
	t.Helper()
	for _, line := range bytes.Split(stream, []byte("\n")) {
		payload, ok := bytes.CutPrefix(line, []byte("data: "))
		if !ok {
			continue
		}
		var ev struct {
			Type     string          `json:"type"`
			Response json.RawMessage `json:"response"`
		}
		if err := json.Unmarshal(payload, &ev); err != nil {
			t.Fatal(err)
		}
		if ev.Type == "response.completed" {
			return ev.Response
		}
	}
	t.Fatal("capture has no response.completed event")
	return nil
}

// The request bodies are synthetic (the capture holds only the response),
// naming the captured model.
var (
	grokTestStreamRequest = []byte(`{"model":"grok-4.7-build","stream":true,"input":[{"role":"user","content":[{"type":"input_text","text":"hello grok"}]}]}`)
	grokTestJSONRequest   = []byte(`{"model":"grok-4.7-build","stream":false,"input":[{"role":"user","content":[{"type":"input_text","text":"hello grok"}]}]}`)
)

// The captured usage: input_tokens 14277 (10112 of them cached) and
// output_tokens 32 (31 of them reasoning). The Responses parser
// (parseOpenAIResponse) records input_tokens and output_tokens only.
// They already include the cached and reasoning tokens, which it does not
// record separately, and it ignores the xAI-specific fields.
const (
	grokCapturedIn  = 14277
	grokCapturedOut = 32
)

// TestGrokUsageTracking checks that a Grok Build turn on the CLI chat
// proxy is recorded as a "grok" session keyed by x-grok-session-id, with
// the token counts from the Responses usage object, for both a streamed
// and a non-streamed response.
func TestGrokUsageTracking(t *testing.T) {
	stream := grokCaptured(t)
	cases := []struct {
		name      string
		req, resp []byte
		in, out   int64
	}{
		{"sse", grokTestStreamRequest, stream, grokCapturedIn, grokCapturedOut},
		{"json (derived)", grokTestJSONRequest, grokDerivedJSON(t, stream), grokCapturedIn, grokCapturedOut},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := lockGateway(t)
			g.trackLLMUsage(nil, mustRoute(t, "cli-chat-proxy.grok.com", "/v1/responses"), "cli-chat-proxy.grok.com", c.req, c.resp, "grok-sess-1", time.Time{})
			s := onlySession(t, g)
			if s == nil || s.typ != "grok" || s.id != shortHash("grok-sess-1") {
				t.Fatalf("session = %+v, want type grok keyed by x-grok-session-id", s)
			}
			if s.model != "grok-4.7-build" {
				t.Errorf("model = %q, want grok-4.7-build", s.model)
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

	g.trackLLMUsage(nil, mustRoute(t, "cli-chat-proxy.grok.com", "/v1/responses"), "cli-chat-proxy.grok.com", grokTestStreamRequest, grokCaptured(t), "grok-sess-1", time.Time{})

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	m := attrMap(spans[0].Attributes())
	if got := m["gen_ai.provider.name"].AsString(); got != "x_ai" {
		t.Errorf("gen_ai.provider.name = %q, want x_ai", got)
	}
	for _, k := range []string{"gen_ai.request.model", "gen_ai.response.model"} {
		if got := m[k].AsString(); got != "grok-4.7-build" {
			t.Errorf("%s = %q, want grok-4.7-build", k, got)
		}
	}
	if got := m["gen_ai.usage.input_tokens"].AsInt64(); got != grokCapturedIn {
		t.Errorf("gen_ai.usage.input_tokens = %d, want %d", got, grokCapturedIn)
	}
	if got := m["gen_ai.usage.output_tokens"].AsInt64(); got != grokCapturedOut {
		t.Errorf("gen_ai.usage.output_tokens = %d, want %d", got, grokCapturedOut)
	}
	// The Responses path does not record cached input tokens separately
	// (only the Anthropic path sets CacheReadTokens), so the captured
	// cached_tokens does not become a cache_read attribute.
	if v, ok := m["gen_ai.usage.cache_read.input_tokens"]; ok {
		t.Errorf("gen_ai.usage.cache_read.input_tokens = %d, want unset on the Responses path", v.AsInt64())
	}
}
