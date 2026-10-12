package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// Fake secrets only.
const (
	judgePromptAgentPlaceholder = "agent-placeholder-0000"
	judgePromptAgentSecret      = "fake-agent-real-secret-7f3a9c"
	judgePromptJudgeSecret      = "fake-judge-key-4b8e21d6"
)

// promptRecordingInjector swaps the agent's placeholder for the real
// secret in both the Authorization header and the body, the way a
// header credential plus a body-rewriting credential would. It counts
// calls so the test can see whether injection ran before the judge.
type promptRecordingInjector struct {
	calls *atomic.Int32
}

func (p promptRecordingInjector) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	p.calls.Add(1)
	req.Header.Set("Authorization", "Bearer "+string(sec.Bytes))
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		body = bytes.ReplaceAll(body, []byte(judgePromptAgentPlaceholder), sec.Bytes)
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}
	return nil
}

type judgeKeyInjector struct{}

func (judgeKeyInjector) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	req.Header.Set("x-api-key", string(sec.Bytes))
	return nil
}

type mapSecrets map[string]string

func (m mapSecrets) Get(name string) (runtime.Secret, error) {
	return runtime.Secret{Bytes: []byte(m[name])}, nil
}

// recordingJudge stands in for api.anthropic.com. It records the
// prompt it receives and how many agent injections had happened at
// that moment, then answers with reply. Any other host goes to the
// real transport.
type recordingJudge struct {
	next          http.RoundTripper
	reply         string
	agentInjects  *atomic.Int32
	mu            sync.Mutex
	prompt        string
	apiKey        string
	injectsAtCall int32
	called        bool
}

func (j *recordingJudge) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "api.anthropic.com" {
		return j.next.RoundTrip(req)
	}
	var body struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	raw, _ := io.ReadAll(req.Body)
	_ = json.Unmarshal(raw, &body)
	j.mu.Lock()
	j.called = true
	j.injectsAtCall = j.agentInjects.Load()
	j.apiKey = req.Header.Get("x-api-key")
	for _, m := range body.Messages {
		j.prompt += m.Content
	}
	j.mu.Unlock()
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(j.reply)),
		Request:    req,
	}, nil
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type judgedRequest struct {
	status       int
	body         string
	logs         string
	event        Event
	judge        *recordingJudge
	agentInjects int32
}

// runJudgedRequest sends one agent POST through the MITM path to an
// llm_approver-gated rule whose judge answers with judgeText.
func runJudgedRequest(t *testing.T, judgeText string) judgedRequest {
	t.Helper()
	gw, diags := config.LoadBytes([]byte(`
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
endpoint "https" "api" {
  hosts = ["api.example.test"]
}
credential "bearer_token" "pat" { endpoint = https.api }
credential "anthropic_manual_key" "judgekey" {}
approver "llm_approver" "judge" {
  model      = "claude-test"
  credential = anthropic_manual_key.judgekey
  policy     = "deny everything"
}
rule "judged-post" {
  endpoint  = https.api
  condition = "http.method == 'POST'"
  approve   = [llm_approver.judge]
}
profile "default" { credentials = [bearer_token.pat] }
`), "llm-judge-prompt-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load config: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile config: %v", err)
	}
	ep := policy.Endpoints["api"]
	if ep == nil {
		t.Fatal("missing compiled api endpoint")
	}
	var agentInjects atomic.Int32
	policy.Credentials["pat"].Body = promptRecordingInjector{calls: &agentInjects}
	policy.Credentials["judgekey"].Body = judgeKeyInjector{}

	reply, _ := json.Marshal(map[string]any{"content": []map[string]any{{"type": "text", "text": judgeText}}})
	judge := &recordingJudge{next: http.DefaultTransport, agentInjects: &agentInjects, reply: string(reply)}
	savedTransport := http.DefaultTransport
	http.DefaultTransport = judge
	t.Cleanup(func() { http.DefaultTransport = savedTransport })
	var logs syncBuffer
	savedLog := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(savedLog) })

	sink, err := NewSink(nil, 8)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	defer close(sink.ch)
	events, cancelEvents := sink.Subscribe()
	defer cancelEvents()
	certs, _ := inMemoryCertCache(t)
	g := &Gateway{certs: certs, sink: sink, secrets: mapSecrets{
		"pat":      judgePromptAgentSecret,
		"judgekey": judgePromptJudgeSecret,
	}}
	g.cfg.Store(gw)
	g.policy.Store(policy)

	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.mitmHTTPS(serverConn, "api.example.test", ep)
	}()
	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: "api.example.test"})
	defer func() { _ = clientTLS.Close() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	requestBody := `{"token":"` + judgePromptAgentPlaceholder + `"}`
	req, err := http.NewRequest(http.MethodPost, "https://api.example.test/v1/things?key="+judgePromptAgentPlaceholder, strings.NewReader(requestBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+judgePromptAgentPlaceholder)
	req.Header.Set("Content-Type", "application/json")
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	ev := waitHTTPSAuditEnd(t, events, "denied")

	_ = clientTLS.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not exit after client close")
	}
	return judgedRequest{
		status:       resp.StatusCode,
		body:         string(respBody),
		logs:         logs.String(),
		event:        ev,
		judge:        judge,
		agentInjects: agentInjects.Load(),
	}
}

// Threat model for judge output: the llm_approver prompt is built from
// the agent's request before the gateway injects the real credential,
// so the judge sees the agent's placeholder, never the real secret. The
// judge-call key travels only in the judge request's headers.
func TestLLMJudgePromptIsBuiltBeforeCredentialInjection(t *testing.T) {
	got := runJudgedRequest(t, "deny\nrecorded")
	if got.status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 from the judge's deny", got.status)
	}
	j := got.judge
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.called {
		t.Fatal("judge was never called")
	}
	if j.injectsAtCall != 0 {
		t.Fatalf("agent credential was injected %d times before the judge call; the prompt would be post-injection", j.injectsAtCall)
	}
	if !strings.Contains(j.prompt, judgePromptAgentPlaceholder) {
		t.Fatalf("prompt does not carry the agent's placeholder: %q", j.prompt)
	}
	for _, secret := range []string{judgePromptAgentSecret, judgePromptJudgeSecret} {
		if strings.Contains(j.prompt, secret) {
			t.Fatalf("prompt carries a real secret %q: %q", secret, j.prompt)
		}
	}
	if j.apiKey != judgePromptJudgeSecret {
		t.Fatalf("judge request x-api-key = %q, want the judge-call credential", j.apiKey)
	}
	if got.agentInjects != 0 {
		t.Fatalf("a denied request was injected %d times", got.agentInjects)
	}
}

// A judge reply that repeats the judge-call key must not carry it to
// the agent's 403 body, the gateway log, or the dashboard event.
func TestLLMJudgeDenyReasonRedactsJudgeKeyEndToEnd(t *testing.T) {
	got := runJudgedRequest(t, "deny\nthe key is "+judgePromptJudgeSecret)
	if got.status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", got.status)
	}
	for where, text := range map[string]string{
		"403 body":     got.body,
		"gateway log":  got.logs,
		"event reason": got.event.Reason,
	} {
		if strings.Contains(text, judgePromptJudgeSecret) {
			t.Fatalf("%s carries the judge key: %q", where, text)
		}
		if !strings.Contains(text, "clawpatrol-redacted-secret") {
			t.Fatalf("%s = %q, want the redaction marker", where, text)
		}
	}
}
