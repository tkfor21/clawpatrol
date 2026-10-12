package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// fakeEchoedSecret is the credential the gateway injects upstream in
// these tests. It is synthetic; the assertions only ever report
// whether it appeared, never the value.
const fakeEchoedSecret = "sk-test-SECRET-0123456789"

type echoedSecretStore struct{}

func (echoedSecretStore) Get(string) (runtime.Secret, error) {
	return runtime.Secret{Bytes: []byte(fakeEchoedSecret)}, nil
}

// lockedLogBuffer collects log output written from gateway goroutines.
type lockedLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureGatewayLog(t *testing.T) *lockedLogBuffer {
	t.Helper()
	logs := &lockedLogBuffer{}
	oldOutput := log.Writer()
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(oldOutput) })
	return logs
}

// echoUpstreamMode selects how a test upstream reflects the bearer
// token it received.
type echoUpstreamMode int

const (
	// echoInResponseHeaders answers 200 with the token in X-Echo and
	// in a Location fragment.
	echoInResponseHeaders echoUpstreamMode = iota
	// echoAsMalformedHeaderLine sends a header line with no colon
	// that is the token, so net/http's parse error quotes it.
	echoAsMalformedHeaderLine
	// echoAsMalformedStatusCode puts the token where the status code
	// belongs, so net/http's parse error quotes it.
	echoAsMalformedStatusCode
)

// newSecretEchoTransport starts a TLS upstream that reflects the
// injected bearer token per mode and returns a transport dialing it.
// sawSecret flips once the upstream receives the injected token, so a
// test can prove the secret was really on the wire.
func newSecretEchoTransport(t *testing.T, mode echoUpstreamMode) (*http.Transport, *atomic.Bool) {
	t.Helper()
	sawSecret := &atomic.Bool{}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		sawSecret.Store(true)
		if mode == echoInResponseHeaders {
			w.Header().Set("X-Echo", "you sent "+token)
			w.Header().Set("Location", "https://app.example.test/cb#access_token="+token)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("upstream response writer is not a Hijacker")
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		switch mode {
		case echoAsMalformedHeaderLine:
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\n" + token + "\r\nContent-Length: 0\r\n\r\n")
		case echoAsMalformedStatusCode:
			_, _ = buf.WriteString("HTTP/1.1 " + token + " OK\r\nContent-Length: 0\r\n\r\n")
		}
		_ = buf.Flush()
	}))
	t.Cleanup(upstream.Close)

	upstreamAddr := upstream.Listener.Addr().String()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, upstreamAddr)
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: false,
	}
	t.Cleanup(tr.CloseIdleConnections)
	return tr, sawSecret
}

type secretEchoHarness struct {
	g      *Gateway
	db     *sql.DB
	sink   *Sink
	ep     *config.CompiledEndpoint
	events <-chan eventPacket
}

func newSecretEchoHarness(t *testing.T, tr *http.Transport) *secretEchoHarness {
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
profile "default" { credentials = [bearer_token.pat] }
rule "allow-api" {
  endpoint = https.api
  verdict  = "allow"
}
`), "secret-echo-test.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	policy, err := config.Compile(gw)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	ep := policy.Endpoints["api"]

	db, err := OpenDB(filepath.Join(t.TempDir(), "clawpatrol.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	sink, err := NewSink(db, 8)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = sink.Close(ctx)
	})
	events, cancelEvents := sink.Subscribe()
	t.Cleanup(cancelEvents)

	certs, _ := inMemoryCertCache(t)
	g := &Gateway{db: db, certs: certs, sink: sink, secrets: echoedSecretStore{}}
	g.cfg.Store(gw)
	g.policy.Store(policy)
	g.transports.Store(ep, tr)
	return &secretEchoHarness{g: g, db: db, sink: sink, ep: ep, events: events}
}

// roundTrip sends one agent request through mitmHTTPS, waits for the
// terminal event, and flushes the sink so the action row is on disk.
func (h *secretEchoHarness) roundTrip(t *testing.T, wantAction string) (int, Event) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.g.mitmHTTPS(serverConn, "api.example.test", h.ep)
	}()
	clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, ServerName: "api.example.test"})
	defer func() { _ = clientTLS.Close() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://api.example.test/v1/me", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer placeholder-token")
	if err := req.Write(clientTLS); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	end := waitHTTPSAuditEnd(t, h.events, wantAction)
	_ = clientTLS.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("gateway did not exit after client close")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := h.sink.Close(ctx); err != nil {
		t.Fatalf("flush sink: %v", err)
	}
	return resp.StatusCode, end
}

func (h *secretEchoHarness) apiActionJSON(t *testing.T, id string) string {
	t.Helper()
	rw := httptest.NewRecorder()
	(&webMux{g: h.g}).apiActionByID(rw, httptest.NewRequest(http.MethodGet, "/api/actions/"+id, nil))
	if rw.Code != http.StatusOK {
		t.Fatalf("GET /api/actions/<id> status = %d", rw.Code)
	}
	return rw.Body.String()
}

func TestMITMRespHeadersNotPersisted(t *testing.T) {
	tr, sawSecret := newSecretEchoTransport(t, echoInResponseHeaders)
	h := newSecretEchoHarness(t, tr)

	status, end := h.roundTrip(t, "allow")
	if status != http.StatusOK {
		t.Fatalf("agent status = %d, want 200", status)
	}
	if !sawSecret.Load() {
		t.Fatal("upstream never received the injected secret; test would be vacuous")
	}

	for _, name := range []string{"X-Echo", "Location"} {
		v, ok := end.RespHeaders[name]
		if !ok {
			t.Fatalf("event resp_headers missing %s", name)
		}
		if strings.Contains(v, fakeEchoedSecret) {
			t.Errorf("event resp_headers[%s] contains the injected secret", name)
		}
		if !strings.Contains(v, credentialSampleRedaction) {
			t.Errorf("event resp_headers[%s] lacks the redaction marker", name)
		}
	}

	var column string
	if err := h.db.QueryRow(`SELECT resp_headers FROM actions WHERE action_id = ?`, end.ID).Scan(&column); err != nil {
		t.Fatalf("query actions.resp_headers: %v", err)
	}
	if strings.Contains(column, fakeEchoedSecret) {
		t.Error("actions.resp_headers column contains the injected secret")
	}
	if !strings.Contains(column, credentialSampleRedaction) {
		t.Error("actions.resp_headers column lacks the redaction marker")
	}

	body := h.apiActionJSON(t, end.ID)
	if strings.Contains(body, fakeEchoedSecret) {
		t.Error("GET /api/actions/<id> returns the injected secret")
	}
	if !strings.Contains(body, credentialSampleRedaction) {
		t.Error("GET /api/actions/<id> lacks the redaction marker")
	}
}

func TestMITMUpstreamParseErrorReasonRedactsSecret(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode echoUpstreamMode
	}{
		{"malformed header line", echoAsMalformedHeaderLine},
		{"malformed status code", echoAsMalformedStatusCode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureGatewayLog(t)
			tr, sawSecret := newSecretEchoTransport(t, tc.mode)
			h := newSecretEchoHarness(t, tr)

			status, end := h.roundTrip(t, "error")
			if status != http.StatusBadGateway {
				t.Fatalf("agent status = %d, want 502", status)
			}
			if !sawSecret.Load() {
				t.Fatal("upstream never received the injected secret; test would be vacuous")
			}
			if !strings.Contains(end.Reason, "malformed") {
				t.Fatalf("event reason does not describe the parse error (len=%d)", len(end.Reason))
			}
			if strings.Contains(end.Reason, fakeEchoedSecret) {
				t.Error("event reason contains the injected secret")
			}
			if !strings.Contains(end.Reason, credentialSampleRedaction) {
				t.Error("event reason lacks the redaction marker")
			}
			if body := h.apiActionJSON(t, end.ID); strings.Contains(body, fakeEchoedSecret) {
				t.Error("GET /api/actions/<id> returns the injected secret")
			}
			if strings.Contains(logs.String(), fakeEchoedSecret) {
				t.Error("gateway log contains the injected secret")
			}
			if !strings.Contains(logs.String(), "mitm upstream") {
				t.Error("gateway log lacks the upstream failure line")
			}
		})
	}
}

// The retry relay harness injects its persisted credential
// "retry-relay-test-token"; its upstream is swapped for one that
// echoes that token into an unparseable status line.
func TestHITLRetryUpstreamParseErrorRedactsLastError(t *testing.T) {
	logs := captureGatewayLog(t)
	h := newHITLRetryRelayHarness(t)
	tr, sawSecret := newSecretEchoTransport(t, echoAsMalformedStatusCode)
	h.gateway.transports.Store(h.endpoint, tr)
	const secret = "retry-relay-test-token"

	requestBody := `{"resource":"example","approved":true}`
	op := h.createApprovedRetryOperation(t, "hitl_op_retry_parse_error", requestBody)
	resp := h.sendRetryRequest(t, op.ID, requestBody)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("retry status = %d, want 502", resp.StatusCode)
	}
	if !sawSecret.Load() {
		t.Fatal("upstream never received the injected secret; test would be vacuous")
	}
	got := h.getOperation(t, op.ID)
	if got.State != HITLOperationStateUpstreamFailed {
		t.Fatalf("state = %s, want %s", got.State, HITLOperationStateUpstreamFailed)
	}
	if !strings.Contains(got.LastError, "malformed") {
		t.Fatalf("last_error does not describe the parse error (len=%d)", len(got.LastError))
	}
	if strings.Contains(got.LastError, secret) {
		t.Error("HITL last_error contains the injected secret")
	}
	if strings.Contains(logs.String(), secret) {
		t.Error("gateway log contains the injected secret")
	}
}

// An approval that lands inside the sync wait runs the upstream call
// under the async operation; its upstream_failed reason must not carry
// the injected token either.
func TestHITLAsyncUpstreamParseErrorRedactsLastError(t *testing.T) {
	logs := captureGatewayLog(t)
	h := newHITLAsyncE2EHarnessWithSyncWait(t, "10s")
	tr, sawSecret := newSecretEchoTransport(t, echoAsMalformedStatusCode)
	h.gateway.transports.Store(h.endpoint, tr)
	const secret = "retry-relay-test-token"

	opID := make(chan string, 1)
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if pending := h.gateway.hitl.List(); len(pending) == 1 && pending[0].OperationID != "" {
				opID <- pending[0].OperationID
				h.gateway.hitl.DecideWithResult(pending[0].ID, runtime.HITLDecision{Allow: true, By: "dashboard"})
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		close(opID)
	}()

	resp := h.sendMITMRequest(t, http.MethodPost, "", `{"resource":"example"}`)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 after in-wait approval", resp.StatusCode)
	}
	if !sawSecret.Load() {
		t.Fatal("upstream never received the injected secret; test would be vacuous")
	}
	id, ok := <-opID
	if !ok || id == "" {
		t.Fatal("no pending async HITL operation was observed")
	}
	got, err := h.store.GetForPrincipal(context.Background(), id, hitlRetryRelayTestProfile, hitlPeerPrincipalID(hitlRetryRelayTestPeerIP))
	if err != nil {
		t.Fatalf("GetForPrincipal: %v", err)
	}
	if got.State != HITLOperationStateUpstreamFailed {
		t.Fatalf("state = %s, want %s", got.State, HITLOperationStateUpstreamFailed)
	}
	if !strings.Contains(got.LastError, "malformed") {
		t.Fatalf("last_error does not describe the parse error (len=%d)", len(got.LastError))
	}
	if strings.Contains(got.LastError, secret) {
		t.Error("HITL last_error contains the injected secret")
	}
	if strings.Contains(logs.String(), secret) {
		t.Error("gateway log contains the injected secret")
	}
}
