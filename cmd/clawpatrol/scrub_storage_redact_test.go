package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"golang.org/x/oauth2"
)

// fakeRefreshToken is a test-only OAuth refresh token the gateway holds
// for a credential. It never goes upstream, but a hostile upstream that
// learned it can still echo it back.
const fakeRefreshToken = "refresh-token-fake-0123456789abcdef"

// refreshEchoBody answers 200 with the refresh token in a JSON body.
const refreshEchoBody echoUpstreamMode = 100

// holdRefreshToken registers name with the gateway's OAuth registry and
// stores fakeRefreshToken for it, so scrubSecretsFor lists it.
func holdRefreshToken(t *testing.T, g *Gateway, name string) {
	t.Helper()
	r, err := NewOAuthRegistry(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Register(name, OAuthIntegration{OAuth: config.OAuthConfig{ClientID: "c", TokenURL: "https://idp.example.test/token"}})
	if err := r.Set(t.Context(), name, &oauth2.Token{AccessToken: "access-token-fake-0123456789", RefreshToken: fakeRefreshToken, Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	g.oauth = r
}

// newRefreshEchoUpstream starts a TLS upstream that answers an
// authorized request by echoing fakeRefreshToken per mode, and returns
// its address. sawAuth flips once the upstream receives an injected
// Authorization header, proving the credential was resolved (so the
// gateway's scrub list is populated).
func newRefreshEchoUpstream(t *testing.T, mode echoUpstreamMode) (string, *atomic.Bool) {
	t.Helper()
	sawAuth := &atomic.Bool{}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		sawAuth.Store(true)
		if mode == refreshEchoBody {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"refresh_token":"` + fakeRefreshToken + `"}`))
			return
		}
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		switch mode {
		case echoAsMalformedStatusCode:
			_, _ = buf.WriteString("HTTP/1.1 " + fakeRefreshToken + " OK\r\nContent-Length: 0\r\n\r\n")
		case echoAsMalformedTrailer:
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n" + fakeRefreshToken + "\r\n\r\n")
		case echoAsWSRefusalReason:
			_, _ = buf.WriteString("HTTP/1.1 403 Forbidden " + fakeRefreshToken + "\r\nContent-Length: 0\r\n\r\n")
		}
		_ = buf.Flush()
	}))
	t.Cleanup(upstream.Close)
	return upstream.Listener.Addr().String(), sawAuth
}

func newRefreshEchoTransport(t *testing.T, mode echoUpstreamMode) (*http.Transport, *atomic.Bool) {
	t.Helper()
	addr, sawAuth := newRefreshEchoUpstream(t, mode)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: false,
	}
	t.Cleanup(tr.CloseIdleConnections)
	return tr, sawAuth
}

// Fix round 1: a refresh token quoted in an upstream parse error is
// redacted from the stored event reason, the stored action and the log,
// like the injected secret is.
func TestMITMUpstreamParseErrorRedactsRefreshToken(t *testing.T) {
	logs := captureGatewayLog(t)
	tr, sawAuth := newRefreshEchoTransport(t, echoAsMalformedStatusCode)
	h := newSecretEchoHarness(t, tr)
	holdRefreshToken(t, h.g, "pat")

	status, end := h.roundTrip(t, "error")
	if status != http.StatusBadGateway {
		t.Fatalf("agent status = %d, want 502", status)
	}
	if !sawAuth.Load() {
		t.Fatal("upstream never received an injected credential; test would be vacuous")
	}
	if strings.Contains(end.Reason, fakeRefreshToken) || !strings.Contains(end.Reason, credentialSampleRedaction) {
		t.Errorf("event reason holds the refresh token %v, has the marker %v; want the marker only",
			strings.Contains(end.Reason, fakeRefreshToken), strings.Contains(end.Reason, credentialSampleRedaction))
	}
	if body := h.apiActionJSON(t, end.ID); strings.Contains(body, fakeRefreshToken) {
		t.Error("GET /api/actions/<id> returns the refresh token")
	}
	assertLogLinesRedacted(t, logs, "mitm upstream ", fakeRefreshToken)
}

// Fix round 1: a refresh token in a response body is redacted from the
// stored body snapshot (an unscrubbed connection: the agent sees the
// body as sent, the gateway's store does not).
func TestMITMRespBodySnapshotRedactsRefreshToken(t *testing.T) {
	tr, sawAuth := newRefreshEchoTransport(t, refreshEchoBody)
	h := newSecretEchoHarness(t, tr)
	holdRefreshToken(t, h.g, "pat")

	status, end := h.roundTrip(t, "allow")
	if status != http.StatusOK {
		t.Fatalf("agent status = %d, want 200", status)
	}
	if !sawAuth.Load() {
		t.Fatal("upstream never received an injected credential; test would be vacuous")
	}
	if strings.Contains(end.RespBody, fakeRefreshToken) || !strings.Contains(end.RespBody, credentialSampleRedaction) {
		t.Errorf("stored response body holds the refresh token %v, has the marker %v; want the marker only",
			strings.Contains(end.RespBody, fakeRefreshToken), strings.Contains(end.RespBody, credentialSampleRedaction))
	}
	if body := h.apiActionJSON(t, end.ID); strings.Contains(body, fakeRefreshToken) {
		t.Error("GET /api/actions/<id> returns the refresh token")
	}
}

// Fix round 1: a refresh token quoted in a response-write error (a
// malformed trailer) is redacted from the log.
func TestMITMRespWriteErrorLogRedactsRefreshToken(t *testing.T) {
	logs := captureGatewayLog(t)
	tr, sawAuth := newRefreshEchoTransport(t, echoAsMalformedTrailer)
	h := newSecretEchoHarness(t, tr)
	holdRefreshToken(t, h.g, "pat")

	req, err := http.NewRequest(http.MethodGet, "https://api.example.test/v1/me", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if status := sendAgentRequest(t, h.g, "api.example.test", h.ep, req); status != http.StatusOK {
		t.Fatalf("agent status = %d, want 200 head before the broken trailer", status)
	}
	if !sawAuth.Load() {
		t.Fatal("upstream never received an injected credential; test would be vacuous")
	}
	assertLogLinesRedacted(t, logs, "mitm resp write ", fakeRefreshToken)
}

// Fix round 1: HITL last_error never holds a refresh token quoted in an
// upstream parse error or a response-write error.
func TestHITLRetryUpstreamErrorRedactsRefreshToken(t *testing.T) {
	for _, tc := range hitlEchoCases {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureGatewayLog(t)
			h := newHITLRetryRelayHarness(t)
			holdRefreshToken(t, h.gateway, "pat")
			tr, sawAuth := newRefreshEchoTransport(t, tc.mode)
			h.gateway.transports.Store(h.endpoint, tr)

			requestBody := `{"resource":"example","approved":true}`
			op := h.createApprovedRetryOperation(t, "hitl_op_retry_refresh_echo", requestBody)
			req, err := http.NewRequest(http.MethodPost, "https://"+hitlRetryRelayTestHost+hitlRetryRelayTestPath, strings.NewReader(requestBody))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(hitlRetryOperationHeader, op.ID)
			if status := sendAgentRequest(t, h.gateway, hitlRetryRelayTestHost, h.endpoint, req); status != tc.wantStatus {
				t.Fatalf("retry status = %d, want %d", status, tc.wantStatus)
			}
			if !sawAuth.Load() {
				t.Fatal("upstream never received an injected credential; test would be vacuous")
			}
			assertLastErrorRedacted(t, h.getOperation(t, op.ID), fakeRefreshToken)
			assertLogLinesRedacted(t, logs, tc.logPrefix, fakeRefreshToken)
		})
	}
}

// Fix round 1: a refused WS upgrade whose status line quotes the
// refresh token is logged redacted.
func TestWSUpgradeRefusalLogRedactsRefreshToken(t *testing.T) {
	logs := captureGatewayLog(t)
	addr, sawAuth := newRefreshEchoUpstream(t, echoAsWSRefusalReason)
	h := newSecretEchoHarness(t, &http.Transport{})
	holdRefreshToken(t, h.g, "pat")
	h.g.dialer = redirectDialer{addr: addr}
	h.ep.Body = insecureUpstreamTLS{}

	req, err := http.NewRequest(http.MethodGet, "https://api.example.test/v1/socket", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	if status := sendAgentRequest(t, h.g, "api.example.test", h.ep, req); status != http.StatusForbidden {
		t.Fatalf("agent status = %d, want the upstream 403", status)
	}
	if !sawAuth.Load() {
		t.Fatal("upstream never received an injected credential; test would be vacuous")
	}
	assertLogLinesRedacted(t, logs, "ws upgrade non-101 ", fakeRefreshToken)
}

// Fix round 1: the stored request snapshot (headers and body) is
// redacted with the full list too, on a normal response and on an
// upstream parse error.
func TestMITMRequestSnapshotRedactsRefreshToken(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mode       echoUpstreamMode
		action     string
		checkHdrs  bool
		wantStatus int
	}{
		{"200", refreshEchoBody, "allow", true, http.StatusOK},
		{"parse error", echoAsMalformedStatusCode, "error", false, http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, sawAuth := newRefreshEchoTransport(t, tc.mode)
			h := newSecretEchoHarness(t, tr)
			holdRefreshToken(t, h.g, "pat")
			req, err := http.NewRequest(http.MethodPost, "https://api.example.test/v1/me", strings.NewReader(`{"note":"`+fakeRefreshToken+`"}`))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Note", fakeRefreshToken)
			if status := sendAgentRequest(t, h.g, "api.example.test", h.ep, req); status != tc.wantStatus {
				t.Fatalf("agent status = %d, want %d", status, tc.wantStatus)
			}
			if !sawAuth.Load() {
				t.Fatal("upstream never received an injected credential; test would be vacuous")
			}
			end := waitHTTPSAuditEnd(t, h.events, tc.action)
			if strings.Contains(end.ReqBody, fakeRefreshToken) || !strings.Contains(end.ReqBody, credentialSampleRedaction) {
				t.Errorf("stored request body holds the refresh token %v, has the marker %v; want the marker only",
					strings.Contains(end.ReqBody, fakeRefreshToken), strings.Contains(end.ReqBody, credentialSampleRedaction))
			}
			if v := end.ReqHeaders["X-Note"]; tc.checkHdrs && (strings.Contains(v, fakeRefreshToken) || !strings.Contains(v, credentialSampleRedaction)) {
				t.Errorf("stored X-Note header holds the refresh token %v, has the marker %v; want the marker only",
					strings.Contains(v, fakeRefreshToken), strings.Contains(v, credentialSampleRedaction))
			}
		})
	}
}

// Fix round 1: the scrub 502 (an unscannable response on a scrubbed
// connection) stores the request snapshot redacted with the full list.
func TestMITMScrub502RequestSnapshotRedactsRefreshToken(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_TOK", testSecret)
	h := newCredentialMatchHarnessWith(t, scrubHCL, "openai", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write([]byte("x"))
	}))
	holdRefreshToken(t, h.gateway, "tok")
	events, cancel := h.gateway.sink.Subscribe()
	defer cancel()
	hdr := http.Header{"Authorization": {"Bearer placeholder"}, "Content-Type": {"application/json"}}
	if status, _, _ := gatewaySend(t, h.gateway, "api.openai.com", http.MethodPost, "/v1/chat/completions", hdr, `{"note":"`+fakeRefreshToken+`"}`); status != http.StatusBadGateway {
		t.Fatalf("status = %d, want the scrub 502", status)
	}
	for _, ev := range collectEvents(events, 300*time.Millisecond) {
		if ev.Status != "502" {
			continue
		}
		if strings.Contains(ev.ReqBody, fakeRefreshToken) || !strings.Contains(ev.ReqBody, credentialSampleRedaction) {
			t.Fatalf("stored request body holds the refresh token %v, has the marker %v; want the marker only",
				strings.Contains(ev.ReqBody, fakeRefreshToken), strings.Contains(ev.ReqBody, credentialSampleRedaction))
		}
		return
	}
	t.Fatal("no 502 event")
}
