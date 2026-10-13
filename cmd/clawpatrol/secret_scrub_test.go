package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
	"golang.org/x/oauth2"
)

const testSecret = "real-access-token-0123456789abcdef"

func TestSecretScrubberReplaces(t *testing.T) {
	hits := 0
	r := newSecretScrubber(strings.NewReader(`{"echo":"`+testSecret+`"}`), scrubSecretList(testSecret), func(n int) { hits += n })
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), testSecret) || !strings.Contains(string(out), scrubMarker) || hits != 1 {
		t.Fatalf("out=%q hits=%d", out, hits)
	}
}

func TestSecretScrubberSplitAcrossReads(t *testing.T) {
	src := "data: {\"delta\":\"" + testSecret + "\"}\n\ndata: [DONE]\n"
	r := newSecretScrubber(iotest.OneByteReader(strings.NewReader(src)), scrubSecretList(testSecret), nil)
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), testSecret) {
		t.Fatalf("secret split across reads leaked: %q", out)
	}
	if !strings.HasSuffix(string(out), "data: [DONE]\n") {
		t.Fatalf("tail lost: %q", out)
	}
}

func TestSecretScrubberDoesNotStallStreams(t *testing.T) {
	pr, pw := io.Pipe()
	r := newSecretScrubber(pr, scrubSecretList(testSecret), nil)
	go func() { _, _ = pw.Write([]byte("data: hello\n\n")) }()
	buf := make([]byte, 64)
	n, err := r.Read(buf) // must return without waiting for more input
	if err != nil || string(buf[:n]) != "data: hello\n\n" {
		t.Fatalf("Read = %q, %v", buf[:n], err)
	}
	_ = pw.Close()
}

func TestSecretScrubberHoldsOnlyPartialPrefix(t *testing.T) {
	pr, pw := io.Pipe()
	r := newSecretScrubber(pr, scrubSecretList(testSecret), nil)
	go func() { _, _ = pw.Write([]byte("abc" + testSecret[:5])) }()
	buf := make([]byte, 64)
	n, _ := r.Read(buf)
	if string(buf[:n]) != "abc" {
		t.Fatalf("first Read = %q, want only the non-prefix bytes", buf[:n])
	}
	go func() { _, _ = pw.Write([]byte(testSecret[5:] + "z")); _ = pw.Close() }()
	rest, _ := io.ReadAll(r)
	if strings.Contains(string(rest), testSecret[5:]) || string(rest) != scrubMarker+"z" {
		t.Fatalf("rest = %q", rest)
	}
}

func TestScrubSecretListIgnoresShortValues(t *testing.T) {
	got := scrubSecretList("", "admin", "0123456789abcdef", "0123456789abcdef")
	if len(got) != 1 || string(got[0]) != "0123456789abcdef" {
		t.Fatalf("got %q", got)
	}
}

// A secret that contains another must be replaced whole: the longer one
// is matched first, so no tail of it survives.
func TestScrubSecretListLongestFirst(t *testing.T) {
	short := "0123456789abcdef"
	long := short + "-and-more-secret"
	out, hits := scrubBytes([]byte("x"+long+"y"), scrubSecretList(short, long))
	if string(out) != "x"+scrubMarker+"y" || hits != 1 {
		t.Fatalf("out=%q hits=%d", out, hits)
	}
}

func TestPrepareScrubbedRequest(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/codex/responses", nil)
	req.Header.Set("Accept-Encoding", "br, gzip")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits")
	prepareScrubbedRequest(req)
	if req.Header.Get("Accept-Encoding") != "identity" || req.Header.Get("Sec-WebSocket-Extensions") != "" {
		t.Fatalf("headers = %v; want identity encoding and no WS extensions", req.Header)
	}
}

func TestReframeWSRefusal(t *testing.T) {
	head := []byte("HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\nContent-Encoding: identity\r\nConnection: keep-alive\r\n\r\n")
	got := string(reframeWSRefusal(head, 42))
	want := "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 42\r\nConnection: close\r\n\r\n"
	if got != want {
		t.Fatalf("reframed head = %q, want %q", got, want)
	}
}

// A secret split between a FIN=0 text frame and its continuation is
// still matched, because strict mode scrubs whole messages.
func TestPumpWSScrubSplitAcrossFragments(t *testing.T) {
	var src, dst bytes.Buffer
	src.Write(buildFrameRaw(0x01, false, [4]byte{}, []byte(`{"token":"`+testSecret[:10]))) // text, FIN=0
	src.Write(buildFrameRaw(0x89, false, [4]byte{}, []byte("ping")))                       // interleaved control frame
	src.Write(buildFrameRaw(0x80, false, [4]byte{}, []byte(testSecret[10:]+`"}`)))         // continuation, FIN=1
	hits := 0
	err := pumpWS(bufio.NewReader(&src), &dst, wsParams{}, false, nil, wsScrubRewriter(scrubSecretList(testSecret), func(n int) { hits += n }), true, nil)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("pumpWS: %v", err)
	}
	if bytes.Contains(dst.Bytes(), []byte(testSecret[:10])) || bytes.Contains(dst.Bytes(), []byte(testSecret[10:])) || hits != 1 {
		t.Fatalf("fragmented secret leaked: %q hits=%d", dst.Bytes(), hits)
	}
	if !bytes.Contains(dst.Bytes(), []byte("ping")) {
		t.Fatal("interleaved control frame was dropped")
	}
	if pi, mi := bytes.Index(dst.Bytes(), []byte("ping")), bytes.Index(dst.Bytes(), []byte(scrubMarker)); pi > mi {
		t.Fatal("the interleaved ping must be forwarded at once, ahead of the reassembled message")
	}
}

func TestPumpWSStrictCapsReassembly(t *testing.T) {
	var src, dst bytes.Buffer
	chunk := bytes.Repeat([]byte("a"), 64*1024)
	src.Write(buildFrameRaw(0x01, false, [4]byte{}, chunk)) // text, FIN=0
	for range wsScrubMessageLimit / len(chunk) {
		src.Write(buildFrameRaw(0x00, false, [4]byte{}, chunk)) // continuation, never FIN
	}
	err := pumpWS(bufio.NewReader(&src), &dst, wsParams{}, false, nil, wsScrubRewriter(scrubSecretList(testSecret), nil), true, nil)
	if !errors.Is(err, errWSScrubMessageTooLarge) {
		t.Fatalf("pumpWS err = %v, want errWSScrubMessageTooLarge", err)
	}
}

func TestPumpWSServerScrub(t *testing.T) {
	var src, dst bytes.Buffer
	src.Write(buildFrameRaw(0x81, false, [4]byte{}, []byte(`{"token":"`+testSecret+`"}`)))
	hits := 0
	err := pumpWS(bufio.NewReader(&src), &dst, wsParams{}, false, nil, wsScrubRewriter(scrubSecretList(testSecret), func(n int) { hits += n }), true, nil)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("pumpWS: %v", err)
	}
	if bytes.Contains(dst.Bytes(), []byte(testSecret)) || !bytes.Contains(dst.Bytes(), []byte(scrubMarker)) || hits != 1 {
		t.Fatalf("frame not scrubbed: %q hits=%d", dst.Bytes(), hits)
	}
}

// D4: header values are scrubbed in place; names and other values are
// left alone.
func TestScrubHeaderValues(t *testing.T) {
	h := http.Header{
		"X-Echo":       {"Bearer " + testSecret, "clean"},
		"Content-Type": {"application/json"},
	}
	hits := 0
	scrubHeaderValues(h, scrubSecretList(testSecret), func(n int) { hits += n })
	if h.Get("X-Echo") != "Bearer "+scrubMarker || h.Values("X-Echo")[1] != "clean" || h.Get("Content-Type") != "application/json" || hits != 1 {
		t.Fatalf("headers = %v hits=%d", h, hits)
	}
}

// D4: trailer values are scrubbed once the body is drained, which is
// when Go fills a response's declared trailers.
func TestTrailerScrubBody(t *testing.T) {
	trailer := http.Header{"X-Echo-Trailer": nil}
	src := &fillTrailerOnEOF{r: strings.NewReader("body"), trailer: trailer, value: testSecret}
	rc := newTrailerScrubBody(io.NopCloser(src), trailer, scrubSecretList(testSecret), nil)
	if b, err := io.ReadAll(rc); err != nil || string(b) != "body" {
		t.Fatalf("body = %q, %v", b, err)
	}
	if got := trailer.Get("X-Echo-Trailer"); got != scrubMarker {
		t.Fatalf("trailer = %q, want the marker", got)
	}
}

// fillTrailerOnEOF mimics net/http's client body: declared trailer
// values appear only when the body reaches EOF.
type fillTrailerOnEOF struct {
	r       io.Reader
	trailer http.Header
	value   string
}

func (f *fillTrailerOnEOF) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if errors.Is(err, io.EOF) {
		f.trailer.Set("X-Echo-Trailer", f.value)
		f.trailer.Set("Set-Cookie", "session=leak")
	}
	return n, err
}

// Round-2 S108: an auth-bearing trailer field that net/http fills at EOF
// is stripped at EOF, also with no secrets (an unscrubbed connection).
func TestTrailerScrubBodyStripsAuthTrailers(t *testing.T) {
	trailer := http.Header{"X-Echo-Trailer": nil, "Set-Cookie": nil}
	src := &fillTrailerOnEOF{r: strings.NewReader("body"), trailer: trailer, value: "plain"}
	rc := newTrailerScrubBody(io.NopCloser(src), trailer, nil, nil)
	if _, err := io.ReadAll(rc); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := trailer.Get("Set-Cookie"); got != "" {
		t.Fatalf("Set-Cookie trailer = %q, want it stripped", got)
	}
	if got := trailer.Get("X-Echo-Trailer"); got != "plain" {
		t.Fatalf("X-Echo-Trailer = %q, want it untouched with no secrets", got)
	}
}

// D4: the raw WS upgrade head is scrubbed with the server rewriter; the
// head's CRLF framing survives because the marker has no CR or LF.
func TestScrubWSHead(t *testing.T) {
	head := []byte("HTTP/1.1 101 Switching Protocols\r\nX-Echo: " + testSecret + "\r\n\r\n")
	got := string(scrubWSHead(head, wsScrubRewriter(scrubSecretList(testSecret), nil)))
	if got != "HTTP/1.1 101 Switching Protocols\r\nX-Echo: "+scrubMarker+"\r\n\r\n" {
		t.Fatalf("head = %q", got)
	}
	if string(scrubWSHead(head, nil)) != string(head) {
		t.Fatal("a nil rewriter (unscrubbed connection) must leave the head unchanged")
	}
}

// D9: the scrub turns on for a provider API host, or for a credential
// type a provider owns on any host; never without a secret.
func TestScrubActiveFor(t *testing.T) {
	cases := []struct {
		host, typ string
		secrets   bool
		want      bool
	}{
		{"api.openai.com", "bearer_token", true, true},
		{"api.example.test", "anthropic_oauth_subscription", true, true},
		{"api.example.test:8443", "openai_codex_oauth", true, true},
		{"api.example.test", "bearer_token", true, false},
		{"api.example.test", "", true, false},
		{"api.openai.com", "anthropic_manual_key", false, false},
	}
	for _, tc := range cases {
		if got := scrubActiveFor(tc.host, tc.typ, tc.secrets); got != tc.want {
			t.Errorf("scrubActiveFor(%q, %q, %v) = %v, want %v", tc.host, tc.typ, tc.secrets, got, tc.want)
		}
	}
}

func TestPumpWSStrictRejectsCompressedText(t *testing.T) {
	var src, dst bytes.Buffer
	src.Write(buildFrameRaw(0xC1, false, [4]byte{}, []byte{0x01, 0x02})) // FIN|RSV1|text
	err := pumpWS(bufio.NewReader(&src), &dst, wsParams{}, false, nil, wsScrubRewriter(scrubSecretList(testSecret), nil), true, nil)
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("pumpWS err = %v, want compressed-frame error", err)
	}
	if dst.Len() != 0 {
		t.Fatalf("compressed frame forwarded: %q", dst.Bytes())
	}
}

// R3-01: in strict mode the frame observer gets the scrubbed message.
func TestPumpWSStrictObserverSeesScrubbed(t *testing.T) {
	var src, dst bytes.Buffer
	src.Write(buildFrameRaw(0x81, false, [4]byte{}, []byte(`{"t":"`+testSecret+`"}`)))
	var seen [][]byte
	onP := func(b []byte) { seen = append(seen, append([]byte(nil), b...)) }
	err := pumpWS(bufio.NewReader(&src), &dst, wsParams{}, false, onP, wsScrubRewriter(scrubSecretList(testSecret), nil), true, nil)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("pumpWS: %v", err)
	}
	if len(seen) != 1 || bytes.Contains(seen[0], []byte(testSecret)) || !bytes.Contains(seen[0], []byte(scrubMarker)) {
		t.Fatalf("observer saw %q, want one scrubbed message", seen)
	}
}

// R3-03: control payloads on a scrubbed connection are scrubbed too.
func TestPumpWSScrubControlFrames(t *testing.T) {
	closeWith := func(reason string) []byte {
		p := make([]byte, 2, 2+len(reason))
		binary.BigEndian.PutUint16(p, 1008)
		return buildFrameRaw(0x88, false, [4]byte{}, append(p, reason...))
	}
	long := strings.Repeat("r", 100) + testSecret[:16] // marker growth pushes it past 125
	for name, tc := range map[string]struct {
		frame   []byte
		secrets [][]byte
		check   func(out []byte) bool
	}{
		"close reason": {closeWith(testSecret), scrubSecretList(testSecret), func(out []byte) bool {
			return bytes.Contains(out, []byte(scrubMarker)) && bytes.Contains(out, []byte{0x03, 0xF0}) // 1008 kept
		}},
		"ping": {buildFrameRaw(0x89, false, [4]byte{}, []byte(testSecret)), scrubSecretList(testSecret), func(out []byte) bool { return bytes.Contains(out, []byte(scrubMarker)) }},
		"pong": {buildFrameRaw(0x8A, false, [4]byte{}, []byte(testSecret)), scrubSecretList(testSecret), func(out []byte) bool { return bytes.Contains(out, []byte(scrubMarker)) }},
		"close too long after scrub": {closeWith(long), scrubSecretList(testSecret[:16]), func(out []byte) bool {
			return bytes.Equal(out, buildFrameRaw(0x88, false, [4]byte{}, []byte{0x03, 0xF3}))
		}},
	} {
		var src, dst bytes.Buffer
		src.Write(tc.frame)
		src.Write(buildFrameRaw(0x81, false, [4]byte{}, []byte("after"))) // a close ends the pump; nothing after it is sent
		err := pumpWS(bufio.NewReader(&src), &dst, wsParams{}, false, nil, wsScrubRewriter(tc.secrets, nil), true, nil)
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("%s: pumpWS: %v", name, err)
		}
		if bytes.Contains(dst.Bytes(), []byte(testSecret)) || bytes.Contains(dst.Bytes(), []byte(testSecret[:16])) || !tc.check(dst.Bytes()) {
			t.Fatalf("%s: agent bytes %q", name, dst.Bytes())
		}
		if isClose := tc.frame[0] == 0x88; isClose == bytes.Contains(dst.Bytes(), []byte("after")) {
			t.Fatalf("%s: frame after it forwarded=%v, want it only after a ping or pong", name, !isClose)
		}
	}
}

// R3-06: the scrub list holds the secret, every Extras value of scrub
// length, and the credential's OAuth refresh token. Every value is at
// least minScrubLen bytes, so none is dropped for being short.
func TestScrubSecretsForIncludesExtrasAndRefreshToken(t *testing.T) {
	r, err := NewOAuthRegistry(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Register("tok", OAuthIntegration{OAuth: config.OAuthConfig{ClientID: "c", TokenURL: "https://idp.example.test/token"}})
	const refresh = "refresh-token-value-0123456789abcdef"
	if err := r.Set(t.Context(), "tok", &oauth2.Token{AccessToken: "access-token-value-0123456789", RefreshToken: refresh, Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	g := &Gateway{oauth: r}
	got := g.scrubSecretsFor("tok", runtime.Secret{Bytes: []byte("bytes-secret-0123456789abcdef"), Extras: map[string]string{"x": "extra-secret-0123456789abcdef"}})
	for _, want := range []string{"bytes-secret-0123456789abcdef", "extra-secret-0123456789abcdef", refresh} {
		if !slices.ContainsFunc(got, func(b []byte) bool { return string(b) == want }) {
			t.Errorf("scrub list %q is missing %q", got, want)
		}
	}
}

// S-04: the injected secret is on the scrub list whatever its length;
// minScrubLen still drops a short Extras value.
func TestScrubSecretsForKeepsShortPrimary(t *testing.T) {
	g := &Gateway{}
	got := g.scrubSecretsFor("tok", runtime.Secret{Bytes: []byte("sk-short-123"), Extras: map[string]string{"user": "bob"}})
	if len(got) != 1 || string(got[0]) != "sk-short-123" {
		t.Fatalf("scrub list has %d entries, want exactly the 12-byte injected secret", len(got))
	}
}

const scrubHCL = `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "https" "openai" { hosts = ["api.openai.com"] }

credential "bearer_token" "tok" { endpoint = https.openai }

rule "allow" {
  endpoint  = https.openai
  condition = "true"
  verdict   = "allow"
}

profile "default" { credentials = [bearer_token.tok] }
`

func TestMITMScrubGzipAndUnknownEncoding(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_TOK", testSecret)
	gz := func(p []byte) []byte {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		_, _ = zw.Write(p)
		_ = zw.Close()
		return b.Bytes()
	}
	echo := func(enc string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Accept-Encoding"); got != "identity" {
				t.Errorf("upstream Accept-Encoding = %q, want identity", got)
			}
			payload := []byte(`{"echo":"` + strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") + `"}`)
			switch enc {
			case "gzip":
				w.Header().Set("Content-Encoding", "gzip")
				payload = gz(payload)
			case "x-gzip":
				w.Header().Set("Content-Encoding", "x-gzip")
				payload = gz(payload)
			case "stacked":
				w.Header().Add("Content-Encoding", "gzip")
				w.Header().Add("Content-Encoding", "br")
				payload = gz(payload)
			case "br":
				w.Header().Set("Content-Encoding", "br")
			case "identity":
				w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
			}
			_, _ = w.Write(payload)
		})
	}
	hdr := http.Header{"Authorization": {"Bearer placeholder"}}
	for _, enc := range []string{"identity", "gzip"} {
		// 200 with the secret echoed: scrubbed, sent without Content-Encoding.
		h := newCredentialMatchHarnessWith(t, scrubHCL, "openai", echo(enc))
		status, rh, body := gatewaySend(t, h.gateway, "api.openai.com", http.MethodPost, "/v1/chat/completions", hdr, "{}")
		if status != 200 || strings.Contains(body, testSecret) || !strings.Contains(body, scrubMarker) || rh.Get("Content-Encoding") != "" {
			t.Fatalf("%s: status=%d enc=%q body=%q", enc, status, rh.Get("Content-Encoding"), body)
		}
	}
	for _, enc := range []string{"br", "stacked", "x-gzip"} {
		h := newCredentialMatchHarnessWith(t, scrubHCL, "openai", echo(enc))
		status, _, body := gatewaySend(t, h.gateway, "api.openai.com", http.MethodPost, "/v1/chat/completions", hdr, "{}")
		if status != http.StatusBadGateway || strings.Contains(body, testSecret) {
			t.Fatalf("%s: status=%d body=%q, want 502", enc, status, body)
		}
	}
	// The scrubbed body is longer than the upstream's Content-Length, so
	// the wrapped response must drop it and re-frame; the keep-alive
	// connection must still carry the next request (R3-07).
	h := newCredentialMatchHarnessWith(t, scrubHCL, "openai", echo("identity"))
	conn, br, closeFn := gatewayConn(t, h.gateway, "api.openai.com")
	defer closeFn()
	for i := range 2 {
		status, _, body := gatewayRoundTrip(t, conn, br, "api.openai.com", http.MethodPost, "/v1/chat/completions", hdr, "{}")
		if status != 200 || strings.Contains(body, testSecret) || !strings.Contains(body, scrubMarker) {
			t.Fatalf("keep-alive request %d: status=%d body=%q", i+1, status, body)
		}
	}
}

// Two requests on one keep-alive connection: a 204 (and a HEAD) on a
// scrubbed host must not be re-framed as chunked, or the next response
// on the connection fails to parse.
func TestMITMScrubNoBodyStatusesKeepAlive(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_TOK", testSecret)
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/empty":
			w.WriteHeader(http.StatusNoContent)
		case "/head":
			w.Header().Set("Content-Length", "42")
			w.WriteHeader(http.StatusOK)
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	})
	h := newCredentialMatchHarnessWith(t, scrubHCL, "openai", upstream)
	tc, br, closeFn := gatewayConn(t, h.gateway, "api.openai.com")
	defer closeFn()
	hdr := http.Header{"Authorization": {"Bearer placeholder"}}
	if status, _, _ := gatewayRoundTrip(t, tc, br, "api.openai.com", http.MethodGet, "/empty", hdr, ""); status != http.StatusNoContent {
		t.Fatalf("204 request: status %d", status)
	}
	status, rh, _ := gatewayRoundTrip(t, tc, br, "api.openai.com", http.MethodHead, "/head", hdr, "")
	if status != http.StatusOK || rh.Get("Content-Length") != "42" {
		t.Fatalf("HEAD: status %d Content-Length %q, want 200 and the upstream's 42", status, rh.Get("Content-Length"))
	}
	if status, _, body := gatewayRoundTrip(t, tc, br, "api.openai.com", http.MethodGet, "/json", hdr, ""); status != http.StatusOK || body != `{"ok":true}` {
		t.Fatalf("follow-up on the same connection: status %d body %q", status, body)
	}
}

// D4: a secret echoed in a response header and in a trailer reaches the
// agent as the marker in both.
func TestMITMScrubHeaderAndTrailerValues(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_TOK", testSecret)
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Trailer", "X-Echo-Trailer")
		w.Header().Set("X-Echo", tok)
		_, _ = w.Write([]byte(`{"ok":true}`))
		w.Header().Set("X-Echo-Trailer", tok)
	})
	h := newCredentialMatchHarnessWith(t, scrubHCL, "openai", upstream)
	tc, br, closeFn := gatewayConn(t, h.gateway, "api.openai.com")
	defer closeFn()
	req, _ := http.NewRequest(http.MethodGet, "https://api.openai.com/v1/models", nil)
	req.Header.Set("Authorization", "Bearer placeholder")
	if err := req.Write(tc); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if _, err := io.ReadAll(resp.Body); err != nil { // trailers arrive after the body
		t.Fatalf("read body: %v", err)
	}
	_ = resp.Body.Close()
	if got := resp.Header.Get("X-Echo"); got != scrubMarker {
		t.Fatalf("header X-Echo = %q, want the marker", got)
	}
	if got := resp.Trailer.Get("X-Echo-Trailer"); got != scrubMarker {
		t.Fatalf("trailer X-Echo-Trailer = %q, want the marker", got)
	}
}

// Round-2 S108: an upstream Set-Cookie trailer never reaches the agent,
// on a connection the scrub does not cover (platform.claude.com with a
// generic bearer_token is neither a provider API host nor a
// provider-owned credential type).
func TestMITMTrailerAuthHeadersStripped(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_TOK", testSecret)
	upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Trailer", "Set-Cookie, X-Plain-Trailer")
		_, _ = w.Write([]byte("docs"))
		w.Header().Set("Set-Cookie", "session=leak")
		w.Header().Set("X-Plain-Trailer", "kept")
	})
	h := newCredentialMatchHarnessWith(t, claudeHostsHCL, "claudehosts", upstream)
	tc, br, closeFn := gatewayConn(t, h.gateway, "platform.claude.com")
	defer closeFn()
	req, _ := http.NewRequest(http.MethodGet, "https://platform.claude.com/llms.txt", nil)
	req.Header.Set("Authorization", "Bearer placeholder")
	if err := req.Write(tc); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	_ = resp.Body.Close()
	if got := resp.Trailer.Get("Set-Cookie"); got != "" {
		t.Fatalf("Set-Cookie trailer = %q reached the agent", got)
	}
	if got := resp.Trailer.Get("X-Plain-Trailer"); got != "kept" {
		t.Fatalf("X-Plain-Trailer = %q, want the ordinary trailer forwarded", got)
	}
}

const providerCredOffAPIHCL = `
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "https" "other" { hosts = ["api.example.test"] }

credential "anthropic_manual_key" "ak" { endpoint = https.other }

rule "allow" {
  endpoint  = https.other
  condition = "true"
  verdict   = "allow"
}

profile "default" { credentials = [anthropic_manual_key.ak] }
`

// D9: a provider-owned credential type bound on a host that is not a
// provider API host still gets the scrub, including identity encoding.
func TestMITMScrubProviderCredentialOffAPIHost(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_AK", testSecret)
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept-Encoding"); got != "identity" {
			t.Errorf("upstream Accept-Encoding = %q, want identity", got)
		}
		_, _ = w.Write([]byte(`{"echo":"` + r.Header.Get("x-api-key") + `"}`))
	})
	h := newCredentialMatchHarnessWith(t, providerCredOffAPIHCL, "other", upstream)
	status, _, body := gatewaySend(t, h.gateway, "api.example.test", http.MethodPost, "/v1/x",
		http.Header{"x-api-key": {"placeholder"}}, "{}")
	if status != http.StatusOK || strings.Contains(body, testSecret) || !strings.Contains(body, scrubMarker) {
		t.Fatalf("status %d body %q; want the marker, never the secret", status, body)
	}
}

// R3-04: the unscannable-response 502 records the request snapshot like
// any other upstream failure. S-03: the stored event never quotes the
// upstream Content-Encoding value, which an upstream can set to the
// secret it was sent.
func TestMITMScrub502RecordsRequestSnapshot(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_TOK", testSecret)
	for _, echo := range []bool{false, true} {
		h := newCredentialMatchHarnessWith(t, scrubHCL, "openai", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			enc := "br"
			if echo {
				enc = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			}
			w.Header().Set("Content-Encoding", enc)
			_, _ = w.Write([]byte("x"))
		}))
		events, cancel := h.gateway.sink.Subscribe()
		hdr := http.Header{"Authorization": {"Bearer placeholder"}, "Content-Type": {"application/json"}}
		if status, _, _ := gatewaySend(t, h.gateway, "api.openai.com", http.MethodPost, "/v1/chat/completions", hdr, `{"model":"gpt-x","input":"hello-snapshot"}`); status != http.StatusBadGateway {
			cancel()
			t.Fatalf("echo=%v: status = %d, want 502", echo, status)
		}
		found := false
		timeout := time.After(300 * time.Millisecond)
	collect:
		for {
			select {
			case pkt, ok := <-events:
				if !ok {
					break collect
				}
				if pkt.ev.Status != "502" {
					continue
				}
				found = true
				if !strings.Contains(pkt.ev.ReqBody, "hello-snapshot") {
					t.Errorf("echo=%v: 502 event request body = %q, want the request snapshot", echo, pkt.ev.ReqBody)
				}
				if strings.Contains(pkt.ev.Reason, testSecret) || bytes.Contains(pkt.raw, []byte(testSecret)) || bytes.Contains(pkt.raw, []byte(strings.ToLower(testSecret))) {
					t.Errorf("echo=%v: the stored 502 event holds the secret (Content-Encoding value quoted)", echo)
				}
			case <-timeout:
				break collect
			}
		}
		cancel()
		if !found {
			t.Fatalf("echo=%v: no 502 event", echo)
		}
	}
}

// S-01: on a scrubbed connection, a 101 on the plain HTTP path (an h2c
// or other non-WebSocket upgrade, asked for or not) is refused with a
// 502; the raw upstream stream behind it never reaches the agent.
func TestMITMScrubRefusesProtocolSwitch(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_TOK", testSecret)
	for _, tc := range []struct{ name, agentHdr, upgrade string }{
		{"h2c upgrade", "Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n", "h2c"},
		{"other upgrade", "Connection: Upgrade\r\nUpgrade: foo\r\n", "foo"},
		{"unsolicited", "Connection: close\r\n", "foo"},
	} {
		h := newCredentialMatchHarnessWith(t, scrubHCL, "openai", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			hj, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			_, _ = io.WriteString(hj, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+tc.upgrade+"\r\n\r\nraw-stream "+tok+" end")
			time.Sleep(150 * time.Millisecond)
			_ = hj.Close()
		}))
		conn, br, closeFn := gatewayConn(t, h.gateway, "api.openai.com")
		_, _ = io.WriteString(conn, "GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer placeholder\r\n"+tc.agentHdr+"\r\n")
		_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		got, _ := io.ReadAll(br)
		closeFn()
		half := len(testSecret) / 2
		if bytes.Contains(got, []byte(testSecret[:half])) || bytes.Contains(got, []byte(testSecret[half:])) {
			t.Fatalf("%s: the raw upstream stream after a 101 reached the agent", tc.name)
		}
		if line, _, _ := bytes.Cut(got, []byte("\r\n")); !bytes.HasPrefix(line, []byte("HTTP/1.1 502 ")) {
			t.Fatalf("%s: agent status line %q, want the scrub 502", tc.name, line)
		}
	}
}

// S-04: a credential shorter than minScrubLen is still scrubbed from the
// response header and body.
func TestMITMScrubShortPrimarySecret(t *testing.T) {
	const short = "sk-short-123" // 12 bytes
	t.Setenv("CLAWPATROL_SECRET_TOK", short)
	h := newCredentialMatchHarnessWith(t, scrubHCL, "openai", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("X-Echo", tok)
		_, _ = io.WriteString(w, `{"echo":"`+tok+`"}`)
	}))
	status, rh, body := gatewaySend(t, h.gateway, "api.openai.com", http.MethodGet, "/v1/models", http.Header{"Authorization": {"Bearer placeholder"}}, "")
	if status != http.StatusOK || rh.Get("X-Echo") != scrubMarker || strings.Contains(body, short) || !strings.Contains(body, scrubMarker) {
		t.Fatalf("status %d, X-Echo is the marker %v, body holds the secret %v; want 200 and the marker in both", status, rh.Get("X-Echo") == scrubMarker, strings.Contains(body, short))
	}
}

// D-R4-2 (A): the audit snapshot of the response headers masks the whole
// scrub list, so an OAuth refresh token an upstream echoes in a header
// is not stored; the agent sees the marker.
func TestMITMRespHeadersRedactScrubList(t *testing.T) {
	t.Setenv("CLAWPATROL_SECRET_TOK", testSecret)
	const refresh = "refresh-token-value-0123456789abcdef"
	h := newCredentialMatchHarnessWith(t, scrubHCL, "openai", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Echo", refresh)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	r, err := NewOAuthRegistry(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Register("tok", OAuthIntegration{OAuth: config.OAuthConfig{ClientID: "c", TokenURL: "https://idp.example.test/token"}})
	if err := r.Set(t.Context(), "tok", &oauth2.Token{AccessToken: "access-token-value-0123456789", RefreshToken: refresh, Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	h.gateway.oauth = r
	events, cancel := h.gateway.sink.Subscribe()
	defer cancel()
	status, rh, _ := gatewaySend(t, h.gateway, "api.openai.com", http.MethodGet, "/v1/models", http.Header{"Authorization": {"Bearer placeholder"}}, "")
	if status != http.StatusOK || rh.Get("X-Echo") != scrubMarker {
		t.Fatalf("status %d X-Echo %q, want 200 and the marker", status, rh.Get("X-Echo"))
	}
	for _, ev := range collectEvents(events, 300*time.Millisecond) {
		if ev.Status == "200" {
			if v, ok := ev.RespHeaders["X-Echo"]; !ok || strings.Contains(v, refresh) {
				t.Fatalf("stored X-Echo = %q (present %v), want it present with the refresh token redacted", v, ok)
			}
			return
		}
	}
	t.Fatal("no 200 event")
}

// redirectDialer (upstream_secret_echo_test.go) sends every gateway
// dial to one local address.

// wsUpgradeThroughGateway drives a WS upgrade (offering
// permessage-deflate) through the MITM on a scrubbed host to an
// upstream that records whether it saw Sec-WebSocket-Extensions, writes
// reply(tok) raw, and closes 200 ms later. It returns the agent-visible
// bytes.
func wsUpgradeThroughGateway(t *testing.T, sawExt *atomic.Bool, reply func(tok string) string) []byte {
	t.Helper()
	t.Setenv("CLAWPATROL_SECRET_TOK", testSecret)
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawExt.Store(r.Header.Get("Sec-WebSocket-Extensions") != "")
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		hj, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = io.WriteString(hj, reply(tok))
		time.Sleep(200 * time.Millisecond)
		_ = hj.Close()
	}))
	upCerts, caPEM := inMemoryCertCache(t)
	upCert, err := upCerts.mint("api.openai.com")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	up.TLS = &tls.Config{Certificates: []tls.Certificate{*upCert}, NextProtos: []string{"http/1.1"}}
	up.StartTLS()
	t.Cleanup(up.Close)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("test CA did not parse")
	}
	h := newCredentialMatchHarnessWith(t, scrubHCL, "openai", http.NotFoundHandler())
	h.gateway.dialer = redirectDialer{addr: up.Listener.Addr().String()}
	h.gateway.upstreamTestRoots = roots
	conn, br, closeFn := gatewayConn(t, h.gateway, "api.openai.com")
	defer closeFn()
	_, _ = io.WriteString(conn, "GET /v1/realtime HTTP/1.1\r\nHost: api.openai.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Extensions: permessage-deflate\r\n"+
		"Authorization: Bearer placeholder\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, _ := io.ReadAll(br)
	return got
}

// wsRefusalThroughGateway is wsUpgradeThroughGateway for a refusal.
func wsRefusalThroughGateway(t *testing.T, refusal func(tok string) string) []byte {
	t.Helper()
	return wsUpgradeThroughGateway(t, new(atomic.Bool), refusal)
}

func TestHandleWSUpgradeRefusalChunkedSecret(t *testing.T) {
	got := wsRefusalThroughGateway(t, func(tok string) string {
		h := len(tok) / 2
		return "HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: chunked\r\n\r\n" +
			fmt.Sprintf("%x\r\n%s\r\n", h, tok[:h]) + fmt.Sprintf("%x\r\n%s\r\n", len(tok)-h, tok[h:]) + "0\r\n\r\n"
	})
	half := len(testSecret) / 2
	if bytes.Contains(got, []byte(testSecret[:half])) || bytes.Contains(got, []byte(testSecret[half:])) {
		t.Fatalf("a half of the secret reached the agent through chunk framing: %q", got)
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(got)), nil)
	if err != nil {
		t.Fatalf("agent could not parse the refusal %q: %v", got, err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || string(body) != scrubMarker {
		t.Fatalf("agent body = %q (%v), want exactly the decoded, scrubbed body", body, err)
	}
}

func TestHandleWSUpgradeRefusalCapSplit(t *testing.T) {
	got := wsRefusalThroughGateway(t, func(tok string) string {
		b := strings.Repeat("x", 2048-(len(tok)-1)) + tok + strings.Repeat("y", 100)
		return fmt.Sprintf("HTTP/1.1 401 Unauthorized\r\nContent-Length: %d\r\n\r\n%s", len(b), b)
	})
	if bytes.Contains(got, []byte(testSecret[:len(testSecret)-1])) {
		t.Fatal("the first len-1 bytes of the secret reached the agent across the read cap")
	}
	if !bytes.Contains(got, []byte(wsRefusalWithheld)) {
		t.Fatalf("agent got %q, want the withheld notice for an over-cap body", got)
	}
}

// R3-02: an encoded refusal body cannot be scanned, so it is withheld.
func TestHandleWSUpgradeRefusalEncodedWithheld(t *testing.T) {
	got := wsRefusalThroughGateway(t, func(tok string) string {
		b := "x" + tok
		return fmt.Sprintf("HTTP/1.1 401 Unauthorized\r\nContent-Encoding: br\r\nContent-Length: %d\r\n\r\n%s", len(b), b)
	})
	if bytes.Contains(got, []byte(testSecret)) || !bytes.Contains(got, []byte(wsRefusalWithheld)) {
		t.Fatalf("agent got %q, want the withheld notice for an encoded body", got)
	}
}

// S-02: the 101 test reads the status-code field, so a refusal whose
// reason phrase contains " 101 " still takes the refusal scrub.
func TestHandleWSUpgradeRefusalReasonPhrase101(t *testing.T) {
	got := wsRefusalThroughGateway(t, func(tok string) string {
		b := `{"e":"` + tok + `","pad":"` + strings.Repeat("p", 40) + `"}`
		return fmt.Sprintf("HTTP/1.1 400 Bad 101 Request\r\nContent-Length: %d\r\n\r\n%s", len(b), b)
	})
	half := len(testSecret) / 2
	leaked := bytes.Contains(got, []byte(testSecret[:half])) || bytes.Contains(got, []byte(testSecret[half:]))
	if leaked || !bytes.Contains(got, []byte(scrubMarker)) {
		t.Fatalf("a 400 whose reason phrase holds \" 101 \" was not scrubbed as a refusal: a piece of the secret present %v, marker present %v",
			leaked, bytes.Contains(got, []byte(scrubMarker)))
	}
}

// TestMITMScrubWebSocket drives WS upgrades end to end on a scrubbed
// host: the upstream sees no Sec-WebSocket-Extensions, and the 101
// head, a server text message split across two fragments, and a
// refusal body all carry the marker, never the secret or a piece of it
// (R3-05).
func TestMITMScrubWebSocket(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		var sawExt atomic.Bool
		got := wsUpgradeThroughGateway(t, &sawExt, func(tok string) string {
			if refuse {
				b := `{"error":"bad key ` + tok + `"}`
				return fmt.Sprintf("HTTP/1.1 401 Unauthorized\r\nContent-Length: %d\r\n\r\n%s", len(b), b)
			}
			return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nX-Echo: " + tok + "\r\n\r\n" +
				string(buildFrameRaw(0x01, false, [4]byte{}, []byte(`{"t":"`+tok[:10]))) + // text, FIN=0
				string(buildFrameRaw(0x80, false, [4]byte{}, []byte(tok[10:]+`"}`))) // continuation, FIN=1
		})
		if sawExt.Load() {
			t.Errorf("refuse=%v: upstream saw Sec-WebSocket-Extensions on a scrubbed connection", refuse)
		}
		if bytes.Contains(got, []byte(testSecret[:10])) || bytes.Contains(got, []byte(testSecret[10:])) || bytes.Count(got, []byte(scrubMarker)) < 1 {
			t.Fatalf("refuse=%v: agent bytes %q, want the marker and no secret", refuse, got)
		}
		if !refuse && bytes.Count(got, []byte(scrubMarker)) < 2 {
			t.Fatalf("101: agent bytes %q, want the marker in the X-Echo head value and in the text message", got)
		}
	}
}
