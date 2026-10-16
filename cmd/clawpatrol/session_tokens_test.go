package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// realWorkerToken is a synthetic JWT-shaped worker token. Assertions
// only ever report whether it appeared, never the value.
const realWorkerToken = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ3b3JrZXIifQ.c2lnbmF0dXJlLXRlc3Qtb25seQ"

// opaqueToken is a valid token that isn't JWT-shaped, so tests can check
// each layer without the JWT shape check standing in for it.
const opaqueToken = "opaque-worker-token-0123456789abcdef"

var testGrant = &agentprovider.SessionTokenGrant{
	Host: "api.anthropic.com", IssuePath: "/v1/code/sessions/{id}/bridge", UsePath: "/v1/code/sessions/{id}/worker",
	TokenField: "worker_jwt", TTLField: "expires_in", KeepFields: []string{"api_base_url", "worker_epoch", "mcp_config"},
}

var ownerA = sessionTokenOwner{agent: "10.55.0.2", profile: "default", credential: "claude", host: "api.anthropic.com"}

func TestSessionTokenStoreIssueResolve(t *testing.T) {
	s := newSessionTokenStore()
	ph, err := s.issue(ownerA, "cse_1", realWorkerToken, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.HasPrefix(ph, sessionTokenPlaceholderPrefix) || len(ph) != len(sessionTokenPlaceholderPrefix)+32 || strings.Contains(ph, realWorkerToken) {
		t.Fatalf("placeholder shape %q", ph)
	}
	if got, ok := s.resolve(ownerA, "cse_1", ph); !ok || got != realWorkerToken {
		t.Fatalf("resolve own placeholder: ok=%v", ok)
	}
	other := func(mut func(o *sessionTokenOwner)) sessionTokenOwner { o := ownerA; mut(&o); return o }
	misses := []struct {
		name    string
		owner   sessionTokenOwner
		session string
		ph      string
	}{
		{"other agent", other(func(o *sessionTokenOwner) { o.agent = "10.55.0.3" }), "cse_1", ph},
		{"other profile", other(func(o *sessionTokenOwner) { o.profile = "ops" }), "cse_1", ph},
		{"other credential", other(func(o *sessionTokenOwner) { o.credential = "claude2" }), "cse_1", ph},
		{"other host", other(func(o *sessionTokenOwner) { o.host = "api.other.test" }), "cse_1", ph},
		{"other session", ownerA, "cse_2", ph},
		{"empty session", ownerA, "", ph},
		{"forged placeholder", ownerA, "cse_1", sessionTokenPlaceholderPrefix + strings.Repeat("0", 32)},
		{"real token as placeholder", ownerA, "cse_1", realWorkerToken},
		{"empty placeholder", ownerA, "cse_1", ""},
		{"placeholder prefix", ownerA, "cse_1", ph[:len(ph)-1]},
	}
	for _, m := range misses {
		if got, ok := s.resolve(m.owner, m.session, m.ph); ok || got != "" {
			t.Errorf("%s: resolved (ok=%v); must miss", m.name, ok)
		}
	}
}

func TestSessionTokenStoreRefusesEmptyOwnerParts(t *testing.T) {
	s := newSessionTokenStore()
	for _, o := range []sessionTokenOwner{
		{profile: "default", credential: "claude", host: "api.anthropic.com"},
		{agent: "10.55.0.2", profile: "default", host: "api.anthropic.com"},
		{agent: "10.55.0.2", profile: "default", credential: "claude"},
	} {
		if _, err := s.issue(o, "cse_1", realWorkerToken, time.Hour); err == nil {
			t.Errorf("issue with owner %+v succeeded; an incomplete owner must be refused", o)
		}
	}
	if _, err := s.issue(ownerA, "", realWorkerToken, time.Hour); err == nil {
		t.Error("issue with empty session succeeded")
	}
	if _, err := s.issue(ownerA, "cse_1", "", time.Hour); err == nil {
		t.Error("issue with empty token succeeded")
	}
	for _, ttl := range []time.Duration{0, -time.Second} {
		if _, err := s.issue(ownerA, "cse_1", realWorkerToken, ttl); err == nil {
			t.Errorf("issue with ttl %v succeeded", ttl)
		}
	}
}

func TestSessionTokenStoreExpiry(t *testing.T) {
	s := newSessionTokenStore()
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	ph, err := s.issue(ownerA, "cse_1", realWorkerToken, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(9 * time.Second)
	if _, ok := s.resolve(ownerA, "cse_1", ph); !ok {
		t.Fatal("resolve before expiry missed")
	}
	now = now.Add(time.Second)
	if _, ok := s.resolve(ownerA, "cse_1", ph); ok {
		t.Fatal("resolve at expiry hit; the entry must be gone")
	}
	// The TTL is capped, whatever the upstream says.
	now = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	ph, _ = s.issue(ownerA, "cse_1", realWorkerToken, 1000*time.Hour)
	now = now.Add(sessionTokenMaxTTL)
	if _, ok := s.resolve(ownerA, "cse_1", ph); ok {
		t.Fatalf("resolve after %v hit; the TTL cap did not apply", sessionTokenMaxTTL)
	}
}

func TestSessionTokenStoreCapsPerOwner(t *testing.T) {
	s := newSessionTokenStore()
	var phs []string
	for i := 0; i <= sessionTokenMaxPerOwner; i++ {
		ph, err := s.issue(ownerA, fmt.Sprintf("cse_%d", i), fmt.Sprintf("%s%d", realWorkerToken, i), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		phs = append(phs, ph)
	}
	if _, ok := s.resolve(ownerA, "cse_0", phs[0]); ok {
		t.Fatal("oldest entry survived past the per-owner cap")
	}
	for i := 1; i <= sessionTokenMaxPerOwner; i++ {
		if _, ok := s.resolve(ownerA, fmt.Sprintf("cse_%d", i), phs[i]); !ok {
			t.Fatalf("entry %d evicted early", i)
		}
	}
	// Another owner has its own budget.
	ownerB := ownerA
	ownerB.agent = "10.55.0.9"
	if _, err := s.issue(ownerB, "cse_x", realWorkerToken, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.resolve(ownerA, "cse_1", phs[1]); !ok {
		t.Fatal("another owner's issue evicted owner A's entry")
	}
	if n := s.size(); n != sessionTokenMaxPerOwner+1 {
		t.Fatalf("store holds %d entries, want %d", n, sessionTokenMaxPerOwner+1)
	}
}

func TestSessionTokenStorePlaceholdersUnique(t *testing.T) {
	s := newSessionTokenStore()
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		o := ownerA
		o.agent = fmt.Sprintf("10.55.%d.%d", i/250, i%250)
		ph, err := s.issue(o, "cse_1", realWorkerToken, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if seen[ph] {
			t.Fatalf("duplicate placeholder after %d issues", i)
		}
		seen[ph] = true
	}
}

// Review #25 round 3: a credential change or reload while an issue
// request is in flight must win; the late issue is refused.
func TestSessionTokenStoreEpochRefusesStaleIssue(t *testing.T) {
	s := newSessionTokenStore()
	for _, change := range []func(){
		func() { s.dropCredential("claude") },
		func() { s.dropCredential("unrelated") },
		func() { s.retainCredentials(map[string]bool{"claude": true}) },
	} {
		at := s.epoch()
		change()
		if _, err := s.issueAt(ownerA, "cse_1", realWorkerToken, time.Hour, at); err == nil {
			t.Fatal("issue started before a credential change succeeded after it")
		}
		if _, err := s.issueAt(ownerA, "cse_1", realWorkerToken, time.Hour, s.epoch()); err != nil {
			t.Fatalf("issue at the current epoch: %v", err)
		}
	}
}

func TestSessionTokenStoreConcurrent(t *testing.T) {
	s := newSessionTokenStore()
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			o := ownerA
			o.agent = fmt.Sprintf("10.55.0.%d", w)
			for i := 0; i < 200; i++ {
				sess := fmt.Sprintf("cse_%d", i%40)
				ph, err := s.issue(o, sess, realWorkerToken, time.Hour)
				if err != nil {
					t.Error(err)
					return
				}
				if got, ok := s.resolve(o, sess, ph); ok && got != realWorkerToken {
					t.Error("resolved a wrong token")
					return
				}
			}
		}(w)
	}
	wg.Wait()
}

// --- swapIssuedSessionToken --------------------------------------------

type issueRecorder struct {
	tokens []string
	ttls   []time.Duration
	fail   error
}

func (r *issueRecorder) issue(token string, ttl time.Duration) (string, error) {
	if r.fail != nil {
		return "", r.fail
	}
	r.tokens = append(r.tokens, token)
	r.ttls = append(r.ttls, ttl)
	return sessionTokenPlaceholderPrefix + "0123456789abcdef0123456789abcdef", nil
}

func bridgeResponse(status int, body string, hdr http.Header) *http.Response {
	if hdr == nil {
		hdr = http.Header{}
	}
	if hdr.Get("Content-Type") == "" {
		hdr.Set("Content-Type", "application/json")
	}
	return &http.Response{
		StatusCode: status, Status: http.StatusText(status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: hdr, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)),
	}
}

func readAll(t *testing.T, r *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSwapIssuedSessionTokenRewrites(t *testing.T) {
	body := `{"api_base_url":"https://api.anthropic.com","worker_jwt":"` + realWorkerToken + `","expires_in":3600,"worker_epoch":7,"mcp_config":{"servers":[{"url":"https://api.anthropic.com/mcp"}]},"debug":"` + realWorkerToken + `"}`
	resp := bridgeResponse(200, body, nil)
	rec := &issueRecorder{}
	tok, err := swapIssuedSessionToken(resp, testGrant, rec.issue)
	if err != nil {
		t.Fatalf("swap: %v", err)
	}
	if tok != realWorkerToken || len(rec.tokens) != 1 || rec.tokens[0] != realWorkerToken || rec.ttls[0] != time.Hour {
		t.Fatalf("issued %d token(s), ttl %v; want the worker token once with 1h", len(rec.tokens), rec.ttls)
	}
	out := readAll(t, resp)
	if strings.Contains(out, realWorkerToken) {
		t.Fatal("rewritten body still carries the real token")
	}
	if resp.ContentLength != int64(len(out)) || resp.Header.Get("Content-Length") != fmt.Sprint(len(out)) {
		t.Fatalf("framing: ContentLength %d header %q, body %d bytes", resp.ContentLength, resp.Header.Get("Content-Length"), len(out))
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("rewritten body is not JSON: %v", err)
	}
	if got["worker_jwt"] != sessionTokenPlaceholderPrefix+"0123456789abcdef0123456789abcdef" {
		t.Fatalf("worker_jwt = %v", got["worker_jwt"])
	}
	if got["api_base_url"] != "https://api.anthropic.com" || got["expires_in"] != float64(3600) || got["worker_epoch"] != float64(7) {
		t.Fatalf("other fields changed: %v", got)
	}
	// Key order is kept (clients may not care, but nothing else moves).
	// Fixed order: the token field, the TTL, then KeepFields; "debug"
	// (not kept) is gone with the copy of the token it held.
	if !strings.HasPrefix(out, `{"worker_jwt":`) || strings.Contains(out, "debug") || !strings.Contains(out, `"mcp_config":{`) {
		t.Fatalf("output shape: %s", out)
	}
}

func TestSwapIssuedSessionTokenEscapedCopies(t *testing.T) {
	// A JSON encoder may write "/" as "\/". A token with "/" must not
	// survive in either spelling anywhere in the body.
	tok := "abc/def.ghi/jkl.mnopqrstuvwxyz0123"
	esc := strings.ReplaceAll(tok, "/", `\/`)
	body := `{"worker_jwt":"` + esc + `","expires_in":60,"note":"` + tok + `","note2":"` + esc + `"}`
	resp := bridgeResponse(200, body, nil)
	rec := &issueRecorder{}
	if _, err := swapIssuedSessionToken(resp, testGrant, rec.issue); err != nil {
		t.Fatalf("swap: %v", err)
	}
	out := readAll(t, resp)
	if strings.Contains(out, tok) || strings.Contains(out, esc) {
		t.Fatalf("a copy of the token survived: %s", out)
	}
	if len(rec.tokens) != 1 || rec.tokens[0] != tok {
		t.Fatalf("issued %q, want the decoded token", rec.tokens)
	}
}

// A key spelled with escapes is the same key to every JSON parser,
// Claude Code's included, so it is the token field and gets swapped.
func TestSwapIssuedSessionTokenEscapedKey(t *testing.T) {
	body := `{"worker\u005fjwt":"` + realWorkerToken + `","expires_in":60,"x":"` + realWorkerToken + `"}`
	resp := bridgeResponse(200, body, nil)
	rec := &issueRecorder{}
	if _, err := swapIssuedSessionToken(resp, testGrant, rec.issue); err != nil {
		t.Fatalf("swap: %v", err)
	}
	out := readAll(t, resp)
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil || strings.Contains(out, realWorkerToken) {
		t.Fatalf("rewrite left the token or broke the JSON (err %v)", err)
	}
	if got["worker_jwt"] != sessionTokenPlaceholderPrefix+"0123456789abcdef0123456789abcdef" {
		t.Fatalf("worker_jwt = %v", got["worker_jwt"])
	}
}

// Only a non-2xx with no token-like content passes through; see
// TestSwapIssuedSessionTokenFailsClosed for everything that doesn't.
func TestSwapIssuedSessionTokenPassesThroughWithoutToken(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{
		{409, `{"error":{"type":"conflict","expected_epoch":3,"actual_epoch":4}}`},
		{403, `{"error":{"type":"untrusted_device"}}`},
		{500, `upstream broke`},
		{404, ``},
	} {
		resp := bridgeResponse(tc.status, tc.body, nil)
		rec := &issueRecorder{}
		if _, err := swapIssuedSessionToken(resp, testGrant, rec.issue); err != nil {
			t.Errorf("%d %q: %v; a response with no token must pass through", tc.status, tc.body, err)
			continue
		}
		out := readAll(t, resp)
		if len(rec.tokens) != 0 {
			t.Errorf("%d: issued %d", tc.status, len(rec.tokens))
		}
		if !json.Valid([]byte(tc.body)) {
			if out != "" {
				t.Errorf("%d: a non-JSON body must be dropped, got %q", tc.status, out)
			}
			continue
		}
		if !jsonEqual(t, out, tc.body) {
			t.Errorf("%d: body meaning changed: %q", tc.status, out)
		}
	}
}

// Every response the gateway can't prove token-free after a rewrite is
// refused (the caller answers 502), and the token never reaches the
// caller's copy of the body.
func TestSwapIssuedSessionTokenFailsClosed(t *testing.T) {
	big := `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"pad":"` + strings.Repeat("x", sessionTokenMaxBody) + `"}`
	cases := []struct {
		name   string
		status int
		body   string
		hdr    http.Header
		rec    *issueRecorder
	}{
		{"gzip encoded", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60}`, http.Header{"Content-Encoding": {"gzip"}}, nil},
		{"br encoded", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60}`, http.Header{"Content-Encoding": {"br"}}, nil},
		{"too big", 200, big, nil, nil},
		{"not json", 200, `worker_jwt=` + realWorkerToken, nil, nil},
		{"json array", 200, `[{"worker_jwt":"` + realWorkerToken + `","expires_in":60}]`, nil, nil},
		{"json string", 200, `"` + realWorkerToken + `"`, nil, nil},
		{"trailing data", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60}{"x":1}`, nil, nil},
		{"truncated", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60`, nil, nil},
		{"token not a string", 200, `{"worker_jwt":{"t":"` + realWorkerToken + `"},"expires_in":60}`, nil, nil},
		{"token with space", 200, `{"worker_jwt":"` + realWorkerToken + ` x","expires_in":60}`, nil, nil},
		{"token with quote escape", 200, `{"worker_jwt":"` + realWorkerToken + `\"x","expires_in":60}`, nil, nil},
		{"token too short", 200, `{"worker_jwt":"abc","expires_in":60}`, nil, nil},
		{"empty token", 200, `{"worker_jwt":"","expires_in":60}`, nil, nil},
		{"ttl missing", 200, `{"worker_jwt":"` + realWorkerToken + `"}`, nil, nil},
		{"ttl string", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":"60"}`, nil, nil},
		{"ttl zero", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":0}`, nil, nil},
		{"ttl negative", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":-5}`, nil, nil},
		{"ttl null", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":null}`, nil, nil},
		{"duplicate token key", 200, `{"worker_jwt":"` + realWorkerToken + `","worker_jwt":"` + realWorkerToken + `x","expires_in":60}`, nil, nil},
		{"duplicate escaped key", 200, `{"worker_jwt":"` + realWorkerToken + `","worker_jwt":"other-token-value-0123456789","expires_in":60}`, nil, nil},
		{"nested token field", 200, `{"worker_jwt":"` + realWorkerToken + `","mcp_config":{"worker_jwt":"` + realWorkerToken + `x"},"expires_in":60}`, nil, nil},
		{"nested escaped token field", 200, `{"worker_jwt":"` + realWorkerToken + `","mcp_config":[{"worker\u005fjwt":"` + realWorkerToken + `x"}],"expires_in":60}`, nil, nil},
		{"duplicate ttl key", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"expires_in":99999999}`, nil, nil},
		{"token in a header", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60}`, http.Header{"X-Debug": {"t=" + realWorkerToken}}, nil},
		{"token on a non-200", 401, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60}`, nil, nil},
		{"nested token field on a non-200", 409, `{"error":{"worker_jwt":"` + realWorkerToken + `"}}`, nil, nil},
		// Review #25 I1/I2/M3/M4/M5: the token in any other spelling or
		// place, or a 2xx without exactly one top-level token field.
		{"unicode-escaped copy", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"api_base_url":"\u0065` + realWorkerToken[1:] + `"}`, nil, nil},
		{"fully escaped copy", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"mcp_config":{"x":"` + uEscapeAll(realWorkerToken) + `"}}`, nil, nil},
		{"percent-encoded copy", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"api_base_url":"https://x/?t=` + strings.ReplaceAll(realWorkerToken, ".", "%2E") + `"}`, nil, nil},
		{"no token field", 200, `{"api_base_url":"https://api.anthropic.com","worker_epoch":7}`, nil, nil},
		{"renamed camel", 200, `{"workerJwt":"` + realWorkerToken + `","expires_in":60}`, nil, nil},
		{"renamed upper", 200, `{"WORKER_JWT":"` + realWorkerToken + `","expires_in":60}`, nil, nil},
		{"renamed nested", 200, `{"worker":{"jwt":"` + realWorkerToken + `"},"expires_in":60}`, nil, nil},
		{"201 other field", 201, `{"jwt":"` + realWorkerToken + `"}`, nil, nil},
		{"204 empty", 204, ``, nil, nil},
		{"non-200 escaped jwt", 400, `{"error":"\u0065` + realWorkerToken[1:] + `"}`, nil, nil},
		{"second jwt-shaped value", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"mcp_config":{"other":"eyJhbGciOiJub25lIn0.eyJ4IjoxfQ.c2ln"}}`, nil, nil},
		{"multi content-encoding", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60}`, http.Header{"Content-Encoding": {"identity", "gzip"}}, nil},
		{"multi content-encoding non-200", 409, `{}`, http.Header{"Content-Encoding": {"identity", "gzip"}}, nil},
		// Each layer on its own: an opaque (non-JWT) token, so the JWT
		// shape check can't stand in for the field checks.
		{"opaque: non-200 names the field", 409, `{"error":{"worker_jwt":"` + opaqueToken + `"}}`, nil, nil},
		{"opaque: duplicate key", 200, `{"worker_jwt":"` + opaqueToken + `","worker_jwt":"` + opaqueToken + `x","expires_in":60}`, nil, nil},
		{"opaque: nested field", 200, `{"worker_jwt":"` + opaqueToken + `","expires_in":60,"mcp_config":{"worker_jwt":"` + opaqueToken + `y"}}`, nil, nil},
		// Parser differentials: Go replaces invalid UTF-8 and lone
		// surrogates with U+FFFD where a JavaScript client may not.
		{"invalid utf-8", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"x":"` + "\xff\xfe" + `"}`, nil, nil},
		{"lone surrogate escape", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"x":"\ud800"}`, nil, nil},
		{"surrogate in key", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"\udc00":1}`, nil, nil},
		{"bom", 200, "\ufeff" + `{"worker_jwt":"` + realWorkerToken + `","expires_in":60}`, nil, nil},
		// Fail-open on non-2xx: the token in a header of an error or a
		// redirect.
		{"redirect location", 302, ``, http.Header{"Location": {"https://x/?t=" + realWorkerToken}}, nil},
		{"error header", 401, `{}`, http.Header{"X-Trace": {realWorkerToken}}, nil},
		// Review #25 round 2.
		{"N1 duplicate top-level key", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"api_base_url":"\u0065` + realWorkerToken[1:] + `","api_base_url":"https://x"}`, nil, nil},
		{"N2 percent token behind an invalid escape", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"api_base_url":"https://x/?a=%zz&t=%65` + realWorkerToken[1:] + `"}`, nil, nil},
		{"N2 non-2xx percent token behind an invalid escape", 409, `{"error":{"u":"%zz%65` + realWorkerToken[1:] + `"}}`, nil, nil},
		{"N3 2xx header percent-encoded", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60}`, http.Header{"X-Echo": {"%65" + realWorkerToken[1:]}}, nil},
		// Review #25 round 3: the token base64- or hex-encoded in a kept
		// field, alone, inside text, or inside an encoded JSON blob.
		{"R3 mcp_config base64 json blob", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"mcp_config":"` + base64.StdEncoding.EncodeToString([]byte(`{"mcpServers":{"meta":{"headers":{"Authorization":"Bearer `+realWorkerToken+`"}}}}`)) + `"}`, nil, nil},
		{"R3 base64url of token", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"mcp_config":{"auth":"` + base64.RawURLEncoding.EncodeToString([]byte(realWorkerToken)) + `"}}`, nil, nil},
		{"R3 base64 in text", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"mcp_config":{"h":"Bearer ` + base64.StdEncoding.EncodeToString([]byte(realWorkerToken)) + ` x"}}`, nil, nil},
		{"R3 hex of token", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"mcp_config":{"k":"` + hex.EncodeToString([]byte(realWorkerToken)) + `"}}`, nil, nil},
		{"R3 base64 of opaque token", 200, `{"worker_jwt":"` + opaqueToken + `","expires_in":60,"api_base_url":"https://x/` + base64.StdEncoding.EncodeToString([]byte(opaqueToken)) + `"}`, nil, nil},
		{"R3 escaped token in a base64 json blob", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"mcp_config":"` + base64.StdEncoding.EncodeToString([]byte(`{"a":"`+uEscapeAll(realWorkerToken)+`"}`)) + `"}`, nil, nil},
		{"R3 misaligned base64 run", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"mcp_config":{"b":"QQ` + base64.StdEncoding.EncodeToString([]byte("ab"+realWorkerToken)) + `"}}`, nil, nil},
		{"R3 non-2xx url-base64 of a jwt after a slash", 403, `{"detail":"https://xy/` + base64.URLEncoding.EncodeToString([]byte(realWorkerToken)) + `"}`, nil, nil},
		{"R3 nibble-shifted hex", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"mcp_config":{"h":"a` + hex.EncodeToString([]byte(realWorkerToken)) + `b"}}`, nil, nil},
		{"R3 line-wrapped base64", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"mcp_config":{"w":"` + wrapEvery(base64.StdEncoding.EncodeToString([]byte("xy"+realWorkerToken)), 20, `\n`) + `"}}`, nil, nil},
		{"R3 non-2xx hex of a jwt", 409, `{"d":"` + hex.EncodeToString([]byte(realWorkerToken)) + `"}`, nil, nil},
		{"R3 non-2xx base64 of a jwt", 403, `{"source":"x","detail":"` + base64.StdEncoding.EncodeToString([]byte(realWorkerToken)) + `"}`, nil, nil},
		{"R3 header base64 of token", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60}`, http.Header{"X-T": {base64.StdEncoding.EncodeToString([]byte(realWorkerToken))}}, nil},
		// Review #25 round 4: a token with whitespace inside a kept field,
		// and oversized headers (a decode-work DoS otherwise).
		{"R4 spaced token", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"mcp_config":{"s":"` + strings.Join(strings.Split(realWorkerToken, ""), " ") + `"}}`, nil, nil},
		{"R4 newline token", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"mcp_config":{"s":"` + wrapEvery(realWorkerToken, 7, `\n`) + `"}}`, nil, nil},
		{"R4 header value over the cap", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60}`, http.Header{"X-Big": {strings.Repeat("A", 9<<10)}}, nil},
		{"R4 headers over the total cap", 409, `{}`, bigHeaders(40, 1<<10), nil},
		{"store refuses", 200, `{"worker_jwt":"` + realWorkerToken + `","expires_in":60}`, nil, &issueRecorder{fail: fmt.Errorf("no agent identity")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := bridgeResponse(tc.status, tc.body, tc.hdr)
			rec := tc.rec
			if rec == nil {
				rec = &issueRecorder{}
			}
			_, err := swapIssuedSessionToken(resp, testGrant, rec.issue)
			if err == nil {
				t.Fatalf("swap accepted it; want a refusal")
			}
			if strings.Contains(err.Error(), realWorkerToken) {
				t.Fatal("the error text carries the token")
			}
			if strings.Contains(err.Error(), "gzip") || strings.Contains(err.Error(), "br\"") {
				t.Fatal("the error text quotes upstream header bytes")
			}
			if tc.rec == nil && len(rec.tokens) != 0 {
				t.Fatalf("issued %d placeholder(s) for a refused response", len(rec.tokens))
			}
		})
	}
}

// Review #25 round 2 (N1): the agent gets a canonical re-encoding of
// exactly what was checked, and only the fields clients read. A
// duplicate nested key resolves the way every parser of the canonical
// bytes reads it; unknown top-level fields are dropped.
func TestSwapIssuedSessionTokenCanonicalOutput(t *testing.T) {
	body := `{"debug":"anything","worker_jwt":"` + realWorkerToken + `","expires_in":60.5,"worker_epoch":"7","api_base_url":"https:\/\/api.anthropic.com","mcp_config":{"a":"\u0065` + realWorkerToken[1:] + `","a":"ok","n":[1,2.50,{"k":null}]}}`
	resp := bridgeResponse(200, body, nil)
	rec := &issueRecorder{}
	if _, err := swapIssuedSessionToken(resp, testGrant, rec.issue); err != nil {
		t.Fatalf("swap: %v", err)
	}
	out := readAll(t, resp)
	if strings.Contains(out, "debug") {
		t.Fatal("an unlisted top-level field reached the agent")
	}
	if strings.Contains(out, `\u`) || strings.Contains(out, realWorkerToken) || strings.Contains(out, realWorkerToken[1:]) {
		t.Fatalf("output is not canonical or holds the token: %s", out)
	}
	want := `{"worker_jwt":"` + sessionTokenPlaceholderPrefix + `0123456789abcdef0123456789abcdef","expires_in":60.5,"api_base_url":"https://api.anthropic.com","worker_epoch":"7","mcp_config":{"a":"ok","n":[1,2.50,{"k":null}]}}`
	if out != want {
		t.Fatalf("output\n got %s\nwant %s", out, want)
	}
}

// A non-2xx JSON body is forwarded as the canonical re-encoding of what
// was checked, never as upstream bytes: an earlier duplicate key holding
// an escaped token is gone.
func TestSwapIssuedSessionTokenNon2xxCanonical(t *testing.T) {
	body := `{"error":{"m":"\u0065` + realWorkerToken[1:] + `","m":"ok"}}`
	resp := bridgeResponse(409, body, nil)
	if _, err := swapIssuedSessionToken(resp, testGrant, (&issueRecorder{}).issue); err != nil {
		t.Fatalf("swap: %v", err)
	}
	out := readAll(t, resp)
	if strings.Contains(out, realWorkerToken[1:]) || out != `{"error":{"m":"ok"}}` {
		t.Fatalf("forwarded %q, want the canonical {\"error\":{\"m\":\"ok\"}}", out)
	}
}

// A non-2xx body that isn't JSON is dropped (the agent gets the status
// and an empty body), whatever it holds.
func TestSwapIssuedSessionTokenDropsNon2xxText(t *testing.T) {
	for _, body := range []string{"oops worker_jwt=" + realWorkerToken, "trace: " + realWorkerToken, "worker_jwt=" + opaqueToken, "plain text"} {
		resp := bridgeResponse(500, body, nil)
		if _, err := swapIssuedSessionToken(resp, testGrant, (&issueRecorder{}).issue); err != nil {
			t.Fatalf("%.20q: %v", body, err)
		}
		if out := readAll(t, resp); out != "" || resp.StatusCode != 500 {
			t.Fatalf("%.20q: forwarded %d %q, want 500 with an empty body", body, resp.StatusCode, out)
		}
	}
}

// Review #25 round 4 (R4-1): the token scan has a work budget; a
// pathological input is refused quickly instead of burning CPU.
func TestSwapIssuedSessionTokenScanIsBounded(t *testing.T) {
	// The reviewer's worst case: a percent layer and a JSON string at
	// every level of a three-deep base64 chain (about 0.9 s unbounded).
	l := alnum(14000)
	for range 3 {
		j, _ := json.Marshal("%252525" + l)
		l = "%252525" + base64.StdEncoding.EncodeToString(j)
	}
	body := `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"mcp_config":{"p":"` + l + `"}}`
	if len(body) > sessionTokenMaxBody {
		body = body[:0] + `{"worker_jwt":"` + realWorkerToken + `","expires_in":60,"mcp_config":{"p":"` + l[:sessionTokenMaxBody-200] + `"}}`
	}
	// Deterministic: the scanner runs out of budget and says "holds".
	sc := newTokenScan(realWorkerToken)
	if !sc.holds(l) || sc.budget >= 0 {
		t.Fatalf("pathological input: holds=%v budget left %d; want the budget spent and a refusal", sc.holds(l), sc.budget)
	}
	// End to end it is refused, well within a generous wall-clock bound
	// (unbounded, this input took about 1 s, and ~10x that under -race).
	start := time.Now()
	_, err := swapIssuedSessionToken(bridgeResponse(200, body, nil), testGrant, (&issueRecorder{}).issue)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("scan took %v; the work budget must bound it", d)
	}
	if err == nil {
		t.Fatal("a scan that ran out of budget passed; it must refuse")
	}
}

// alnum returns n deterministic alphanumeric characters.
func alnum(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	x := uint32(7)
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = chars[x>>24%uint32(len(chars))]
	}
	return string(b)
}

func TestSwapIssuedSessionTokenCapsReadAtLimit(t *testing.T) {
	// An endless body must not be read without bound.
	resp := bridgeResponse(200, "", nil)
	resp.ContentLength = -1
	resp.Body = io.NopCloser(io.MultiReader(strings.NewReader(`{"worker_jwt":"`+realWorkerToken+`","pad":"`), infiniteX{}))
	done := make(chan error, 1)
	go func() {
		_, err := swapIssuedSessionToken(resp, testGrant, (&issueRecorder{}).issue)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an endless body was accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("swap read an endless body without a limit")
	}
}

type infiniteX struct{}

func (infiniteX) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

// FuzzSwapIssuedSessionToken: whatever the upstream sends, when the swap
// says yes the agent-bound body and headers hold no copy of the token
// it saw, and when it says no nothing was issued.
func FuzzSwapIssuedSessionToken(f *testing.F) {
	f.Add(`{"worker_jwt":"`+realWorkerToken+`","expires_in":60}`, realWorkerToken, 200)
	f.Add(`{"a":1,"worker_jwt":"`+realWorkerToken+`","expires_in":1.5,"b":["`+realWorkerToken+`"]}`, realWorkerToken, 200)
	f.Add(`{"worker_jwt":"a\/b\/c.defghijklmnop","expires_in":60}`, "a/b/c.defghijklmnop", 200)
	f.Add(`{"worker_jwt":"`+realWorkerToken+`","expires_in":60}`, realWorkerToken, 200)
	f.Add(`{}`, "", 409)
	f.Fuzz(func(t *testing.T, body, planted string, status int) {
		if status < 100 || status > 599 {
			return
		}
		resp := bridgeResponse(status, body, nil)
		rec := &issueRecorder{}
		tok, err := swapIssuedSessionToken(resp, testGrant, rec.issue)
		if err != nil {
			return
		}
		out, rerr := io.ReadAll(resp.Body)
		if rerr != nil {
			t.Fatal(rerr)
		}
		if tok != "" {
			if bytes.Contains(out, []byte(tok)) || bytes.Contains(out, []byte(strings.ReplaceAll(tok, "/", `\/`))) {
				t.Fatalf("accepted, but the body still holds the token")
			}
			if len(rec.tokens) != 1 || rec.tokens[0] != tok {
				t.Fatalf("accepted %q but issued %q", tok, rec.tokens)
			}
			var m map[string]json.RawMessage
			if err := json.Unmarshal(out, &m); err != nil {
				t.Fatalf("accepted, but the body is not a JSON object: %v", err)
			}
		} else {
			if status/100 == 2 {
				t.Fatalf("a %d passed through; a 2xx must carry exactly one token or be refused", status)
			}
			if len(rec.tokens) != 0 {
				t.Fatal("pass-through issued a placeholder")
			}
			if len(out) != 0 && !json.Valid(out) {
				t.Fatal("a non-2xx was forwarded with a non-JSON body")
			}
			if jwtLike.Match(out) {
				t.Fatal("a non-2xx was forwarded holding something JWT-shaped")
			}
			// A pass-through body never carries a decodable token field.
			var m map[string]json.RawMessage
			if json.Unmarshal(out, &m) == nil {
				if _, ok := m["worker_jwt"]; ok {
					t.Fatalf("passed through a body with a worker_jwt field")
				}
			}
		}
	})
}

// uEscapeAll spells every byte of s as a JSON \u escape.
func uEscapeAll(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, `\u%04x`, r)
	}
	return b.String()
}

// jsonEqual reports whether a and b decode to the same JSON value.
func jsonEqual(t *testing.T, a, b string) bool {
	t.Helper()
	var va, vb any
	if err := json.Unmarshal([]byte(a), &va); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(b), &vb); err != nil {
		return false
	}
	ja, _ := json.Marshal(va)
	jb, _ := json.Marshal(vb)
	return string(ja) == string(jb)
}

// wrapEvery inserts sep after every n characters of s.
func wrapEvery(s string, n int, sep string) string {
	var b strings.Builder
	for i := 0; i < len(s); i += n {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(s[i:min(i+n, len(s))])
	}
	return b.String()
}

// bigHeaders returns n headers of size bytes each.
func bigHeaders(n, size int) http.Header {
	h := http.Header{}
	for i := range n {
		h.Set(fmt.Sprintf("X-H%d", i), strings.Repeat("a", size))
	}
	return h
}
