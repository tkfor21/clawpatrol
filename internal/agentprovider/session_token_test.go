package agentprovider

import (
	"net/url"
	"testing"
)

func sessionTokenProviders() []*Provider {
	return []*Provider{{
		ID: "alpha", DisplayName: "Alpha",
		APIHosts: []string{"api.alpha.test"},
		SessionTokens: []SessionTokenGrant{{
			Host:       "api.alpha.test",
			IssuePath:  "/v1/code/sessions/{id}/bridge",
			UsePath:    "/v1/code/sessions/{id}/worker",
			TokenField: "worker_jwt",
			TTLField:   "expires_in",
			KeepFields: []string{"api_base_url", "worker_epoch", "mcp_config"},
		}},
	}}
}

// The issue side matches every spelling the normalizer covers (I15: an
// off gateway refuses them all, an on gateway rewrites them all). The use side matches only the canonical
// spelling, so the real token never leaves on an ambiguous path.
func TestSessionTokenFor(t *testing.T) {
	withProviders(t, sessionTokenProviders()...)
	cases := []struct {
		host, rawURL string
		role         SessionTokenRole
		id           string
	}{
		// Issue: canonical and every normalizing spelling.
		{"api.alpha.test", "/v1/code/sessions/cse_01AbC-9/bridge", SessionTokenIssue, "cse_01AbC-9"},
		{"API.alpha.test:443", "/v1/code/sessions/cse_1/bridge", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/bridge/", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "//v1//code/sessions/cse_1/bridge", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/./bridge", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/x/../bridge", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/V1/Code/Sessions/cse_1/BRIDGE", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/%62ridge", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/bridge?x=1", SessionTokenIssue, "cse_1"},
		// Matrix parameters some server stacks drop before routing.
		{"api.alpha.test", "/v1/code/sessions/cse_1/bridge;x=1", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1;v=2/bridge", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/bridge%3Bx", SessionTokenIssue, "cse_1"},
		// An id the template can't bind is still an issue request, with
		// no id: an off gateway refuses it, an on gateway fails closed.
		{"api.alpha.test", "/v1/code/sessions/a%2Fb/bridge", SessionTokenIssue, ""},
		{"api.alpha.test", "/v1/code/sessions/a.b/bridge", SessionTokenIssue, ""},
		{"api.alpha.test", "/v1/code/sessions/%20/bridge", SessionTokenIssue, ""},
		// Router differentials: a backslash some stacks treat as "/",
		// and a second layer of percent-encoding some stacks decode.
		{"api.alpha.test", `/v1/code/sessions/cse_1\bridge`, SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1%5Cbridge", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/%2562ridge", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1%252Fbridge", SessionTokenIssue, "cse_1"},
		// Review #25 round 2: Tomcat-style "..;", trailing junk on the
		// last segment, fullwidth and zero-width characters, "?"/"#"
		// smuggled escaped, and a third encoding layer.
		{"api.alpha.test", "/v1/code/sessions/cse_1/x/..;/bridge", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/x/..%3B/bridge", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/bridge%20", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/bridge%00", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/bridge.", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/bridge.json", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/bridge%3Fx", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/bridge%23x", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/%EF%BD%82%EF%BD%92%EF%BD%89%EF%BD%84%EF%BD%87%EF%BD%85", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/bri%E2%80%8Bdge", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1%25252Fbridge", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/%EF%BD%83ode/sessions/cse_1/bridge", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code%20/sessions/cse_1/bridge", SessionTokenIssue, "cse_1"},
		{"api.alpha.test", "/v1/code./sessions/cse_1/bridge", SessionTokenIssue, "cse_1"},
		// Use: canonical only.
		{"api.alpha.test", "/v1/code/sessions/cse_1/worker", SessionTokenUse, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/worker/events", SessionTokenUse, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/worker/events/delivery", SessionTokenUse, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/worker?epoch=3", SessionTokenUse, "cse_1"},
		{"api.alpha.test", "/v1/code/sessions/cse_1/worker/", SessionTokenNone, ""},
		{"api.alpha.test", "/v1/code/sessions/cse_1/worker/../worker", SessionTokenNone, ""},
		{"api.alpha.test", "//v1/code/sessions/cse_1/worker", SessionTokenNone, ""},
		{"api.alpha.test", "/v1/code/sessions/cse_1/Worker", SessionTokenNone, ""},
		{"api.alpha.test", "/v1/code/sessions/cse_1/worker%2Fevents", SessionTokenNone, ""},
		{"api.alpha.test", "/v1/code/sessions/cse_1/%77orker", SessionTokenNone, ""},
		{"api.alpha.test", "/v1/code/sessions/cse_1/workers", SessionTokenNone, ""},
		{"api.alpha.test", "/v1/code/sessions/cse_1/worker/../../../api/oauth/profile", SessionTokenNone, ""},
		{"api.alpha.test", "/v1/code/sessions/a.b/worker", SessionTokenNone, ""},
		{"api.alpha.test", "/v1/code/sessions/cse_1/worker;x", SessionTokenNone, ""},
		{"api.alpha.test", `/v1/code/sessions/cse_1\worker`, SessionTokenNone, ""},
		{"api.alpha.test", "/v1/code/sessions/cse_1/worker%20", SessionTokenNone, ""},
		{"api.alpha.test", "/v1/code/sessions/cse_1/worker.json", SessionTokenNone, ""},
		// Elsewhere.
		{"api.alpha.test", "/v1/code/sessions/cse_1", SessionTokenNone, ""},
		{"api.alpha.test", "/v1/code/sessions/cse_1/client/presence", SessionTokenNone, ""},
		{"api.alpha.test", "/v1/messages", SessionTokenNone, ""},
		{"other.test", "/v1/code/sessions/cse_1/bridge", SessionTokenNone, ""},
		{"other.test", "/v1/code/sessions/cse_1/worker", SessionTokenNone, ""},
	}
	for _, tc := range cases {
		u, err := url.Parse("https://" + tc.host + tc.rawURL)
		if err != nil {
			t.Fatalf("%s: %v", tc.rawURL, err)
		}
		p, g, role, id := SessionTokenFor(tc.host, u)
		if role != tc.role || id != tc.id {
			t.Errorf("%s%s: role %v id %q, want %v %q", tc.host, tc.rawURL, role, id, tc.role, tc.id)
			continue
		}
		if role == SessionTokenNone {
			if p != nil || g != nil {
				t.Errorf("%s%s: no match must return nil provider and grant", tc.host, tc.rawURL)
			}
			continue
		}
		if p == nil || p.ID != "alpha" || g == nil || g.TokenField != "worker_jwt" {
			t.Errorf("%s%s: got provider %v grant %v", tc.host, tc.rawURL, p, g)
		}
	}
}

func TestSessionTokenForNilURL(t *testing.T) {
	withProviders(t, sessionTokenProviders()...)
	if _, _, role, _ := SessionTokenFor("api.alpha.test", nil); role != SessionTokenNone {
		t.Fatalf("nil URL: role %v", role)
	}
}

// Review #25 C1, defense in depth: an opaque target ("scheme:path") has
// no Path; on a grant host it is still an issue request (with no id),
// so an off gateway refuses it and an on gateway fails closed.
func TestSessionTokenForOpaque(t *testing.T) {
	withProviders(t, sessionTokenProviders()...)
	for _, raw := range []string{"http:v1/code/sessions/abc/bridge", "x:v1/code/sessions/abc/worker", "https:anything"} {
		u, err := url.Parse(raw)
		if err != nil || u.Opaque == "" {
			t.Fatalf("%s: not opaque (err %v)", raw, err)
		}
		if _, _, role, id := SessionTokenFor("api.alpha.test", u); role != SessionTokenIssue || id != "" {
			t.Errorf("%s: role %v id %q, want an issue request with no id", raw, role, id)
		}
		if _, _, role, _ := SessionTokenFor("other.test", u); role != SessionTokenNone {
			t.Errorf("%s on another host: role %v", raw, role)
		}
	}
}
