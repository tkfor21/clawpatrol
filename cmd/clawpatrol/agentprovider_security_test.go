package main

import (
	"bytes"
	"context"
	"fmt"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/agentprovider"
	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// TestSecurityAuthHostsNeverForwarded pins I12 and DEV-4 (gate before
// endpoint lookup): whatever unknown_host says, and even when an HCL
// endpoint explicitly claims the auth host, the agent gets 403 and the
// gateway neither dials (MITM transport or splice) nor resolves the host.
func TestSecurityAuthHostsNeverForwarded(t *testing.T) { // I12
	var authHosts []string
	for _, p := range agentprovider.All() {
		authHosts = append(authHosts, p.AuthHosts...)
	}
	claimed := `"` + strings.Join(authHosts, `", "`) + `"`
	policies := []struct {
		name, hcl, endpoint string
	}{
		{"unknown_host=inspect", authGateHCL, "unknown"},
		{"unknown_host=passthrough", withUnknownHost(authGateHCL, "passthrough"), "unknown"},
		{"unknown_host=deny", withUnknownHost(authGateHCL, "deny"), "unknown"},
		{"endpoint claims auth hosts", fmt.Sprintf(`
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "https" "authclaim" { hosts = [%s] }

rule "allow-all" {
  endpoint  = https.authclaim
  condition = "true"
  verdict   = "allow"
}

profile "default" { credentials = [] }
`, claimed), "authclaim"},
	}
	for _, pol := range policies {
		for _, p := range agentprovider.All() {
			for _, host := range p.AuthHosts {
				h := newCredentialMatchHarness(t, pol.hcl, pol.endpoint)
				dialer := &recordingDialer{}
				resolver := &tableResolver{answers: [][]netip.Addr{addrs(t, "203.0.113.10")}}
				h.gateway.dialer, h.gateway.resolver = dialer, resolver
				status, _, _ := gatewaySend(t, h.gateway, host, http.MethodGet, "/", nil, "")
				if status != http.StatusForbidden {
					t.Errorf("%s: %s/%s GET / = %d, want 403", pol.name, p.ID, host, status)
				}
				if got, _ := h.dialedAddr.Load().(string); got != "" {
					t.Errorf("%s: %s/%s was forwarded through the MITM transport to %q", pol.name, p.ID, host, got)
				}
				if len(dialer.asked) != 0 || resolver.calls != 0 {
					t.Errorf("%s: %s/%s: splice path dialed %v / resolved %d time(s)", pol.name, p.ID, host, dialer.asked, resolver.calls)
				}
			}
		}
	}
}

// withUnknownHost switches authGateHCL's unknown_host policy. Its
// allow-all rule on https.unknown is valid only under "inspect"
// (compile.go), so any other policy disables it.
func withUnknownHost(hcl, policy string) string {
	hcl = strings.Replace(hcl, `unknown_host = "inspect"`, `unknown_host = "`+policy+`"`, 1)
	return strings.Replace(hcl, `verdict   = "allow"`, "verdict   = \"allow\"\n  disabled  = true", 1)
}

// TestSecurityAuthPathsNeverForwarded pins D1 for every provider's
// AuthPaths rule: 403 and no dial, in every spelling an upstream would
// normalize, under unknown_host = "inspect" and under an endpoint that
// claims the host with a bound credential. A path no rule covers on the
// same host is still forwarded, so no rule gates a whole host. Under
// unknown_host = "passthrough" an unclaimed host is spliced and never
// reaches the MITM loop; the user kept that documented scope (R2-D1).
func TestSecurityAuthPathsNeverForwarded(t *testing.T) { // I12, D1
	t.Setenv("CLAWPATROL_SECRET_TOK", testSecret)
	type rule struct {
		p  *agentprovider.Provider
		ap agentprovider.AuthPath
	}
	var rules []rule
	var hosts []string
	for _, p := range agentprovider.All() {
		for _, ap := range p.AuthPaths {
			rules = append(rules, rule{p, ap})
			if !slices.Contains(hosts, ap.Host) {
				hosts = append(hosts, ap.Host)
			}
		}
	}
	if len(rules) == 0 {
		t.Fatal("no provider declares AuthPaths; the D1 rules are missing")
	}
	claimHCL := fmt.Sprintf(`
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "https" "pathclaim" { hosts = [%s] }

credential "bearer_token" "tok" { endpoint = https.pathclaim }

rule "allow-all" {
  endpoint  = https.pathclaim
  condition = "true"
  verdict   = "allow"
}

profile "default" { credentials = [bearer_token.tok] }
`, `"`+strings.Join(hosts, `", "`)+`"`)
	policies := []struct {
		name, hcl, endpoint string
	}{
		{"unknown_host=inspect", authGateHCL, "unknown"},
		{"endpoint claims the host, credential bound", claimHCL, "pathclaim"},
	}
	hdr := http.Header{"Authorization": {"Bearer placeholder"}}
	for _, pol := range policies {
		for _, r := range rules {
			sample := r.ap.Path
			if r.ap.Match == agentprovider.PathPrefix {
				sample += "x"
			}
			for _, path := range []string{sample, strings.ToUpper(sample), "/zz/.." + sample, "/" + sample} {
				h := newCredentialMatchHarness(t, pol.hcl, pol.endpoint)
				status, _, _ := gatewaySend(t, h.gateway, r.ap.Host, http.MethodPost, path, hdr, "{}")
				if status != http.StatusForbidden {
					t.Errorf("%s: %s %s%s = %d, want 403", pol.name, r.p.ID, r.ap.Host, path, status)
				}
				if got, _ := h.dialedAddr.Load().(string); got != "" {
					t.Errorf("%s: %s %s%s was forwarded to %q", pol.name, r.p.ID, r.ap.Host, path, got)
				}
			}
		}
		for _, host := range hosts {
			h := newCredentialMatchHarness(t, pol.hcl, pol.endpoint)
			status, _, _ := gatewaySend(t, h.gateway, host, http.MethodGet, "/clawpatrol-not-a-login-path", hdr, "")
			if got, _ := h.dialedAddr.Load().(string); status != http.StatusOK || got == "" {
				t.Errorf("%s: GET %s/clawpatrol-not-a-login-path = %d (dialed %q); a path rule must not gate the whole host", pol.name, host, status, got)
			}
		}
	}
}

// TestSecurityAuthHostsGatedOnRelays pins D3 for every provider auth
// host: a ClientHello naming it on a non-443 relay, whole or split
// across TLS records (S101), is refused with zero bytes delivered
// upstream.
func TestSecurityAuthHostsGatedOnRelays(t *testing.T) { // I12, D3
	for _, p := range agentprovider.All() {
		for _, host := range p.AuthHosts {
			for _, fragment := range []bool{false, true} {
				hello := captureClientHello(t, host)
				if fragment {
					hello = fragmentRecord(hello, 64)
				}
				r := newRelayGateRig(t, "")
				agent, done := r.relay(t)
				go func() { _, _ = agent.Write(hello) }()
				waitDone(t, done)
				if b := r.upstreamBytes(t); len(b) != 0 {
					t.Errorf("%s/%s (fragmented=%v): upstream received %d byte(s) on a non-443 relay", p.ID, host, fragment, len(b))
				}
				if ev := awaitRelayEvent(t, r.sink); ev.Mode != "auth-gate" || ev.Action != "deny" {
					t.Errorf("%s/%s (fragmented=%v): relay event = %+v, want an auth-gate deny", p.ID, host, fragment, ev)
				}
			}
		}
	}
}

// TestSecurityAuthHostsGatedOnHelloTricks pins D-R4-10 (A) for every
// provider auth host, on 443 passthrough (Gateway.handle's splice) and on
// a non-443 relay, which share gateClientHellos: a server_name list that
// puts a decoy before the auth host, and a ClientHello 2 that swaps to
// the auth host after a HelloRetryRequest, are both refused. No byte of
// the auth-host ClientHello reaches the upstream (after an HRR the
// upstream holds ClientHello 1, which named the decoy, and nothing more).
func TestSecurityAuthHostsGatedOnHelloTricks(t *testing.T) { // I12, D3, D-R4-10
	paths := []struct {
		name  string
		start func(r *relayGateRig, t *testing.T) (net.Conn, <-chan struct{})
	}{
		{"443 passthrough", func(r *relayGateRig, t *testing.T) (net.Conn, <-chan struct{}) { return r.spliceStart(t) }},
		{"non-443 relay", func(r *relayGateRig, t *testing.T) (net.Conn, <-chan struct{}) { return r.relay(t) }},
	}
	n := 0
	for _, p := range agentprovider.All() {
		for _, host := range p.AuthHosts {
			n++
			for _, path := range paths {
				for _, mixed := range []struct {
					name    string
					entries []sniEntry
				}{
					{"other name type first", []sniEntry{{1, "example.com"}, {0, host}}},
					{"two host_names", []sniEntry{{0, "example.com"}, {0, host}}},
				} {
					r := newRelayGateRig(t, "")
					agent, done := path.start(r, t)
					m := helloMsg(sniExt(mixed.entries...))
					go func() {
						_, _ = agent.Write(append([]byte{0x16, 0x03, 0x01, byte(len(m) >> 8), byte(len(m))}, m...))
						time.AfterFunc(300*time.Millisecond, func() { _ = agent.Close() })
					}()
					if b := r.upstreamBytes(t); len(b) != 0 {
						t.Errorf("%s: %s/%s, mixed SNI list (%s): upstream received %d byte(s), want 0", path.name, p.ID, host, mixed.name, len(b))
					}
					waitDone(t, done)
					if ev := awaitRelayEvent(t, r.sink); ev.Mode != "auth-gate" || ev.Action != "deny" {
						t.Errorf("%s: %s/%s, mixed SNI list (%s): event = %+v, want an auth-gate deny", path.name, p.ID, host, mixed.name, ev)
					}
				}
				r := newRelayGateRig(t, "")
				r.serveHRR(t)
				start := func(t *testing.T) (net.Conn, <-chan struct{}) { return path.start(r, t) }
				hello1, _, done := helloRetryVia(t, start, "example.com", host)
				waitDone(t, done)
				if b := r.upstreamBytes(t); !bytes.Equal(b, hello1) {
					t.Errorf("%s: %s/%s, HRR SNI swap: upstream got %d byte(s), want ClientHello 1 only (%d)", path.name, p.ID, host, len(b), len(hello1))
				}
				if ev := awaitRelayEvent(t, r.sink); ev.Mode != "auth-gate" || ev.Action != "deny" || !strings.Contains(ev.Reason, "HelloRetryRequest") {
					t.Errorf("%s: %s/%s, HRR SNI swap: event = %+v, want an auth-gate deny after the HelloRetryRequest", path.name, p.ID, host, ev)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no provider declares AuthHosts; the loop proved nothing")
	}
}

// TestSecurityAuthPathHostsGatedOnRelays pins R2-D8 for every host that
// carries an AuthPaths rule: a relay sees no paths, so a ClientHello
// naming the host on a non-443 relay, whole or split across TLS records,
// is refused with zero bytes delivered upstream.
func TestSecurityAuthPathHostsGatedOnRelays(t *testing.T) { // I12, R2-D8
	var hosts []string
	for _, p := range agentprovider.All() {
		for _, ap := range p.AuthPaths {
			if !slices.Contains(hosts, ap.Host) {
				hosts = append(hosts, ap.Host)
			}
		}
	}
	if len(hosts) == 0 {
		t.Fatal("no provider declares AuthPaths; the loop proved nothing")
	}
	for _, host := range hosts {
		if !agentprovider.HasAuthPaths(host) {
			t.Errorf("HasAuthPaths(%q) = false for a declared AuthPaths host", host)
		}
		for _, fragment := range []bool{false, true} {
			hello := captureClientHello(t, host)
			if fragment {
				hello = fragmentRecord(hello, 64)
			}
			r := newRelayGateRig(t, "")
			agent, done := r.relay(t)
			go func() { _, _ = agent.Write(hello) }()
			waitDone(t, done)
			if b := r.upstreamBytes(t); len(b) != 0 {
				t.Errorf("%s (fragmented=%v): upstream received %d byte(s) on a non-443 relay", host, fragment, len(b))
			}
			if ev := awaitRelayEvent(t, r.sink); ev.Mode != "auth-gate" || ev.Action != "deny" {
				t.Errorf("%s (fragmented=%v): relay event = %+v, want an auth-gate deny", host, fragment, ev)
			}
		}
	}
}

// TestSecurityScrubActivatesForProviderCredentialTypes pins D9: every
// credential type a provider owns turns I13 on even on a host no
// provider declares, and every provider API host still turns it on for
// a generic credential.
func TestSecurityScrubActivatesForProviderCredentialTypes(t *testing.T) { // I13, D9
	n := 0
	for _, p := range agentprovider.All() {
		for _, typ := range p.CredentialTypes {
			n++
			if !scrubActiveFor("api.not-a-provider.example", typ, true) {
				t.Errorf("%s/%s: scrub not active off the provider's API hosts", p.ID, typ)
			}
		}
		for _, pattern := range p.APIHosts {
			if host := strings.Replace(pattern, "*.", "x.", 1); !scrubActiveFor(host, "bearer_token", true) {
				t.Errorf("%s: API host %s lost the API-host trigger", p.ID, host)
			}
		}
	}
	if n == 0 {
		t.Fatal("no provider declares CredentialTypes; the loop proved nothing")
	}
}

// injectSpec is the I1 expectation per provider credential type: the
// one header that carries the secret and its prefix, copied from the
// spec, not read from the code under test. A provider credential type
// missing here fails the test (R4-06).
var injectSpec = map[string]struct{ header, prefix string }{
	"anthropic_oauth_subscription": {"Authorization", "Bearer "},
	"anthropic_manual_key":         {"x-api-key", ""},
	"openai_codex_oauth":           {"Authorization", "Bearer "},
	"grok_oauth":                   {"Authorization", "Bearer "},
}

func TestSecurityCredentialsInjectRealSecret(t *testing.T) { // I1
	const ph = "PLACEHOLDER-clawpatrol-test"
	const realSecret = "real-secret-value-0123456789abcdef"
	n := 0
	for _, p := range agentprovider.All() {
		for _, typ := range p.CredentialTypes {
			want, ok := injectSpec[typ]
			if !ok {
				t.Errorf("%s/%s: no injectSpec row; add the header and prefix from the spec", p.ID, typ)
				continue
			}
			inj, ok := config.Lookup(config.KindCredential, typ).New().(runtime.HTTPCredentialRuntime)
			if !ok {
				t.Errorf("%s/%s is not an HTTPCredentialRuntime; add an I1 leg for its protocol", p.ID, typ)
				continue
			}
			n++
			host := strings.TrimPrefix(p.APIHosts[0], "*.")
			req, _ := http.NewRequest(http.MethodPost, "https://"+host+"/v1/x", nil)
			req.Header.Set(want.header, want.prefix+ph) // the agent sends its placeholder where the secret goes
			if err := inj.InjectHTTP(context.Background(), req, runtime.Secret{Bytes: []byte(realSecret)}); err != nil {
				t.Errorf("%s/%s: InjectHTTP: %v", p.ID, typ, err)
				continue
			}
			if got := req.Header.Values(want.header); !slices.Equal(got, []string{want.prefix + realSecret}) {
				t.Errorf("%s/%s: %s = %q, want exactly [%q]", p.ID, typ, want.header, got, want.prefix+"<secret>")
			}
			for k, vs := range req.Header {
				// The secret goes in exactly one place: the one value of
				// the expected header checked above. A copy in any other
				// header name or value fails (review I-1).
				if strings.Contains(k, realSecret) {
					t.Errorf("%s/%s: real secret placed in a header name", p.ID, typ)
				}
				for _, v := range vs {
					if strings.Contains(v, ph) {
						t.Errorf("%s/%s: placeholder remains in %s", p.ID, typ, k)
					}
					if strings.Contains(v, realSecret) && !strings.EqualFold(k, want.header) {
						t.Errorf("%s/%s: real secret also placed in %s; it belongs only in %s", p.ID, typ, k, want.header)
					}
				}
			}
			if strings.Contains(req.URL.String(), realSecret) || strings.Contains(req.URL.RawQuery, realSecret) || strings.Contains(req.Host, realSecret) {
				t.Errorf("%s/%s: secret placed in URL", p.ID, typ)
			}
		}
	}
	if n == 0 {
		t.Fatal("no provider credential type was checked; the loop proved nothing")
	}
}

// I2 (spec §10.1 #3): the value a provider credential injects never
// reaches the stored sample. This mirrors the MITM path's redaction list
// (main.go:3104-3150) and header snapshot (main.go:3337).
func TestSecurityInjectedSecretsRedactedFromSamples(t *testing.T) { // I2
	const realSecret = "real-secret-value-0123456789abcdef"
	for _, p := range agentprovider.All() {
		for _, typ := range p.CredentialTypes {
			inj, ok := config.Lookup(config.KindCredential, typ).New().(runtime.HTTPCredentialRuntime)
			if !ok {
				continue
			}
			host := strings.TrimPrefix(p.APIHosts[0], "*.")
			req, _ := http.NewRequest(http.MethodPost, "https://"+host+"/v1/x", nil)
			req.Header.Set("Authorization", "Bearer placeholder")
			sec := runtime.Secret{Bytes: []byte(realSecret)}
			if err := inj.InjectHTTP(context.Background(), req, sec); err != nil {
				t.Errorf("%s/%s: InjectHTTP: %v", p.ID, typ, err)
				continue
			}
			redactions := appendCredentialSecretRedactions(nil, sec)
			if rp, ok := inj.(runtime.HTTPCredentialRedactionProvider); ok {
				for _, s := range rp.ConsumeHTTPRedactions(req) {
					redactions = appendCredentialSecretRedaction(redactions, s)
				}
			}
			// The list alone must cover every injected value: the
			// header-name mask below would hide a list regression for
			// Authorization and x-api-key (R4-08).
			for k, vs := range req.Header {
				for _, v := range vs {
					if strings.Contains(redactCredentialSample(v, redactions), realSecret) {
						t.Errorf("%s/%s: the redaction list misses the value injected into %s", p.ID, typ, k)
					}
				}
			}
			for k, v := range flatHeadersRedacted(req.Header, redactions) {
				if strings.Contains(v, realSecret) {
					t.Errorf("%s/%s: stored header %s carries the real secret", p.ID, typ, k)
				}
			}
		}
	}
}

// I13 on every provider API host (spec §10.1 #4): an upstream that
// echoes the injected secret in a plain body or an SSE stream split
// across two flushes reaches the agent with the marker instead. The WS
// leg is pinned at the pump (TestPumpWSServerScrub,
// TestPumpWSScrubSplitAcrossFragments, TestPrepareScrubbedRequest) and
// live by V10.
func TestSecurityResponseScrubPerProvider(t *testing.T) { // I13
	t.Setenv("CLAWPATROL_SECRET_TOK", testSecret)
	echo := func(sse bool) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !sse {
				_, _ = w.Write([]byte(`{"echo":"` + tok + `"}`))
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			half := len(tok) / 2
			_, _ = w.Write([]byte(`data: {"delta":"` + tok[:half]))
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte(tok[half:] + "\"}\n\n"))
		})
	}
	for _, p := range agentprovider.All() {
		for _, pattern := range p.APIHosts {
			host := strings.Replace(pattern, "*.", "x.", 1)
			hcl := fmt.Sprintf(`
gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}

endpoint "https" "api" { hosts = [%q] }

credential "bearer_token" "tok" { endpoint = https.api }

rule "allow" {
  endpoint  = https.api
  condition = "true"
  verdict   = "allow"
}

profile "default" { credentials = [bearer_token.tok] }
`, host)
			for _, sse := range []bool{false, true} {
				h := newCredentialMatchHarnessWith(t, hcl, "api", echo(sse))
				status, _, body := gatewaySend(t, h.gateway, host, http.MethodPost, "/v1/x",
					http.Header{"Authorization": {"Bearer placeholder"}}, "{}")
				if status != http.StatusOK || strings.Contains(body, testSecret) || !strings.Contains(body, scrubMarker) {
					t.Errorf("%s: %s (sse=%v): status %d body %q; want the marker, never the secret", p.ID, host, sse, status, body)
				}
			}
		}
	}
}

// competingEnvSpec is the I14 expectation per provider, copied from the
// spec (§8.1–8.3, review round 1 additions noted), NOT read from the
// declarations under test. A provider missing here fails the test.
var competingEnvSpec = map[string][]string{
	"claude": {
		"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", // DEV-19, user-approved
		// D6 (review round 2)
		"CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
		"CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR",
		"ANTHROPIC_FOUNDRY_API_KEY", "ANTHROPIC_AWS_API_KEY",
		// R2-D3 (review round 3)
		"ANTHROPIC_FOUNDRY_AUTH_TOKEN",
		"ANTHROPIC_IDENTITY_TOKEN", "ANTHROPIC_IDENTITY_TOKEN_FILE",
		"CLAUDE_CODE_SESSION_ACCESS_TOKEN",
		"CLAUDE_CODE_GATEWAY_TOKEN", "CLAUDE_CODE_GATEWAY_TOKEN_FILE_DESCRIPTOR",
		"CLAUDE_CODE_WEBSOCKET_AUTH_FILE_DESCRIPTOR",
		// D-R4-4 (A) (review round 4)
		"CLAUDE_BG_AUTH_SNAPSHOT_PATH", "CLAUDE_SESSION_INGRESS_TOKEN_FILE",
		"CLAUDE_SECURESTORAGE_CONFIG_DIR", "CLAUDE_BRIDGE_OAUTH_TOKEN",
		// D-R4-4b (review round 4): SDK profile credential files,
		// federation mode, the Unix socket relay, custom headers and the
		// remote-settings hook.
		"ANTHROPIC_CONFIG_DIR", "ANTHROPIC_PROFILE", "CLAUDE_CODE_FEDERATION_CACHE_DIR",
		"ANTHROPIC_UNIX_SOCKET", "ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID",
		"ANTHROPIC_CUSTOM_HEADERS", "CLAUDE_CODE_MOCK_REMOTE_SETTINGS",
	},
	"codex": {"OPENAI_API_KEY", "CODEX_API_KEY"},
	"grok": {
		"XAI_API_KEY", "GROK_CODE_XAI_API_KEY", "GROK_DEPLOYMENT_KEY", "GROK_AUTH_PROVIDER_COMMAND",
		"GROK_AUTH_PATH", "GROK_MODELS_BASE_URL", "GROK_MODELS_LIST_URL", "GROK_CLI_CHAT_PROXY_BASE_URL",
		"GROK_XAI_API_BASE_URL", "GROK_OAUTH2_TEST", "GROK_OIDC_TEST", "GROK_LOCAL_AUTH",
		// grok's own FIRST_PARTY_CREDENTIAL_ENV_VARS (xai-grok-env/src/registry.rs:1-11), review round 1
		"GROK_AUTH", "GROK_EXTRA_AUTH_KEY", "GROK_TRACE_UPLOAD_CREDENTIALS_FILE",
		"CLAWPATROL_GROK_SESSION",
		// D7 (review round 2): config overlay path and managed-config URL
		// (xai-grok-config env_overlay.rs:13, endpoints.rs:52, :288).
		"GROK_CONFIG_PATH", "GROK_MANAGED_CONFIG_URL",
		// D-R4-5 (A) (review round 4): the remote-campaign override
		// (declared in Task 15).
		"GROK_CAMPAIGNS_OVERRIDE",
	},
}

// TestSecurityCompetingEnvStripped checks each provider's spec list in
// two legs: the strip itself, and a wrapped launch through the real
// launcher entry point (`clawpatrol run bash`; D5: argv0 is ignored).
func TestSecurityCompetingEnvStripped(t *testing.T) { // I14, D5
	t.Setenv("HOME", t.TempDir()) // shims write under defaultClawpatrolDir() = $HOME/.clawpatrol
	for _, p := range agentprovider.All() {
		if p.Launcher == nil || len(p.Launcher.Binaries) == 0 {
			continue
		}
		want, ok := competingEnvSpec[p.ID]
		if !ok {
			t.Errorf("%s: no entry in competingEnvSpec; add the provider's competing env from its spec section", p.ID)
			continue
		}
		names := append(slices.Clone(want), genericCompetingEnv...)
		// The spec table above is the floor. Every exact name the provider
		// declares is checked too, so a name added to CompetingEnv later
		// is covered without editing the table (D-R4-4b).
		for _, n := range p.Launcher.CompetingEnv {
			if !strings.HasSuffix(n, "*") && !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
		for _, leg := range []string{"strip", "wrapped launch"} {
			for _, n := range names {
				t.Setenv(n, "real-value")
			}
			if leg == "strip" {
				stripCompetingEnv()
			} else if err := prepareAgentEnv([]string{"/bin/bash"}, func() {}); err != nil {
				t.Fatalf("%s: prepareAgentEnv(bash): %v", p.ID, err)
			}
			for _, n := range names {
				if _, ok := os.LookupEnv(n); ok {
					t.Errorf("%s (%s): %s survived", p.ID, leg, n)
				}
			}
		}
	}
}

// TestSecurityShimTriggersAreStripped pins D5's safety condition: a shim
// trigger an operator sets in the parent shell is stripped before shims
// are picked, so a provider shim only ever runs on a gateway-pushed
// placeholder (C9 keeps every trigger in CompetingEnv).
func TestSecurityShimTriggersAreStripped(t *testing.T) { // I14, D5
	n := 0
	for _, p := range agentprovider.All() {
		if p.Launcher == nil {
			continue
		}
		for _, name := range p.Launcher.ShimTriggerEnv {
			n++
			t.Setenv(name, "operator-real-value")
		}
	}
	if n == 0 {
		t.Fatal("no provider declares ShimTriggerEnv; the check proved nothing")
	}
	stripCompetingEnv()
	if got := shimProviders([]string{"/bin/bash"}, os.Getenv); len(got) != 0 {
		var ids []string
		for _, p := range got {
			ids = append(ids, p.ID)
		}
		t.Fatalf("shims %v would run on operator-set triggers", ids)
	}
}

func TestSecurityProviderCAVarsForced(t *testing.T) { // I5
	// A fixture provider guarantees the loop runs even before any real
	// provider declares a CAEnv (Grok does from Task 15).
	restore := agentprovider.Swap(append(agentprovider.All(), &agentprovider.Provider{
		ID: "catest", DisplayName: "CA Test",
		Launcher: &agentprovider.Launcher{Binaries: []string{"catest"}, CAEnv: []string{"CATEST_EXTRA_CA"}},
	}))
	defer restore()
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caPath, []byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(agentprovider.AllCAEnv(), "CATEST_EXTRA_CA") {
		t.Fatal("fixture CAEnv not registered")
	}
	vars := caPathPushdownVars(caPath)
	for _, name := range agentprovider.AllCAEnv() {
		ok := false
		for _, v := range vars {
			ok = ok || (v.Name == name && v.Value == caPath)
		}
		if !ok {
			t.Errorf("provider CA var %s not pointed at the MITM CA", name)
		}
		if got := dropClawpatrolCAVars([]pushdownEnvVar{{Name: name, Value: "/evil.pem"}}); len(got) != 0 {
			t.Errorf("gateway-sent %s was not dropped", name)
		}
	}
	// Composition: whatever is pushed, every clawpatrol CA var ends at the
	// MITM CA, built-in or provider-declared (R4-05).
	got := agentPushdown(caPath, []pushdownEnvVar{
		{Name: "SSL_CERT_FILE", Value: "/evil.pem"},
		{Name: "NODE_EXTRA_CA_CERTS", Value: "/evil.pem"},
		{Name: "CATEST_EXTRA_CA", Value: "/evil.pem"},
		{Name: "OPENAI_API_KEY", Value: "ph"},
	})
	for _, v := range got {
		if v.Value == "/evil.pem" {
			t.Errorf("pushed %s=/evil.pem survived the composer", v.Name)
		}
	}
	if !slices.ContainsFunc(got, func(v pushdownEnvVar) bool { return v.Name == "OPENAI_API_KEY" && v.Value == "ph" }) {
		t.Error("the composer dropped a non-CA pushed var")
	}
}

// Hooks run by the core get only data that cannot reach the secret
// store: PlaceholderEnv is strings plus a Getenv func; PublicMaterial is
// empty. Known limit: Getenv can read any variable in the launcher's
// process env, which by then holds only placeholders (I14 ran first).
func TestSecurityHookArgumentsCarryNoSecretHandles(t *testing.T) {
	allowedFunc := reflect.TypeOf(func(string) string { return "" })
	pe := reflect.TypeOf(agentprovider.PlaceholderEnv{})
	for i := 0; i < pe.NumField(); i++ {
		f := pe.Field(i)
		if f.Type.Kind() != reflect.String && f.Type != allowedFunc {
			t.Errorf("PlaceholderEnv.%s has type %s; only string and func(string) string are allowed", f.Name, f.Type)
		}
	}
	if n := reflect.TypeOf(agentprovider.PublicMaterial{}).NumField(); n != 0 {
		t.Errorf("PublicMaterial has %d fields; it must stay empty", n)
	}
}

const runtimePkg = "github.com/denoland/clawpatrol/internal/config/runtime"

// hookTypeViolations walks a hook type transitively and reports every
// path that reaches a secret-store type or an interface. *http.Request
// and *http.Response are opaque leaves (R4-07). An interface is
// rejected because it can carry any value at run time, a
// *runtime.Secret included, and the walk cannot see through it (review
// fix round 1). The one interface allowed is error, the result type of
// Shim and Preflight in the spec's signatures (§5).
func hookTypeViolations(root reflect.Type, name string) []string {
	opaque := map[reflect.Type]bool{
		reflect.TypeOf((*http.Request)(nil)):  true,
		reflect.TypeOf((*http.Response)(nil)): true,
	}
	allowedIface := map[reflect.Type]bool{
		reflect.TypeOf((*error)(nil)).Elem(): true,
	}
	forbidden := func(rt reflect.Type) bool {
		switch rt.Name() {
		case "Secret", "Secrets", "OAuthRegistry", "oauthState":
			return true
		}
		return rt.PkgPath() == runtimePkg
	}
	var out []string
	seen := map[reflect.Type]bool{}
	var walk func(rt reflect.Type, path string)
	walk = func(rt reflect.Type, path string) {
		if seen[rt] || opaque[rt] {
			return
		}
		seen[rt] = true
		if forbidden(rt) {
			out = append(out, fmt.Sprintf("%s reaches %s.%s", path, rt.PkgPath(), rt.Name()))
			return
		}
		switch rt.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Chan:
			walk(rt.Elem(), path)
		case reflect.Map:
			walk(rt.Key(), path)
			walk(rt.Elem(), path)
		case reflect.Struct:
			for i := 0; i < rt.NumField(); i++ {
				walk(rt.Field(i).Type, path+"."+rt.Field(i).Name)
			}
		case reflect.Func:
			for i := 0; i < rt.NumIn(); i++ {
				walk(rt.In(i), path)
			}
			for i := 0; i < rt.NumOut(); i++ {
				walk(rt.Out(i), path)
			}
		case reflect.Interface:
			if !allowedIface[rt] {
				out = append(out, fmt.Sprintf("%s has interface type %s; an interface can carry a secret-store value at run time", path, rt))
				return
			}
			for i := 0; i < rt.NumMethod(); i++ {
				walk(rt.Method(i).Type, path)
			}
		}
	}
	walk(root, name)
	return out
}

// The walk itself rejects interface-typed fields and parameters (review
// fix round 1): an any field, a func(any) parameter and a non-error
// interface each fail, while error and plain data pass.
func TestSecurityHookWalkRejectsInterfaces(t *testing.T) {
	type stringer interface{ String() string }
	type withAny struct{ Ctx any }
	for _, tc := range []struct {
		name string
		of   reflect.Type
		bad  bool
	}{
		{"any field", reflect.TypeOf(withAny{}), true},
		{"func(any) parameter", reflect.TypeOf(func(any) error { return nil }), true},
		{"interface{} result", reflect.TypeOf(func() interface{} { return nil }), true},
		{"non-error interface", reflect.TypeOf(func(stringer) {}), true},
		{"error result", reflect.TypeOf(func(string) error { return nil }), false},
		{"plain data", reflect.TypeOf(struct {
			S string
			B []byte
		}{}), false},
	} {
		if got := hookTypeViolations(tc.of, tc.name); (len(got) != 0) != tc.bad {
			t.Errorf("%s: violations %q, want rejected = %v", tc.name, got, tc.bad)
		}
	}
}

// Spec §5, §10.1 #7: no hook signature reaches a secret-store type or an
// interface other than error, transitively (R4-07, review fix round 1).
func TestSecurityHookSignaturesReachNoSecretStore(t *testing.T) {
	for _, h := range []struct {
		name string
		of   reflect.Type
		fld  string
	}{
		{"Launcher.Shim", reflect.TypeOf(agentprovider.Launcher{}), "Shim"},
		{"Launcher.Preflight", reflect.TypeOf(agentprovider.Launcher{}), "Preflight"},
		{"AuthStub.Respond", reflect.TypeOf(agentprovider.AuthStub{}), "Respond"},
		{"AuthPath.Respond", reflect.TypeOf(agentprovider.AuthPath{}), "Respond"},
	} {
		f, ok := h.of.FieldByName(h.fld)
		if !ok {
			t.Fatalf("%s: field not found", h.name)
		}
		for _, v := range hookTypeViolations(f.Type, h.name) {
			t.Error(v)
		}
	}
	// Cheaper and earlier: the agentprovider package never imports the
	// runtime package directly (V4).
	fset := token.NewFileSet()
	files, _ := filepath.Glob("../../internal/agentprovider/*.go")
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) == runtimePkg {
				t.Errorf("%s imports %s; hook types must not reach the secret store", name, runtimePkg)
			}
		}
	}
	if len(files) == 0 {
		t.Fatal("no agentprovider sources found; the import check proved nothing")
	}
}
