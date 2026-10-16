package agentprovider

import "testing"

// withProviders swaps the registry for the duration of a test.
func withProviders(t *testing.T, ps ...*Provider) {
	t.Helper()
	mu.Lock()
	saved := providers
	providers = ps
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		providers = saved
		mu.Unlock()
	})
}

func testProviders() []*Provider {
	return []*Provider{
		{
			ID: "alpha", DisplayName: "Alpha",
			APIHosts:  []string{"api.alpha.test", "*.chat.alpha.test"},
			AuthHosts: []string{"auth.alpha.test"},
			AuxHosts:  []string{"*.alpha.test"},
			Wire: []WireRoute{
				{Host: "api.alpha.test", Path: "/v1/messages", Match: PathExact, Format: WireAnthropicMessages},
				{Host: "*.chat.alpha.test", Path: "/codex/responses", Match: PathContains, Format: WireCodexWS},
			},
			AuthPaths: []AuthPath{
				{Host: "api.alpha.test", Path: "/oauth/", Match: PathPrefix},
				{Host: "api.alpha.test", Path: "/api/keys/create", Match: PathExact},
			},
			CredentialTypes: []string{"alpha_oauth"},
			Launcher:        &Launcher{Binaries: []string{"alpha"}, CAEnv: []string{"ALPHA_EXTRA_CA"}},
			Approver:        &ApproverBackend{ModelPrefixes: []string{"al-"}, URL: "https://api.alpha.test/v1/messages", Format: WireAnthropicMessages},
			BrowserTLS:      true,
		},
		{
			ID: "beta", DisplayName: "Beta",
			APIHosts: []string{"api.beta.test"},
			Wire: []WireRoute{
				{Host: "api.beta.test", Path: "/v1/responses", Match: PathPrefix, Format: WireOpenAIResponses},
			},
			Approver: &ApproverBackend{ModelPrefixes: []string{"be-"}, URL: "https://api.beta.test/v1/responses", Format: WireOpenAIResponses},
		},
	}
}

func TestHostMatching(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"api.alpha.test", "api.alpha.test", true},
		{"api.alpha.test", "API.Alpha.Test.", true},
		{"api.alpha.test", "api.alpha.test:443", true},
		{"api.alpha.test", "x.api.alpha.test", false},
		{"*.alpha.test", "x.alpha.test", true},
		{"*.alpha.test", "alpha.test", false},
		{"*.alpha.test", "evilalpha.test", false},
	}
	for _, tc := range cases {
		if got := hostMatches(tc.pattern, tc.host); got != tc.want {
			t.Errorf("hostMatches(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

func TestLookups(t *testing.T) {
	withProviders(t, testProviders()...)
	if p := AuthProvider("Auth.Alpha.Test."); p == nil || p.ID != "alpha" {
		t.Fatalf("AuthProvider = %v, want alpha", p)
	}
	if p := APIProvider("auth.alpha.test"); p != nil {
		t.Fatalf("APIProvider(auth host) = %s, want nil", p.ID)
	}
	if p := ByHost("cdn.alpha.test"); p == nil || p.ID != "alpha" {
		t.Fatalf("ByHost(aux wildcard) = %v, want alpha", p)
	}
	if p := ByHost("api.beta.test"); p == nil || p.ID != "beta" {
		t.Fatalf("ByHost(api) = %v, want beta", p)
	}
	if p := ByHost("example.test"); p != nil {
		t.Fatalf("ByHost(unknown) = %s, want nil", p.ID)
	}
	if p := ByBinary("/usr/local/bin/alpha"); p == nil || p.ID != "alpha" {
		t.Fatalf("ByBinary = %v, want alpha", p)
	}
	if p := ByBinary("python3"); p != nil {
		t.Fatalf("ByBinary(python3) = %s, want nil", p.ID)
	}
}

func TestWireFor(t *testing.T) {
	withProviders(t, testProviders()...)
	cases := []struct {
		host, path string
		wantID     string
		want       WireFormat
	}{
		{"api.alpha.test", "/v1/messages", "alpha", WireAnthropicMessages},
		{"api.alpha.test", "/v1/messages/count", "", ""},
		{"backend.chat.alpha.test", "/backend-api/codex/responses", "alpha", WireCodexWS},
		{"api.beta.test", "/v1/responses/abc", "beta", WireOpenAIResponses},
		{"api.beta.test", "/v1/models", "", ""},
		{"example.test", "/v1/messages", "", ""},
	}
	for _, tc := range cases {
		p, f := WireFor(tc.host, tc.path)
		gotID := ""
		if p != nil {
			gotID = p.ID
		}
		if gotID != tc.wantID || f != tc.want {
			t.Errorf("WireFor(%q,%q) = (%q,%q), want (%q,%q)", tc.host, tc.path, gotID, f, tc.wantID, tc.want)
		}
	}
}

func TestApproverForLongestPrefix(t *testing.T) {
	// "al-" (alpha) and "al-pro-" (gamma) overlap across providers, so
	// first-match and shortest-first orderings both pick the wrong one.
	gamma := &Provider{
		ID: "gamma", DisplayName: "Gamma",
		Approver: &ApproverBackend{ModelPrefixes: []string{"al-pro-"}, URL: "https://api.gamma.test/v1/messages", Format: WireAnthropicMessages},
	}
	withProviders(t, append(testProviders(), gamma)...)
	if p := ApproverFor("al-pro-2"); p == nil || p.ID != "gamma" {
		t.Fatalf("ApproverFor(al-pro-2) = %v, want gamma", p)
	}
	if p := ApproverFor("al-x"); p == nil || p.ID != "alpha" {
		t.Fatalf("ApproverFor(al-x) = %v, want alpha", p)
	}
	if p := ApproverFor("be-1"); p == nil || p.ID != "beta" {
		t.Fatalf("ApproverFor(be-1) = %v", p)
	}
	if p := ApproverFor("omni"); p != nil {
		t.Fatalf("ApproverFor(omni) = %s, want nil", p.ID)
	}
}

// Exact host patterns beat wildcards even when the wildcard provider is
// registered first, at both the API and aux levels.
func TestExactBeforeWildcardPrecedence(t *testing.T) {
	w := &Provider{ID: "w", APIHosts: []string{"*.x.test"}, AuxHosts: []string{"*.y.test"}}
	e := &Provider{ID: "e", APIHosts: []string{"api.x.test"}, AuxHosts: []string{"cdn.y.test"}}
	withProviders(t, w, e)
	cases := []struct {
		name string
		got  *Provider
		want string
	}{
		{"APIProvider(api.x.test)", APIProvider("api.x.test"), "e"},
		{"ByHost(api.x.test)", ByHost("api.x.test"), "e"},
		{"ByHost(cdn.y.test)", ByHost("cdn.y.test"), "e"},
		{"ByHost(other.x.test)", ByHost("other.x.test"), "w"},
		{"ByHost(other.y.test)", ByHost("other.y.test"), "w"},
	}
	for _, tc := range cases {
		if tc.got == nil || tc.got.ID != tc.want {
			t.Errorf("%s = %v, want %s", tc.name, tc.got, tc.want)
		}
	}
}

// An auth host is never an API host, even when another provider's API
// wildcard covers it (I12).
func TestAPIProviderExcludesAuthHosts(t *testing.T) {
	cover := &Provider{ID: "cover", APIHosts: []string{"*.z.test"}}
	owner := &Provider{ID: "owner", AuthHosts: []string{"auth.z.test"}}
	withProviders(t, cover, owner)
	if p := AuthProvider("auth.z.test"); p == nil || p.ID != "owner" {
		t.Fatalf("AuthProvider = %v, want owner", p)
	}
	if p := APIProvider("auth.z.test"); p != nil {
		t.Fatalf("APIProvider(auth host) = %s, want nil", p.ID)
	}
	if p := APIProvider("api.z.test"); p == nil || p.ID != "cover" {
		t.Fatalf("APIProvider(api.z.test) = %v, want cover", p)
	}
}

// A mixed-case AuthPath.Host must still match the normalized request
// host; otherwise the gate silently fails open.
func TestAuthPathMixedCaseHost(t *testing.T) {
	mixed := &Provider{
		ID:       "mixed",
		APIHosts: []string{"api.alpha.test"},
		AuthPaths: []AuthPath{
			{Host: "API.alpha.test", Path: "/oauth/", Match: PathPrefix},
		},
	}
	withProviders(t, mixed)
	if p, ap := AuthPathFor("api.alpha.test", "/oauth/token"); p == nil || ap == nil || ap.Path != "/oauth/" {
		t.Fatalf("AuthPathFor = (%v, %v), want the /oauth/ rule", p, ap)
	}
	if !HasAuthPaths("api.alpha.test") {
		t.Fatal("HasAuthPaths(api.alpha.test) = false, want true")
	}
}

func TestBrowserTLSAndCAEnv(t *testing.T) {
	withProviders(t, testProviders()...)
	if !BrowserTLS("x.chat.alpha.test") || BrowserTLS("api.beta.test") {
		t.Fatal("BrowserTLS mismatch")
	}
	if BrowserTLS("auth.alpha.test") {
		t.Fatal("auth hosts are never dialed for agents; BrowserTLS must be false")
	}
	got := AllCAEnv()
	if len(got) != 1 || got[0] != "ALPHA_EXTRA_CA" {
		t.Fatalf("AllCAEnv = %v", got)
	}
}

// AuthPathFor matches the cleaned, lowercased request path, so dot
// segments, duplicate slashes, case and a trailing slash cannot step
// around a rule (D1).
func TestAuthPathFor(t *testing.T) {
	withProviders(t, testProviders()...)
	cases := []struct {
		host, path string
		want       string // gated rule path, "" = not gated
	}{
		{"api.alpha.test", "/oauth/token", "/oauth/"},
		{"API.Alpha.Test.", "/OAuth/Authorize", "/oauth/"},
		{"api.alpha.test:443", "/v1/../oauth/token", "/oauth/"},
		{"api.alpha.test", "//oauth/token", "/oauth/"},
		{"api.alpha.test", "/oauth", "/oauth/"},
		{"api.alpha.test", "/api/keys/create", "/api/keys/create"},
		{"api.alpha.test", "/api/keys/create/", "/api/keys/create"},
		{"api.alpha.test", "/api/keys/create2", ""},
		{"api.alpha.test", "/oauthx/token", ""},
		{"api.alpha.test", "/v1/messages", ""},
		{"api.beta.test", "/oauth/token", ""},
	}
	for _, tc := range cases {
		p, ap := AuthPathFor(tc.host, tc.path)
		got := ""
		if ap != nil {
			got = ap.Path
			if p == nil || p.ID != "alpha" {
				t.Errorf("AuthPathFor(%q,%q) provider = %v, want alpha", tc.host, tc.path, p)
			}
		}
		if got != tc.want {
			t.Errorf("AuthPathFor(%q,%q) = %q, want %q", tc.host, tc.path, got, tc.want)
		}
	}
}

// HasAuthPaths reports whether any AuthPaths rule names the host, so the
// non-443 relay gate can refuse TLS to it (R2-D8).
func TestHasAuthPaths(t *testing.T) {
	withProviders(t, testProviders()...)
	cases := []struct {
		host string
		want bool
	}{
		{"api.alpha.test", true},
		{"API.Alpha.Test.", true},
		{"api.alpha.test:8443", true},
		{"auth.alpha.test", false},
		{"x.api.alpha.test", false},
		{"cdn.alpha.test", false},
		{"api.beta.test", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := HasAuthPaths(tc.host); got != tc.want {
			t.Errorf("HasAuthPaths(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestOwnsCredentialType(t *testing.T) {
	withProviders(t, testProviders()...)
	if !OwnsCredentialType("alpha_oauth") {
		t.Fatal("alpha_oauth is declared by alpha")
	}
	if OwnsCredentialType("bearer_token") || OwnsCredentialType("") {
		t.Fatal("a type no provider declares must not count as provider-owned")
	}
}

func TestCredentialTypeOwner(t *testing.T) {
	withProviders(t, testProviders()...)
	if got := CredentialTypeOwner("alpha_oauth"); got != "alpha" {
		t.Fatalf("CredentialTypeOwner(alpha_oauth) = %q, want alpha", got)
	}
	if got := CredentialTypeOwner("bearer_token") + CredentialTypeOwner(""); got != "" {
		t.Fatalf("an unowned type has owner %q, want none", got)
	}
}

func TestSwapRestores(t *testing.T) {
	withProviders(t, testProviders()...)
	restore := Swap([]*Provider{{ID: "gamma", DisplayName: "Gamma"}})
	if ByID("gamma") == nil || ByID("alpha") != nil {
		t.Fatal("Swap did not replace the registry")
	}
	restore()
	if ByID("gamma") != nil || ByID("alpha") == nil {
		t.Fatal("restore did not bring the previous registry back")
	}
}
