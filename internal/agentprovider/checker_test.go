package agentprovider

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
)

type fakeOAuthCred struct{ token, device, auth, register, flow string }

func (f fakeOAuthCred) OAuthFlow() *config.OAuthIntegration {
	return &config.OAuthIntegration{Flow: f.flow, OAuth: config.OAuthConfig{
		TokenURL: f.token, DeviceURL: f.device, AuthURL: f.auth, RegisterURL: f.register,
	}}
}

func fakeLookup(bodies map[string]any) PluginLookup {
	return func(_ config.Kind, typ string) (any, bool) {
		b, ok := bodies[typ]
		return b, ok
	}
}

// lookupByKind is a PluginLookup that honors kind, so a checker that
// looks a credential type up as an endpoint (or the reverse) fails.
func lookupByKind(bodies map[config.Kind]map[string]any) PluginLookup {
	return func(k config.Kind, typ string) (any, bool) {
		b, ok := bodies[k][typ]
		return b, ok
	}
}

func validBase() *Provider {
	return &Provider{
		ID: "alpha", DisplayName: "Alpha",
		APIHosts:        []string{"api.alpha.test"},
		AuthHosts:       []string{"auth.alpha.test"},
		AuxHosts:        []string{"*.alpha.test"},
		AuthPaths:       []AuthPath{{Host: "api.alpha.test", Path: "/oauth/", Match: PathPrefix}, {Host: "docs.alpha.test", Path: "/login/token", Match: PathExact}},
		Wire:            []WireRoute{{Host: "api.alpha.test", Path: "/v1/responses", Match: PathPrefix, Format: WireOpenAIResponses}},
		CredentialTypes: []string{"alpha_oauth"},
		Launcher: &Launcher{
			Binaries:       []string{"alpha"},
			CompetingEnv:   []string{"ALPHA_API_KEY", "ALPHA_SESSION"},
			ShimTriggerEnv: []string{"ALPHA_SESSION"},
			ForceSetEnv:    []string{"ALPHA_IDENTITY_JWT"},
			Shim:           func(PlaceholderEnv) (ShimResult, error) { return ShimResult{}, nil },
			Preflight:      func(PlaceholderEnv) error { return nil },
		},
		Approver: &ApproverBackend{ModelPrefixes: []string{"al-"}, URL: "https://api.alpha.test/v1/responses", Format: WireOpenAIResponses},
		Stubs: []AuthStub{{Host: "auth.alpha.test", Method: http.MethodPost, PathSuffix: "/x",
			Respond: func(*http.Request, PublicMaterial) *http.Response { return nil }}},
	}
}

func validLookup() PluginLookup {
	return fakeLookup(map[string]any{"alpha_oauth": fakeOAuthCred{token: "https://auth.alpha.test/token"}})
}

func TestValidateAcceptsValid(t *testing.T) {
	if err := Validate([]*Provider{validBase()}, validLookup()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(ps []*Provider) []*Provider
		lookup PluginLookup
		want   string
	}{
		{"C0 plain tls malformed", func(ps []*Provider) []*Provider { ps[0].PlainTLSHosts = []string{"bad host:443/x"}; return ps }, nil, `C0: PlainTLSHosts entry "bad host:443/x" must be a lowercase hostname`},
		{"C0 plain tls uppercase", func(ps []*Provider) []*Provider { ps[0].PlainTLSHosts = []string{"UPPER.alpha.test"}; return ps }, nil, `C0: PlainTLSHosts entry "UPPER.alpha.test" must be a lowercase hostname`},
		{"C0 plain tls bare star", func(ps []*Provider) []*Provider { ps[0].PlainTLSHosts = []string{"*"}; return ps }, nil, `PlainTLSHosts entry "*" must be a lowercase hostname`},
		{"C0 plain tls tld wildcard", func(ps []*Provider) []*Provider { ps[0].PlainTLSHosts = []string{"*.com"}; return ps }, nil, `C0: PlainTLSHosts entry "*.com" is too broad`},
		{"C4 plain tls own api host", func(ps []*Provider) []*Provider { ps[0].PlainTLSHosts = []string{"api.alpha.test"}; return ps }, nil, `C4: PlainTLSHosts entry "api.alpha.test" matches or covers an API host`},
		{"C4 plain tls other provider host", func(ps []*Provider) []*Provider { ps[0].PlainTLSHosts = []string{"api.other.test"}; return ps }, nil, `C4: PlainTLSHosts entry "api.other.test" is not equal to or covered by an aux host`},
		{"C0 empty id", func(ps []*Provider) []*Provider { ps[0].ID = ""; return ps }, nil, `C0: ID and DisplayName are required`},
		// A non-normalized declaration never equals NormalizeHost(sni), so
		// it would silently switch the I12 gate off for that host.
		{"C0 auth host trailing dot", func(ps []*Provider) []*Provider { ps[0].AuthHosts = []string{"auth.alpha.test."}; return ps }, nil, `C0: host "auth.alpha.test." must be a lowercase hostname`},
		{"C0 api host uppercase", func(ps []*Provider) []*Provider { ps[0].APIHosts = []string{"API.alpha.test"}; return ps }, nil, `C0: host "API.alpha.test" must be a lowercase hostname`},
		{"C0 aux host with port", func(ps []*Provider) []*Provider { ps[0].AuxHosts = []string{"*.alpha.test:443"}; return ps }, nil, `C0: host "*.alpha.test:443" must be a lowercase hostname`},
		{"C1 auth overlaps api", func(ps []*Provider) []*Provider {
			ps[0].APIHosts = append(ps[0].APIHosts, "*.alpha.test")
			return ps
		}, nil, `C1: auth host "auth.alpha.test" overlaps API host "*.alpha.test" of alpha`},
		{"C1 auth wildcard", func(ps []*Provider) []*Provider {
			ps[0].AuthHosts = []string{"auth.alpha.test", "*.beta.test"}
			return ps
		}, nil, `C1: auth host "*.beta.test" must be exact`},
		{"C1 aux exact equals auth", func(ps []*Provider) []*Provider {
			ps[0].AuxHosts = []string{"auth.alpha.test"}
			return ps
		}, nil, `C1: auth host "auth.alpha.test" is also an exact aux host of alpha`},
		{"C2 token url off auth hosts", nil,
			fakeLookup(map[string]any{"alpha_oauth": fakeOAuthCred{token: "https://api.alpha.test/token"}}), `C2: credential "alpha_oauth" calls "api.alpha.test", which is not an auth host`},
		{"C2 device url off auth hosts", nil,
			fakeLookup(map[string]any{"alpha_oauth": fakeOAuthCred{token: "https://auth.alpha.test/token", device: "https://elsewhere.test/d"}}), `C2: credential "alpha_oauth" calls "elsewhere.test"`},
		{"C3 unknown format", func(ps []*Provider) []*Provider { ps[0].Wire[0].Format = "grpc"; return ps }, nil, `C3: unknown wire format "grpc"`},
		{"C3 route host not api", func(ps []*Provider) []*Provider { ps[0].Wire[0].Host = "other.test"; return ps }, nil, `C3: wire route host "other.test" is not in APIHosts`},
		{"C4 duplicate id", func(ps []*Provider) []*Provider {
			b := validBase()
			b.APIHosts, b.AuthHosts, b.Wire, b.Stubs, b.Approver, b.CredentialTypes = []string{"api.b.test"}, nil, nil, nil, nil, nil
			b.AuxHosts, b.AuthPaths, b.Launcher = nil, nil, nil
			return append(ps, b)
		}, nil, `C4: duplicate provider ID`},
		{"C4 shared api host", func(ps []*Provider) []*Provider {
			return append(ps, &Provider{ID: "beta", DisplayName: "Beta", APIHosts: []string{"api.alpha.test"}})
		}, nil, `beta: C4: host "api.alpha.test" already claimed by alpha`},
		{"C5 stub off auth hosts", func(ps []*Provider) []*Provider { ps[0].Stubs[0].Host = "api.alpha.test"; return ps }, nil, `C5: stub host "api.alpha.test" is not in AuthHosts`},
		{"C6 approver url off api hosts", func(ps []*Provider) []*Provider {
			ps[0].Approver.URL = "https://elsewhere.test/v1"
			return ps
		}, nil, `C6: approver URL host "elsewhere.test" is not an API host`},
		{"C6 prefix collision", func(ps []*Provider) []*Provider {
			return append(ps, &Provider{ID: "beta", DisplayName: "Beta", APIHosts: []string{"api.b.test"},
				Approver: &ApproverBackend{ModelPrefixes: []string{"al-"}, URL: "https://api.b.test/v1", Format: WireOpenAIResponses}})
		}, nil, `C6: model prefix "al-" collides with "al-" of alpha`},
		{"C7 unknown credential type", nil, fakeLookup(map[string]any{}), `C7: credential type "alpha_oauth" is not registered`},
		// C8: path-scoped auth rules (D1).
		{"C8 wildcard host", func(ps []*Provider) []*Provider { ps[0].AuthPaths[0].Host = "*.alpha.test"; return ps }, nil, `C8: auth path host "*.alpha.test" must be exact`},
		{"C8 host not owned", func(ps []*Provider) []*Provider { ps[0].AuthPaths[0].Host = "api.other.test"; return ps }, nil, `C8: auth path host "api.other.test" is not an API or aux host this provider owns`},
		{"C8 host is a whole auth host", func(ps []*Provider) []*Provider { ps[0].AuthPaths[0].Host = "auth.alpha.test"; return ps }, nil, `C8: auth path host "auth.alpha.test" is a whole-host auth host already`},
		{"C8 host owned by another provider", func(ps []*Provider) []*Provider {
			ps[0].AuthPaths[0].Host = "api.b.test"
			return append(ps, &Provider{ID: "beta", DisplayName: "Beta", APIHosts: []string{"api.b.test"}})
		}, nil, `C8: auth path host "api.b.test" is not an API or aux host this provider owns`},
		// User decision X1: a non-normalized AuthPath.Host never equals
		// NormalizeHost(sni) at lookup, so the rule would never fire.
		{"C8 host not normalized", func(ps []*Provider) []*Provider { ps[0].AuthPaths[0].Host = "API.alpha.test"; return ps }, nil, `C8: auth path host "API.alpha.test" must be lowercase and normalized`},
		{"C8 uppercase path", func(ps []*Provider) []*Provider { ps[0].AuthPaths[0].Path = "/OAuth/"; return ps }, nil, `C8: auth path "/OAuth/" must be a clean lowercase path`},
		{"C8 unclean path", func(ps []*Provider) []*Provider { ps[0].AuthPaths[0].Path = "/v1/../oauth/"; return ps }, nil, `C8: auth path "/v1/../oauth/" must be a clean lowercase path`},
		{"C8 prefix without trailing slash", func(ps []*Provider) []*Provider { ps[0].AuthPaths[0].Path = "/oauth"; return ps }, nil, `C8: auth path "/oauth" must be a clean lowercase path`},
		{"C8 whole-host prefix", func(ps []*Provider) []*Provider { ps[0].AuthPaths[0].Path = "/"; return ps }, nil, `C8: auth path "/" must be a clean lowercase path`},
		{"C8 contains match", func(ps []*Provider) []*Provider { ps[0].AuthPaths[0].Match = PathContains; return ps }, nil, `C8: auth path "/oauth/": match must be PathExact or PathPrefix`},
		{"C8 overlaps wire route", func(ps []*Provider) []*Provider {
			ps[0].AuthPaths[0] = AuthPath{Host: "api.alpha.test", Path: "/v1/responses/compact", Match: PathExact}
			return ps
		}, nil, `C8: auth path api.alpha.test/v1/responses/compact overlaps wire route api.alpha.test/v1/responses`},
		{"C8 prefix covers wire route", func(ps []*Provider) []*Provider { ps[0].AuthPaths[0].Path = "/v1/"; return ps }, nil, `C8: auth path api.alpha.test/v1/ overlaps wire route api.alpha.test/v1/responses`},
		// C9: shim triggers (D5).
		{"C9 trigger without shim", func(ps []*Provider) []*Provider { ps[0].Launcher.Shim = nil; return ps }, nil, `C9: ShimTriggerEnv "ALPHA_SESSION" set but Launcher.Shim is nil`},
		{"C9 trigger not competing", func(ps []*Provider) []*Provider { ps[0].Launcher.ShimTriggerEnv = []string{"ALPHA_OTHER"}; return ps }, nil, `C9: ShimTriggerEnv "ALPHA_OTHER" must be an exact name listed in CompetingEnv`},
		{"C9 wildcard trigger", func(ps []*Provider) []*Provider {
			ps[0].Launcher.CompetingEnv = append(ps[0].Launcher.CompetingEnv, "ALPHA_*")
			ps[0].Launcher.ShimTriggerEnv = []string{"ALPHA_*"}
			return ps
		}, nil, `C9: ShimTriggerEnv "ALPHA_*" must be an exact name listed in CompetingEnv`},
		// C10: force-set names (D6).
		{"C10 wildcard force-set", func(ps []*Provider) []*Provider { ps[0].Launcher.ForceSetEnv = []string{"ALPHA_*"}; return ps }, nil, `C10: ForceSetEnv "ALPHA_*" must be an exact name`},
		{"C10 force-set also competing", func(ps []*Provider) []*Provider { ps[0].Launcher.ForceSetEnv = []string{"ALPHA_API_KEY"}; return ps }, nil, `C10: ForceSetEnv "ALPHA_API_KEY" must be an exact name`},
		{"C0 auth host with path", func(ps []*Provider) []*Provider { ps[0].AuthHosts = []string{"auth.alpha.test/"}; return ps }, nil, `C0: host "auth.alpha.test/" must be a lowercase hostname`},
		{"C0 empty label", func(ps []*Provider) []*Provider { ps[0].APIHosts = []string{"api..alpha.test"}; return ps }, nil, `C0: host "api..alpha.test" must be a lowercase hostname`},
		{"C0 inner wildcard", func(ps []*Provider) []*Provider { ps[0].AuxHosts = []string{"a.*.alpha.test"}; return ps }, nil, `C0: host "a.*.alpha.test" must be a lowercase hostname`},
		{"C0 bare star", func(ps []*Provider) []*Provider { ps[0].AuxHosts = []string{"*"}; return ps }, nil, `C0: host "*" must be a lowercase hostname`},
		{"C0 space", func(ps []*Provider) []*Provider { ps[0].APIHosts = []string{"api.alpha.test "}; return ps }, nil, `C0: host "api.alpha.test " must be a lowercase hostname`},
		{"C2 openai_device auth url off auth hosts", nil,
			fakeLookup(map[string]any{"alpha_oauth": fakeOAuthCred{token: "https://auth.alpha.test/token", auth: "https://elsewhere.test/device", flow: "openai_device"}}),
			`C2: credential "alpha_oauth" calls "elsewhere.test"`},
		{"C2 register url off auth hosts", nil,
			fakeLookup(map[string]any{"alpha_oauth": fakeOAuthCred{token: "https://auth.alpha.test/token", register: "https://elsewhere.test/register"}}),
			`C2: credential "alpha_oauth" calls "elsewhere.test"`},
		{"C6 nested prefix", func(ps []*Provider) []*Provider {
			return append(ps, &Provider{ID: "beta", DisplayName: "Beta", APIHosts: []string{"api.b.test"},
				Approver: &ApproverBackend{ModelPrefixes: []string{"al-pro"}, URL: "https://api.b.test/v1", Format: WireOpenAIResponses}})
		}, nil, `C6: model prefix "al-pro" collides with "al-" of alpha`},
		{"C8 encoded path", func(ps []*Provider) []*Provider { ps[0].AuthPaths[0].Path = "/oauth%2f/"; return ps }, nil, `C8: auth path "/oauth%2f/" must be a decoded path`},
		{"C8 query in path", func(ps []*Provider) []*Provider { ps[0].AuthPaths[1].Path = "/login/token?x=1"; return ps }, nil, `C8: auth path "/login/token?x=1" must be a decoded path`},
		{"C8 relative path", func(ps []*Provider) []*Provider { ps[0].AuthPaths[0].Path = "oauth/"; return ps }, nil, `C8: auth path "oauth/" must be a clean lowercase path`},
		{"C0 empty display name", func(ps []*Provider) []*Provider { ps[0].DisplayName = ""; return ps }, nil, `C0: ID and DisplayName are required`},
		{"C5 stub without method", func(ps []*Provider) []*Provider { ps[0].Stubs[0].Method = ""; return ps }, nil, `C5: stub on "auth.alpha.test" needs Method, PathSuffix and Respond`},
		{"C5 stub without suffix", func(ps []*Provider) []*Provider { ps[0].Stubs[0].PathSuffix = ""; return ps }, nil, `C5: stub on "auth.alpha.test" needs Method, PathSuffix and Respond`},
		{"C5 stub without responder", func(ps []*Provider) []*Provider { ps[0].Stubs[0].Respond = nil; return ps }, nil, `C5: stub on "auth.alpha.test" needs Method, PathSuffix and Respond`},
		{"C6 unknown approver format", func(ps []*Provider) []*Provider { ps[0].Approver.Format = "grpc"; return ps }, nil, `C6: approver format "grpc" unknown`},
		{"C7 credential looked up by kind", nil,
			lookupByKind(map[config.Kind]map[string]any{config.KindEndpoint: {"alpha_oauth": fakeOAuthCred{token: "https://auth.alpha.test/token"}}}),
			`C7: credential type "alpha_oauth" is not registered`},
		{"C7 unknown endpoint type", func(ps []*Provider) []*Provider { ps[0].EndpointTypes = []string{"alpha_ep"}; return ps },
			lookupByKind(map[config.Kind]map[string]any{
				config.KindCredential: {"alpha_oauth": fakeOAuthCred{token: "https://auth.alpha.test/token"}, "alpha_ep": struct{}{}},
			}),
			`C7: endpoint type "alpha_ep" is not registered`},
		{"C10 empty force-set name", func(ps []*Provider) []*Provider { ps[0].Launcher.ForceSetEnv = []string{""}; return ps }, nil, `C10: ForceSetEnv "" must be an exact name`},
		// C11: preflight (D7).
		{"C11 preflight without binaries", func(ps []*Provider) []*Provider { ps[0].Launcher.Binaries = nil; return ps }, nil, `C11: Launcher.Preflight set but Launcher.Binaries is empty`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := []*Provider{validBase()}
			if tc.mutate != nil {
				ps = tc.mutate(ps)
			}
			lookup := tc.lookup
			if lookup == nil {
				lookup = validLookup()
			}
			err := Validate(ps, lookup)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

// A browser AuthURL (default auth_code flow) is opened by the operator,
// never called by the gateway, so C2 exempts it (R0-08).
func TestValidateAcceptsPlainTLSHosts(t *testing.T) {
	p := validBase()
	p.AuxHosts = append(p.AuxHosts, "oaiusercontent.com", "*.oaiusercontent.com")
	p.PlainTLSHosts = []string{"oaiusercontent.com", "*.oaiusercontent.com", "files.oaiusercontent.com"}
	if err := Validate([]*Provider{p}, validLookup()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateExemptsBrowserAuthURL(t *testing.T) {
	lookup := fakeLookup(map[string]any{"alpha_oauth": fakeOAuthCred{token: "https://auth.alpha.test/token", auth: "https://login.elsewhere.test/authorize"}})
	if err := Validate([]*Provider{validBase()}, lookup); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestPathsOverlap(t *testing.T) {
	cases := []struct {
		route WireRoute
		ap    AuthPath
		want  bool
	}{
		{WireRoute{Path: "/v1/responses", Match: PathExact}, AuthPath{Path: "/v1/responses", Match: PathExact}, true},
		{WireRoute{Path: "/v1/responses", Match: PathExact}, AuthPath{Path: "/v1/other", Match: PathExact}, false},
		{WireRoute{Path: "/V1/Responses", Match: PathExact}, AuthPath{Path: "/v1/responses", Match: PathExact}, true},
		{WireRoute{Path: "/v1/responses/", Match: PathExact}, AuthPath{Path: "/v1/responses", Match: PathExact}, true},  // R0-10
		{WireRoute{Path: "/v1/responses/", Match: PathPrefix}, AuthPath{Path: "/v1/responses", Match: PathExact}, true}, // R0-10
		{WireRoute{Path: "/v1/", Match: PathPrefix}, AuthPath{Path: "/v1/oauth", Match: PathExact}, true},
		{WireRoute{Path: "/v2/", Match: PathPrefix}, AuthPath{Path: "/v1/oauth", Match: PathExact}, false},
		{WireRoute{Path: "/codex/", Match: PathContains}, AuthPath{Path: "/x/codex/y", Match: PathExact}, true},
		{WireRoute{Path: "/codex/", Match: PathContains}, AuthPath{Path: "/x/y", Match: PathExact}, false},
		{WireRoute{Path: "/oauth/token", Match: PathExact}, AuthPath{Path: "/oauth/", Match: PathPrefix}, true},
		{WireRoute{Path: "/v1/messages", Match: PathExact}, AuthPath{Path: "/oauth/", Match: PathPrefix}, false},
		{WireRoute{Path: "/oauth/x/", Match: PathPrefix}, AuthPath{Path: "/oauth/", Match: PathPrefix}, true},
		{WireRoute{Path: "/", Match: PathPrefix}, AuthPath{Path: "/oauth/", Match: PathPrefix}, true},
		{WireRoute{Path: "/v1/", Match: PathPrefix}, AuthPath{Path: "/oauth/", Match: PathPrefix}, false},
		{WireRoute{Path: "/anything", Match: PathContains}, AuthPath{Path: "/oauth/", Match: PathPrefix}, true},
		{WireRoute{Path: "/oauth", Match: PathExact}, AuthPath{Path: "/oauth/", Match: PathPrefix}, true},
	}
	for _, tc := range cases {
		if got := pathsOverlap(tc.route, tc.ap); got != tc.want {
			t.Errorf("pathsOverlap(%+v, %+v) = %v, want %v", tc.route, tc.ap, got, tc.want)
		}
	}
}

func TestMustValidatePanicsOnBadProvider(t *testing.T) {
	restore := Swap([]*Provider{{ID: "bad", DisplayName: "Bad", AuthHosts: []string{"Auth.Bad.Test"}}})
	defer restore()
	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "C0") {
			t.Fatalf("MustValidate recovered %v, want a C0 panic", r)
		}
	}()
	MustValidate()
}
