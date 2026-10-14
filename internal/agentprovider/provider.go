// Package agentprovider is the registry of agent harness providers
// (Claude Code, Codex, Grok Build, …). A provider declares facts:
// hosts, wire formats, launcher wiring, approver backend. The gateway
// core performs every security-relevant action itself (injection,
// redaction, the auth-host gate, the response secret scrub,
// competing-credential stripping, CA trust), so no declaration can
// opt a provider out of them.
package agentprovider

import "net/http"

// WireFormat is a closed set of LLM wire protocols whose parsers the
// gateway core owns. Providers pick one; they never ship parser code.
type WireFormat string

// Wire formats the core can parse. KnownWireFormats lists them all.
const (
	WireAnthropicMessages WireFormat = "anthropic_messages"
	WireOpenAIResponses   WireFormat = "openai_responses"
	WireOpenAIChat        WireFormat = "openai_chat"
	WireOpenAICompletions WireFormat = "openai_completions"
	// WireCodexWS is the chatgpt.com Codex backend: SSE over HTTP and
	// the same envelopes inside WebSocket text frames.
	WireCodexWS WireFormat = "codex_ws"
)

// KnownWireFormats lists every WireFormat the core can parse.
var KnownWireFormats = []WireFormat{WireAnthropicMessages, WireOpenAIResponses, WireOpenAIChat, WireOpenAICompletions, WireCodexWS}

// PathMatch selects how WireRoute.Path is compared to a request path.
type PathMatch int

// Path match modes for WireRoute.Path and AuthPath.Path.
const (
	PathExact PathMatch = iota
	PathPrefix
	PathContains
)

// WireRoute maps (host pattern, path) to a core parser. Host must
// also appear verbatim in the provider's APIHosts (check C3).
type WireRoute struct {
	Host   string
	Path   string
	Match  PathMatch
	Format WireFormat
}

// Launcher is the `clawpatrol run <binary>` wiring for a provider.
type Launcher struct {
	Binaries []string // argv0 basenames
	// CAEnv names additive CA env vars (the client adds the named
	// file to its own roots). The core points them at the MITM CA and
	// force-sets them like every clawpatrol CA var (invariant I5).
	CAEnv []string
	// CompetingEnv names credential/endpoint env vars that would let
	// the agent authenticate around the gateway (invariant I14). A
	// trailing "*" matches a prefix (e.g. "GROK_OIDC_*"). The core
	// strips the union of every provider's list from every
	// `clawpatrol run`, whatever the wrapped binary is (D5).
	CompetingEnv []string
	// ShimTriggerEnv names env vars the gateway pushdown sets when a
	// credential this provider owns is bound. When any holds a value
	// after pushdown, the core runs Shim even if the wrapped binary
	// belongs to another provider (D5). Each name must also be in
	// CompetingEnv, so its only possible value is the gateway
	// placeholder (check C9).
	ShimTriggerEnv []string
	// ForceSetEnv names env vars whose pushdown value overrides the
	// operator's shell value. Unlike CompetingEnv they are not stripped
	// when nothing is pushed (D6; check C10).
	ForceSetEnv []string
	Shim        Shim
	// Preflight runs on the final agent env (after strip, pushdown and
	// shims) when the wrapped binary is one of Binaries. An error
	// refuses the launch (D7; check C11). It may read files; it gets no
	// handle to the gateway's secrets.
	Preflight func(PlaceholderEnv) error
}

// PlaceholderEnv is everything a Shim may read. It deliberately has
// no handle to the gateway's secret store or OAuth registry.
type PlaceholderEnv struct {
	ClawpatrolDir string                   // defaultClawpatrolDir(): ~/.clawpatrol
	Getenv        func(name string) string // the agent env after pushdown
}

// ShimFile is written by the core with mode 0600 (parent dir 0700).
// Path must be absolute.
type ShimFile struct {
	Path string
	Data []byte
}

// ShimResult is applied by the core. Env may not name a clawpatrol
// CA var or a generic competing credential; the core rejects it.
type ShimResult struct {
	Files  []ShimFile
	Env    map[string]string
	Unset  []string
	Notice string // printed to stderr as "[clawpatrol] <Notice>"
}

// Shim prepares harness-specific placeholder state (e.g. a fake
// session file) before the agent is exec'd.
type Shim func(PlaceholderEnv) (ShimResult, error)

// PublicMaterial is the only argument an AuthStub gets besides the
// request. It is intentionally empty: stubs answer from constants.
type PublicMaterial struct{}

// AuthStub answers one agent request on a provider auth host locally.
// Everything else on that host is denied (invariant I12).
type AuthStub struct {
	Host       string // must be in the provider's AuthHosts (check C5)
	Method     string
	PathSuffix string
	Respond    func(req *http.Request, pm PublicMaterial) *http.Response
}

// AuthPath gates one path on a host the provider otherwise forwards
// (invariant I12, path-scoped; D1). The core answers a matching agent
// request in the MITM loop, before credential resolution: Respond when
// set and non-nil, else 403. Nothing is forwarded upstream.
type AuthPath struct {
	Host string // exact host this provider owns, not an auth host (check C8)
	// Path is lowercase and clean. A PathPrefix rule ends in "/" and
	// also matches the bare directory ("/oauth/" matches "/oauth").
	Path    string
	Match   PathMatch // PathExact or PathPrefix (check C8)
	Respond func(req *http.Request, pm PublicMaterial) *http.Response
}

// ApproverBackend lets llm_approver judge with this provider's models.
type ApproverBackend struct {
	ModelPrefixes []string
	URL           string
	Format        WireFormat
}

// Provider is one agent harness (or, for openai-sdk, one family of
// non-harness SDK clients).
type Provider struct {
	ID          string // sessions.type value
	DisplayName string
	IconURL     string

	APIHosts  []string   // exact host or "*.suffix"
	AuthHosts []string   // exact hosts only
	AuxHosts  []string   // exact host or "*.suffix"; lowest precedence
	AuthPaths []AuthPath // login/token paths on API or aux hosts (D1)

	Wire           []WireRoute
	SessionHeaders []string // first non-empty header value keys the session
	GenAISystem    string   // OTel gen_ai.provider.name

	CredentialTypes []string // HCL credential plugin types owned by this provider
	EndpointTypes   []string // HCL endpoint plugin types owned by this provider

	Launcher   *Launcher
	Approver   *ApproverBackend
	Stubs      []AuthStub
	BrowserTLS bool // dial API/aux hosts with the uTLS Chrome fingerprint
}
