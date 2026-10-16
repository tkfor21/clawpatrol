// Package claude registers the Claude Code agent provider.
package claude

import (
	"net/http"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

func init() {
	agentprovider.Register(&agentprovider.Provider{
		ID:          "claude",
		DisplayName: "Claude Code",
		IconURL:     "https://api.iconify.design/simple-icons:claude.svg?color=%23d97706",
		APIHosts:    []string{"api.anthropic.com"},
		// The gateway's own refresh/exchange calls go to
		// console.anthropic.com (anthropic_oauth.go TokenURL); the agent
		// never needs it, so the whole host is gated (I12).
		AuthHosts: []string{"console.anthropic.com"},
		AuxHosts:  []string{"anthropic.com", "*.anthropic.com", "claude.ai", "*.claude.ai", "claude.com", "*.claude.com"},
		// Claude Code itself logs in and refreshes on hosts that also
		// serve docs the agent fetches, so only the login paths are
		// gated (D1; strings in the Claude Code 2.1.296 binary). The
		// create_api_key path would let an agent mint a permanent API key
		// through the gateway's grant (D2). The same OAuth token handler
		// and create_api_key handler also answer on alias hosts (live
		// probes, 2026-10-11: POST /v1/oauth/token returns invalid_grant on
		// api.anthropic.com and claude.ai; create_api_key returns 401, not
		// 404, on platform.claude.com), so the aliases are gated too.
		AuthPaths: []agentprovider.AuthPath{
			// Claude Code's first-run connectivity check (preflight_endpoint)
			// needs a 200 here; answer it locally so the tree below stays
			// unforwarded (#18). First match wins, so it sits before the prefix.
			{Host: "platform.claude.com", Path: "/v1/oauth/hello", Match: agentprovider.PathExact, Respond: preflightHelloStub},
			{Host: "platform.claude.com", Path: "/v1/oauth/", Match: agentprovider.PathPrefix},
			{Host: "platform.claude.com", Path: "/oauth/", Match: agentprovider.PathPrefix},
			{Host: "claude.com", Path: "/cai/oauth/", Match: agentprovider.PathPrefix},
			{Host: "api.anthropic.com", Path: "/api/oauth/claude_cli/create_api_key", Match: agentprovider.PathExact},
			// Round-2 S105/S106: aliases of the same handlers.
			// create_api_key also answers on claude.ai and claude.com
			// (security review, round 4, X-01; D2).
			{Host: "platform.claude.com", Path: "/api/oauth/claude_cli/create_api_key", Match: agentprovider.PathExact},
			{Host: "claude.ai", Path: "/api/oauth/claude_cli/create_api_key", Match: agentprovider.PathExact},
			{Host: "claude.com", Path: "/api/oauth/claude_cli/create_api_key", Match: agentprovider.PathExact},
			{Host: "api.anthropic.com", Path: "/v1/oauth/", Match: agentprovider.PathPrefix},
			{Host: "claude.ai", Path: "/v1/oauth/", Match: agentprovider.PathPrefix},
			{Host: "claude.ai", Path: "/oauth/", Match: agentprovider.PathPrefix},
		},
		Wire: []agentprovider.WireRoute{
			{Host: "api.anthropic.com", Path: "/v1/messages", Match: agentprovider.PathExact, Format: agentprovider.WireAnthropicMessages},
		},
		GenAISystem:     "anthropic",
		CredentialTypes: []string{"anthropic_oauth_subscription", "anthropic_manual_key"},
		Launcher: &agentprovider.Launcher{
			Binaries: []string{"claude"},
			CompetingEnv: []string{
				"ANTHROPIC_API_KEY",
				"ANTHROPIC_AUTH_TOKEN", // DEV-19, user-approved (D6)
				// D6: other credential sources Claude Code 2.1.296 reads.
				"CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
				"CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR",
				"ANTHROPIC_FOUNDRY_API_KEY", "ANTHROPIC_AWS_API_KEY",
				// R2-D3: further credential sources in the same binary
				// (round-2 S104). CLAUDE_CODE_HOST_CREDS_FILE,
				// CLAUDE_CODE_HOST_AUTH_ENV_VAR and
				// CLAUDE_CODE_HFI_BEARER_TOKEN stay documented residuals.
				"ANTHROPIC_FOUNDRY_AUTH_TOKEN",
				"ANTHROPIC_IDENTITY_TOKEN", "ANTHROPIC_IDENTITY_TOKEN_FILE",
				"CLAUDE_CODE_SESSION_ACCESS_TOKEN",
				"CLAUDE_CODE_GATEWAY_TOKEN", "CLAUDE_CODE_GATEWAY_TOKEN_FILE_DESCRIPTOR",
				"CLAUDE_CODE_WEBSOCKET_AUTH_FILE_DESCRIPTOR",
				// D-R4-4 (A) (round 4): a JSON file holding the claude.ai
				// OAuth token, the file twin of CLAUDE_CODE_SESSION_ACCESS_TOKEN,
				// a dir override that unshadows the operator's real login,
				// and the Remote Control bearer. The other round-4 names are
				// documented residuals (claudeDocumentedResiduals).
				"CLAUDE_BG_AUTH_SNAPSHOT_PATH", "CLAUDE_SESSION_INGRESS_TOKEN_FILE",
				"CLAUDE_SECURESTORAGE_CONFIG_DIR", "CLAUDE_BRIDGE_OAUTH_TOKEN",
				// D-R4-4b (round 4 review): the SDK profile credential
				// files (config dir, profile name, federation token cache),
				// the env-quad federation mode, and the local Unix socket
				// relay that bypasses the network path the gateway sees.
				"ANTHROPIC_CONFIG_DIR", "ANTHROPIC_PROFILE", "CLAUDE_CODE_FEDERATION_CACHE_DIR",
				"ANTHROPIC_UNIX_SOCKET", "ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID",
				// D-R4-4b: a header list that can carry x-api-key or
				// Authorization, and a test hook whose value is an
				// admin-tier settings payload (env, apiKeyHelper).
				"ANTHROPIC_CUSTOM_HEADERS", "CLAUDE_CODE_MOCK_REMOTE_SETTINGS",
			},
			// D5: anthropic_oauth_subscription pushes ANTHROPIC_AUTH_TOKEN;
			// when it holds a value the shim runs whatever binary is wrapped.
			ShimTriggerEnv: []string{"ANTHROPIC_AUTH_TOKEN"},
			Shim:           Shim,
		},
		Approver: &agentprovider.ApproverBackend{
			ModelPrefixes: []string{"claude-"},
			URL:           "https://api.anthropic.com/v1/messages",
			Format:        agentprovider.WireAnthropicMessages,
		},
	})
}

// preflightHelloStub answers Claude Code's GET /v1/oauth/hello with an
// empty 200 (the client checks only the status). Any other method falls
// back to the gate's 403.
func preflightHelloStub(req *http.Request, _ agentprovider.PublicMaterial) *http.Response {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return nil
	}
	return &http.Response{
		Status: "200 OK", StatusCode: http.StatusOK,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:  http.Header{"Cache-Control": {"no-store"}},
		Body:    http.NoBody,
		Request: req,
	}
}
