package claude

import (
	"net/url"
	"slices"
	"testing"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// claudeCodeClientURLs are read from the Claude Code 2.1.296 binary
// (strings ~/.local/share/claude/versions/2.1.296). gate is "host" for a
// whole-host auth host (AuthHosts), "path" for an AuthPaths rule, and ""
// for a URL the agent must still reach.
var claudeCodeClientURLs = []struct {
	url, gate string
}{
	{"https://platform.claude.com/v1/oauth/token", "path"},
	{"https://platform.claude.com/oauth/authorize", "path"},
	{"https://platform.claude.com/oauth/code/callback", "path"},
	{"https://platform.claude.com/oauth/code/success", "path"},
	{"https://claude.com/cai/oauth/authorize", "path"},
	{"https://api.anthropic.com/api/oauth/claude_cli/create_api_key", "path"}, // D2
	{"https://claude.ai/oauth/claude-code-client-metadata", "path"},
	// Alias hosts of the same handlers (round-2 S105/S106; live probes).
	{"https://platform.claude.com/api/oauth/claude_cli/create_api_key", "path"},
	{"https://api.anthropic.com/v1/oauth/token", "path"},
	{"https://claude.ai/v1/oauth/token", "path"},
	{"https://claude.ai/oauth/authorize", "path"},
	// X-01 (round 4, D2): create_api_key also answers on claude.ai and
	// claude.com; profile on the same host stays forwarded.
	{"https://claude.ai/api/oauth/claude_cli/create_api_key", "path"},
	{"https://claude.com/api/oauth/claude_cli/create_api_key", "path"},
	{"https://claude.ai/api/oauth/profile", ""},
	{"https://console.anthropic.com/v1/oauth/token", "host"}, // the gateway's own token endpoint
	{"https://platform.claude.com/llms.txt", ""},
	{"https://platform.claude.com/docs/en/api/messages", ""},
	{"https://claude.com/docs/llms.txt", ""},
	{"https://api.anthropic.com/v1/messages", ""},
	{"https://api.anthropic.com/api/oauth/profile", ""},
}

func TestClaudeCodeClientURLs(t *testing.T) {
	for _, tc := range claudeCodeClientURLs {
		u, err := url.Parse(tc.url)
		if err != nil {
			t.Fatalf("%s: %v", tc.url, err)
		}
		got := ""
		if p := agentprovider.AuthProvider(u.Host); p != nil {
			got = "host"
		} else if p, ap := agentprovider.AuthPathFor(u.Host, u.Path); ap != nil {
			if p.ID != "claude" {
				t.Errorf("%s: gated by %s, want claude", tc.url, p.ID)
			}
			got = "path"
		}
		if got != tc.gate {
			t.Errorf("%s: gate = %q, want %q", tc.url, got, tc.gate)
		}
	}
}

// claudeStripped is the decided set of Claude Code credential env names
// the core strips from every `clawpatrol run` (D6, DEV-19, R2-D3,
// D-R4-4 (A)). claudeDocumentedResiduals are credential sources the user
// decided to leave unstripped and document (R2-D3, D-R4-4 (A); Task 16).
// The recipe in Task 4 lists candidates; a new name needs a user
// decision and a row here.
var claudeStripped = []string{
	"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
	"CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
	"CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR",
	"ANTHROPIC_FOUNDRY_API_KEY", "ANTHROPIC_AWS_API_KEY",
	"ANTHROPIC_FOUNDRY_AUTH_TOKEN", "ANTHROPIC_IDENTITY_TOKEN", "ANTHROPIC_IDENTITY_TOKEN_FILE",
	"CLAUDE_CODE_SESSION_ACCESS_TOKEN", "CLAUDE_CODE_GATEWAY_TOKEN",
	"CLAUDE_CODE_GATEWAY_TOKEN_FILE_DESCRIPTOR", "CLAUDE_CODE_WEBSOCKET_AUTH_FILE_DESCRIPTOR",
	// D-R4-4 (A): model/API and bridge credential sources found in round 4.
	"CLAUDE_BG_AUTH_SNAPSHOT_PATH", "CLAUDE_SESSION_INGRESS_TOKEN_FILE",
	"CLAUDE_SECURESTORAGE_CONFIG_DIR", "CLAUDE_BRIDGE_OAUTH_TOKEN",
	// D-R4-4b: profile credential files, federation cache, env-quad
	// federation mode, and the Unix-socket relay.
	"ANTHROPIC_CONFIG_DIR", "ANTHROPIC_PROFILE", "CLAUDE_CODE_FEDERATION_CACHE_DIR",
	"ANTHROPIC_UNIX_SOCKET", "ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID",
	// Can carry x-api-key / Authorization; payload of admin-tier settings.
	"ANTHROPIC_CUSTOM_HEADERS", "CLAUDE_CODE_MOCK_REMOTE_SETTINGS",
}

// Non-env residuals the strip list cannot close, to document in Task 16:
// ~/.claude (Claude Code's own login files) and the implicit SDK profile
// at ~/.config/anthropic (or $XDG_CONFIG_HOME/anthropic), which Claude
// Code falls back to ("profile-implicit") when it holds a user_oauth or
// oidc_federation credential, with no env var set.
//
// Two more non-env residuals (D-R4-4b): (1) a base-URL override pointing
// at a pre-existing credentialed relay on localhost carries the same
// bypass risk as the stripped ANTHROPIC_UNIX_SOCKET; (2) settings files of
// any tier can supply credentials through an `env` block or `apiKeyHelper`,
// including the project .claude/settings*.json the agent can write. The
// names below only move a path or URL (standing rule: strip a name that
// can supply a credential, document one that only moves a path or URL).
var claudeDocumentedResiduals = []string{
	// D-R4-4b: move the login store / settings root, or hold a public cert.
	"CLAUDE_CONFIG_DIR",                    // relocates ~/.claude; stripping would break profiles outside ~/.claude and the OAuth shim's "both" mode
	"CLAUDE_CODE_CLIENT_CERT",              // public half of the mTLS pair; CLIENT_KEY is already a residual
	"CLAUDE_CODE_MANAGED_SETTINGS_PATH",    // moves the managed-settings channel; stripping would weaken policy
	"CLAUDE_CODE_REMOTE_SETTINGS_PATH",     // file standing in for admin remote settings
	"CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST", // boolean mode selector for host-managed auth, no secret (R2-D3 keeps HOST_CREDS_FILE)
	// D-R4-4b: base-URL redirects, TCP traffic the gateway still intercepts.
	"CLAUDE_CODE_API_BASE_URL",          // twin of ANTHROPIC_BASE_URL; loopback relay caveat above
	"CLAUDE_BRIDGE_BASE_URL",            // Remote Control bridge only; its bearer is stripped
	"CLAUDE_BRIDGE_SESSION_INGRESS_URL", // session ingress URL; its token is stripped
	"CLAUDE_REMOTE_TOOLS_BRIDGE_URL",    // remote-tools websocket; no model credential
	"CLAUDE_CODE_GB_BASE_URL",           // feature-flag server, not auth
	// D-R4-4b: dormant in 2.1.296 (the build's environment selector
	// returns "prod", so the local-OAuth URL builder is dead code); it
	// would become live in an internal or local build. The bare prefix
	// is what the recipe prints for the guard checks.
	"CLAUDE_LOCAL_OAUTH_", "CLAUDE_LOCAL_OAUTH_API_BASE", "CLAUDE_LOCAL_OAUTH_APPS_BASE", "CLAUDE_LOCAL_OAUTH_CONSOLE_BASE",
	// Not an env var: a key of the OAuth config object, the recipe's
	// regex catches it by accident.
	"CLAUDE_AI_AUTHORIZE_URL",
	// R2-D3.
	"CLAUDE_CODE_HOST_CREDS_FILE", "CLAUDE_CODE_HOST_AUTH_ENV_VAR", "CLAUDE_CODE_HFI_BEARER_TOKEN",
	// D-R4-4 (A): not model auth.
	"CLAUDE_TRUSTED_DEVICE_TOKEN", "CCR_AGENT_PROXY_TOKEN_FILE_DESCRIPTOR", "AGENT_PROXY_AUTH_TOKEN",
	"CLAUDE_BG_SOCKET_TOKENS_PATH", "CLAUDE_BG_RV_AUTH", "CLAUDE_BG_PTY_AUTH", "CLAUDE_BG_CLAIM_AUTH",
	"ANTHROPIC_ENVIRONMENT_KEY", "CLAUDE_CODE_MCP_SERVE_AUTH_TOKEN", "CLAUDE_CODE_MEMORY_API_TOKEN",
	"CLAUDE_CODE_MESSAGING_TOKEN", "CLAUDE_CODE_SLACK_TAG_TOKEN", "CLAUDE_CODE_ARTIFACTS_API_TOKEN",
	"CLAUDE_CODE_CLIENT_KEY", "CLAUDE_CODE_CLIENT_KEY_PASSPHRASE",
	"CLAUDE_CODE_CUSTOM_OAUTH_URL", "CLAUDE_CODE_OAUTH_CLIENT_ID",
}

func TestClaudeCompetingEnvIsTheDecidedSet(t *testing.T) {
	p := agentprovider.ByID("claude")
	if p == nil || p.Launcher == nil {
		t.Fatal("claude provider or its launcher is not registered")
	}
	got := slices.Sorted(slices.Values(p.Launcher.CompetingEnv))
	want := slices.Sorted(slices.Values(claudeStripped))
	if !slices.Equal(got, want) {
		t.Fatalf("claude CompetingEnv = %v\nwant the decided set %v", got, want)
	}
	for _, n := range claudeDocumentedResiduals {
		if slices.Contains(got, n) {
			t.Errorf("%s is a documented residual (R2-D3, D-R4-4 (A)) but is stripped; change the decision, not the list", n)
		}
	}
}
