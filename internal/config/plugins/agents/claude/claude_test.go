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
}

var claudeDocumentedResiduals = []string{
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
