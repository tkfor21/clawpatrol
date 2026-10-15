package claude

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// Shim is the `clawpatrol run claude` workaround for Claude Code's local
// auth-mode gate (formerly installClaudeCodeOAuthShim in cmd/clawpatrol;
// see doc/claude-code-oauth.md and anthropics/claude-code#33105).
//
// Claude Code refuses /remote-control whenever ANTHROPIC_AUTH_TOKEN is
// set, and reads OAuth scopes from the LOCAL .credentials.json, so a
// header rewrite at the gateway cannot satisfy it. When the operator opts
// in (CLAWPATROL_CLAUDE_OAUTH_SHIM=1) we write a placeholder
// .credentials.json into a CLAUDE_CONFIG_DIR and unset the bearer so
// Claude Code falls through to subscription OAuth. The gateway still
// swaps the Authorization header upstream. Off by default (R&D decision,
// 2026-06-03): pointing CLAUDE_CONFIG_DIR at a managed dir shadows the
// worker's ~/.claude.
func Shim(pe agentprovider.PlaceholderEnv) (agentprovider.ShimResult, error) {
	bearer := pe.Getenv("ANTHROPIC_AUTH_TOKEN")
	if bearer == "" {
		return agentprovider.ShimResult{}, nil // no OAuth credential bound to this profile
	}
	if pe.Getenv("CLAWPATROL_CLAUDE_OAUTH_SHIM") != "1" {
		return agentprovider.ShimResult{Notice: remoteControlNotice}, nil
	}
	dir := pe.Getenv("CLAUDE_CONFIG_DIR")
	managed := dir == ""
	if managed {
		dir = filepath.Join(pe.ClawpatrolDir, "claude-config")
	}
	credPath := filepath.Join(dir, ".credentials.json")
	if !managed {
		// A real /login in an operator-set dir wins once the bearer is
		// gone, but only a file that parses: an empty or cut file left by
		// a failed earlier write would otherwise be trusted on every later
		// launch (R4-01).
		if b, err := os.ReadFile(credPath); err == nil && json.Valid(b) {
			return agentprovider.ShimResult{Unset: []string{"ANTHROPIC_AUTH_TOKEN"}}, nil
		}
	}
	body, err := credentialsJSON(bearer)
	if err != nil {
		return agentprovider.ShimResult{}, err
	}
	res := agentprovider.ShimResult{
		Files: []agentprovider.ShimFile{{Path: credPath, Data: body}},
		Unset: []string{"ANTHROPIC_AUTH_TOKEN"},
	}
	if managed {
		res.Env = map[string]string{"CLAUDE_CONFIG_DIR": dir}
	}
	return res, nil
}

// credentialsJSON emits the shape Claude Code's /login persists. Both
// tokens are placeholders; expiresAt is parked far in the future so
// Claude Code never tries to refresh (console.anthropic.com is a gated
// auth host anyway).
func credentialsJSON(bearer string) ([]byte, error) {
	return json.MarshalIndent(map[string]any{
		"claudeAiOauth": map[string]any{
			"accessToken":      bearer,
			"refreshToken":     "sk-ant-ort01-clawpatrol-placeholder-do-not-use",
			"expiresAt":        int64(9999999999999), // 2286-11-20T17:46:39.999Z
			"scopes":           []string{"user:inference", "user:profile", "user:sessions:claude_code"},
			"subscriptionType": "max",
		},
	}, "", "  ")
}

const remoteControlNotice = `Claude Code /remote-control and other claude.ai
subscription-only features are disabled in this session: ANTHROPIC_AUTH_TOKEN
is set, so Claude Code treats this as API-key auth and gates them off locally.

To enable them, opt into the OAuth shim:

    CLAWPATROL_CLAUDE_OAUTH_SHIM=1 clawpatrol run claude ...

The shim writes a synthesized .credentials.json and points CLAUDE_CONFIG_DIR at
it for the child. Because that shadows your existing ~/.claude (skills, memory,
MCP servers, project state), it is off by default — set CLAUDE_CONFIG_DIR to
your own dir first if you want both. See doc/claude-code-oauth.md.`
