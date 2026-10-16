// Package grok registers the xAI Grok Build agent provider. Facts are
// taken from the open-source grok-build tree (crates/codegen/...):
// xai-grok-login/src/config.rs (issuer, client id, scopes),
// device_code.rs (device flow), oidc/refresh.rs (rotating refresh).
package grok

const (
	// Issuer is the Grok Build OIDC issuer (xai-grok-login config.rs:124-165).
	Issuer = "https://auth.x.ai"
	// ClientID is grok's public OAuth client id (config.rs:380).
	ClientID = "b1a00492-073a-47ea-816f-4c329264a828"
	// SessionEnv carries the gateway placeholder from env pushdown to the
	// launcher shim, which writes it into a managed auth.json and unsets it.
	SessionEnv = "CLAWPATROL_GROK_SESSION"
)

// Scopes are grok's default scopes (config.rs:16-29). grok-cli:access is
// required for cli-chat-proxy.grok.com; offline_access yields the
// refresh token the gateway keeps.
var Scopes = []string{
	"openid", "profile", "email", "offline_access", "grok-cli:access", "api:access",
	"conversations:read", "conversations:write", "workspaces:read", "workspaces:write",
}
