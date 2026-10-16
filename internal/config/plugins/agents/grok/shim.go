package grok

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// grokAuth mirrors the fields of grok's GrokAuth record (xai-grok-login
// src/model.rs:46-108) that a session needs. There is no refresh_token,
// so grok classifies the entry as a non-refreshable session
// (token_type.rs:26) and never calls auth.x.ai; expires_at is parked in
// 2099, so it never considers the token expired (model.rs:333-356).
// user_id is empty, so grok omits x-grok-user-id and the gateway sets the
// real one (credentials/grok_oauth.go; DEV-3, pending live check V9).
type grokAuth struct {
	Key          string  `json:"key"`
	AuthMode     string  `json:"auth_mode"`
	CreateTime   string  `json:"create_time"`
	UserID       string  `json:"user_id"`
	Email        *string `json:"email"`
	ExpiresAt    string  `json:"expires_at"`
	OIDCIssuer   string  `json:"oidc_issuer"`
	OIDCClientID string  `json:"oidc_client_id"`
}

// Shim writes the placeholder session to <clawpatrol dir>/grok/auth.json
// and points GROK_AUTH_PATH at it. It deliberately does not replace
// GROK_HOME, which would shadow the operator's ~/.grok config, skills and
// MCP servers. With no grok_oauth bound it still points GROK_AUTH_PATH at a
// managed empty store, so grok never falls back to a real login in
// ~/.grok/auth.json under clawpatrol run (locked decision 3: Grok uses
// account OAuth login only, and only the gateway logs in).
func Shim(pe agentprovider.PlaceholderEnv) (agentprovider.ShimResult, error) {
	path := filepath.Join(pe.ClawpatrolDir, "grok", "auth.json")
	ph := pe.Getenv(SessionEnv)
	if ph == "" {
		return agentprovider.ShimResult{
			Files:  []agentprovider.ShimFile{{Path: path, Data: []byte("{}\n")}},
			Env:    map[string]string{"GROK_AUTH_PATH": path},
			Notice: "grok: no grok_oauth credential is bound to this profile, so grok starts signed out (it cannot log in through auth.x.ai, which is gated; connect Grok Build in the dashboard)",
		}, nil
	}
	scope := strings.TrimRight(Issuer, "/") + "::" + ClientID // xai-grok-login config.rs:318-326
	data, err := json.MarshalIndent(map[string]grokAuth{scope: {
		Key:          ph,
		AuthMode:     "oidc",
		CreateTime:   time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:    "2099-01-01T00:00:00Z",
		OIDCIssuer:   Issuer,
		OIDCClientID: ClientID,
	}}, "", "  ")
	if err != nil {
		return agentprovider.ShimResult{}, err
	}
	return agentprovider.ShimResult{
		Files: []agentprovider.ShimFile{{Path: path, Data: data}},
		Env:   map[string]string{"GROK_AUTH_PATH": path},
		Unset: []string{SessionEnv},
	}, nil
}
