package credentials

// grok_oauth: xAI Grok Build session auth. The gateway runs the device-code
// login from the dashboard and keeps the rotating refresh token; the agent
// only ever holds phGrok, written by the launcher shim into a managed
// auth.json (internal/config/plugins/agents/grok). auth.x.ai is a gated
// auth host, so the agent can neither log in nor refresh by itself.

import (
	"context"
	"net/http"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/plugins/agents/grok"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// GrokOAuth is part of the clawpatrol plugin API.
type GrokOAuth struct{}

// InjectHTTP is part of the clawpatrol plugin API. It overwrites the
// bearer and sets x-grok-user-id from the token's sub claim. The shim's
// placeholder session has an empty user_id, so grok omits the header and
// the gateway supplies the real one. Live check V9 confirmed that the
// access token's sub claim equals the account's user_id, which is the
// value grok itself sends there (xai-grok-sampler client.rs:85).
// X-XAI-Token-Auth is not a secret and is left as grok sent it.
func (*GrokOAuth) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	// An agent-set x-grok-user-id never survives, on any path, including
	// the empty-secret return below: only the gateway names the user.
	req.Header.Del("x-grok-user-id")
	if len(sec.Bytes) == 0 {
		return nil
	}
	tok := string(sec.Bytes)
	req.Header.Set("Authorization", "Bearer "+tok)
	if sub := jwtSubject(tok); validUserIDHeader(sub) {
		req.Header.Set("x-grok-user-id", sub)
	}
	return nil
}

// jwtSubject reads (without verifying) the sub claim of an IdP-issued JWT.
func jwtSubject(tok string) string {
	var c struct {
		Sub string `json:"sub"`
	}
	if !decodeJWTClaims(tok, &c) {
		return ""
	}
	return c.Sub
}

// validUserIDHeader reports whether sub can go into a header value as
// is: non-empty and no control byte, so no CR/LF split, NUL or TAB
// (R5-06). A user id has no legitimate control byte.
func validUserIDHeader(sub string) bool {
	for i := 0; i < len(sub); i++ {
		if c := sub[i]; c < 0x20 || c == 0x7f {
			return false
		}
	}
	return sub != ""
}

// EnvVars is part of the clawpatrol plugin API.
func (*GrokOAuth) EnvVars() []config.EnvVar {
	return []config.EnvVar{{
		Name:        grok.SessionEnv,
		Value:       phGrok,
		Description: "placeholder Grok Build session; `clawpatrol run grok` writes it into a managed auth.json",
	}}
}

// OAuthFlow is part of the clawpatrol plugin API. RFC 8628 device flow
// against auth.x.ai, form-encoded, public client.
func (*GrokOAuth) OAuthFlow() *config.OAuthIntegration {
	return &config.OAuthIntegration{
		Type:   "oauth2",
		Header: "Authorization",
		Prefix: "Bearer ",
		Flow:   "device",
		OAuth: config.OAuthConfig{
			ClientID:     grok.ClientID,
			DeviceURL:    grok.Issuer + "/oauth2/device/code",
			TokenURL:     grok.Issuer + "/oauth2/token", // V8 confirms against discovery
			Scopes:       grok.Scopes,
			ExtraParams:  map[string]string{"referrer": "grok-build"},
			PublicClient: true,
		},
	}
}

func init() {
	var _ runtime.HTTPCredentialRuntime = (*GrokOAuth)(nil)
	var _ config.OAuthFlowProvider = (*GrokOAuth)(nil)
	config.Register(&config.Plugin{
		Kind:           config.KindCredential,
		Type:           "grok_oauth",
		Disambiguators: []string{"placeholder"},
		New:            newer[GrokOAuth](),
		Runtime:        (*GrokOAuth)(nil),
		Build:          passthrough,
		Emit:           emptyEmit,
	})
}
