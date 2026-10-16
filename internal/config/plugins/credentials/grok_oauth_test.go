package credentials

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/plugins/agents/grok"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func fakeJWT(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(payload)) + ".sig"
}

func TestGrokOAuthInjectHTTP(t *testing.T) {
	g := &GrokOAuth{}
	tok := fakeJWT(`{"sub":"user-42"}`)
	req, _ := http.NewRequest(http.MethodPost, "https://cli-chat-proxy.grok.com/v1/responses", nil)
	req.Header.Set("Authorization", "Bearer "+phGrok)
	req.Header.Set("X-XAI-Token-Auth", "xai-grok-cli")
	// The agent's own values must not survive beside the real one.
	req.Header.Add("x-grok-user-id", "forged-1")
	req.Header.Add("x-grok-user-id", "forged-2")
	if err := g.InjectHTTP(context.Background(), req, runtime.Secret{Bytes: []byte(tok)}); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer "+tok {
		t.Fatalf("Authorization = %q", got)
	}
	if got := req.Header.Values("x-grok-user-id"); !slices.Equal(got, []string{"user-42"}) {
		t.Fatalf("x-grok-user-id = %q, want exactly [user-42]", got)
	}
	if got := req.Header.Get("X-XAI-Token-Auth"); got != "xai-grok-cli" {
		t.Fatalf("X-XAI-Token-Auth changed to %q", got)
	}

	opaque, _ := http.NewRequest(http.MethodPost, "https://cli-chat-proxy.grok.com/v1/responses", nil)
	opaque.Header.Set("x-grok-user-id", "placeholder-user")
	_ = g.InjectHTTP(context.Background(), opaque, runtime.Secret{Bytes: []byte("opaque-token-0123456789")})
	if _, ok := opaque.Header["X-Grok-User-Id"]; ok {
		t.Fatal("x-grok-user-id kept for a non-JWT token; it must be removed")
	}

	// A sub with a control byte is never put in a header (R5-06).
	for _, sub := range []string{"u\r\nX-Injected: 1", "u\x00v", "u\tv", "u\x7fv"} {
		bad, _ := http.NewRequest(http.MethodPost, "https://cli-chat-proxy.grok.com/v1/responses", nil)
		bad.Header.Set("x-grok-user-id", "forged")
		payload, _ := json.Marshal(map[string]string{"sub": sub})
		_ = g.InjectHTTP(context.Background(), bad, runtime.Secret{Bytes: []byte(fakeJWT(string(payload)))})
		if v := bad.Header.Values("x-grok-user-id"); len(v) != 0 {
			t.Errorf("sub %q: x-grok-user-id = %q, want it removed", sub, v)
		}
	}
}

// With no secret (not connected yet, or needs reauth) the injector leaves
// Authorization as the agent sent it, as before, but an agent-set
// x-grok-user-id must still not ride along upstream.
func TestGrokOAuthInjectHTTPEmptySecretStripsUserID(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://cli-chat-proxy.grok.com/v1/responses", nil)
	req.Header.Set("Authorization", "Bearer "+phGrok)
	req.Header.Add("x-grok-user-id", "forged-1")
	req.Header.Add("x-grok-user-id", "forged-2")
	if err := (&GrokOAuth{}).InjectHTTP(context.Background(), req, runtime.Secret{}); err != nil {
		t.Fatal(err)
	}
	if v := req.Header.Values("x-grok-user-id"); len(v) != 0 {
		t.Fatalf("x-grok-user-id = %q with an empty secret, want it removed", v)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer "+phGrok {
		t.Fatalf("Authorization = %q, want the agent's value left as it was", got)
	}
}

func TestGrokOAuthFlow(t *testing.T) {
	f := (&GrokOAuth{}).OAuthFlow()
	if f.Flow != "device" || !f.OAuth.PublicClient || f.OAuth.ClientID != grok.ClientID {
		t.Fatalf("flow = %+v", f)
	}
	for _, raw := range []string{f.OAuth.DeviceURL, f.OAuth.TokenURL} {
		if u, _ := url.Parse(raw); u.Host != "auth.x.ai" {
			t.Fatalf("%s is not on auth.x.ai", raw)
		}
	}
	if f.OAuth.ExtraParams["referrer"] != "grok-build" {
		t.Fatalf("ExtraParams = %v", f.OAuth.ExtraParams)
	}
	if !slices.Contains(f.OAuth.Scopes, "grok-cli:access") || !slices.Contains(f.OAuth.Scopes, "offline_access") {
		t.Fatalf("scopes = %v", f.OAuth.Scopes)
	}
}

func TestGrokOAuthEnvVarsPushPlaceholderOnly(t *testing.T) {
	vars := (&GrokOAuth{}).EnvVars()
	if len(vars) != 1 || vars[0].Name != grok.SessionEnv || vars[0].Value != phGrok {
		t.Fatalf("EnvVars = %+v", vars)
	}
}
