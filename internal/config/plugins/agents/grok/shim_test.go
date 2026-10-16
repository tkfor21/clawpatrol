package grok

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// The literal below is credentials.phGrok's value (unexported in another
// package); the two must agree, since the shim writes what pushdown sends.
func TestShimWritesNonRefreshablePlaceholderSession(t *testing.T) {
	dir := t.TempDir()
	res, err := Shim(agentprovider.PlaceholderEnv{ClawpatrolDir: dir, Getenv: env(map[string]string{SessionEnv: "grok-clawpatrol-placeholder-do-not-use"})})
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(dir, "grok", "auth.json")
	if len(res.Files) != 1 || res.Files[0].Path != wantPath {
		t.Fatalf("files = %+v", res.Files)
	}
	if res.Env["GROK_AUTH_PATH"] != wantPath {
		t.Fatalf("GROK_AUTH_PATH = %q", res.Env["GROK_AUTH_PATH"])
	}
	if len(res.Unset) != 1 || res.Unset[0] != SessionEnv {
		t.Fatalf("unset = %v", res.Unset)
	}
	var doc map[string]map[string]any
	if err := json.Unmarshal(res.Files[0].Data, &doc); err != nil {
		t.Fatal(err)
	}
	entry, ok := doc[Issuer+"::"+ClientID]
	if !ok || len(doc) != 1 {
		t.Fatalf("scope keys = %v, want exactly %q", doc, Issuer+"::"+ClientID)
	}
	if entry["key"] != "grok-clawpatrol-placeholder-do-not-use" || entry["auth_mode"] != "oidc" ||
		entry["oidc_issuer"] != Issuer || entry["oidc_client_id"] != ClientID ||
		entry["expires_at"] != "2099-01-01T00:00:00Z" || entry["user_id"] != "" {
		t.Fatalf("entry = %v", entry)
	}
	if _, has := entry["refresh_token"]; has {
		t.Fatal("refresh_token present: grok would try to refresh against auth.x.ai")
	}
	for _, k := range []string{"create_time", "email"} { // required by GrokAuth serde (model.rs:46-108)
		if _, has := entry[k]; !has {
			t.Fatalf("missing required field %q", k)
		}
	}
}

// With no grok_oauth bound, grok must still never fall back to the
// operator's ~/.grok/auth.json under clawpatrol run: the shim points
// GROK_AUTH_PATH at a managed, empty store ("{}" is a valid store with
// no login; xai-grok-login storage.rs:89-92).
func TestShimWithoutCredentialWritesEmptyStore(t *testing.T) {
	dir := t.TempDir()
	res, err := Shim(agentprovider.PlaceholderEnv{ClawpatrolDir: dir, Getenv: env(nil)})
	if err != nil || res.Notice == "" {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	wantPath := filepath.Join(dir, "grok", "auth.json")
	if len(res.Files) != 1 || res.Files[0].Path != wantPath || string(res.Files[0].Data) != "{}\n" {
		t.Fatalf("files = %+v, want an empty store at %s", res.Files, wantPath)
	}
	if res.Env["GROK_AUTH_PATH"] != wantPath {
		t.Fatalf("GROK_AUTH_PATH = %q, want %q", res.Env["GROK_AUTH_PATH"], wantPath)
	}
}
