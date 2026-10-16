package grok

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// preflightEnv points grok's system dir and $GROK_HOME at temp dirs.
func preflightEnv(t *testing.T) (pe agentprovider.PlaceholderEnv, sysDir, home string) {
	t.Helper()
	sysDir, home = t.TempDir(), t.TempDir()
	saved := systemConfigDir
	systemConfigDir = sysDir
	t.Cleanup(func() { systemConfigDir = saved })
	return agentprovider.PlaceholderEnv{Getenv: env(map[string]string{"GROK_HOME": home})}, sysDir, home
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPreflightAllowsCleanOrMissingConfig(t *testing.T) {
	pe, _, home := preflightEnv(t)
	if err := Preflight(pe); err != nil {
		t.Fatalf("no config files: %v", err)
	}
	writeFile(t, filepath.Join(home, "config.toml"), "[ui]\ntheme = \"dark\"\n\n[endpoints]\n")
	if err := Preflight(pe); err != nil {
		t.Fatalf("clean config with an empty [endpoints] table: %v", err)
	}
	// R2-D4: per-model tables that set none of the credential keys are
	// fine, and so is an empty [auth_provider] table.
	writeFile(t, filepath.Join(home, "config.toml"), "[auth_provider]\n\n[model.custom]\ncontext_window = 200000\n\n[model_providers.corp]\ncontext_window = 200000\n")
	if err := Preflight(pe); err != nil {
		t.Fatalf("per-model tables without credential keys: %v", err)
	}
	// D-R4-5 (A): empty header and query tables add nothing.
	writeFile(t, filepath.Join(home, "config.toml"), "[models]\nextra_headers = {}\n\n[model.custom]\nquery_params = {}\nenv_http_headers = {}\n\n[model_providers.corp]\nextra_headers = {}\n")
	if err := Preflight(pe); err != nil {
		t.Fatalf("empty header and query tables: %v", err)
	}
}

// D7: each credential source refuses the launch, naming the file and the
// key, in every TOML spelling (table, dotted key, inline table, quoted
// and escaped key).
func TestPreflightRefusesCredentialSources(t *testing.T) {
	cases := []struct{ file, body, key string }{
		{"config.toml", "[grok_com_config]\nauth_provider_command = \"/usr/local/bin/get-token\"\n", "grok_com_config.auth_provider_command"},
		{"config.toml", "[grok_com_config.oidc]\nissuer = \"https://idp.example.test\"\nclient_id = \"c\"\n", "grok_com_config.oidc"},
		{"config.toml", "[auth.oauth2]\nissuer = \"https://idp.example.test\"\n", "auth.oauth2"},
		{"config.toml", "auth = { auth_provider_command = \"x\" }\n", "auth.auth_provider_command"},
		{"config.toml", "grok_com_config.oidc.issuer = \"https://idp.example.test\"\n", "grok_com_config.oidc"},
		{"config.toml", "[grok_com_config]\n\"auth_provider_command\" = \"x\"\n", "grok_com_config.auth_provider_command"},
		{"config.toml", "[grok_com_config]\n\"\\u0061uth_provider_command\" = \"x\"\n", "grok_com_config.auth_provider_command"},
		{"config.toml", "[endpoints]\ncli_chat_proxy_base_url = \"https://proxy.example.test\"\n", "[endpoints]"},
		{"config.toml", "endpoints.models_base_url = \"https://models.example.test\"\n", "[endpoints]"},
		{"managed_config.toml", "[endpoints]\nxai_api_base_url = \"https://x.example.test\"\n", "[endpoints]"},
		{"requirements.toml", "[grok_com_config]\noauth2 = { issuer = \"https://idp.example.test\" }\n", "grok_com_config.oauth2"},
		// Round-2 F102/S102: [[version_overrides]] and [[campaigns]]
		// entries are patches grok deep-merges into the layer, whatever
		// their version bounds.
		{"config.toml", "[[version_overrides]]\n[version_overrides.grok_com_config]\nauth_provider_command = \"/tmp/get-token\"\n", "version_overrides[0].grok_com_config.auth_provider_command"},
		{"config.toml", "[[version_overrides]]\nminimum_version = \"99.0.0\"\n[version_overrides.auth.oidc]\nissuer = \"https://idp.example.test\"\n", "version_overrides[0].auth.oidc"},
		{"config.toml", "[[version_overrides]]\nminimum_version = \"1.0.0\"\n[[version_overrides]]\n[version_overrides.grok_com_config]\noauth2 = { issuer = \"https://idp.example.test\" }\n", "version_overrides[1].grok_com_config.oauth2"},
		{"managed_config.toml", "[[version_overrides]]\n[version_overrides.endpoints]\ncli_chat_proxy_base_url = \"https://proxy.example.test\"\n", "version_overrides[0].endpoints"},
		{"config.toml", "[[campaigns]]\n[campaigns.endpoints]\nmodels_base_url = \"https://models.example.test\"\n", "campaigns[0].endpoints"},
		{"config.toml", "version_overrides = \"x\"\n", "version_overrides (not an array of tables)"},
		// R2-D4: [auth_provider.<name>] command tables, and per-model
		// tables that name their own credential or destination, at top
		// level and inside every version_overrides and campaigns entry.
		{"config.toml", "[auth_provider.corp]\ncommand = \"/usr/local/bin/mint-token\"\n", "auth_provider.corp"},
		{"config.toml", "[model_providers.corp]\nbase_url = \"https://llm.example.test/v1\"\n", "model_providers.corp.base_url"},
		{"config.toml", "[model_providers.corp]\nenv_key = \"CORP_LLM_KEY\"\n", "model_providers.corp.env_key"},
		{"config.toml", "[model_providers.corp.auth]\ncommand = \"/usr/local/bin/mint-token\"\n", "model_providers.corp.auth"},
		{"config.toml", "model_providers.corp.api_key = \"k\"\n", "model_providers.corp.api_key"},
		{"config.toml", "[model.\"grok-4\"]\napi_key = \"k\"\n", "model.grok-4.api_key"},
		{"config.toml", "[model.custom]\nauth_provider = \"corp\"\n", "model.custom.auth_provider"},
		{"config.toml", "[model.custom]\napi_base_url = \"https://alt.example.test\"\n", "model.custom.api_base_url"},
		{"config.toml", "[model.custom]\nmtls_cert_dir = \"/etc/grok-certs\"\n", "model.custom.mtls_cert_dir"},
		{"managed_config.toml", "[model.custom]\nbase_url = \"https://m.example.test\"\n", "model.custom.base_url"},
		{"config.toml", "[[version_overrides]]\n[version_overrides.auth_provider.corp]\ncommand = \"x\"\n", "version_overrides[0].auth_provider.corp"},
		{"config.toml", "[[version_overrides]]\n[version_overrides.model.custom]\napi_key = \"k\"\n", "version_overrides[0].model.custom.api_key"},
		{"config.toml", "[[campaigns]]\n[campaigns.model_providers.corp]\nbase_url = \"https://x.example.test\"\n", "campaigns[0].model_providers.corp.base_url"},
		// Parser differential (round 4): grok parses TOML 1.1 (toml 0.9.12
		// +spec-1.1.0), so a \x escape in a key, a literal-quoted key, and
		// an inline table spread over lines with a trailing comma are all
		// the refused key. The decoder must read them the same way.
		{"config.toml", "[grok_com_config]\n\"\\x61uth_provider_command\" = \"x\"\n", "grok_com_config.auth_provider_command"},
		{"config.toml", "[grok_com_config]\n'auth_provider_command' = \"x\"\n", "grok_com_config.auth_provider_command"},
		{"config.toml", "auth = {\n  auth_provider_command = \"x\",\n}\n", "auth.auth_provider_command"},
		// R5-07: grok reads the inline-array form of these patch lists too
		// (toml::Value does not tell [[x]] from x = [{...}]).
		{"config.toml", "version_overrides = [{ grok_com_config = { auth_provider_command = \"x\" } }]\n", "version_overrides[0].grok_com_config.auth_provider_command"},
		{"config.toml", "campaigns = [{ endpoints = { models_base_url = \"https://m.example.test\" } }]\n", "campaigns[0].endpoints"},
		// D-R4-5 (A): per-model and per-provider header and query tables,
		// and the global [models].extra_headers, at top level and in a
		// version_overrides or campaigns entry.
		{"config.toml", "[model.custom]\nextra_headers = { X-Api-Key = \"k\" }\n", "model.custom.extra_headers"},
		{"config.toml", "[model.custom.env_http_headers]\nAuthorization = \"CORP_TOKEN\"\n", "model.custom.env_http_headers"},
		{"config.toml", "[model.custom.query_params]\nkey = \"k\"\n", "model.custom.query_params"},
		{"config.toml", "[model_providers.corp]\nextra_headers = { X-Api-Key = \"k\" }\n", "model_providers.corp.extra_headers"},
		{"config.toml", "[model_providers.corp.env_http_headers]\nAuthorization = \"CORP_TOKEN\"\n", "model_providers.corp.env_http_headers"},
		{"config.toml", "[model_providers.corp]\nquery_params = { key = \"k\" }\n", "model_providers.corp.query_params"},
		{"config.toml", "[models.extra_headers]\nAuthorization = \"Bearer k\"\n", "models.extra_headers"},
		{"managed_config.toml", "[models]\nextra_headers = \"not a table\"\n", "models.extra_headers"},
		{"config.toml", "[[campaigns]]\n[campaigns.models]\nextra_headers = { X-Api-Key = \"k\" }\n", "campaigns[0].models.extra_headers"},
		{"config.toml", "[[campaigns]]\n[campaigns.model.custom]\nenv_http_headers = { Authorization = \"CORP_TOKEN\" }\n", "campaigns[0].model.custom.env_http_headers"},
		{"config.toml", "[[campaigns]]\n[campaigns.model_providers.corp]\nextra_headers = { X-Api-Key = \"k\" }\n", "campaigns[0].model_providers.corp.extra_headers"},
		{"config.toml", "[[version_overrides]]\n[version_overrides.model_providers.corp]\nquery_params = { key = \"k\" }\n", "version_overrides[0].model_providers.corp.query_params"},
	}
	for _, tc := range cases {
		pe, _, home := preflightEnv(t)
		path := filepath.Join(home, tc.file)
		writeFile(t, path, tc.body)
		err := Preflight(pe)
		if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), tc.key) {
			t.Errorf("%s %q: err = %v, want a refusal naming %s and %s", tc.file, tc.body, err, path, tc.key)
		}
	}
}

func TestPreflightReadsSystemLayers(t *testing.T) {
	for _, f := range []string{"managed_config.toml", "requirements.toml"} {
		pe, sysDir, _ := preflightEnv(t)
		path := filepath.Join(sysDir, f)
		writeFile(t, path, "[grok_com_config]\nauth_provider_command = \"x\"\n")
		if err := Preflight(pe); err == nil || !strings.Contains(err.Error(), path) {
			t.Errorf("%s: err = %v, want a refusal naming it", path, err)
		}
	}
}

// With GROK_HOME unset, grok reads $HOME/.grok (xai-dirs lib.rs:48-58).
func TestPreflightDefaultsToHomeDotGrok(t *testing.T) {
	pe, _, _ := preflightEnv(t)
	home := t.TempDir()
	pe.Getenv = env(map[string]string{"HOME": home})
	path := filepath.Join(home, ".grok", "config.toml")
	writeFile(t, path, "[endpoints]\nmodels_base_url = \"https://m.example.test\"\n")
	if err := Preflight(pe); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("err = %v, want a refusal naming %s", err, path)
	}
}

// A config the preflight cannot parse refuses too: it cannot confirm the
// file is safe.
func TestPreflightRefusesUnparsableConfig(t *testing.T) {
	pe, _, home := preflightEnv(t)
	path := filepath.Join(home, "config.toml")
	writeFile(t, path, "this is = = not toml\n")
	if err := Preflight(pe); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("err = %v, want a refusal naming %s", err, path)
	}
}

// A config file that cannot be read refuses the launch, naming the
// file. A directory in its place fails for root too, unlike chmod 0
// (R5-07).
func TestPreflightRefusesUnreadableConfig(t *testing.T) {
	pe, _, home := preflightEnv(t)
	path := filepath.Join(home, "config.toml")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Preflight(pe); err == nil || !strings.Contains(err.Error(), "cannot read grok config "+path) {
		t.Fatalf("err = %v, want a cannot-read refusal naming %s", err, path)
	}
}

// settingsCache builds a settings_cache.json in the shape grok writes
// (xai-grok-cloud-config settings_cache.rs:37-51). The signature is junk:
// the preflight does not check it, because a forged entry is the threat.
func settingsCache(t *testing.T, campaigns ...map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"grok_version": "0.0.0", "settings": map[string]any{"campaigns": campaigns}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"payload": string(payload), "signature": []int{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// D-R4-5 (A): grok applies the campaigns in a fresh settings cache at
// startup with no allowlist, and anyone who can write the file can sign
// it, so a campaign there that names a credential source or re-points an
// endpoint refuses the launch, naming the file and the key. A cache whose
// campaigns set nothing of the kind, or that has none, is fine; one that
// does not parse refuses.
func TestPreflightChecksSettingsCacheCampaigns(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"no campaigns", settingsCache(t), ""},
		{"harmless campaign", settingsCache(t, map[string]any{"id": "c1", "ui": map[string]any{"theme": "dark"}}), ""},
		{"endpoints", settingsCache(t, map[string]any{"id": "c1"}, map[string]any{"id": "c2", "endpoints": map[string]any{"models_base_url": "https://m.example.test"}}), "campaigns[1].endpoints"},
		{"model api_key", settingsCache(t, map[string]any{"id": "c1", "model": map[string]any{"grok-4": map[string]any{"api_key": "k"}}}), "campaigns[0].model.grok-4.api_key"},
		{"global extra_headers", settingsCache(t, map[string]any{"id": "c1", "models": map[string]any{"extra_headers": map[string]any{"Authorization": "Bearer k"}}}), "campaigns[0].models.extra_headers"},
		{"login override", settingsCache(t, map[string]any{"id": "c1", "grok_com_config": map[string]any{"auth_provider_command": "x"}}), "campaigns[0].grok_com_config.auth_provider_command"},
		{"not json", "{not json", "does not parse"},
		{"payload not json", `{"payload":"{not json","signature":[]}`, "does not parse"},
	} {
		pe, _, home := preflightEnv(t)
		path := filepath.Join(home, "settings_cache.json")
		writeFile(t, path, tc.body)
		err := Preflight(pe)
		if tc.want == "" {
			if err != nil {
				t.Errorf("%s: err = %v, want none", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want a refusal naming %s and %s", tc.name, err, path, tc.want)
		}
	}
}
