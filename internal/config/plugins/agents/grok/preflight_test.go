package grok

import (
	"encoding/json"
	"maps"
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
	// Fix round 1 (S1): grok parses a whitespace-only file as an empty
	// table (xai-grok-config loader.rs:13-15); its model tables are
	// case-sensitive serde structs with no rename (xai-grok-shell
	// agent/config.rs:3459-3461), so API_KEY is an ignored unknown field
	// there too; and the web_search domain lists carry no credential.
	for _, body := range []string{
		" \r\n\t\n",
		"[model.custom]\nAPI_KEY = \"k\"\n",
		"[toolset.web_search]\nallowed_domains = [\"docs.example.test\"]\nextra_headers = {}\n",
		"[toolset.web_fetch]\nallowed_domains = [\"docs.example.test\"]\n",
	} {
		writeFile(t, filepath.Join(home, "config.toml"), body)
		if err := Preflight(pe); err != nil {
			t.Fatalf("%q: %v", body, err)
		}
	}
}

// Minor 2: with neither GROK_HOME nor HOME set, the preflight cannot tell
// which grok home grok will read (grok falls back to the passwd entry's
// home directory via std::env::home_dir, xai-dirs lib.rs:33-38, :50-58),
// so it refuses rather than skipping the user layers.
func TestPreflightRefusesWithoutHome(t *testing.T) {
	pe, _, _ := preflightEnv(t)
	pe.Getenv = env(nil)
	if err := Preflight(pe); err == nil || !strings.Contains(err.Error(), "GROK_HOME") {
		t.Fatalf("err = %v, want a refusal naming GROK_HOME", err)
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
		// Fix round 1 (S1). [grok_com_config] also names the relay
		// WebSocket endpoint (xai-grok-login config.rs:179-191, :209-210),
		// an endpoint override like [endpoints].
		{"config.toml", "[grok_com_config]\ngrok_ws_url = \"wss://relay.example.test\"\n", "grok_com_config.grok_ws_url"},
		{"config.toml", "[auth]\ngrok_ws_origin = \"https://origin.example.test\"\n", "auth.grok_ws_origin"},
		// A login section that is not a table: grok fails to deserialize it
		// (config.rs:272-277); fail closed rather than skip it.
		{"config.toml", "grok_com_config = \"x\"\n", "grok_com_config (not a table)"},
		{"config.toml", "auth = [1]\n", "auth (not a table)"},
		// [toolset.web_search] is a full sampler config (xai-grok-shell
		// tools/config.rs:162, xai-grok-sampler config.rs:38-64) with its
		// own key, destination and headers; grok calls them sinks
		// (xai-grok-config config_override.rs:108-109).
		{"config.toml", "[toolset.web_search]\napi_key = \"k\"\n", "toolset.web_search.api_key"},
		{"config.toml", "[toolset.web_search]\nbase_url = \"https://s.example.test\"\n", "toolset.web_search.base_url"},
		{"config.toml", "[toolset.web_search]\nmtls_cert_dir = \"/etc/c\"\n", "toolset.web_search.mtls_cert_dir"},
		{"config.toml", "[toolset.web_search.extra_headers]\nAuthorization = \"Bearer k\"\n", "toolset.web_search.extra_headers"},
		{"config.toml", "[toolset.web_search]\nenv_http_headers = { Authorization = \"T\" }\n", "toolset.web_search.env_http_headers"},
		{"config.toml", "[toolset.web_search]\nquery_params = { key = \"k\" }\n", "toolset.web_search.query_params"},
		{"config.toml", "toolset = \"x\"\n", "toolset (not a table)"},
		{"config.toml", "[[campaigns]]\n[campaigns.toolset.web_search]\napi_key = \"k\"\n", "campaigns[0].toolset.web_search.api_key"},
		// Parser differential rows: a BOM, CRLF line ends and leading
		// blank lines read the same in both parsers; a duplicate key or
		// table, which grok's toml 0.9 rejects, does not parse here either
		// (refused, never read last-wins); a dotted key a later [header]
		// extends still shows the refused key.
		{"config.toml", "\xef\xbb\xbf[grok_com_config]\nauth_provider_command = \"x\"\n", "grok_com_config.auth_provider_command"},
		{"config.toml", "\r\n  \r\n[grok_com_config]\r\nauth_provider_command = \"x\"\r\n", "grok_com_config.auth_provider_command"},
		{"config.toml", "[model.custom]\ncontext_window = 1\ncontext_window = 2\n", "does not parse"},
		{"config.toml", "[endpoints]\n[endpoints]\n", "does not parse"},
		{"config.toml", "[grok_com_config]\nauth_provider_command = \"x\"\n[grok_com_config]\nauth_provider_label = \"y\"\n", "does not parse"},
		{"config.toml", "grok_com_config.preferred_method = \"api_key\"\n[grok_com_config.oidc]\nissuer = \"https://idp.example.test\"\n", "grok_com_config.oidc"},
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
		// Fix round 1: grok's serde_json is case-sensitive and refuses a
		// duplicate struct field (settings_cache.rs:37-51; remote_settings.rs:622-623),
		// so a case-folding or last-wins reader would read a different
		// campaign list than grok. Keys match exactly, and any duplicate
		// key refuses.
		{"case-variant campaigns hides the real list", `{"payload":` + jsonString(t, `{"settings":{"campaigns":[{"id":"c","endpoints":{"models_base_url":"https://m.example.test"}}],"Campaigns":[]}}`) + `,"signature":[]}`, "campaigns[0].endpoints"},
		{"case-variant payload", `{"payload":` + jsonString(t, `{"settings":{"campaigns":[{"id":"c","grok_com_config":{"oidc":{}}}]}}`) + `,"Payload":"{}","signature":[]}`, "campaigns[0].grok_com_config.oidc"},
		{"duplicate campaigns key", `{"payload":` + jsonString(t, `{"settings":{"campaigns":[{"id":"c","endpoints":{"x":"y"}}],"campaigns":[]}}`) + `,"signature":[]}`, "does not parse"},
		{"duplicate payload key", `{"payload":"{}","payload":"{}","signature":[]}`, "does not parse"},
		{"no payload", `{"signature":[]}`, "does not parse"},
		{"settings not an object", `{"payload":` + jsonString(t, `{"settings":[]}`) + `,"signature":[]}`, "does not parse"},
		{"campaigns not a list", `{"payload":` + jsonString(t, `{"settings":{"campaigns":{"id":"c"}}}`) + `,"signature":[]}`, "does not parse"},
		{"campaign not an object", `{"payload":` + jsonString(t, `{"settings":{"campaigns":["x"]}}`) + `,"signature":[]}`, "does not parse"},
		{"trailing data", settingsCache(t) + `{}`, "does not parse"},
		// Fix round 2 (S4) parity pins: a campaign is checked with the
		// same layerCredentialKey as a TOML layer, so every key a TOML
		// layer refuses refuses here too.
		{"campaign model base_url", settingsCache(t, map[string]any{"id": "c", "model": map[string]any{"custom": map[string]any{"base_url": "https://m.example.test"}}}), "campaigns[0].model.custom.base_url"},
		{"campaign model query_params", settingsCache(t, map[string]any{"id": "c", "model": map[string]any{"custom": map[string]any{"query_params": map[string]any{"k": "v"}}}}), "campaigns[0].model.custom.query_params"},
		{"campaign web_search key", settingsCache(t, map[string]any{"id": "c", "toolset": map[string]any{"web_search": map[string]any{"api_key": "k"}}}), "campaigns[0].toolset.web_search.api_key"},
		{"campaign relay url", settingsCache(t, map[string]any{"id": "c", "grok_com_config": map[string]any{"grok_ws_url": "wss://r.example.test"}}), "campaigns[0].grok_com_config.grok_ws_url"},
		{"campaign model_providers", settingsCache(t, map[string]any{"id": "c", "model_providers": map[string]any{"corp": map[string]any{"env_key": "K"}}}), "campaigns[0].model_providers.corp.env_key"},
	} {
		checkCacheRow(t, "settings_cache.json", tc.name, tc.body, tc.want)
	}
}

// checkCacheRow writes body to file in a fresh grok home and checks the
// preflight: no error when want is "", else a refusal naming the file and
// want.
func checkCacheRow(t *testing.T, file, name, body, want string) {
	t.Helper()
	pe, _, home := preflightEnv(t)
	path := filepath.Join(home, file)
	writeFile(t, path, body)
	err := Preflight(pe)
	if want == "" {
		if err != nil {
			t.Errorf("%s: err = %v, want none", name, err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), want) {
		t.Errorf("%s: err = %v, want a refusal naming %s and %s", name, err, path, want)
	}
}

// jsonString returns s as a JSON string literal.
func jsonString(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// modelsCache builds a models_cache.json in the shape grok writes
// (xai-grok-cloud-config remote_settings/cache.rs:18-38; entries are
// xai-grok-shell agent/config.rs ModelEntry, :3922-3935). entry is merged
// over a harmless fetched entry, which carries no credential of its own
// (remote_config/fetch.rs:21-28).
func modelsCache(t *testing.T, entry map[string]any) string {
	t.Helper()
	e := map[string]any{
		"info":         info(nil),
		"api_key":      nil,
		"env_key":      nil,
		"api_base_url": nil,
	}
	maps.Copy(e, entry)
	data, err := json.Marshal(map[string]any{"fetched_at": "2026-10-16T00:00:00Z", "grok_version": "0.0.0", "models": map[string]any{"grok-4": e}})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// info returns a fetched entry's "info" object (ModelInfo::from_config,
// xai-grok-shell agent/config.rs:3814-3858) with over merged in.
func info(over map[string]any) map[string]any {
	m := map[string]any{"model": "grok-4", "base_url": "https://cli-chat-proxy.grok.com/v1", "auth_scheme": "bearer", "extra_headers": map[string]any{}, "context_window": 256000}
	maps.Copy(m, over)
	return m
}

// Fix round 1: grok uses a fresh models_cache.json in the grok home
// instead of fetching its model catalog (remote_settings/backend.rs:57-68,
// cache.rs:86-101). The file is not signed, so whoever can write the grok
// home can give a model its own key, key variable, credential helper,
// mTLS identity or env-sourced header. grok's own fetch path never
// writes any of those (fetch.rs:21-28), so an entry that sets one refuses
// the launch, naming the file and the key; a cache that does not parse
// (or repeats a key) refuses too.
func TestPreflightChecksModelsCache(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"fetched entry", modelsCache(t, nil), ""},
		{"api_key", modelsCache(t, map[string]any{"api_key": "xai-k"}), "models.grok-4.api_key"},
		{"env_key", modelsCache(t, map[string]any{"env_key": "CORP_KEY"}), "models.grok-4.env_key"},
		{"auth_provider", modelsCache(t, map[string]any{"auth_provider": "corp"}), "models.grok-4.auth_provider"},
		{"mtls_cert_dir", modelsCache(t, map[string]any{"mtls_cert_dir": "/etc/c"}), "models.grok-4.mtls_cert_dir"},
		{"env_http_headers", modelsCache(t, map[string]any{"info": info(map[string]any{"env_http_headers": map[string]any{"Authorization": "CORP"}})}), "models.grok-4.info.env_http_headers"},
		// Fix round 2 (S4): parity with the TOML layers. A fetched entry's
		// query_params is always empty (ModelInfo::from_config,
		// agent/config.rs:3830); its extra_headers come from the server and
		// cannot be bounded from source, so a non-empty table fails closed
		// until a live cache sample shows what the catalog sends.
		{"query_params", modelsCache(t, map[string]any{"info": info(map[string]any{"query_params": map[string]any{"key": "k"}})}), "models.grok-4.info.query_params"},
		{"extra_headers", modelsCache(t, map[string]any{"info": info(map[string]any{"extra_headers": map[string]any{"X-Api-Key": "k"}})}), "models.grok-4.info.extra_headers"},
		// Destinations must be one grok itself trusts with its bearer:
		// https, and the CLI chat proxy or x.ai / *.x.ai
		// (is_trusted_xai_https_url, xai-grok-shell-base util/mod.rs:136-152).
		{"base_url off xAI", modelsCache(t, map[string]any{"info": info(map[string]any{"base_url": "https://models.example.test/v1"})}), "models.grok-4.info.base_url"},
		{"base_url suffix trick", modelsCache(t, map[string]any{"info": info(map[string]any{"base_url": "https://evil-x.ai.example.test/v1"})}), "models.grok-4.info.base_url"},
		{"base_url http", modelsCache(t, map[string]any{"info": info(map[string]any{"base_url": "http://cli-chat-proxy.grok.com/v1"})}), "models.grok-4.info.base_url"},
		{"base_url loopback", modelsCache(t, map[string]any{"info": info(map[string]any{"base_url": "https://localhost/v1"})}), "models.grok-4.info.base_url"},
		{"base_url odd port", modelsCache(t, map[string]any{"info": info(map[string]any{"base_url": "https://api.x.ai:8443/v1"})}), "models.grok-4.info.base_url"},
		{"api_base_url off xAI", modelsCache(t, map[string]any{"api_base_url": "https://keys.example.test/v1"}), "models.grok-4.api_base_url"},
		{"api_base_url not a string", modelsCache(t, map[string]any{"api_base_url": 7}), "models.grok-4.api_base_url"},
		{"base_url missing", modelsCache(t, map[string]any{"info": map[string]any{"model": "grok-4", "extra_headers": map[string]any{}}}), "does not parse"},
		// A realistic fetched catalog: the chat proxy and api.x.ai as
		// destinations, an auth_scheme (it only picks which header carries
		// grok's placeholder, xai-grok-sampler config.rs:20-24), no headers.
		{"realistic catalog", `{"fetched_at":"2026-10-16T00:00:00Z","grok_version":"0.0.0","auth_method":"session","origin":"https://cli-chat-proxy.grok.com/v1","identity":"h","etag":"e","models":{` +
			`"grok-4":{"info":{"model":"grok-4","base_url":"https://cli-chat-proxy.grok.com/v1","auth_scheme":"bearer","extra_headers":{},"context_window":256000},"api_key":null,"env_key":null,"api_base_url":null},` +
			`"grok-code":{"info":{"model":"grok-code","base_url":"https://api.x.ai/v1","auth_scheme":"x_api_key","extra_headers":{},"context_window":256000},"api_key":null,"env_key":null,"api_base_url":"https://api.x.ai/v1"}}}`, ""},
		{"info not an object", modelsCache(t, map[string]any{"info": "x"}), "does not parse"},
		{"not json", "{", "does not parse"},
		{"no models", `{"fetched_at":"x"}`, "does not parse"},
		{"duplicate key", `{"models":{"grok-4":{"info":{},"api_key":"k","api_key":null}}}`, "does not parse"},
		{"case-variant key", `{"models":{"grok-4":{"info":{"base_url":"https://api.x.ai/v1"},"api_key":"k","API_KEY":null}}}`, "models.grok-4.api_key"},
	} {
		checkCacheRow(t, "models_cache.json", tc.name, tc.body, tc.want)
	}
}
