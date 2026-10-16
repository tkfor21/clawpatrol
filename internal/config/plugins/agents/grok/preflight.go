package grok

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/BurntSushi/toml"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// systemConfigDir is grok's root-owned config dir on unix
// (xai-grok-config/src/paths.rs:23-29). A var so tests can point it at a
// temp dir.
var systemConfigDir = "/etc/grok"

// configFiles lists every TOML layer grok merges into its effective
// config (xai-grok-config config_layers.rs, ConfigLayers::load): the
// system managed config and requirements, then $GROK_HOME's managed
// config, user config and requirements. $GROK_HOME is used verbatim
// when non-empty, else $HOME/.grok (xai-dirs/src/lib.rs:48-58).
func configFiles(pe agentprovider.PlaceholderEnv) []string {
	files := []string{
		filepath.Join(systemConfigDir, "managed_config.toml"), // loader.rs:126-133
		filepath.Join(systemConfigDir, "requirements.toml"),   // validation.rs:117-120
	}
	if home := grokHome(pe); home != "" {
		files = append(files,
			filepath.Join(home, "managed_config.toml"), // loader.rs:112-114
			filepath.Join(home, "config.toml"),         // loader.rs:83-91
			filepath.Join(home, "requirements.toml"),   // validation.rs:108-115
		)
	}
	return files
}

// grokHome is $GROK_HOME when non-empty, else $HOME/.grok, else ""
// (xai-dirs/src/lib.rs:48-58).
func grokHome(pe agentprovider.PlaceholderEnv) string {
	if home := pe.Getenv("GROK_HOME"); home != "" {
		return home
	}
	if h := pe.Getenv("HOME"); h != "" {
		return filepath.Join(h, ".grok")
	}
	return ""
}

// settingsCacheFile is grok's signed on-disk cache of its remote
// settings, in the grok home (xai-grok-cloud-config/src/settings_cache.rs:12,
// :94-99). A fresh entry for the current account is used at startup
// instead of a fetch (settings_get.rs:510-525), and its campaigns patch
// the effective config with no allowlist (xai-grok-config
// effective_config.rs:198-216, config_layers.rs:201-220). The HMAC key
// that signs it is in grok's source (settings_cache.rs:326-355), so
// whoever can write the file can forge an entry (D-R4-5 (A)).
const settingsCacheFile = "settings_cache.json"

// Preflight refuses `clawpatrol run grok` when a grok config layer names
// a credential source or an endpoint override of its own, which would let
// grok authenticate around the gateway (D7), including an
// [auth_provider.<name>] command, a per-model credential key (R2-D4), or
// a per-model or global header or query table (D-R4-5 (A)). It also
// checks the campaigns in grok's settings cache (D-R4-5 (A)). The core
// runs it on the final agent env, so GROK_CONFIG_PATH,
// GROK_MANAGED_CONFIG_URL and GROK_CAMPAIGNS_OVERRIDE are already stripped
// (CompetingEnv) and only these files remain. A file that cannot be read
// or parsed also refuses: the preflight cannot confirm it is safe.
func Preflight(pe agentprovider.PlaceholderEnv) error {
	for _, f := range configFiles(pe) {
		data, err := os.ReadFile(f)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("cannot read grok config %s (%w); refusing to start grok, because clawpatrol cannot confirm it names no credential source of its own", f, err)
		}
		var doc map[string]any
		if _, err := toml.Decode(string(data), &doc); err != nil {
			return fmt.Errorf("grok config %s does not parse (%w); refusing to start grok, because clawpatrol cannot confirm it names no credential source of its own", f, err)
		}
		if key := credentialKey(doc); key != "" {
			return fmt.Errorf("grok config %s sets %s, which would let grok authenticate around the gateway, so clawpatrol run grok refuses to start; remove it, or run grok outside clawpatrol", f, key)
		}
	}
	home := grokHome(pe)
	if home == "" {
		return nil
	}
	f := filepath.Join(home, settingsCacheFile)
	data, err := os.ReadFile(f)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot read grok settings cache %s (%w); refusing to start grok, because clawpatrol cannot confirm its campaigns name no credential source", f, err)
	}
	key, ok := settingsCacheKey(data)
	if !ok {
		return fmt.Errorf("grok settings cache %s does not parse; refusing to start grok, because clawpatrol cannot confirm its campaigns name no credential source; delete the file (grok fetches its settings again)", f)
	}
	if key != "" {
		return fmt.Errorf("grok settings cache %s carries a campaign that sets %s, which would let grok authenticate around the gateway, so clawpatrol run grok refuses to start; delete the file (grok fetches its settings again)", f, key)
	}
	return nil
}

// settingsCacheKey returns "campaigns[<i>].<key>" for the first campaign
// in a grok settings cache that names a credential source or an endpoint
// override, or "". ok is false when data is not the shape grok writes: a
// JSON object whose "payload" string is a JSON object whose
// settings.campaigns is a list of objects (settings_cache.rs:37-51; a
// campaign is its id plus the flattened patch, xai-grok-config
// remote_settings.rs:8-13). The signature is not checked: a forged entry
// is exactly what this looks for.
func settingsCacheKey(data []byte) (string, bool) {
	var signed struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal(data, &signed) != nil {
		return "", false
	}
	var payload struct {
		Settings struct {
			Campaigns []map[string]any `json:"campaigns"`
		} `json:"settings"`
	}
	if json.Unmarshal([]byte(signed.Payload), &payload) != nil {
		return "", false
	}
	for i, c := range payload.Settings.Campaigns {
		if key := layerCredentialKey(c); key != "" {
			return fmt.Sprintf("campaigns[%d].%s", i, key), true
		}
	}
	return "", true
}

// credentialKey returns the first key in doc that names a grok credential
// source or endpoint override, or "". It checks the layer itself and
// every [[version_overrides]] and [[campaigns]] entry (round-2
// F102/S102): grok deep-merges those entries into the layer as patches
// (xai-grok-config loader.rs:76-81, :128-133; version_overrides.rs:71-123;
// campaigns.rs:116). An entry with no minimum_version applies to every
// grok version, and trusted version_overrides may set auth tables
// (config_override.rs:89-98), so every entry is checked whatever its
// version bounds (fail closed). A value that is not an array of tables
// refuses too.
func credentialKey(doc map[string]any) string {
	if key := layerCredentialKey(doc); key != "" {
		if key == "endpoints" {
			return "[endpoints]"
		}
		return key
	}
	for _, arr := range []string{"version_overrides", "campaigns"} {
		v, ok := doc[arr]
		if !ok {
			continue
		}
		entries, ok := patchEntries(v)
		if !ok {
			return arr + " (not an array of tables)"
		}
		for i, e := range entries {
			if key := layerCredentialKey(e); key != "" {
				return fmt.Sprintf("%s[%d].%s", arr, i, key)
			}
		}
	}
	return ""
}

// patchEntries returns the tables of a [[version_overrides]] or
// [[campaigns]] value: an array of tables, or an inline array whose
// every element is a table.
func patchEntries(v any) ([]map[string]any, bool) {
	switch a := v.(type) {
	case []map[string]any:
		return a, true
	case []any:
		out := make([]map[string]any, 0, len(a))
		for _, e := range a {
			m, ok := e.(map[string]any)
			if !ok {
				return nil, false
			}
			out = append(out, m)
		}
		return out, true
	}
	return nil, false
}

// layerCredentialKey checks one table (a layer or a patch). [auth] folds
// into [grok_com_config] (xai-grok-login config.rs:469-485), whose oidc,
// oauth2 and auth_provider_command fields select how grok logs in
// (config.rs:56-69). A non-empty [endpoints] table re-points inference
// and the proxy (xai-grok-config endpoints.rs:118-131); it returns
// "endpoints" for it. [auth_provider.<name>] command tables and
// per-model credential keys refuse too (R2-D4), and so does a non-empty
// global [models].extra_headers, which grok folds into every model
// (xai-grok-shell/src/agent/config.rs:3050-3072; D-R4-5 (A)).
func layerCredentialKey(doc map[string]any) string {
	for _, table := range []string{"grok_com_config", "auth"} {
		t, ok := doc[table].(map[string]any)
		if !ok {
			continue
		}
		for _, k := range []string{"auth_provider_command", "oidc", "oauth2"} {
			if _, ok := t[k]; ok {
				return table + "." + k
			}
		}
	}
	switch e := doc["endpoints"].(type) {
	case nil:
	case map[string]any:
		if len(e) > 0 {
			return "endpoints"
		}
	default:
		return "endpoints"
	}
	if models, ok := doc["models"].(map[string]any); ok && nonEmpty(models, "extra_headers") {
		return "models.extra_headers"
	}
	if key := authProviderKey(doc); key != "" {
		return key
	}
	for _, table := range []string{"model_providers", "model"} {
		if key := modelCredentialKey(doc[table], table); key != "" {
			return key
		}
	}
	return ""
}

// authProviderKey returns "auth_provider.<name>" for the first
// [auth_provider.<name>] command table (by sorted name), or "" (R2-D4).
// Each one is a credential helper grok runs to mint a model's bearer
// token (xai-grok-shell/src/agent/config.rs:1281-1345, AuthProviderConfig
// in xai-grok-config-types/src/auth_provider.rs:9-20). grok skips a
// section or entry that is not a table, so neither is refused.
func authProviderKey(doc map[string]any) string {
	section, ok := doc["auth_provider"].(map[string]any)
	if !ok {
		return ""
	}
	for _, name := range slices.Sorted(maps.Keys(section)) {
		if _, ok := section[name].(map[string]any); ok {
			return "auth_provider." + name
		}
	}
	return ""
}

// modelCredentialKeys are the [model_providers.<id>] and [model.<id>] keys
// that give a model its own credential or destination (R2-D4):
// ModelProviderConfig (xai-grok-shell/src/agent/model_providers.rs:11-28:
// base_url :12, api_base_url :13, env_key :14, api_key :15,
// auth_provider :22, auth :23) and ConfigModelOverride
// (xai-grok-shell/src/agent/config.rs:3461-3518: base_url :3464,
// mtls_cert_dir :3467, api_key :3472, env_key :3474, auth_provider :3477,
// api_base_url :3479). env_key can name any environment variable, which
// the fixed-name env strip cannot cover.
var modelCredentialKeys = []string{"api_key", "env_key", "auth_provider", "auth", "base_url", "api_base_url", "mtls_cert_dir"}

// modelHeaderKeys are the [model_providers.<id>] and [model.<id>] tables
// grok adds to every request of that model (D-R4-5 (A)): extra_headers
// (literal headers), env_http_headers (a header filled from any named
// environment variable, as env_key is) and query_params
// (model_providers.rs:17-21; config.rs:3485-3489; sent by
// xai-grok-sampler/src/client.rs:277-300, :367-403, :543-558). An empty
// table adds nothing and is allowed.
var modelHeaderKeys = []string{"extra_headers", "env_http_headers", "query_params"}

// nonEmpty reports whether t sets k to anything but an empty table. A
// value of another type counts as set (fail closed).
func nonEmpty(t map[string]any, k string) bool {
	v, ok := t[k]
	if !ok {
		return false
	}
	m, isTable := v.(map[string]any)
	return !isTable || len(m) > 0
}

// modelCredentialKey returns "<table>.<id>.<key>" for the first entry of
// a [model_providers] or [model] section (by sorted id) that sets one of
// modelCredentialKeys, or a non-empty modelHeaderKeys table, or "". grok
// ignores a section or entry that is not a table (model_providers.rs:77-90,
// config_model_override_parse.rs:201-233), so neither is refused.
func modelCredentialKey(v any, table string) string {
	section, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	for _, id := range slices.Sorted(maps.Keys(section)) {
		entry, ok := section[id].(map[string]any)
		if !ok {
			continue
		}
		for _, k := range modelCredentialKeys {
			if _, ok := entry[k]; ok {
				return table + "." + id + "." + k
			}
		}
		for _, k := range modelHeaderKeys {
			if nonEmpty(entry, k) {
				return table + "." + id + "." + k
			}
		}
	}
	return ""
}
