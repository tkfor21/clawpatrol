package grok

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

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

// modelsCacheFile is grok's unsigned on-disk cache of its model catalog,
// in the grok home (xai-grok-cloud-config remote_settings/cache.rs:11,
// :68). A fresh entry is used instead of a fetch (backend.rs:57-68), and
// each entry is a full model definition with its own credential fields
// (xai-grok-shell agent/config.rs ModelEntry, :3922-3935).
const modelsCacheFile = "models_cache.json"

// Preflight refuses `clawpatrol run grok` when a grok config layer names
// a credential source or an endpoint override of its own, which would let
// grok authenticate around the gateway (D7), including an
// [auth_provider.<name>] command, a per-model credential key (R2-D4), or
// a per-model or global header or query table (D-R4-5 (A)). It also
// checks the campaigns in grok's settings cache (D-R4-5 (A)) and the
// entries in its models cache. The core runs it on the final agent env,
// so GROK_CONFIG, GROK_CONFIG_PATH, GROK_MANAGED_CONFIG_URL and
// GROK_CAMPAIGNS_OVERRIDE are already stripped (CompetingEnv) and only
// these files remain. A file that cannot be read or parsed also refuses:
// the preflight cannot confirm it is safe. So does an env with neither
// GROK_HOME nor HOME: grok would then resolve its home from the passwd
// entry (std::env::home_dir, xai-dirs lib.rs:33-38, :50-58), which the
// preflight does not guess.
func Preflight(pe agentprovider.PlaceholderEnv) error {
	home := grokHome(pe)
	if home == "" {
		return errors.New("neither GROK_HOME nor HOME is set, so clawpatrol cannot tell which grok home grok will read and refuses to start grok; set GROK_HOME or HOME")
	}
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
	for _, c := range []struct {
		file, what string
		check      func([]byte) (string, bool)
	}{
		{settingsCacheFile, "settings cache", settingsCacheKey},
		{modelsCacheFile, "models cache", modelsCacheKey},
	} {
		f := filepath.Join(home, c.file)
		data, err := os.ReadFile(f)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("cannot read grok %s %s (%w); refusing to start grok, because clawpatrol cannot confirm it names no credential source", c.what, f, err)
		}
		key, ok := c.check(data)
		if !ok {
			return fmt.Errorf("grok %s %s does not parse as the cache grok writes (another grok version may have written it); refusing to start grok, because clawpatrol cannot confirm it names no credential source; delete the file (grok fetches it again)", c.what, f)
		}
		if key != "" {
			return fmt.Errorf("grok %s %s sets %s, which would let grok authenticate around the gateway, so clawpatrol run grok refuses to start; delete the file (grok fetches it again)", c.what, f, key)
		}
	}
	return nil
}

// settingsCacheKey returns "campaigns[<i>].<key>" for the first campaign
// in a grok settings cache that names a credential source or an endpoint
// override, or "". ok is false when data is not the shape grok writes: a
// JSON object whose "payload" string is a JSON object whose "settings"
// is an object whose "campaigns", when present, is a list of objects
// (settings_cache.rs:37-51; RemoteSettings.campaigns, remote_settings.rs:622-623;
// a campaign is its id plus the flattened patch, remote_settings.rs:8-13).
// Keys match exactly and a repeated key refuses (strictJSON), so this
// reads the campaign list grok's serde_json reads. The signature is not
// checked: a forged entry is exactly what this looks for.
func settingsCacheKey(data []byte) (string, bool) {
	signed, ok := strictJSON(data).(map[string]any)
	if !ok {
		return "", false
	}
	raw, ok := signed["payload"].(string)
	if !ok {
		return "", false
	}
	payload, ok := strictJSON([]byte(raw)).(map[string]any)
	if !ok {
		return "", false
	}
	settings, ok := payload["settings"].(map[string]any)
	if !ok {
		return "", false
	}
	v := settings["campaigns"]
	if v == nil {
		// Absent applies no campaign; null fails grok's Vec decode, so
		// grok drops the whole entry and applies none either.
		return "", true
	}
	list, ok := v.([]any)
	if !ok {
		return "", false
	}
	for i, e := range list {
		c, ok := e.(map[string]any)
		if !ok {
			return "", false
		}
		if key := layerCredentialKey(c); key != "" {
			return fmt.Sprintf("campaigns[%d].%s", i, key), true
		}
	}
	return "", true
}

// modelsCacheEntryKeys are the ModelEntry fields that give a cached model
// its own credential (xai-grok-shell agent/config.rs:3926-3933). grok's
// fetch path writes none of them (remote_config/fetch.rs:21-28), so a
// non-null value can only have been planted.
var modelsCacheEntryKeys = []string{"api_key", "env_key", "auth_provider", "mtls_cert_dir"}

// modelsCacheInfoTables are the ModelInfo header and query tables a cached
// model may not set (fix round 2, parity with modelHeaderKeys in the TOML
// layers). A fetched entry's query_params and env_http_headers are always
// empty (ModelInfo::from_config, xai-grok-shell agent/config.rs:3830-3831).
// Its extra_headers are copied from the server (:3829), which source
// cannot bound, so a non-empty table fails closed; a live models_cache.json
// sample (the user-present step) should confirm the catalog sends none.
var modelsCacheInfoTables = []string{"extra_headers", "query_params", "env_http_headers"}

// modelsCacheKey returns "models.<id>.<key>" for the first cached model
// (by sorted id) that sets one of modelsCacheEntryKeys, a non-empty
// modelsCacheInfoTables table, or a destination (info.base_url,
// api_base_url) grok itself would not trust with its bearer
// (trustedXAIURL), or "". ok is false when data is not the shape grok
// writes: a JSON object whose "models" is an object of objects, each with
// an "info" object holding a string base_url (remote_settings/cache.rs:18-38;
// ModelInfo.base_url is required, agent/config.rs:3679). info.auth_scheme
// is not refused: it only picks whether grok's placeholder goes in
// Authorization or x-api-key (xai-grok-sampler config.rs:20-24), and no
// TOML layer refuses it either.
func modelsCacheKey(data []byte) (string, bool) {
	doc, ok := strictJSON(data).(map[string]any)
	if !ok {
		return "", false
	}
	models, ok := doc["models"].(map[string]any)
	if !ok {
		return "", false
	}
	for _, id := range slices.Sorted(maps.Keys(models)) {
		entry, ok := models[id].(map[string]any)
		if !ok {
			return "", false
		}
		info, ok := entry["info"].(map[string]any)
		if !ok {
			return "", false
		}
		base, ok := info["base_url"].(string)
		if !ok {
			return "", false
		}
		for _, k := range modelsCacheEntryKeys {
			if v := entry[k]; v != nil {
				return "models." + id + "." + k, true
			}
		}
		for _, k := range modelsCacheInfoTables {
			if info[k] != nil && nonEmpty(info, k) {
				return "models." + id + ".info." + k, true
			}
		}
		if !trustedXAIURL(base) {
			return "models." + id + ".info.base_url", true
		}
		if v := entry["api_base_url"]; v != nil {
			if u, ok := v.(string); !ok || !trustedXAIURL(u) {
				return "models." + id + ".api_base_url", true
			}
		}
	}
	return "", true
}

// trustedXAIURL mirrors grok's own rule for where its session bearer may
// go (is_trusted_xai_https_url, xai-grok-shell-base util/mod.rs:136-152):
// https, not loopback, and the production CLI chat proxy (:95-106) or
// x.ai / *.x.ai. It is stricter in two ways (fail closed): a port other
// than 443 and user info in the URL refuse.
func trustedXAIURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	if p := u.Port(); p != "" && p != "443" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "cli-chat-proxy.grok.com" || h == "x.ai" || strings.HasSuffix(h, ".x.ai")
}

// errStrictJSON reports JSON that strictJSON refuses.
var errStrictJSON = errors.New("repeated or malformed JSON object key")

// strictJSON decodes data as exactly one JSON value, with object keys
// kept exact-case (map[string]any), and returns nil when it does not
// parse, has trailing data, or repeats a key in any object. grok's
// serde_json matches field names exactly and refuses a repeated struct
// field; Go's encoding/json struct decoding folds case and keeps the last
// repeat, so it could read a different value than grok does.
func strictJSON(data []byte) any {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := strictValue(dec)
	if err != nil {
		return nil
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil
	}
	return v
}

// strictValue reads one JSON value from dec, refusing repeated keys.
func strictValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil
	}
	switch d {
	case '{':
		m := map[string]any{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			k, ok := kt.(string)
			if !ok {
				return nil, errStrictJSON
			}
			if _, dup := m[k]; dup {
				return nil, errStrictJSON
			}
			if m[k], err = strictValue(dec); err != nil {
				return nil, err
			}
		}
		_, err := dec.Token() // the closing '}'
		return m, err
	case '[':
		a := []any{}
		for dec.More() {
			v, err := strictValue(dec)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		_, err := dec.Token() // the closing ']'
		return a, err
	}
	return nil, errStrictJSON
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
		// Each entry is checked as one flat patch, not recursed into:
		// grok strips version_overrides and campaigns (and the
		// auth_provider and model_providers command tables) from every
		// patch it applies, so a nested list inside an entry never takes
		// effect (xai-grok-config config_override.rs:76-93).
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
// [grok_com_config] also names the relay WebSocket endpoint, grok_ws_url
// and grok_ws_origin (xai-grok-login config.rs:179-191, :209-210), refused
// like [endpoints]; a login section that is not a table, which grok fails
// to read (config.rs:272-277), refuses rather than being skipped; and
// [toolset.web_search], a full sampler config with its own key,
// destination and headers (xai-grok-shell tools/config.rs:162;
// xai-grok-sampler config.rs:38-64), refuses for those keys (fix round 1).
func layerCredentialKey(doc map[string]any) string {
	for _, table := range []string{"grok_com_config", "auth"} {
		v, present := doc[table]
		if !present {
			continue
		}
		t, ok := v.(map[string]any)
		if !ok {
			return table + " (not a table)"
		}
		for _, k := range loginKeys {
			if _, ok := t[k]; ok {
				return table + "." + k
			}
		}
	}
	if key := webSearchKey(doc); key != "" {
		return key
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

// loginKeys are the [grok_com_config] (and [auth]) keys that choose how
// grok logs in or where its relay WebSocket connects.
var loginKeys = []string{"auth_provider_command", "oidc", "oauth2", "grok_ws_url", "grok_ws_origin"}

// webSearchKey returns "toolset.web_search.<key>" when [toolset.web_search]
// sets a credential or destination of its own (modelCredentialKeys) or a
// non-empty header or query table (modelHeaderKeys), "toolset (not a
// table)" or "toolset.web_search (not a table)" for a value grok cannot
// read as its toolset config, or "".
func webSearchKey(doc map[string]any) string {
	v, present := doc["toolset"]
	if !present {
		return ""
	}
	toolset, ok := v.(map[string]any)
	if !ok {
		return "toolset (not a table)"
	}
	v, present = toolset["web_search"]
	if !present {
		return ""
	}
	ws, ok := v.(map[string]any)
	if !ok {
		return "toolset.web_search (not a table)"
	}
	for _, k := range modelCredentialKeys {
		if _, ok := ws[k]; ok {
			return "toolset.web_search." + k
		}
	}
	for _, k := range modelHeaderKeys {
		if nonEmpty(ws, k) {
			return "toolset.web_search." + k
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
