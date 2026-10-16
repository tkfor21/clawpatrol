package grok

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capturedModelsResponse is a real GET cli-chat-proxy.grok.com/v1/models
// response (session auth, grok 1.0.50, 2026-10-16), kept verbatim. It is
// the model catalog, with no credential or account data in it.
const capturedModelsResponse = "testdata/cli-chat-proxy-v1-models.json"

// grokDefaultInferenceBaseURL is where grok points a fetched model with
// no base_url of its own: EndpointsConfig::resolve_inference_base_url
// falls back to proxy_url, the production CLI chat proxy (xai-grok-config
// endpoints.rs:134-142; xai-grok-env lib.rs:21, :27).
const grokDefaultInferenceBaseURL = "https://cli-chat-proxy.grok.com/v1"

// cachedEntryFromCatalog builds the models_cache.json entry grok writes
// for one /v1/models row under session auth, following grok's fetch path
// field by field:
//   - parse_remote_model_value (xai-grok-shell remote/client.rs:598-760)
//     reads base_url from "baseUrl" or "base_url", else the default
//     inference URL (:615-617); api_base_url from "apiBaseUrl" or
//     "api_base_url" (:708); extra_headers only from "extraHeaders"
//     (:707); auth_scheme is always None (:737).
//   - build_prefetched_map (remote_config/fetch.rs:13-32) sets api_key,
//     env_key, auth_provider and mtls_cert_dir to None and api_base_url to
//     the row's own value; session auth adds no override (fetch.rs:74-79).
//   - ModelInfo::from_config (agent/config.rs:3814-3858) keeps
//     extra_headers, sets auth_scheme to its default (Bearer, serialized
//     "bearer", xai-grok-sampler config.rs:18-24) and leaves query_params
//     and env_http_headers empty, which serde omits (config.rs:3693-3696).
//   - ModelEntry (config.rs:3922-3935) serializes api_key, env_key and
//     api_base_url as null when None and omits auth_provider and
//     mtls_cert_dir.
//
// Fields the preflight does not read (names, context windows, reasoning
// efforts, ...) are carried over as the row gives them.
func cachedEntryFromCatalog(t *testing.T, row map[string]any) (string, map[string]any) {
	t.Helper()
	str := func(keys ...string) (string, bool) {
		for _, k := range keys {
			if s, ok := row[k].(string); ok {
				return s, true
			}
		}
		return "", false
	}
	model, ok := str("model", "modelId", "id")
	if !ok {
		t.Fatalf("catalog row has no model: %v", row)
	}
	key := model
	if id, ok := str("id"); ok {
		key = id
	}
	info := map[string]any{}
	for k, v := range row {
		switch k {
		case "object", "owned_by": // OpenAI list fields grok does not keep
		default:
			info[k] = v
		}
	}
	info["model"] = model
	info["base_url"] = grokDefaultInferenceBaseURL
	if b, ok := str("baseUrl", "base_url"); ok {
		info["base_url"] = b
	}
	delete(info, "baseUrl")
	info["auth_scheme"] = "bearer"
	headers, _ := row["extraHeaders"].(map[string]any)
	if headers == nil {
		headers = map[string]any{}
	}
	info["extra_headers"] = headers
	delete(info, "extraHeaders")
	for _, k := range []string{"apiKey", "api_key", "envKey", "env_key", "apiBaseUrl", "api_base_url", "query_params", "env_http_headers"} {
		delete(info, k)
	}
	var apiBase any
	if b, ok := str("apiBaseUrl", "api_base_url"); ok {
		apiBase = b
	}
	return key, map[string]any{"info": info, "api_key": nil, "env_key": nil, "api_base_url": apiBase}
}

// TestPreflightPassesCapturedModelsCache resolves the models-cache
// blocker with live data: the models_cache.json grok writes from a real
// /v1/models response passes the preflight. The capture names no
// destination, header, key or auth scheme of its own, so every cached
// model goes to grok's default CLI chat proxy with an empty extra_headers
// table. The cache envelope is ModelsCache::persist's
// (xai-grok-cloud-config remote_settings/cache.rs:18-38, :130-139).
func TestPreflightPassesCapturedModelsCache(t *testing.T) {
	raw, err := os.ReadFile(capturedModelsResponse)
	if err != nil {
		t.Fatal(err)
	}
	var resp struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data) != 4 {
		t.Fatalf("capture has %d models, want 4", len(resp.Data))
	}
	models := map[string]any{}
	for _, row := range resp.Data {
		// The capture's facts this test rests on: an xAI catalog on the
		// Responses API that names no destination, header, key or scheme.
		if row["owned_by"] != "xAI" || row["api_backend"] != "responses" {
			t.Fatalf("capture row %v: want owned_by xAI, api_backend responses", row["id"])
		}
		for _, k := range []string{"baseUrl", "base_url", "apiBaseUrl", "api_base_url", "extraHeaders", "extra_headers", "query_params", "env_http_headers", "apiKey", "api_key", "envKey", "env_key", "auth_scheme", "authScheme"} {
			if _, ok := row[k]; ok {
				t.Fatalf("capture row %v sets %s", row["id"], k)
			}
		}
		key, entry := cachedEntryFromCatalog(t, row)
		models[key] = entry
	}
	cache, err := json.Marshal(map[string]any{
		"fetched_at":   "2026-10-16T05:37:00Z",
		"grok_version": "1.0.50",
		"auth_method":  "session",
		"origin":       grokDefaultInferenceBaseURL + "/models",
		"identity":     "",
		"models":       models,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkCacheRow(t, modelsCacheFile, "captured catalog", string(cache), "")

	// A cache whose shape this preflight does not know (for example one
	// an older or newer grok wrote) is refused with a message that says
	// what to do, and the launch succeeds again once grok refetches it.
	pe, _, home := preflightEnv(t)
	path := filepath.Join(home, modelsCacheFile)
	writeFile(t, path, `{"models":{"grok-4.7":{"info":{"model":"grok-4.7"}}}}`)
	err = Preflight(pe)
	if err == nil || !strings.Contains(err.Error(), "grok models cache "+path+" does not parse as the cache grok writes") || !strings.HasSuffix(err.Error(), "delete the file (grok fetches it again)") {
		t.Fatalf("stale-shape cache: err = %v", err)
	}
	writeFile(t, path, string(cache))
	if err := Preflight(pe); err != nil {
		t.Fatalf("refetched cache: err = %v, want none", err)
	}
}
