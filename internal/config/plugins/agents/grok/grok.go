package grok

import "github.com/denoland/clawpatrol/internal/agentprovider"

func init() {
	agentprovider.Register(&agentprovider.Provider{
		ID:          "grok",
		DisplayName: "Grok Build",
		// No icon until one is approved: simple-icons has no xAI or Grok
		// mark, and its "x" key is the X (formerly Twitter) logo. The
		// dashboard falls back to its default dot.
		IconURL: "",
		// Session auth sends everything (inference, /models, /settings,
		// /user, traces) to the CLI chat proxy (xai-grok-config endpoints.rs:133-142).
		// Live check V3: the code.grok.com/ws/code-agent relay carries the
		// session bearer (Authorization, X-XAI-Token-Auth, x-userid;
		// xai-grok-shell agent/relay.rs:372-399), but it opens only in
		// `grok agent headless` and leader mode and no wire parser fits
		// it, so it is not declared: the gateway never injects there, the
		// relay only ever carries the placeholder, and those modes are
		// unsupported. grok.com/ws/gw/ is gateway-bridge mode only, reached
		// through GROK_GATEWAY_URL, which CompetingEnv strips.
		//
		// Other hosts grok calls, left undeclared on purpose (final fix
		// wave host decisions): api.x.ai/v1/tokenize-text carries the
		// session bearer but only feeds a token-count telemetry event
		// (xai-grok-shell session/acp_session_impl/context_snapshot.rs:11-52,
		// :55-67, :282-288), so with the placeholder it fails and the event omits
		// the counts; grok.com/_data/v1/events (product telemetry, whose
		// URL and key are build-time values) sends the events key in
		// x-api-key, never the session (xai-grok-telemetry
		// client.rs:309-337, config.rs:184-195); the
		// self-updater at x.ai/cli is unauthenticated (xai-grok-update
		// version.rs:17, :260-310). Declaring a host would send the real
		// session token there and scrub its responses, so only a host whose
		// feature operators need, and that needs the bearer, is declared.
		APIHosts:  []string{"cli-chat-proxy.grok.com"},
		AuthHosts: []string{"auth.x.ai", "accounts.x.ai"},
		AuxHosts:  []string{"assets.grok.com"},
		// xai-grok-sampler client.rs:1299-1330. Live check V2 observed
		// POST /v1/responses on cli-chat-proxy.grok.com.
		Wire: []agentprovider.WireRoute{
			{Host: "cli-chat-proxy.grok.com", Path: "/v1/responses", Match: agentprovider.PathPrefix, Format: agentprovider.WireOpenAIResponses},
			{Host: "cli-chat-proxy.grok.com", Path: "/v1/chat/completions", Match: agentprovider.PathPrefix, Format: agentprovider.WireOpenAIChat},
			{Host: "cli-chat-proxy.grok.com", Path: "/v1/messages", Match: agentprovider.PathPrefix, Format: agentprovider.WireAnthropicMessages},
		},
		SessionHeaders:  []string{"x-grok-session-id", "x-grok-conv-id"}, // client.rs:71-86
		GenAISystem:     "x_ai",                                          // OTel semconv v1.39.0 gen_ai.provider.name
		CredentialTypes: []string{"grok_oauth"},
		Launcher: &agentprovider.Launcher{
			Binaries: []string{"grok"},
			CAEnv:    []string{"GROK_EXTRA_CA_BUNDLE"}, // xai-grok-extra-ca lib.rs:217-236
			// Live check V5 (grok's tool sandbox proxy env escaping the
			// netns) passed on Linux: grok's tool had no proxy variable and
			// its traffic crossed the gateway. The macOS pass is pending;
			// until it reports, no sandbox proxy var is listed here (the
			// plan's default).
			CompetingEnv: []string{ // xai-grok-env lib.rs; model_fetch_auth.rs:36-50; config.rs:396
				"GROK_CODE_XAI_API_KEY", "GROK_DEPLOYMENT_KEY", "GROK_AUTH_PROVIDER_COMMAND",
				"GROK_AUTH_PATH", "GROK_MODELS_BASE_URL", "GROK_MODELS_LIST_URL",
				"GROK_CLI_CHAT_PROXY_BASE_URL", "GROK_XAI_API_BASE_URL",
				"GROK_OAUTH2_*", "GROK_OIDC_*", "GROK_LOCAL_AUTH",
				// grok's FIRST_PARTY_CREDENTIAL_ENV_VARS (xai-grok-env/src/registry.rs:1-11).
				// GROK_AUTH is inline auth JSON that overrides auth.json (xai-grok-login manager.rs:341-352).
				"GROK_AUTH", "GROK_EXTRA_AUTH_KEY", "GROK_TRACE_UPLOAD_CREDENTIALS_FILE",
				// Listed so an operator-set value is stripped and the pushdown
				// placeholder is force-set (isForceSetEnv); the shim unsets it.
				SessionEnv,
				// D7: a config overlay file and the managed-config URL
				// (xai-grok-config env_overlay.rs:13; endpoints.rs:52, :288).
				"GROK_CONFIG_PATH", "GROK_MANAGED_CONFIG_URL",
				// D-R4-5 (A): a JSON campaign list that replaces every other
				// campaign source, beats the kill switch, and may patch
				// [endpoints] and [model.<id>] with no allowlist
				// (xai-grok-config effective_config.rs:115-145, :198-215).
				"GROK_CAMPAIGNS_OVERRIDE",
				// Fix round 1 (S2). The inline JSON config overlay: its
				// allowlist keeps the whole [models] table, so it can set
				// [models].extra_headers (xai-grok-config env_overlay.rs:10,
				// config_override.rs:103-105). Stripped like
				// GROK_CONFIG_PATH; this supersedes leaving it unstripped
				// as a documented residual (R2-D4), and is flagged for the
				// user.
				"GROK_CONFIG",
				// Endpoint overrides of the URLs grok sends its session
				// to: GROK_PRODUCTION_{CLI_CHAT_PROXY_BASE_URL,WS_ORIGIN,
				// ASSET_SERVER_URL,WS_URL,GATEWAY_WS_URL} (xai-grok-env
				// lib.rs:59-87), the relay WebSocket (xai-grok-login
				// config.rs:389-392), the cloud gateway (xai-grok-shell-base
				// env.rs:22), and the grok.com REST clients (xai-grok-shell
				// remote/client.rs:17, :325; conversations_client.rs:95;
				// workspaces_client.rs:66; chat_models_client.rs:83;
				// skills_client.rs:367).
				"GROK_PRODUCTION_*", "GROK_WS_URL", "GROK_WS_ORIGIN", "GROK_GATEWAY_URL",
				"GROK_CODE_WEB_URL", "GROK_CODE_BACKEND_URL", "GROK_CONVERSATIONS_BASE_URL",
				"GROK_WORKSPACES_BASE_URL", "GROK_MODES_BASE_URL", "GROK_SKILLS_BASE_URL",
				// Feedback, trace-upload and internal OTLP destinations and
				// headers (xai-grok-config endpoints.rs:280-293; grok lists
				// GROK_INTERNAL_OTLP_HEADERS as a first-party credential,
				// xai-grok-env registry.rs:10), and the telemetry events
				// key, URL and token (xai-grok-telemetry config.rs:254-260).
				"GROK_FEEDBACK_BASE_URL", "GROK_TRACE_UPLOAD_URL", "GROK_TRACE_UPLOAD_ENDPOINT_URL",
				"GROK_INTERNAL_OTLP_HEADERS", "GROK_INTERNAL_OTLP_TRACES_ENDPOINT",
				"GROK_TELEMETRY_EVENTS_URL", "GROK_TELEMETRY_EVENTS_API_KEY", "GROK_TELEMETRY_MIXPANEL_TOKEN",
				// Not listed, on purpose: GROK_HOME (DEV-8; the preflight
				// reads the same home grok does); OTEL_EXPORTER_OTLP_*,
				// although grok's FIRST_PARTY_CREDENTIAL_ENV_VARS lists
				// OTEL_EXPORTER_OTLP_HEADERS (xai-grok-env registry.rs:9):
				// it carries the operator's own collector credential, not
				// an xAI one, and Claude Code reads it too, so the
				// all-provider strip (DEV-23) would break Claude telemetry;
				// GROK_WEB_FETCH_PROXY and HTTP(S)_PROXY (route traffic,
				// carry no credential, and egress still crosses the
				// gateway); GROK_AGENT_SECRET (the local `agent serve`
				// secret, xai-grok-pager app/cli.rs:355); and the
				// GROK_AUTH_PROVIDER_ACCESS_TOKEN family, which grok sets
				// on its helper's env rather than reads
				// (xai-grok-login auth_provider.rs:349-353).
			},
			// D5: a pushed grok_oauth placeholder runs this shim even when
			// the wrapped binary is not grok (clawpatrol run bash).
			ShimTriggerEnv: []string{SessionEnv},
			Shim:           Shim,
			Preflight:      Preflight, // D7
		},
		Approver: &agentprovider.ApproverBackend{
			ModelPrefixes:   []string{"grok-"},
			URL:             "https://cli-chat-proxy.grok.com/v1/responses",
			Format:          agentprovider.WireOpenAIResponses,
			Headers:         map[string]string{"X-XAI-Token-Auth": "xai-grok-cli"},
			CredentialTypes: []string{"grok_oauth"}, // spec §5.1/§8.3: never send another provider's token here
		},
	})
}
