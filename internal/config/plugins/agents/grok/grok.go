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
		// The code.grok.com and grok.com WebSocket features are not
		// declared until live check V3 shows whether they carry the
		// session bearer; until then they are not brokered.
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
			// netns) is pending; until it reports, no sandbox proxy var is
			// listed here (the plan's default).
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
