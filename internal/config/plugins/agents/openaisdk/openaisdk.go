// Package openaisdk registers plain OpenAI SDK traffic on
// api.openai.com. It is not an agent harness: no launcher, no login.
// Before this provider existed, every such client was labeled "codex".
package openaisdk

import "github.com/denoland/clawpatrol/internal/agentprovider"

func init() {
	agentprovider.Register(&agentprovider.Provider{
		ID:          "openai-sdk",
		DisplayName: "OpenAI SDK",
		IconURL:     "https://api.iconify.design/simple-icons:openai.svg",
		APIHosts:    []string{"api.openai.com"},
		Wire: []agentprovider.WireRoute{
			{Host: "api.openai.com", Path: "/v1/chat/completions", Match: agentprovider.PathPrefix, Format: agentprovider.WireOpenAIChat},
			{Host: "api.openai.com", Path: "/v1/responses", Match: agentprovider.PathPrefix, Format: agentprovider.WireOpenAIResponses},
			{Host: "api.openai.com", Path: "/v1/completions", Match: agentprovider.PathPrefix, Format: agentprovider.WireOpenAICompletions},
		},
		GenAISystem: "openai",
		Approver: &agentprovider.ApproverBackend{
			// Explicit prefixes replace the old strings.HasPrefix(model, "o").
			ModelPrefixes: []string{"gpt-", "o1", "o3", "o4"},
			URL:           "https://api.openai.com/v1/responses",
			Format:        agentprovider.WireOpenAIResponses,
		},
		BrowserTLS: true,
	})
}
