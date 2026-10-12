// Package codex registers the OpenAI Codex CLI agent provider.
package codex

import (
	"io"
	"net/http"
	"strings"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// SyntheticRuntimeID is the agent_runtime_id baked into the Agent
// Identity JWT the openai_codex_https endpoint mints. Task-register
// stubs only ever answer for this id.
const SyntheticRuntimeID = "clawpatrol-codex"

func init() {
	agentprovider.Register(&agentprovider.Provider{
		ID:          "codex",
		DisplayName: "Codex",
		IconURL:     "https://api.iconify.design/simple-icons:openai.svg",
		APIHosts:    []string{"chatgpt.com", "*.chatgpt.com"},
		AuthHosts:   []string{"auth.openai.com"},
		// Bare openai.com stays an aux host: it is codex-typed and on the
		// uTLS list today (dial.go:29-32), and "*.openai.com" does not
		// cover the bare name.
		AuxHosts: []string{"openai.com", "*.openai.com", "oaiusercontent.com", "*.oaiusercontent.com"},
		Wire: []agentprovider.WireRoute{
			{Host: "chatgpt.com", Path: "/codex/responses", Match: agentprovider.PathContains, Format: agentprovider.WireCodexWS},
			{Host: "*.chatgpt.com", Path: "/codex/responses", Match: agentprovider.PathContains, Format: agentprovider.WireCodexWS},
		},
		SessionHeaders:  []string{"Session_id", "Session-Id"},
		GenAISystem:     "openai",
		CredentialTypes: []string{"openai_codex_oauth"},
		EndpointTypes:   []string{"openai_codex_https"},
		Launcher: &agentprovider.Launcher{
			Binaries:     []string{"codex"},
			CompetingEnv: []string{"OPENAI_API_KEY", "CODEX_API_KEY"}, // spec §8.2
			// D6: the openai_codex_https endpoint pushes a synthetic Agent
			// Identity JWT under these names (openai_codex_https.go:109-119);
			// a pushed value overrides the operator's shell value. They are
			// not stripped when nothing is pushed (DEV-27).
			ForceSetEnv: []string{"CODEX_ACCESS_TOKEN", "CODEX_AGENT_IDENTITY"},
		},
		BrowserTLS: true,
		// Not in the pre-registry uTLS set (chatgpt.com, openai.com only).
		PlainTLSHosts: []string{"oaiusercontent.com", "*.oaiusercontent.com"},
		Stubs: []agentprovider.AuthStub{{
			// codex >= 0.142 registers agent tasks on auth.openai.com. Answer
			// only for OUR synthetic runtime id; any other runtime id gets 403.
			Host:       "auth.openai.com",
			Method:     http.MethodPost,
			PathSuffix: "/v1/agent/" + SyntheticRuntimeID + "/task/register",
			Respond:    taskRegisterStub,
		}},
	})
}

func taskRegisterStub(req *http.Request, _ agentprovider.PublicMaterial) *http.Response {
	const body = `{"task_id":"clawpatrol-task"}`
	return &http.Response{
		Status: "200 OK", StatusCode: http.StatusOK,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:        http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}
