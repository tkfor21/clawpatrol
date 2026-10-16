package all

import (
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/agentprovider"
	"github.com/denoland/clawpatrol/internal/config"
)

// Importing this package runs agentprovider.MustValidate in init, so a
// bad declaration panics the test binary before this test runs.
func TestBuiltinProvidersRegistered(t *testing.T) {
	for _, id := range []string{"claude", "codex", "grok", "openai-sdk"} {
		if agentprovider.ByID(id) == nil {
			t.Errorf("provider %q not registered", id)
		}
	}
	if p := agentprovider.AuthProvider("auth.openai.com"); p == nil || p.ID != "codex" {
		t.Errorf("auth.openai.com auth provider = %v, want codex", p)
	}
	if p := agentprovider.AuthProvider("console.anthropic.com"); p == nil || p.ID != "claude" {
		t.Errorf("console.anthropic.com auth provider = %v, want claude", p)
	}
	// Grok Build: binary, auth host and inference wire route all resolve
	// to the one registered provider.
	p := agentprovider.ByID("grok")
	if p == nil || agentprovider.ByBinary("grok") != p || agentprovider.AuthProvider("auth.x.ai") != p {
		t.Fatalf("grok provider wiring = %+v", p)
	}
	if rp, f := agentprovider.WireFor("cli-chat-proxy.grok.com", "/v1/responses"); rp != p || f != agentprovider.WireOpenAIResponses {
		t.Fatalf("WireFor = %v %q", rp, f)
	}
}

// Importing this package runs its init, which must call
// agentprovider.MustValidate. Dropping or renaming that init leaves
// C0–C11 unchecked at startup, so this test fails (R1-03).
func TestStartupValidationRan(t *testing.T) {
	if !agentprovider.Validated() {
		t.Fatal("plugins/all's init did not run agentprovider.MustValidate")
	}
}

// D-R4-8 (A): config load refuses an llm_approver whose credential type
// another provider owns, and accepts the judge's own provider's type.
func TestLLMApproverRejectsForeignProviderCredential(t *testing.T) {
	const base = `gateway {
  state_dir  = "/opt/clawpatrol"
  public_url = "https://gw.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
endpoint "https" "grok" { hosts = ["cli-chat-proxy.grok.com"] }
credential "grok_oauth" "grok" { endpoint = https.grok }
credential "anthropic_manual_key" "ak" {}
`
	for _, tc := range []struct {
		model, cred string
		ok          bool
	}{
		{"claude-sonnet-4", "grok_oauth.grok", false},
		{"gpt-5", "grok_oauth.grok", false},
		{"claude-sonnet-4", "anthropic_manual_key.ak", true},
		{"grok-4", "grok_oauth.grok", true},
	} {
		src := base + "approver \"llm_approver\" \"judge\" {\n  model      = \"" + tc.model + "\"\n  credential = " + tc.cred + "\n}\n"
		_, diags := config.LoadBytes([]byte(src), "in.hcl")
		if tc.ok && diags.HasErrors() {
			t.Errorf("%s + %s: %v, want it to load", tc.model, tc.cred, diags)
		}
		if !tc.ok && (!diags.HasErrors() || !strings.Contains(diags.Error(), "cannot back this judge")) {
			t.Errorf("%s + %s: diags = %v, want a cannot-back-this-judge error", tc.model, tc.cred, diags)
		}
	}
}
