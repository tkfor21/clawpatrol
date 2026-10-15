package all

import (
	"testing"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// Importing this package runs agentprovider.MustValidate in init, so a
// bad declaration panics the test binary before this test runs.
func TestBuiltinProvidersRegistered(t *testing.T) {
	for _, id := range []string{"claude", "codex", "openai-sdk"} {
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
}

// Importing this package runs its init, which must call
// agentprovider.MustValidate. Dropping or renaming that init leaves
// C0–C11 unchecked at startup, so this test fails (R1-03).
func TestStartupValidationRan(t *testing.T) {
	if !agentprovider.Validated() {
		t.Fatal("plugins/all's init did not run agentprovider.MustValidate")
	}
}
