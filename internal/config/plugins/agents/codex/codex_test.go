package codex

import (
	"slices"
	"testing"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// The decided Codex env sets: stripped names (spec §8.2) and force-set
// names (D6, DEV-27).
func TestCodexLauncherEnvDeclarations(t *testing.T) {
	p := agentprovider.ByID("codex")
	if p == nil || p.Launcher == nil {
		t.Fatal("codex provider or its launcher is not registered")
	}
	if got, want := p.Launcher.CompetingEnv, []string{"OPENAI_API_KEY", "CODEX_API_KEY"}; !slices.Equal(got, want) {
		t.Errorf("codex CompetingEnv = %v, want %v", got, want)
	}
	if got, want := p.Launcher.ForceSetEnv, []string{"CODEX_ACCESS_TOKEN", "CODEX_AGENT_IDENTITY"}; !slices.Equal(got, want) {
		t.Errorf("codex ForceSetEnv = %v, want %v", got, want)
	}
}
