package claude

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

func fakeEnv(m map[string]string) agentprovider.PlaceholderEnv {
	return agentprovider.PlaceholderEnv{ClawpatrolDir: "/cp", Getenv: func(k string) string { return m[k] }}
}

func TestShim(t *testing.T) {
	opDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(opDir, ".credentials.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("no bearer", func(t *testing.T) {
		res, err := Shim(fakeEnv(nil))
		if err != nil || len(res.Files) != 0 || len(res.Env) != 0 || len(res.Unset) != 0 || res.Notice != "" {
			t.Fatalf("res = %+v err = %v, want empty", res, err)
		}
	})
	t.Run("no opt-in", func(t *testing.T) {
		res, err := Shim(fakeEnv(map[string]string{"ANTHROPIC_AUTH_TOKEN": "b"}))
		if err != nil || res.Notice != remoteControlNotice || len(res.Files) != 0 {
			t.Fatalf("res = %+v err = %v", res, err)
		}
	})
	t.Run("opt-in managed", func(t *testing.T) {
		res, err := Shim(fakeEnv(map[string]string{"ANTHROPIC_AUTH_TOKEN": "b", "CLAWPATROL_CLAUDE_OAUTH_SHIM": "1"}))
		if err != nil || len(res.Files) != 1 {
			t.Fatalf("res = %+v err = %v", res, err)
		}
		if res.Files[0].Path != "/cp/claude-config/.credentials.json" {
			t.Fatalf("path = %s", res.Files[0].Path)
		}
		var got struct {
			C struct {
				AccessToken string `json:"accessToken"`
			} `json:"claudeAiOauth"`
		}
		if err := json.Unmarshal(res.Files[0].Data, &got); err != nil || got.C.AccessToken != "b" {
			t.Fatalf("json = %s err = %v", res.Files[0].Data, err)
		}
		if res.Env["CLAUDE_CONFIG_DIR"] != "/cp/claude-config" || !slices.Equal(res.Unset, []string{"ANTHROPIC_AUTH_TOKEN"}) {
			t.Fatalf("res = %+v", res)
		}
	})
	t.Run("operator dir with credentials", func(t *testing.T) {
		res, err := Shim(fakeEnv(map[string]string{"ANTHROPIC_AUTH_TOKEN": "b", "CLAWPATROL_CLAUDE_OAUTH_SHIM": "1", "CLAUDE_CONFIG_DIR": opDir}))
		if err != nil || len(res.Files) != 0 || !slices.Equal(res.Unset, []string{"ANTHROPIC_AUTH_TOKEN"}) {
			t.Fatalf("res = %+v err = %v", res, err)
		}
	})
	t.Run("operator dir with a broken credentials file", func(t *testing.T) {
		broken := t.TempDir()
		if err := os.WriteFile(filepath.Join(broken, ".credentials.json"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		res, err := Shim(fakeEnv(map[string]string{"ANTHROPIC_AUTH_TOKEN": "b", "CLAWPATROL_CLAUDE_OAUTH_SHIM": "1", "CLAUDE_CONFIG_DIR": broken}))
		if err != nil || len(res.Files) != 1 || res.Files[0].Path != filepath.Join(broken, ".credentials.json") {
			t.Fatalf("res = %+v err = %v, want the empty file rewritten", res, err)
		}
	})
}
