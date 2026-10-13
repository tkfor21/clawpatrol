//go:build linux

package main

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// The sudo path captures the user's env for the root helper. It must
// already hold the pushed placeholder, the shim must have run on it,
// and no un-pushed operator credential may remain (R4-02, R4-03).
func TestPrepareSudoUserEnvRunsPushdownBeforeShim(t *testing.T) {
	var shimSaw []string
	restore := agentprovider.Swap([]*agentprovider.Provider{{ID: "ord", DisplayName: "Ord", Launcher: &agentprovider.Launcher{
		Binaries: []string{"ordbin"}, CompetingEnv: []string{"FIX_PH"}, ShimTriggerEnv: []string{"FIX_PH"},
		Shim: func(pe agentprovider.PlaceholderEnv) (agentprovider.ShimResult, error) {
			shimSaw = append(shimSaw, pe.Getenv("FIX_PH"))
			return agentprovider.ShimResult{}, nil
		},
	}}})
	defer restore()
	t.Setenv("HOME", t.TempDir()) // defaultClawpatrolDir() = $HOME/.clawpatrol; ensureCABundle writes there
	t.Setenv("CLAWPATROL_NO_ENV", "")
	t.Setenv("FIX_PH", "real-operator-value")
	t.Setenv("XAI_API_KEY", "xai-real-operator-key") // not pushed: must be gone
	for name := range clawpatrolCAVarNames {
		t.Setenv(name, "") // restored after the test; pushdown force-sets them
	}
	prevD, prevG := envPushdownDaemonFetcher, envPushdownGatewayFetcher
	t.Cleanup(func() { envPushdownDaemonFetcher, envPushdownGatewayFetcher = prevD, prevG })
	envPushdownDaemonFetcher = func() ([]pushdownEnvVar, error) {
		return []pushdownEnvVar{{Name: "FIX_PH", Value: "placeholder"}}, nil
	}
	if err := prepareSudoUserEnv([]string{"/usr/bin/python3"}); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("FIX_PH"); got != "placeholder" {
		t.Fatalf("FIX_PH = %q, want the placeholder", got)
	}
	if !slices.Equal(shimSaw, []string{"placeholder"}) {
		t.Fatalf("shim saw %q; the pushed trigger must start it, after the pushdown", shimSaw)
	}
	if _, ok := os.LookupEnv("XAI_API_KEY"); ok {
		t.Fatal("XAI_API_KEY survived prepareSudoUserEnv")
	}
}

func TestPrepareWholeMachineEnvStrips(t *testing.T) {
	t.Setenv("CLAWPATROL_NO_ENV", "1") // I14 has no opt-out
	t.Setenv("XAI_API_KEY", "xai-real-operator-key")
	if err := prepareWholeMachineEnv([]string{"python3"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := os.LookupEnv("XAI_API_KEY"); ok {
		t.Fatal("XAI_API_KEY survived the whole-machine launcher")
	}
}

// The root helper uses the captured env verbatim: it must not re-add
// a name the user-side shim unset, or append a duplicate that libc
// getenv would read first.
func TestBuildPrivilegedEnvUsesCapturedEnv(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "env")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("A=1\x00SSL_CERT_FILE=/ca.crt\x00")
	_ = f.Close()
	got := buildPrivilegedEnv(f.Name())
	if len(got) != 2 || got[0] != "A=1" || got[1] != "SSL_CERT_FILE=/ca.crt" {
		t.Fatalf("env = %q, want the captured env verbatim", got)
	}
	if _, err := os.Stat(f.Name()); !os.IsNotExist(err) {
		t.Fatal("env file was not deleted")
	}
}

// The captured env holds no un-pushed competing name and no name twice
// (libc's getenv takes the first of two; R4-03, V4 V-M3).
func TestCaptureSudoUserEnvHasNoUnpushedCompetingName(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLAWPATROL_NO_ENV", "")
	t.Setenv("XAI_API_KEY", "xai-real-operator-key")
	t.Setenv("OPENAI_API_KEY", "sk-real-operator-key")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-real-operator-key")
	for name := range clawpatrolCAVarNames {
		t.Setenv(name, "")
	}
	prevD, prevG := envPushdownDaemonFetcher, envPushdownGatewayFetcher
	t.Cleanup(func() { envPushdownDaemonFetcher, envPushdownGatewayFetcher = prevD, prevG })
	envPushdownDaemonFetcher = func() ([]pushdownEnvVar, error) {
		return []pushdownEnvVar{{Name: "ANTHROPIC_API_KEY", Value: "sk-ant-clawpatrol-placeholder"}}, nil
	}
	env, err := captureSudoUserEnv([]string{"/usr/bin/python3"})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, kv := range env {
		name, val, _ := strings.Cut(kv, "=")
		seen[name]++
		if (name == "XAI_API_KEY" || name == "OPENAI_API_KEY") || (name == "ANTHROPIC_API_KEY" && val != "sk-ant-clawpatrol-placeholder") {
			t.Errorf("captured env carries %s", name)
		}
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("captured env has %s %d times", name, n)
		}
	}
}
