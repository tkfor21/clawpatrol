//go:build linux

package main

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// These tests drive the real Linux launcher entry points in a re-exec'd
// test process (fail exits the process). The child mode is named by
// launcherChildEnv; the parent checks the exit code, stderr and what the
// child left on disk. No real credential is used: the operator values
// are fakes carrying launchTestMarker.

const (
	launcherChildEnv = "CLAWPATROL_TEST_LAUNCHER_CHILD"
	launchTestMarker = "t11-fake-operator-value"
	refusal          = "pf refuses the launch"
)

// refusingProviders registers one provider, for the binary "pfbin",
// whose preflight refuses every launch (D7).
func refusingProviders() []*agentprovider.Provider {
	return []*agentprovider.Provider{{ID: "pf", DisplayName: "PF", Launcher: &agentprovider.Launcher{
		Binaries:  []string{"pfbin"},
		Preflight: func(agentprovider.PlaceholderEnv) error { return errors.New(refusal) },
	}}}
}

// runLauncherChild re-runs test in a child process with mode set, and
// returns its exit code and stderr.
func runLauncherChild(t *testing.T, test, mode string, env ...string) (int, string) {
	t.Helper()
	home := t.TempDir()
	c := exec.Command(os.Args[0], "-test.run=^"+test+"$", "-test.count=1")
	c.Env = append(os.Environ(), append([]string{
		launcherChildEnv + "=" + mode,
		"HOME=" + home,
		"XDG_STATE_HOME=" + filepath.Join(home, "state"),
		"CLAWPATROL_NO_ENV=",
	}, env...)...)
	var stderr strings.Builder
	c.Stderr = &stderr
	err := c.Run()
	code := 0
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("child: %v", err)
	}
	return code, stderr.String()
}

// stubSudoLauncher replaces runViaSudo's daemon check and sudo command
// in a child process. The fake sudo touches marker (the launch
// happened), copies the env file the root helper would read to envCopy,
// and runs `true` instead of sudo.
func stubSudoLauncher(t *testing.T, marker, envCopy string, pushed []pushdownEnvVar) {
	sudoDaemonConnect = func() (net.Conn, error) {
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}
	envPushdownDaemonFetcher = func() ([]pushdownEnvVar, error) { return pushed, nil }
	if err := os.MkdirAll(daemonRuntimeDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	sudoCommand = func(_ string, args ...string) *exec.Cmd {
		_ = os.WriteFile(marker, nil, 0o600)
		if i := slices.Index(args, "--env-file"); i >= 0 && i+1 < len(args) && envCopy != "" {
			if b, err := os.ReadFile(args[i+1]); err == nil {
				_ = os.WriteFile(envCopy, b, 0o600)
			}
		}
		return exec.Command("true")
	}
}

// Review I-1 (N-16): a refused preflight on the whole-machine path
// exits with the refusal before the agent is exec'd.
func TestRunWholeMachineDirectAbortsOnPreflightRefusal(t *testing.T) {
	if os.Getenv(launcherChildEnv) == "whole-machine" {
		agentprovider.Swap(refusingProviders())
		envPushdownGatewayFetcher = func(string) ([]pushdownEnvVar, error) { return nil, nil }
		runWholeMachineDirect([]string{os.Getenv("T11_AGENT")})
		os.Exit(0) // not reached: the agent exec replaces this process, or fail exits
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "agent-ran")
	agent := filepath.Join(dir, "pfbin")
	if err := os.WriteFile(agent, []byte("#!/bin/sh\n: > \"$T11_MARKER\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	code, stderr := runLauncherChild(t, "TestRunWholeMachineDirectAbortsOnPreflightRefusal", "whole-machine",
		"T11_AGENT="+agent, "T11_MARKER="+marker)
	if code != 2 || !strings.Contains(stderr, refusal) {
		t.Errorf("exit = %d, stderr = %q; want exit 2 with the refusal", code, stderr)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("the agent ran despite the refused preflight")
	}
}

// Review I-1 (N-18): a refused preflight on the sudo path exits with
// the refusal before sudo is started.
func TestRunViaSudoAbortsOnPreflightRefusal(t *testing.T) {
	if os.Getenv(launcherChildEnv) == "sudo-refused" {
		agentprovider.Swap(refusingProviders())
		stubSudoLauncher(t, os.Getenv("T11_MARKER"), "", nil)
		runViaSudo([]string{"pfbin"})
		os.Exit(0)
	}
	marker := filepath.Join(t.TempDir(), "sudo-ran")
	code, stderr := runLauncherChild(t, "TestRunViaSudoAbortsOnPreflightRefusal", "sudo-refused", "T11_MARKER="+marker)
	if code != 2 || !strings.Contains(stderr, refusal) {
		t.Errorf("exit = %d, stderr = %q; want exit 2 with the refusal", code, stderr)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("sudo was started despite the refused preflight")
	}
}

// Review I-2 (N-19, R4-03): the env file runViaSudo hands the root
// helper holds no operator value of a stripped name, in any position,
// and no name twice (libc's getenv takes the first).
func TestRunViaSudoEnvFileHoldsNoOperatorCredential(t *testing.T) {
	operator := []string{"XAI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE", "CODEX_API_KEY"}
	if os.Getenv(launcherChildEnv) == "sudo-envfile" {
		stubSudoLauncher(t, os.Getenv("T11_MARKER"), os.Getenv("T11_ENVCOPY"),
			[]pushdownEnvVar{{Name: "ANTHROPIC_API_KEY", Value: "sk-ant-clawpatrol-placeholder"}})
		runViaSudo([]string{"/usr/bin/python3"})
		os.Exit(0)
	}
	dir := t.TempDir()
	marker, envCopy := filepath.Join(dir, "sudo-ran"), filepath.Join(dir, "env")
	env := []string{"T11_MARKER=" + marker, "T11_ENVCOPY=" + envCopy}
	for _, n := range operator {
		env = append(env, n+"="+launchTestMarker)
	}
	code, stderr := runLauncherChild(t, "TestRunViaSudoEnvFileHoldsNoOperatorCredential", "sudo-envfile", env...)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	data, err := os.ReadFile(envCopy)
	if err != nil {
		t.Fatalf("sudo never got an env file: %v", err)
	}
	seen := map[string]int{}
	for _, kv := range strings.Split(string(data), "\x00") {
		if kv == "" {
			continue
		}
		name, val, _ := strings.Cut(kv, "=")
		seen[name]++
		if strings.Contains(val, launchTestMarker) {
			t.Errorf("env file carries the operator's %s", name)
		}
		if name == "ANTHROPIC_API_KEY" && val != "sk-ant-clawpatrol-placeholder" {
			t.Errorf("env file's ANTHROPIC_API_KEY is not the pushed placeholder")
		}
	}
	for name, n := range seen {
		if n > 1 {
			t.Errorf("env file has %s %d times", name, n)
		}
	}
	if seen["ANTHROPIC_API_KEY"] != 1 {
		t.Errorf("env file has ANTHROPIC_API_KEY %d times, want the placeholder once", seen["ANTHROPIC_API_KEY"])
	}
}
