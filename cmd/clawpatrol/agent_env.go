package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// genericCompetingEnv are provider API keys stripped from every
// `clawpatrol run` child regardless of the wrapped binary (I14). The
// only value one may then hold is a gateway pushdown placeholder.
var genericCompetingEnv = []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY"}

// isClawpatrolCAVar reports whether name is a CA trust var clawpatrol
// owns: the built-in set plus every provider-declared additive CA var.
func isClawpatrolCAVar(name string) bool {
	return clawpatrolCAVarNames[name] || slices.Contains(agentprovider.AllCAEnv(), name)
}

// isForceSetEnv: pushdown values for these names override whatever the
// operator's shell had: CA vars, competing credential names whose only
// legitimate value is the gateway placeholder, and provider ForceSetEnv
// names (D6).
func isForceSetEnv(name string) bool {
	if isClawpatrolCAVar(name) || slices.Contains(genericCompetingEnv, name) {
		return true
	}
	for _, p := range agentprovider.All() {
		if p.Launcher != nil && (slices.Contains(p.Launcher.CompetingEnv, name) || slices.Contains(p.Launcher.ForceSetEnv, name)) {
			return true
		}
	}
	return false
}

func competingMatches(pattern, name string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(name, prefix)
	}
	return pattern == name
}

// stripCompetingEnv unsets, in this process, every credential env var
// that would let an agent authenticate around the gateway: the generic
// set plus every provider's CompetingEnv, whatever the wrapped binary is
// (D5: `clawpatrol run bash` starts agents too). Called before pushdown
// is applied. No opt-out (I14).
func stripCompetingEnv() []string {
	patterns := slices.Clone(genericCompetingEnv)
	for _, p := range agentprovider.All() {
		if p.Launcher != nil {
			patterns = append(patterns, p.Launcher.CompetingEnv...)
		}
	}
	var stripped []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		for _, pat := range patterns {
			if competingMatches(pat, name) {
				_ = os.Unsetenv(name)
				stripped = append(stripped, name)
				break
			}
		}
	}
	sort.Strings(stripped)
	if len(stripped) > 0 {
		fmt.Fprintf(os.Stderr, "[clawpatrol] removed %s from the agent environment: agent credentials are brokered by the gateway\n", strings.Join(stripped, ", "))
	}
	return stripped
}

// shimProviders lists, in registration order, the providers whose shim
// runs for cmd: the wrapped binary's provider, and every provider whose
// ShimTriggerEnv holds a value after pushdown (D5). The list is built
// before any shim runs, so one shim's Unset cannot hide another's
// trigger.
func shimProviders(cmd []string, getenv func(string) string) []*agentprovider.Provider {
	var argv0 *agentprovider.Provider
	if len(cmd) > 0 {
		argv0 = agentprovider.ByBinary(cmd[0])
	}
	var out []*agentprovider.Provider
	for _, p := range agentprovider.All() {
		if p.Launcher == nil || p.Launcher.Shim == nil {
			continue
		}
		run := p == argv0
		for _, n := range p.Launcher.ShimTriggerEnv {
			run = run || getenv(n) != ""
		}
		if run {
			out = append(out, p)
		}
	}
	return out
}

// installProviderShim runs every shim shimProviders picks for cmd.
func installProviderShim(cmd []string) error {
	for _, p := range shimProviders(cmd, os.Getenv) {
		res, err := p.Launcher.Shim(agentprovider.PlaceholderEnv{ClawpatrolDir: defaultClawpatrolDir(), Getenv: os.Getenv})
		if err != nil {
			return fmt.Errorf("%s launcher shim: %w", p.ID, err)
		}
		if err := applyShimResult(res); err != nil {
			return fmt.Errorf("%s launcher shim: %w", p.ID, err)
		}
	}
	return nil
}

// runProviderPreflight runs the wrapped binary's provider Preflight on the
// final agent env (after strip, pushdown and shims). An error refuses
// the launch (D7).
func runProviderPreflight(cmd []string) error {
	if len(cmd) == 0 {
		return nil
	}
	p := agentprovider.ByBinary(cmd[0])
	if p == nil || p.Launcher == nil || p.Launcher.Preflight == nil {
		return nil
	}
	if err := p.Launcher.Preflight(agentprovider.PlaceholderEnv{ClawpatrolDir: defaultClawpatrolDir(), Getenv: os.Getenv}); err != nil {
		return fmt.Errorf("%s preflight: %w", p.ID, err)
	}
	return nil
}

// shimFileWrite writes a shim file's bytes. A var so tests can make the
// write fail.
var shimFileWrite = func(f *os.File, b []byte) (int, error) { return f.Write(b) }

// applyShimResult writes shim files (0600, parent 0700, atomic) and
// applies env changes. A shim may never touch CA trust or the generic
// competing credentials.
func applyShimResult(res agentprovider.ShimResult) error {
	for k := range res.Env {
		if isClawpatrolCAVar(k) || slices.Contains(genericCompetingEnv, k) {
			return fmt.Errorf("shim may not set %s", k)
		}
	}
	for _, f := range res.Files {
		if !filepath.IsAbs(f.Path) {
			return fmt.Errorf("shim file %q: path must be absolute", f.Path)
		}
		if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".clawpatrol-shim-*")
		if err != nil {
			return err
		}
		// Plain assignments to the outer err: every step's error must
		// reach the check below (DEV-12, spec §9: a shim file write
		// failure aborts the run; R4-01).
		err = tmp.Chmod(0o600)
		if err == nil {
			_, err = shimFileWrite(tmp, f.Data)
		}
		if err == nil {
			err = tmp.Sync() // some filesystems report ENOSPC or EIO only at sync or close
		}
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Rename(tmp.Name(), f.Path)
		}
		if err != nil {
			_ = os.Remove(tmp.Name())
			return fmt.Errorf("write %s: %w", f.Path, err)
		}
	}
	for k, v := range res.Env {
		_ = os.Setenv(k, v)
	}
	for _, k := range res.Unset {
		_ = os.Unsetenv(k)
	}
	if res.Notice != "" {
		fmt.Fprintln(os.Stderr, "[clawpatrol] "+res.Notice)
	}
	return nil
}

// prepareAgentEnv is the one place a launcher prepares the agent's
// process environment, in DEV-9 order: strip competing credentials (I14,
// no opt-out, every provider's list; D5), apply the launcher's pushdown
// (CA vars, placeholders and ForceSetEnv names; applyPushdown honors
// CLAWPATROL_NO_ENV), run the provider shims, which read the pushed
// placeholders (D5), then the wrapped binary's preflight, which may
// refuse the launch (D7). Every launcher calls it exactly once, before
// exec or env capture (TestLaunchersUsePrepareAgentEnv).
func prepareAgentEnv(cmd []string, applyPushdown func()) error {
	stripCompetingEnv()
	applyPushdown()
	if err := installProviderShim(cmd); err != nil {
		return err
	}
	return runProviderPreflight(cmd)
}
