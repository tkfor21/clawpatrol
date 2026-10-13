package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

func TestCompetingEnvStripThenPlaceholder(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-real-operator-key")
	t.Setenv("XAI_API_KEY", "xai-real-operator-key")
	t.Setenv("CLAWPATROL_NO_ENV", "")
	stripped := stripCompetingEnv()
	for _, want := range []string{"ANTHROPIC_API_KEY", "XAI_API_KEY"} {
		if !slices.Contains(stripped, want) {
			t.Fatalf("stripped = %v, missing %s", stripped, want)
		}
	}
	applyEnvPushdownVars([]pushdownEnvVar{{Name: "ANTHROPIC_API_KEY", Value: "sk-ant-clawpatrol-placeholder"}})
	if got := os.Getenv("ANTHROPIC_API_KEY"); got != "sk-ant-clawpatrol-placeholder" {
		t.Fatalf("ANTHROPIC_API_KEY = %q, want the placeholder", got)
	}
	if got, ok := os.LookupEnv("XAI_API_KEY"); ok {
		t.Fatalf("XAI_API_KEY = %q, want unset (no placeholder pushed)", got)
	}
	// Without a strip, a pushed generic competing name still overrides
	// the operator's value. The generic names are force-set on their own:
	// with no provider declaring OPENAI_API_KEY, it is still force-set
	// (R4-11).
	restore := agentprovider.Swap(nil)
	defer restore()
	t.Setenv("OPENAI_API_KEY", "sk-real-operator-key")
	applyEnvPushdownVars([]pushdownEnvVar{{Name: "OPENAI_API_KEY", Value: "sk-clawpatrol-placeholder"}})
	if got := os.Getenv("OPENAI_API_KEY"); got != "sk-clawpatrol-placeholder" {
		t.Fatalf("OPENAI_API_KEY = %q, want the pushed placeholder", got)
	}
}

func TestStripCompetingEnvAppliesEvenWithNoEnvOptOut(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-real")
	t.Setenv("CLAWPATROL_NO_ENV", "1")
	stripCompetingEnv()
	if _, ok := os.LookupEnv("OPENAI_API_KEY"); ok {
		t.Fatal("OPENAI_API_KEY survived; I14 has no opt-out")
	}
}

// D5: the strip ignores argv0. A wrapped launch (`clawpatrol run bash`)
// removes every provider's competing names, not only the wrapped
// binary's.
func TestStripCompetingEnvIgnoresArgv0(t *testing.T) {
	names := []string{"ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_FOUNDRY_API_KEY", "CLAUDE_CODE_SESSION_ACCESS_TOKEN", "CODEX_API_KEY",
		// D-R4-4 (A): Claude credential-file, store and bridge names (Task 4)
		"CLAUDE_BG_AUTH_SNAPSHOT_PATH", "CLAUDE_SESSION_INGRESS_TOKEN_FILE", "CLAUDE_SECURESTORAGE_CONFIG_DIR", "CLAUDE_BRIDGE_OAUTH_TOKEN",
		// D-R4-4b: SDK profile credential files, federation mode, the
		// Unix socket relay, custom headers and the remote-settings hook.
		"ANTHROPIC_CONFIG_DIR", "ANTHROPIC_PROFILE", "CLAUDE_CODE_FEDERATION_CACHE_DIR", "ANTHROPIC_UNIX_SOCKET",
		"ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID", "ANTHROPIC_CUSTOM_HEADERS", "CLAUDE_CODE_MOCK_REMOTE_SETTINGS"}
	// Every exact name a registered provider declares is stripped too, so
	// a name added to a CompetingEnv later is covered without editing this
	// list (the literal list above pins the names that must never drop).
	for _, p := range agentprovider.All() {
		if p.Launcher == nil {
			continue
		}
		for _, n := range p.Launcher.CompetingEnv {
			if !strings.HasSuffix(n, "*") && !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	for _, n := range names {
		t.Setenv(n, "real-operator-value")
	}
	stripped := stripCompetingEnv()
	for _, n := range names {
		if _, ok := os.LookupEnv(n); ok || !slices.Contains(stripped, n) {
			t.Errorf("%s survived the strip (stripped = %v)", n, stripped)
		}
	}
	// A trailing "*" strips a prefix (grok's GROK_OAUTH2_* from Task 15).
	restore := agentprovider.Swap(append(agentprovider.All(), &agentprovider.Provider{ID: "wild", DisplayName: "Wild",
		Launcher: &agentprovider.Launcher{CompetingEnv: []string{"FIX_WILD_*"}}}))
	defer restore()
	t.Setenv("FIX_WILD_TOKEN", "real")
	t.Setenv("FIX_WILDX", "kept")
	stripCompetingEnv()
	if _, ok := os.LookupEnv("FIX_WILD_TOKEN"); ok {
		t.Error("FIX_WILD_TOKEN survived a FIX_WILD_* pattern")
	}
	if os.Getenv("FIX_WILDX") != "kept" {
		t.Error("FIX_WILDX was stripped; FIX_WILD_* matches the prefix FIX_WILD_ only")
	}
}

// D6: a pushed CODEX_ACCESS_TOKEN replaces the operator's shell value.
// It is force-set only: with nothing pushed, the operator value stays
// (DEV-27).
func TestForceSetEnvOverridesOperatorValue(t *testing.T) {
	t.Setenv("CLAWPATROL_NO_ENV", "")
	t.Setenv("CODEX_ACCESS_TOKEN", "operator-real-jwt")
	stripCompetingEnv()
	if got := os.Getenv("CODEX_ACCESS_TOKEN"); got != "operator-real-jwt" {
		t.Fatalf("CODEX_ACCESS_TOKEN = %q after the strip; it is force-set only, never stripped", got)
	}
	applyEnvPushdownVars([]pushdownEnvVar{{Name: "CODEX_ACCESS_TOKEN", Value: "synthetic-agent-identity-jwt"}})
	if got := os.Getenv("CODEX_ACCESS_TOKEN"); got != "synthetic-agent-identity-jwt" {
		t.Fatalf("CODEX_ACCESS_TOKEN = %q, want the pushed value", got)
	}
}

// D5: the wrapped binary's provider shim runs, and so does the shim of
// every provider whose trigger var holds a pushed value. Each runs once,
// in registration order; a provider with neither never runs.
func TestInstallProviderShimRunsPushedProviders(t *testing.T) {
	var ran []string
	shim := func(id string) agentprovider.Shim {
		return func(agentprovider.PlaceholderEnv) (agentprovider.ShimResult, error) {
			ran = append(ran, id)
			return agentprovider.ShimResult{}, nil
		}
	}
	fixture := func(id, bin, trigger string) *agentprovider.Provider {
		return &agentprovider.Provider{ID: id, DisplayName: id, Launcher: &agentprovider.Launcher{
			Binaries: []string{bin}, CompetingEnv: []string{trigger}, ShimTriggerEnv: []string{trigger}, Shim: shim(id),
		}}
	}
	restore := agentprovider.Swap([]*agentprovider.Provider{
		fixture("pushed", "pushedbin", "PUSHED_PH"),
		fixture("argv", "argvbin", "ARGV_PH"),
		fixture("idle", "idlebin", "IDLE_PH"),
	})
	defer restore()
	t.Setenv("PUSHED_PH", "placeholder")
	t.Setenv("ARGV_PH", "")
	t.Setenv("IDLE_PH", "")
	for _, tc := range []struct {
		argv0, argvPH string
		want          []string
	}{
		{"/bin/bash", "", []string{"pushed"}},
		{"/usr/local/bin/argvbin", "", []string{"pushed", "argv"}},
		{"argvbin", "placeholder", []string{"pushed", "argv"}},
	} {
		ran = nil
		t.Setenv("ARGV_PH", tc.argvPH)
		if err := installProviderShim([]string{tc.argv0}); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(ran, tc.want) {
			t.Errorf("argv0 %s (ARGV_PH=%q): shims ran %v, want %v", tc.argv0, tc.argvPH, ran, tc.want)
		}
	}
}

// D7: the wrapped binary's preflight runs last, on the final env (it
// sees what the shim set), and its error refuses the launch. Another
// binary's launch does not run it.
func TestPrepareAgentEnvRunsPreflightLast(t *testing.T) {
	var seen string
	restore := agentprovider.Swap([]*agentprovider.Provider{{ID: "pf", DisplayName: "PF", Launcher: &agentprovider.Launcher{
		Binaries: []string{"pfbin"},
		Shim: func(agentprovider.PlaceholderEnv) (agentprovider.ShimResult, error) {
			return agentprovider.ShimResult{Env: map[string]string{"PF_SHIM_SET": "yes"}}, nil
		},
		Preflight: func(pe agentprovider.PlaceholderEnv) error {
			seen = pe.Getenv("PF_SHIM_SET")
			return errors.New("pf config names a credential source")
		},
	}}})
	defer restore()
	t.Setenv("PF_SHIM_SET", "") // restored after the test; the shim sets it
	err := prepareAgentEnv([]string{"pfbin"}, func() {})
	if err == nil || !strings.Contains(err.Error(), "pf config names a credential source") {
		t.Fatalf("prepareAgentEnv err = %v, want the preflight's refusal", err)
	}
	if seen != "yes" {
		t.Fatalf("preflight saw PF_SHIM_SET=%q, want the shim's value (preflight runs last)", seen)
	}
	if err := prepareAgentEnv([]string{"python3"}, func() {}); err != nil {
		t.Fatalf("another binary's launch ran the preflight: %v", err)
	}
}

func TestApplyShimResultRejectsProtectedVars(t *testing.T) {
	for _, name := range []string{"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "ANTHROPIC_API_KEY"} {
		err := applyShimResult(agentprovider.ShimResult{Env: map[string]string{name: "/tmp/x"}})
		if err == nil {
			t.Errorf("shim setting %s was accepted", name)
		}
	}
	if err := applyShimResult(agentprovider.ShimResult{Files: []agentprovider.ShimFile{{Path: "relative.json"}}}); err == nil {
		t.Error("relative shim file path was accepted")
	}
}

func TestApplyShimResultWritesPrivateFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "auth.json")
	if err := applyShimResult(agentprovider.ShimResult{Files: []agentprovider.ShimFile{{Path: p, Data: []byte("{}")}}}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", st.Mode().Perm())
	}
}

// DEV-12, spec §9: a shim error, or a failed write of a shim file,
// refuses the launch, installs no file and applies no env change
// (R4-01).
func TestPrepareAgentEnvAbortsOnShimError(t *testing.T) {
	target := filepath.Join(t.TempDir(), "cfg", ".credentials.json")
	cases := []struct {
		name  string
		shim  func(agentprovider.PlaceholderEnv) (agentprovider.ShimResult, error)
		write func(*os.File, []byte) (int, error)
	}{
		{"shim returns an error", func(agentprovider.PlaceholderEnv) (agentprovider.ShimResult, error) {
			return agentprovider.ShimResult{}, errors.New("shim broke")
		}, nil},
		{"file write fails", func(agentprovider.PlaceholderEnv) (agentprovider.ShimResult, error) {
			return agentprovider.ShimResult{Files: []agentprovider.ShimFile{{Path: target, Data: []byte(`{"k":"v"}`)}}, Unset: []string{"SHIMFAIL_PH"}}, nil
		}, func(*os.File, []byte) (int, error) { return 0, errors.New("write: no space left on device") }},
	}
	for _, tc := range cases {
		restore := agentprovider.Swap([]*agentprovider.Provider{{ID: "sf", DisplayName: "SF", Launcher: &agentprovider.Launcher{
			Binaries: []string{"sfbin"}, Shim: tc.shim,
		}}})
		saved := shimFileWrite
		if tc.write != nil {
			shimFileWrite = tc.write
		}
		t.Setenv("SHIMFAIL_PH", "placeholder")
		err := prepareAgentEnv([]string{"sfbin"}, func() {})
		shimFileWrite = saved
		restore()
		if err == nil {
			t.Errorf("%s: prepareAgentEnv err = nil, want the launch refused", tc.name)
		}
		if _, serr := os.Stat(target); !os.IsNotExist(serr) {
			t.Errorf("%s: a shim file was installed despite the failure", tc.name)
		}
		if os.Getenv("SHIMFAIL_PH") != "placeholder" {
			t.Errorf("%s: the shim's Unset ran despite the failure", tc.name)
		}
	}
}

// prepareAgentEnv runs strip → pushdown → shim → preflight (DEV-9,
// DEV-16): the operator value is gone before the pushdown, and the shim
// and the preflight both see the pushed placeholder (R4-02).
func TestPrepareAgentEnvOrder(t *testing.T) {
	var shimSaw, preflightSaw []string
	restore := agentprovider.Swap([]*agentprovider.Provider{{ID: "ord", DisplayName: "Ord", Launcher: &agentprovider.Launcher{
		Binaries: []string{"ordbin"}, CompetingEnv: []string{"FIX_PH"}, ShimTriggerEnv: []string{"FIX_PH"},
		Shim: func(pe agentprovider.PlaceholderEnv) (agentprovider.ShimResult, error) {
			shimSaw = append(shimSaw, pe.Getenv("FIX_PH"))
			return agentprovider.ShimResult{}, nil
		},
		Preflight: func(pe agentprovider.PlaceholderEnv) error {
			preflightSaw = append(preflightSaw, pe.Getenv("FIX_PH"))
			return nil
		},
	}}})
	defer restore()
	t.Setenv("CLAWPATROL_NO_ENV", "")
	t.Setenv("FIX_PH", "real-operator-value")
	pushes := 0
	err := prepareAgentEnv([]string{"ordbin"}, func() {
		if _, ok := os.LookupEnv("FIX_PH"); ok {
			t.Error("pushdown ran before the strip")
		}
		pushes++
		applyEnvPushdownVars([]pushdownEnvVar{{Name: "FIX_PH", Value: "placeholder"}})
	})
	if err != nil {
		t.Fatal(err)
	}
	if pushes != 1 || os.Getenv("FIX_PH") != "placeholder" {
		t.Fatalf("pushes = %d, FIX_PH = %q", pushes, os.Getenv("FIX_PH"))
	}
	if !slices.Equal(shimSaw, []string{"placeholder"}) || !slices.Equal(preflightSaw, []string{"placeholder"}) {
		t.Fatalf("shim saw %q, preflight saw %q; want each to run once on the pushed placeholder", shimSaw, preflightSaw)
	}
}

// Every launcher entry point prepares the agent env exactly once,
// unconditionally, before it launches or captures anything, and only
// the launchers and the Linux helpers call the preparation helpers.
// The check reads the AST (comments do not count) of every file,
// whatever its build tag (R4-04). A new run_*.go file fails until it is
// listed here.
func TestLaunchersUsePrepareAgentEnv(t *testing.T) {
	type entry struct{ fn, helper string }
	launchers := map[string][]entry{
		"run_linux.go":        {{"runRun", "prepareAgentEnv"}, {"runWholeMachineDirect", "prepareWholeMachineEnv"}},
		"run_sudo_linux.go":   {{"runViaSudo", "captureSudoUserEnv"}},
		"run_darwin.go":       {{"runRun", "prepareAgentEnv"}},
		"run_tsnet_darwin.go": {{"runRunTsnet", "prepareAgentEnv"}},
	}
	notLaunchers := map[string]bool{"run_other.go": true, "run_safety.go": true, "run_dns_lockdown_linux.go": true, "run_tsnet_common.go": true}
	// file:helper → calls. Any other caller, or a second call, fails.
	wantCalls := map[string]int{
		"run_linux.go:prepareAgentEnv":          1,
		"run_linux.go:prepareWholeMachineEnv":   1,
		"run_sudo_linux.go:captureSudoUserEnv":  1,
		"run_darwin.go:prepareAgentEnv":         1,
		"run_tsnet_darwin.go:prepareAgentEnv":   1,
		"agent_env_linux.go:prepareAgentEnv":    2, // prepareWholeMachineEnv, prepareSudoUserEnv
		"agent_env_linux.go:prepareSudoUserEnv": 1, // captureSudoUserEnv
		"integrations.go:caPathPushdownVars":    1, // only inside agentPushdown (R4-05)
		"integrations.go:dropClawpatrolCAVars":  1, // only inside agentPushdown (R4-05)
	}
	helpers := map[string]bool{
		"prepareAgentEnv": true, "prepareWholeMachineEnv": true, "prepareSudoUserEnv": true, "captureSudoUserEnv": true,
		"stripCompetingEnv": true, "installProviderShim": true, "runProviderPreflight": true,
		"caPathPushdownVars": true, "dropClawpatrolCAVars": true,
	}
	launch := map[string]bool{"Command": true, "Exec": true, "writePrivilegedEnvFile": true}
	fset := token.NewFileSet()
	names, _ := filepath.Glob("*.go")
	gotCalls := map[string]int{}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") || name == "agent_env.go" {
			continue // agent_env.go defines the helpers and calls the pieces
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && helpers[id.Name] {
					gotCalls[name+":"+id.Name]++
				}
			}
			return true
		})
		if strings.HasPrefix(name, "run_") && !notLaunchers[name] {
			if _, ok := launchers[name]; !ok {
				t.Errorf("%s: unknown launcher file; list its entry points in TestLaunchersUsePrepareAgentEnv", name)
			}
		}
		for _, e := range launchers[name] {
			checkLauncherEntry(t, f, name, e.fn, e.helper, launch)
		}
	}
	for k, n := range wantCalls {
		if gotCalls[k] != n {
			t.Errorf("%s: %d calls, want %d", k, gotCalls[k], n)
		}
	}
	for k, n := range gotCalls {
		if _, ok := wantCalls[k]; !ok {
			t.Errorf("%s: %d unexpected call(s); only the listed launchers may call it", k, n)
		}
	}
}

// checkLauncherEntry requires fn's body to hold, as a top-level
// statement, `if err := helper(...); err != nil {...}` or
// `x, err := helper(...)`, and that statement to come before fn's last
// launch call (exec.Command, syscall.Exec, writePrivilegedEnvFile). For
// writePrivilegedEnvFile the argument must be the variable the helper
// returned.
func checkLauncherEntry(t *testing.T, f *ast.File, file, fn, helper string, launch map[string]bool) {
	t.Helper()
	var body *ast.BlockStmt
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == fn {
			body = fd.Body
		}
	}
	if body == nil {
		t.Errorf("%s: no func %s", file, fn)
		return
	}
	isHelperCall := func(e ast.Expr) bool {
		c, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		id, ok := c.Fun.(*ast.Ident)
		return ok && id.Name == helper
	}
	prepPos, captured := token.NoPos, ""
	for _, st := range body.List {
		switch s := st.(type) {
		case *ast.IfStmt:
			as, ok := s.Init.(*ast.AssignStmt)
			cond, cok := s.Cond.(*ast.BinaryExpr)
			if ok && len(as.Rhs) == 1 && isHelperCall(as.Rhs[0]) && cok && cond.Op == token.NEQ {
				if x, ok := cond.X.(*ast.Ident); ok && x.Name == "err" {
					if y, ok := cond.Y.(*ast.Ident); ok && y.Name == "nil" {
						prepPos = s.Pos()
					}
				}
			}
		case *ast.AssignStmt:
			if len(s.Rhs) == 1 && isHelperCall(s.Rhs[0]) && len(s.Lhs) == 2 {
				if id, ok := s.Lhs[0].(*ast.Ident); ok {
					prepPos, captured = s.Pos(), id.Name
				}
			}
		}
	}
	if !prepPos.IsValid() {
		t.Errorf("%s: %s must call %s unconditionally at the top level of its body", file, fn, helper)
		return
	}
	var lastLaunch token.Pos
	ast.Inspect(body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fun := c.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		if launch[name] {
			lastLaunch = c.Pos()
			if name == "writePrivilegedEnvFile" {
				if len(c.Args) != 1 {
					t.Errorf("%s: %s: writePrivilegedEnvFile needs one argument", file, fn)
				} else if id, ok := c.Args[0].(*ast.Ident); !ok || id.Name != captured {
					t.Errorf("%s: %s: writePrivilegedEnvFile must get the env %s returned", file, fn, helper)
				}
			}
		}
		return true
	})
	if !lastLaunch.IsValid() || lastLaunch < prepPos {
		t.Errorf("%s: %s: %s must run before the launch call", file, fn, helper)
	}
}
