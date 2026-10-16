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
	// The parent dir the shim creates is private too (review M-2).
	dst, err := os.Stat(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	if dst.Mode().Perm() != 0o700 {
		t.Fatalf("parent dir mode = %v, want 0700", dst.Mode().Perm())
	}
}

// DEV-12, spec §9: a shim error, or a failed write of a shim file,
// refuses the launch, installs no file and applies no env change
// (R4-01).
func TestPrepareAgentEnvAbortsOnShimError(t *testing.T) {
	target := filepath.Join(t.TempDir(), "cfg", ".credentials.json")
	// A non-empty directory at the target path makes the final rename
	// fail portably (review I-5).
	dirTarget := filepath.Join(t.TempDir(), "cfg", ".credentials.json")
	if err := os.MkdirAll(filepath.Join(dirTarget, "keep"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A regular file where the parent dir must go makes MkdirAll fail
	// (review M-1).
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fileShim := func(path string) func(agentprovider.PlaceholderEnv) (agentprovider.ShimResult, error) {
		return func(agentprovider.PlaceholderEnv) (agentprovider.ShimResult, error) {
			return agentprovider.ShimResult{Files: []agentprovider.ShimFile{{Path: path, Data: []byte(`{"k":"v"}`)}}, Unset: []string{"SHIMFAIL_PH"}}, nil
		}
	}
	cases := []struct {
		name  string
		shim  func(agentprovider.PlaceholderEnv) (agentprovider.ShimResult, error)
		write func(*os.File, []byte) (int, error)
		// installed reports whether a shim file landed; nil checks target.
		installed func() bool
	}{
		{name: "shim returns an error", shim: func(agentprovider.PlaceholderEnv) (agentprovider.ShimResult, error) {
			return agentprovider.ShimResult{}, errors.New("shim broke")
		}},
		{name: "file write fails", shim: fileShim(target),
			write: func(*os.File, []byte) (int, error) { return 0, errors.New("write: no space left on device") }},
		{name: "rename fails", shim: fileShim(dirTarget), installed: func() bool {
			st, err := os.Stat(dirTarget)
			return err != nil || !st.IsDir()
		}},
		{name: "parent dir cannot be created", shim: fileShim(filepath.Join(blocker, "sub", "x.json")), installed: func() bool {
			st, err := os.Stat(blocker)
			return err != nil || !st.Mode().IsRegular()
		}},
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
		if tc.installed == nil {
			if _, serr := os.Stat(target); !os.IsNotExist(serr) {
				t.Errorf("%s: a shim file was installed despite the failure", tc.name)
			}
		} else if tc.installed() {
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
	type entry struct {
		fn, helper string
		preOK      []string // helper-management launches allowed before the helper
	}
	launchers := map[string][]entry{
		"run_linux.go":        {{"runRun", "prepareAgentEnv", nil}, {"runWholeMachineDirect", "prepareWholeMachineEnv", nil}},
		"run_sudo_linux.go":   {{"runViaSudo", "captureSudoUserEnv", nil}},
		"run_darwin.go":       {{"runRun", "prepareAgentEnv", nil}},
		"run_tsnet_darwin.go": {{"runRunTsnet", "prepareAgentEnv", []string{"install", "start-tsnet"}}},
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
	launch := map[string]bool{"Command": true, "Exec": true, "sudoCommand": true, "writePrivilegedEnvFile": true}
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
			checkLauncherEntry(t, f, name, e.fn, e.helper, launch, e.preOK)
			checkNoShadowedNames(t, f, name, e.fn, helpers)
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

// checkNoShadowedNames fails if fn declares, anywhere in its signature
// or body (`:=`, var, const, type, range, a func literal's parameters or
// results), a local named fail or one of the preparation helpers. The
// launcher checks match those names, so a local `fail` that only logs, or
// a local no-op `prepareAgentEnv`, would satisfy them without aborting or
// preparing anything (review round 2, B2 and B7). Rejecting the local
// declaration makes every such name resolve to the package-level func.
func checkNoShadowedNames(t *testing.T, f *ast.File, file, fn string, helpers map[string]bool) {
	t.Helper()
	reserved := func(name string) bool { return name == "fail" || helpers[name] }
	report := func(id *ast.Ident) {
		if id != nil && reserved(id.Name) {
			t.Errorf("%s: %s declares a local %s, shadowing the package-level func", file, fn, id.Name)
		}
	}
	fields := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, fld := range fl.List {
			for _, id := range fld.Names {
				report(id)
			}
		}
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Name.Name != fn {
			continue
		}
		// fd.Type's params and results are visited as an *ast.FuncType below.
		ast.Inspect(fd, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.FuncType:
				fields(s.Params)
				fields(s.Results)
			case *ast.AssignStmt:
				if s.Tok == token.DEFINE {
					for _, l := range s.Lhs {
						if id, ok := l.(*ast.Ident); ok {
							report(id)
						}
					}
				}
			case *ast.RangeStmt:
				if s.Tok == token.DEFINE {
					for _, e := range []ast.Expr{s.Key, s.Value} {
						if id, ok := e.(*ast.Ident); ok {
							report(id)
						}
					}
				}
			case *ast.ValueSpec:
				for _, id := range s.Names {
					report(id)
				}
			case *ast.TypeSpec:
				report(s.Name)
			}
			return true
		})
	}
}

// checkLauncherEntry requires fn's body to hold, as a top-level
// statement, either `if err := helper(...); err != nil { fail(..., err) }`
// or `x, err := helper(...)` followed directly by
// `if err != nil { fail(..., err) }`: a refused preparation aborts the
// launch (review I-1). Every launch call in fn's body (exec.Command,
// syscall.Exec, sudoCommand, writePrivilegedEnvFile), on any branch and
// in any closure, must come after that statement, except an
// `exec.Command(macHelperPath, "<subcommand>")` listed in preOK, which
// manages the helper and never starts the agent (review I-3). For
// writePrivilegedEnvFile the argument must be the variable the helper
// returned, and nothing may assign that variable again (review I-2).
func checkLauncherEntry(t *testing.T, f *ast.File, file, fn, helper string, launch map[string]bool, preOK []string) {
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
	isIdent := func(e ast.Expr, name string) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == name
	}
	isHelperCall := func(e ast.Expr) bool {
		c, ok := e.(*ast.CallExpr)
		return ok && isIdent(c.Fun, helper)
	}
	isErrNeNil := func(e ast.Expr) bool {
		b, ok := e.(*ast.BinaryExpr)
		return ok && b.Op == token.NEQ && isIdent(b.X, "err") && isIdent(b.Y, "nil")
	}
	// failsOnErr: the block is exactly `fail(..., err)`.
	failsOnErr := func(b *ast.BlockStmt) bool {
		if b == nil || len(b.List) != 1 {
			return false
		}
		es, ok := b.List[0].(*ast.ExprStmt)
		if !ok {
			return false
		}
		c, ok := es.X.(*ast.CallExpr)
		if !ok || !isIdent(c.Fun, "fail") {
			return false
		}
		return slices.ContainsFunc(c.Args, func(a ast.Expr) bool { return isIdent(a, "err") })
	}
	prepPos, captured, found := token.NoPos, "", false
	var captureStmt ast.Stmt
	for i, st := range body.List {
		switch s := st.(type) {
		case *ast.IfStmt:
			as, ok := s.Init.(*ast.AssignStmt)
			if !ok || len(as.Rhs) != 1 || !isHelperCall(as.Rhs[0]) {
				continue
			}
			found = true
			if len(as.Lhs) == 1 && isIdent(as.Lhs[0], "err") && isErrNeNil(s.Cond) && failsOnErr(s.Body) && s.Else == nil {
				prepPos = s.Pos()
			}
		case *ast.AssignStmt:
			if len(s.Rhs) != 1 || !isHelperCall(s.Rhs[0]) {
				continue
			}
			found = true
			if len(s.Lhs) != 2 || !isIdent(s.Lhs[1], "err") || i+1 >= len(body.List) {
				continue
			}
			id, ok := s.Lhs[0].(*ast.Ident)
			next, nok := body.List[i+1].(*ast.IfStmt)
			if ok && nok && next.Init == nil && isErrNeNil(next.Cond) && failsOnErr(next.Body) && next.Else == nil {
				prepPos, captured, captureStmt = s.Pos(), id.Name, s
			}
		}
	}
	if !found {
		t.Errorf("%s: %s must call %s unconditionally at the top level of its body", file, fn, helper)
		return
	}
	if !prepPos.IsValid() {
		t.Errorf("%s: %s must fail(..., err) right after %s returns an error (a refused preparation aborts the launch)", file, fn, helper)
		return
	}
	// helperLaunch: exec.Command(macHelperPath, "<sub>") with <sub> in preOK.
	helperLaunch := func(c *ast.CallExpr) bool {
		if c.Ellipsis.IsValid() || len(c.Args) < 2 || !isIdent(c.Args[0], "macHelperPath") {
			return false
		}
		lit, ok := c.Args[1].(*ast.BasicLit)
		return ok && lit.Kind == token.STRING && slices.Contains(preOK, strings.Trim(lit.Value, "\"`"))
	}
	var lastLaunch token.Pos
	ast.Inspect(body, func(n ast.Node) bool {
		if as, ok := n.(*ast.AssignStmt); ok && captured != "" && as != captureStmt {
			for _, l := range as.Lhs {
				if isIdent(l, captured) {
					t.Errorf("%s: %s: %s is assigned again after %s captured it", file, fn, captured, helper)
				}
			}
		}
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
		if !launch[name] {
			return true
		}
		if c.Pos() < prepPos {
			if !helperLaunch(c) {
				t.Errorf("%s: %s: a %s call runs before %s", file, fn, name, helper)
			}
			return true
		}
		lastLaunch = c.Pos()
		if name == "writePrivilegedEnvFile" {
			if len(c.Args) != 1 {
				t.Errorf("%s: %s: writePrivilegedEnvFile needs one argument", file, fn)
			} else if !isIdent(c.Args[0], captured) || captured == "" {
				t.Errorf("%s: %s: writePrivilegedEnvFile must get the env %s returned", file, fn, helper)
			}
		}
		return true
	})
	if !lastLaunch.IsValid() {
		t.Errorf("%s: %s: no launch call after %s", file, fn, helper)
	}
}

// D7: `clawpatrol run grok` runs the real grok provider's preflight, by
// bare name and by path, and refuses a config that re-points grok's
// endpoints, naming the file (R5-03).
func TestGrokLaunchRunsPreflight(t *testing.T) {
	t.Setenv("HOME", t.TempDir())  // the grok shim writes under $HOME/.clawpatrol
	t.Setenv("GROK_AUTH_PATH", "") // restored after the test; the shim sets it
	grokHome := t.TempDir()
	t.Setenv("GROK_HOME", grokHome)
	cfg := filepath.Join(grokHome, "config.toml")
	if err := os.WriteFile(cfg, []byte("[endpoints]\nmodels_base_url = \"https://models.example.test\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p := agentprovider.ByBinary("grok"); p == nil || p.Launcher == nil || p.Launcher.Preflight == nil {
		t.Fatal("the grok provider declares no Preflight; D7 is disconnected")
	}
	for _, argv0 := range []string{"grok", "/usr/local/bin/grok"} {
		if err := prepareAgentEnv([]string{argv0}, func() {}); err == nil || !strings.Contains(err.Error(), cfg) {
			t.Errorf("%s: prepareAgentEnv err = %v, want a refusal naming %s", argv0, err, cfg)
		}
	}
}
