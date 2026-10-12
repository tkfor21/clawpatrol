package claude

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"testing"
)

// claudeReviewedNonCredential lists env names the recipe prints that a
// binary reading (task-4-review.md §1a/§1b) showed carry no model or API
// credential. Names only; the reasons are one line each.
var claudeReviewedNonCredential = []string{
	// Settings that only match the TOKEN regex: token counts, not secrets.
	"CLAUDE_CODE_ENABLE_TOKEN_USAGE_ATTACHMENT", "CLAUDE_CODE_FILE_READ_MAX_OUTPUT_TOKENS",
	"CLAUDE_CODE_IDLE_COMPACT_MIN_TOKENS", "CLAUDE_CODE_IDLE_TOKEN_THRESHOLD",
	"CLAUDE_CODE_MAX_CONTEXT_TOKENS", "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
	"CLAUDE_CODE_RESUME_TOKEN_THRESHOLD", "CLAUDE_CODE_TOTAL_TOKENS_REMINDER",
	"CLAUDE_CODE_TOTAL_TOKENS_REMINDER_AFTER_USER_TURN", "CLAUDE_CODE_TOTAL_TOKENS_REMINDER_BUDGET",
	"CLAUDE_CODE_WORKFLOW_SIZE_WARNING_TOKENS",
	// Timeouts, TTLs and lock flags.
	"CLAUDE_CODE_API_KEY_HELPER_TTL_MS",           // cache TTL of the settings-configured key helper
	"CLAUDE_CODE_PROXY_AUTH_HELPER_TTL_MS",        // TTL for the HTTP-proxy auth helper
	"CLAUDE_CODE_HOST_AUTH_REFRESH_TIMEOUT_MS",    // timeout in the host-managed-auth set
	"CLAUDE_CODE_OAUTH_401_WAIT_MS",               // wait after a 401
	"CLAUDE_CODE_AUTH_FAIL_EXIT_MS",               // exit delay after auth failure
	"CLAUDE_CODE_DISABLE_AUTH_REFRESH_LOCK",       // lock flag
	"CLAUDE_CODE_OTEL_HEADERS_HELPER_DEBOUNCE_MS", // debounce for the OTEL headers helper
	// Flags and capability bits that carry no secret.
	"CLAUDE_CODE_ENABLE_PROXY_AUTH_HELPER",         // enable flag for the HTTP-proxy auth helper
	"CLAUDE_CODE_PROXY_AUTHENTICATE",               // challenge string passed into the proxy helper
	"CLAUDE_CODE_SDK_HAS_HOST_AUTH_REFRESH",        // capability flag
	"CLAUDE_CODE_SDK_HAS_OAUTH_REFRESH",            // capability flag
	"CLAUDE_CODE_SKIP_ANTHROPIC_AWS_AUTH",          // boolean: skip cloud signing
	"CLAUDE_CODE_SKIP_ANTHROPIC_GOOGLE_CLOUD_AUTH", // boolean: skip cloud signing
	"CLAUDE_CODE_SKIP_AWS_CRED_CACHE",              // boolean
	"CLAUDE_CODE_SKIP_BEDROCK_AUTH",                // boolean: skip cloud signing
	"CLAUDE_CODE_SKIP_FOUNDRY_AUTH",                // boolean: skip cloud signing
	"CLAUDE_CODE_SKIP_MANTLE_AUTH",                 // boolean: skip cloud signing
	"CLAUDE_CODE_SKIP_VERTEX_AUTH",                 // boolean: skip cloud signing
	"CLAUDE_CODE_FORCE_WINDOWS_CREDMAN",            // Windows secure-storage selector; run targets Linux and macOS
	"CLAUDE_CODE_ARG_KEY_SHAPE",                    // arg-shape flag
	"CLAUDE_CODE_HOST_SESSION_ID",                  // session id, not a secret
	"CLAUDE_CODE_SUBAGENT_PROMPT_SNAPSHOT",         // prompt snapshot flag
	"CLAUDE_CODE_POLICY_HELPER_PS1_PATH",           // Windows policy helper path
	"CLAUDE_CODE_POLICY_HELPER_PSMODULEPATH",       // Windows policy helper path
	// Public identifiers and scopes.
	"CLAUDE_CODE_DESIGN_OAUTH_CLIENT_ID", // public client-id override for /design-login; flow stays on path-gated URLs
	"CLAUDE_CODE_OAUTH_SCOPES",           // inert once CLAUDE_CODE_OAUTH_REFRESH_TOKEN is stripped
	"ANTHROPIC_WEBHOOK_SIGNING_KEY",      // verifies inbound webhooks; not request auth
	"ANTHROPIC_SERVICE_ACCOUNT_ID",       // WIF parameter, no secret
	"ANTHROPIC_WORKSPACE_ID",             // WIF parameter, no secret
	"ANTHROPIC_SCOPE",                    // WIF parameter, no secret
	// Task 4 fix round 1 (task-4-names-21.md): class (c).
	"CLAUDE_AI_PROFILE_SCOPE",             // not an env var: an OAuth scope constant
	"CLAUDE_CODE_CERT_STORE",              // CA source selector; fails closed
	"CLAUDE_CODE_DISABLE_ADMIN_ENV_UNION", // bool: first admin env instead of union
	"CLAUDE_CODE_ENVIRONMENT_KIND",        // remote/BYOC mode label
	"CLAUDE_CODE_PROFILE_QUERY",           // performance profiling
	"CLAUDE_CODE_PROFILE_STARTUP",         // startup profiling sampling
	"CLAUDE_CODE_PROXY_RESOLVES_HOSTS",    // bool: skip local DNS behind a proxy
	"CLAUDE_CODE_REMOTE_SESSION_ID",       // session id, non-auth header source
	"CLAUDE_ENV_FILE",                     // shell script for Bash tool subprocesses, not the API client
	// Env-var look-alikes and Remote Control bridge selectors.
	"CLAUDE_API_KEY",    // UI placeholder text in the GitHub-app setup
	"USE_STAGING_OAUTH", // only switches the bridge websocket host; the build's env selector ignores it
	"USE_LOCAL_OAUTH",   // only switches the bridge websocket host; the build's env selector ignores it
}

var (
	// The widened recipe: the original regexes plus PROFILE, CONFIG_DIR,
	// FEDERATION, UNIX_SOCKET and ORGANIZATION_ID.
	reClaudeNames1 = regexp.MustCompile(`(?:CLAUDE_CODE|ANTHROPIC)_[A-Z0-9_]*(?:OAUTH|TOKEN|KEY|AUTH|HELPER|CRED|PROFILE|CONFIG_DIR|FEDERATION|UNIX_SOCKET|ORGANIZATION_ID)[A-Z0-9_]*`)
	reClaudeNames2 = regexp.MustCompile(`CLAUDE_[A-Z0-9_]*(?:TOKEN|AUTH|SNAPSHOT|SECURESTORAGE|CONFIG_DIR|PROFILE)[A-Z0-9_]*`)
	// The binary's own credential and secret env arrays, anchored on a
	// member each: the secret-env array, the file-descriptor list it
	// spreads, the credential-path list, and the federation parameter list.
	reClaudeArrays = []*regexp.Regexp{
		regexp.MustCompile(`\["CLAUDE_CODE_OAUTH_TOKEN"[^\]]*\]`),
		regexp.MustCompile(`\[[^\]]*CCR_AGENT_PROXY_TOKEN_FILE_DESCRIPTOR[^\]]*\]`),
		regexp.MustCompile(`\[[^\]]*"CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"[^\]]*\]`),
		regexp.MustCompile(`\[[^\]]*"ANTHROPIC_FEDERATION_RULE_ID"[^\]]*\]`),
	}
	reClaudeArrayName = regexp.MustCompile(`[A-Z][A-Z0-9_]{3,}`)
)

// claudeNamespace reports whether an env name belongs to Claude Code or
// the Anthropic SDK. The binary's credential-path arrays also list other
// tools' names (AWS_*, GOOGLE_*, KUBECONFIG, ...) that Claude Code only
// guards from settings; they are host credentials of those tools, not
// Claude model auth, and are out of scope here. USE_STAGING_OAUTH,
// USE_LOCAL_OAUTH and the CCR/agent-proxy names are in scope by name.
func claudeNamespace(n string) bool {
	for _, p := range []string{"CLAUDE_", "ANTHROPIC_", "CCR_", "AGENT_PROXY_", "USE_STAGING_", "USE_LOCAL_"} {
		if len(n) >= len(p) && n[:len(p)] == p {
			return true
		}
	}
	return false
}

// newestClaudeBinary returns the most recently modified file in
// ~/.local/share/claude/versions, or "" when none is installed.
func newestClaudeBinary(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	matches, _ := filepath.Glob(filepath.Join(home, ".local", "share", "claude", "versions", "*"))
	var best string
	var bestTime int64
	for _, m := range matches {
		fi, err := os.Stat(m)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if mt := fi.ModTime().UnixNano(); best == "" || mt > bestTime {
			best, bestTime = m, mt
		}
	}
	return best
}

// TestClaudeBinaryEnvNamesClassified turns the Task 4 env-name recipe into
// a test: every credential-shaped env name in the installed Claude Code
// binary must be stripped, a documented residual, or reviewed as not a
// credential. A new name fails here and needs a user decision (stop and
// escalate). It prints names only, never values.
func TestClaudeBinaryEnvNamesClassified(t *testing.T) {
	bin := newestClaudeBinary(t)
	if bin == "" {
		t.Skip("no Claude Code binary under ~/.local/share/claude/versions")
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Skipf("cannot read %s: %v", filepath.Base(bin), err)
	}
	found := map[string]bool{}
	for _, m := range reClaudeNames1.FindAll(data, -1) {
		found[string(m)] = true
	}
	for _, m := range reClaudeNames2.FindAll(data, -1) {
		found[string(m)] = true
	}
	for _, re := range reClaudeArrays {
		for _, arr := range re.FindAll(data, -1) {
			for _, n := range reClaudeArrayName.FindAll(arr, -1) {
				found[string(n)] = true
			}
		}
	}
	if len(found) == 0 {
		t.Fatalf("recipe found no env names in %s; the regexes no longer match this binary", filepath.Base(bin))
	}
	var unknown []string
	for n := range found {
		if !claudeNamespace(n) {
			continue
		}
		if !slices.Contains(claudeStripped, n) && !slices.Contains(claudeDocumentedResiduals, n) &&
			!slices.Contains(claudeReviewedNonCredential, n) {
			unknown = append(unknown, n)
		}
	}
	sort.Strings(unknown)
	for _, n := range unknown {
		t.Errorf("%s (in %s): not in claudeStripped, claudeDocumentedResiduals or claudeReviewedNonCredential; read the binary, classify it, and escalate if it is a credential source", n, filepath.Base(bin))
	}
}
