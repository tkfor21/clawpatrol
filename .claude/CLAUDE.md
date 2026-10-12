# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

It is the single source of truth for repo-level agent instructions.
`AGENTS.md` at the repo root is a symlink to this file so Codex and
Claude Code both pick it up. `site/CLAUDE.md` adds rules for the
landing page.

## What this is

Claw Patrol is a wire-level policy gateway for AI agents. It sits
between agents and production, parses their traffic per protocol
(HTTPS, Postgres, ClickHouse, Kubernetes, SSH), and gates each action
against HCL rules whose conditions are CEL expressions. Real secrets
stay in the gateway: agents send placeholder credentials, and the
gateway swaps in the real ones on the way upstream. It ships as one Go
binary (`cmd/clawpatrol`) with a React dashboard embedded in it.

## Commands

```sh
make                 # dashboard (deno) + go build -> ./clawpatrol
make release         # stripped -s -w -trimpath build, mirrors release.yml
make test            # go test ./...
make lint            # golangci-lint + oxlint
make fmt             # gofmt (skipping third_party/) + dashboard oxfmt
make fmt-check       # the CI format gate
go run ./internal/tools/docgen   # regenerate site/doc/config-reference.md
./clawpatrol validate examples/gateway.example.hcl   # CI validates every examples/*.hcl
```

Run a single test: `go test ./cmd/clawpatrol/ -run 'TestName'` or
`go test ./internal/config/... -run 'TestName'`. The per-OS sandbox
CI jobs run `go test ./internal/sandbox/... ./internal/config/extplugin/...`
and `go test ./cmd/clawpatrol/ -run 'Sandbox|Dial|Nosy|Plugin|ExternalCredential'`;
use the same filter when touching sandbox or external-plugin code.

- **Build the dashboard first.** `dashboard/embed.go` uses
  `//go:embed all:dist`, so `cmd/clawpatrol` and `go vet`/lint need
  `dashboard/dist`. Run `make dashboard` once on a fresh checkout
  before `go test`/`go build` (CI does the same).
- Dashboard tooling is Deno (`cd dashboard && deno task build|lint|format`).
  npm/pnpm are not used.
- **Linux-only paths:** `run` on Linux (netns), the daemon, and the
  plugin sandbox (namespaces, Landlock fallback via
  `CLAWPATROL_SANDBOX_BACKEND=landlock`) only build or run on Linux.
  The macOS seatbelt backend and `macos/` system extension need
  macOS. It's fine to lean on CI for the platforms you aren't on.
  When debugging `run` on Linux, the daemon log at
  `~/.local/state/clawpatrol/run/daemon.log` usually has the real cause.
  `doc/dev-setup.md` covers prerequisites and the macOS extension build.
- **`docgen` freshness is a test.** `internal/tools/docgen` has
  `TestGeneratedDocIsFresh`. Touching any documented HCL field means
  re-running docgen and committing `site/doc/config-reference.md`.

## Formatting gates

CI fails fast on unformatted code. Run `make fmt-check` before pushing
(or `make fmt` to fix). This runs `gofmt` over tracked Go files
**excluding `third_party/`** and `deno task format:check` in
`dashboard/`. Never run `gofmt -w .` from the root: `third_party/tailscale`
is a vendored, patched copy of `tailscale.com` (wired in by a `replace`
in `go.mod`, see `third_party/tailscale/PATCH.md`), and it must stay
byte-identical to upstream apart from the documented patches.

## Architecture

Product-level architecture (actors, connection modes, the dispatch
decision, SNI and Postgres claiming, DNS→VIP interception) is in
`site/doc/architecture.md`. Implementation notes are in `doc/`. Read
`doc/code-vocabulary.md` before touching plugin/runtime code.

**Three deployment shapes, one binary.** `main.go` switches on the
subcommand: `gateway` (the proxy), `join` (a WireGuard tunnel for the
whole host), `run` (a per-process tunnel, via netns on Linux and
NetworkExtension on macOS), plus `validate`, `test`, `plugins`, and
internal helpers (`daemon-internal`, `relay-*`, `__run-privileged`).
`cmd/clawpatrol` is one large `main` package. Platform splits use
`_linux.go` / `_darwin.go` / `_other.go` suffixes.

**Config is plugin-driven** (`internal/config`, grammar reference in
`internal/config/README.md`):
- Policy blocks have two labels, `kind "type" "name"` (approver,
  credential, endpoint, tunnel), plus `rule` and `profile`. All names
  share one flat namespace, and references are bare names.
- Each type is a `config.Plugin` registered via `config.Register`
  (`internal/config/plugin.go`) with decode, `Refs`, `Validate`,
  `Build`, optional `CompileRule`, `Emit` (HCL round-trip), and a
  `Runtime`.
- Built-in plugins live under `internal/config/plugins/{approvers,credentials,endpoints,tunnels,rules,facets}`
  and are pulled in by blank imports in `internal/config/plugins/all/all.go`.
  A new plugin package must be added there.
- **Facets** (`plugins/facets/{https,k8s,sql,ssh}`) define the CEL
  facts a rule can test for each protocol family. There is one `rule`
  plugin, and it infers the family from the rule's endpoints.
- **Runtime** is the request-time half. It is stored as `any` and
  type-asserted by the dispatcher (`internal/config/runtime/`) against
  interfaces such as `HTTPCredentialRuntime`, `PostgresCredentialRuntime`,
  `ConnEndpointRuntime`, `PlaceholderDetector`, and `ApproverRuntime`.
  `runtime/checker.go` validates these at init. A plugin with no
  runtime is schema-only.

**External plugins** (`internal/config/extplugin`, SDK in `pluginsdk/`)
run out of process inside a sandbox (`internal/sandbox`) and talk to
the gateway over a wire protocol. Third-party integrations, including
HITL notifiers and approvers, belong here, not in core. If the plugin
interfaces can't express something, extending them is welcome core
work.

**Human-in-the-loop:** rules can deny, allow, or pause for an
approver. The `hitl_*` files in `cmd/clawpatrol` hold the pending
operation store, fingerprinting, and retry relay.

## Change conventions (from CONTRIBUTING.md)

- PR titles take the form `area: what changed` (`gateway: ...`, `run: ...`,
  `dashboard: ...`, `docs: ...`). Make one change per PR, and include a
  regression test with every fix.
- Keep the HCL config format stable. Don't rename or restructure blocks
  or attributes as a side effect of another change.
- Product docs go in `site/doc/` (rendered at clawpatrol.dev/docs).
  Implementation notes go in `doc/`.

## Dates and times

Render every timestamp in the UI as `yyyy-MM-dd HH:mm:ss.SSS` (24-hour,
locale-independent, millisecond precision). When only the time of day
is shown, use `HH:mm:ss.SSS`.

The helpers are in `dashboard/src/lib/format.ts`:

- `fmtDateTime(t)` gives the full timestamp.
- `fmtTime(t)` gives the time of day only.

Do not call `toLocaleDateString`, `toLocaleTimeString`, or
`toLocaleString` to render dates and times. Their output differs by
locale (`5/11/2026` in en-US, `11/05/2026` in en-GB, `11.5.2026` in
de-DE), which makes log entries unreadable across a team. Number
formatting (`Intl.NumberFormat`, `Number.toLocaleString`) is fine.
This rule covers dates and times only.

## `cmd/clawpatrol/testdata/`

This is the self-test corpus for `clawpatrol test` (see
`site/doc/clawpatrol-test.md`). `example.hcl` is the policy under
test, and the `*.json` files are action fixtures. The goal is one
fixture per CEL branch in `example.hcl`, so that every rule's `allow`
and `deny` arm runs at least once. Adding a rule means adding fixtures
for both arms.

To generate new fixtures, run the gateway against `example.hcl`, issue
the request you want to capture, click "Download action" on the
dashboard's request detail page, and drop the file into `testdata/`.
Don't hand-edit recorded JSON. If the format changes, regenerate.

Keep fixtures minimal and synthetic: public hostnames, no real IPs, no
production credentials.
