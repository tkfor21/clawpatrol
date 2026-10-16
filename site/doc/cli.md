# CLI Reference

The `clawpatrol` binary is the unified entry point for both the
gateway server and the client tools. Same binary, different
subcommands.

## Install

```bash
curl -fsSL https://clawpatrol.dev/install.sh | sh
```

Statically-linked Go binary, dropped in `~/.local/bin`. macOS and
Linux on amd64 + arm64. Set `CLAWPATROL_FROM_SOURCE=1` to build from
source instead (requires Go + `gh auth login`).

## Commands

### `clawpatrol gateway`

Run the gateway daemon against an HCL config. Start from
[`gateway.example.hcl`](https://github.com/denoland/clawpatrol/blob/main/examples/gateway.example.hcl)
— see [Getting Started](/docs/getting-started/) for the operational
fields you need to edit.

```bash
clawpatrol gateway <config.hcl>
```

By default the gateway is read-only-config: the dashboard can
generate HCL from observed actions, but it will not edit the running
file. Set `dashboard_config_writes = true` in `gateway {}` to let the
dashboard append generated rules after validating the full candidate
config and hot-reloading it. Git-managed deployments should leave it
false and push edits through their normal review/deploy flow. See
[config-reference](config-reference) for the HCL grammar.

### `clawpatrol join`

Enroll the current device with a gateway. Prints a one-time code,
opens the dashboard so an operator can confirm and assign a
profile, persists the WireGuard conf, and installs the CA in your
trust store. Falls back to the Tailscale path (see `login` below)
when the gateway runs in Tailscale mode.

```bash
clawpatrol join <gateway-url> [flags]
```

| Flag | Default | Notes |
|---|---|---|
| `--hostname NAME` | OS hostname | Device name registered with the gateway |
| `--profile NAME` | gateway default | Profile to assign at approval time |
| `--whole-machine` | off | Route every packet through the gateway. Linux installs system Tailscale (or `wg-quick` for WG gateways); macOS uses the NE in whole-host config. Default: per-process via `clawpatrol run`. |
| `--no-trust` | off | Fetch the CA but skip system trust install |
| `--ca-dir DIR` | `~/.clawpatrol` | Where to store the fetched CA |
| `--ca-fingerprint FP` | unset | SHA-256 fingerprint the gateway's CA must match before it is written or trusted. Read it off the dashboard. Pins a non-interactive join instead of relying on the operator comparing the printed fingerprint by eye. Accepts the digest with or without colons. |
| `--name NAME` | `clawpatrol` | Exit-node hostname (Tailscale gateway, `--whole-machine` only) |

### `clawpatrol login`

Tailscale-based onboarding alternative for fleets already on a
tailnet. Joins the device to the tailnet, finds the gateway by its
exit-node hostname, and installs the CA.

```bash
clawpatrol login [flags]
```

| Flag | Default | Notes |
|---|---|---|
| `--name NAME` | `clawpatrol` | Exit-node hostname to look for on the tailnet |
| `--no-trust` | off | Fetch the CA but skip system trust install |
| `--no-exit-node` | off | Skip setting the tailscale exit-node (run manually) |

### `clawpatrol run`

Run a command with its traffic routed through the joined gateway.

```bash
clawpatrol run -- <command> [args...]
```

`run` reads the WG conf that `clawpatrol join` wrote to the standard
location; there is no flag to point it elsewhere. On Linux the wrapped
command runs in an unprivileged user namespace with a private WG
tunnel; on macOS the Network Extension does the capture.

Linux only, and only on the no-`sudo` path described below:
`--no-auto-expose` (before the `--`) disables the loopback relay that
mirrors TCP listeners inside the namespace back to the host and
forwards the wrapped command's connections to 127.0.0.1 out to host
services. macOS does not parse it.

```bash
clawpatrol run -- claude
clawpatrol run -- gh pr create
clawpatrol run -- psql 'host=db user=agent'
```

The agent sees a normal network — outbound flows just route through
the gateway, which matches each request against the rules, injects
the configured credential, and forwards.

#### Agent credentials in the environment

Every way of launching `clawpatrol run` (the per-process tunnel and
the `sudo` path on Linux, a `--whole-machine` device, and macOS)
prepares the child's environment in the same order:

1. Remove competing credential variables: names an agent could use to
   authenticate around the gateway.
2. Apply the env pushdown (CA bundle variables and credential
   placeholders). A pushed value for a removed name, a CA variable, or
   `CODEX_ACCESS_TOKEN`/`CODEX_AGENT_IDENTITY` replaces whatever your
   shell had.
3. Run the launcher shim of each agent that needs one (below).
4. For `clawpatrol run grok`, check grok's config files (see
   [`clawpatrol run grok`](#clawpatrol-run-grok)).

The removed names are printed on stderr
(`[clawpatrol] removed … from the agent environment`). There is no
opt-out. The list is the union of every agent's list, whatever the
wrapped binary is, because a wrapper (`clawpatrol run bash`, `make`, a
script) can start an agent too:

- **Every launch:** `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
  `XAI_API_KEY`.
- **Claude Code:** `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`,
  `CLAUDE_CODE_OAUTH_REFRESH_TOKEN`,
  `CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR`,
  `CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR`, `ANTHROPIC_FOUNDRY_API_KEY`,
  `ANTHROPIC_AWS_API_KEY`, `ANTHROPIC_FOUNDRY_AUTH_TOKEN`,
  `ANTHROPIC_IDENTITY_TOKEN`, `ANTHROPIC_IDENTITY_TOKEN_FILE`,
  `CLAUDE_CODE_SESSION_ACCESS_TOKEN`, `CLAUDE_CODE_GATEWAY_TOKEN`,
  `CLAUDE_CODE_GATEWAY_TOKEN_FILE_DESCRIPTOR`,
  `CLAUDE_CODE_WEBSOCKET_AUTH_FILE_DESCRIPTOR`,
  `CLAUDE_BG_AUTH_SNAPSHOT_PATH`, `CLAUDE_SESSION_INGRESS_TOKEN_FILE`,
  `CLAUDE_SECURESTORAGE_CONFIG_DIR`, `CLAUDE_BRIDGE_OAUTH_TOKEN`,
  `ANTHROPIC_CONFIG_DIR`, `ANTHROPIC_PROFILE`,
  `CLAUDE_CODE_FEDERATION_CACHE_DIR`, `ANTHROPIC_UNIX_SOCKET`,
  `ANTHROPIC_FEDERATION_RULE_ID`, `ANTHROPIC_ORGANIZATION_ID`,
  `ANTHROPIC_CUSTOM_HEADERS`, `CLAUDE_CODE_MOCK_REMOTE_SETTINGS`.
- **Codex:** `CODEX_API_KEY`.
- **Grok Build:** `GROK_CODE_XAI_API_KEY`, `GROK_DEPLOYMENT_KEY`,
  `GROK_AUTH_PROVIDER_COMMAND`, `GROK_AUTH_PATH`, `GROK_AUTH`,
  `GROK_EXTRA_AUTH_KEY`, `GROK_TRACE_UPLOAD_CREDENTIALS_FILE`,
  `GROK_LOCAL_AUTH`, every `GROK_OAUTH2_*` and `GROK_OIDC_*` name,
  `CLAWPATROL_GROK_SESSION`; the config overrides `GROK_CONFIG`,
  `GROK_CONFIG_PATH`, `GROK_MANAGED_CONFIG_URL` and
  `GROK_CAMPAIGNS_OVERRIDE`; and the endpoint overrides
  `GROK_CLI_CHAT_PROXY_BASE_URL`, `GROK_XAI_API_BASE_URL`,
  `GROK_MODELS_BASE_URL`, `GROK_MODELS_LIST_URL`, every
  `GROK_PRODUCTION_*` name, `GROK_WS_URL`, `GROK_WS_ORIGIN`,
  `GROK_GATEWAY_URL`, `GROK_CODE_WEB_URL`, `GROK_CODE_BACKEND_URL`,
  `GROK_CONVERSATIONS_BASE_URL`, `GROK_WORKSPACES_BASE_URL`,
  `GROK_MODES_BASE_URL`, `GROK_SKILLS_BASE_URL`,
  `GROK_FEEDBACK_BASE_URL`, `GROK_TRACE_UPLOAD_URL`,
  `GROK_TRACE_UPLOAD_ENDPOINT_URL`, `GROK_INTERNAL_OTLP_HEADERS`,
  `GROK_INTERNAL_OTLP_TRACES_ENDPOINT`, `GROK_TELEMETRY_EVENTS_URL`,
  `GROK_TELEMETRY_EVENTS_API_KEY` and `GROK_TELEMETRY_MIXPANEL_TOKEN`.

Keep real credentials out of the shell you launch agents from anyway:
these lists cover the names each agent is known to read, not every
file or setting it can load a credential from. [Security Model ›
Credential sources clawpatrol cannot strip](/docs/security-model/#credential-sources-clawpatrol-cannot-strip)
lists the known gaps.

**Launcher shims.** A shim runs for the wrapped binary's agent, and
also for every agent whose placeholder the gateway pushed, whatever
the wrapped binary is. So `clawpatrol run bash` with a Grok Build
credential bound still gets grok's managed `GROK_AUTH_PATH`, and with
an Anthropic OAuth credential bound it gets Claude Code's shim:

- The Claude shim's `/remote-control` notice now prints on every
  `clawpatrol run` when an Anthropic OAuth credential
  (`anthropic_oauth_subscription`) is bound, not only on
  `clawpatrol run claude`.
- With `CLAWPATROL_CLAUDE_OAUTH_SHIM=1` set, a wrapped launch such as
  `clawpatrol run python app.py` also loses `ANTHROPIC_AUTH_TOKEN` and,
  unless you set `CLAUDE_CONFIG_DIR` yourself, gets `CLAUDE_CONFIG_DIR`
  pointed at the managed dir `~/.clawpatrol/claude-config`. An SDK
  client that needs `ANTHROPIC_AUTH_TOKEN` should run without that
  variable set.

#### `clawpatrol run grok`

`clawpatrol run grok` (or `clawpatrol run -- grok …`) points
`GROK_AUTH_PATH` at a managed `auth.json` under `~/.clawpatrol/grok/`.
It holds the gateway's placeholder session when a `grok_oauth`
credential is bound to the device's profile, and an empty store when
none is, so grok never falls back to a login of its own in
`~/.grok/auth.json`. Your `~/.grok` config, skills and MCP servers
stay in use. `GROK_EXTRA_CA_BUNDLE` is set to the gateway CA, so grok
trusts the gateway's certificates. See
[Credentials › grok_oauth](/docs/credentials/#grok_oauth).

Before grok starts, clawpatrol reads every config file grok merges
and refuses to start grok, naming the file and the key, when one of
them gives grok a credential, a header, or an endpoint of its own.
Those would let grok authenticate around the gateway. The files are
`/etc/grok/managed_config.toml`, `/etc/grok/requirements.toml`, and
`managed_config.toml`, `config.toml` and `requirements.toml` under
`$GROK_HOME` (default `~/.grok`). It refuses when a file sets:

- in `[grok_com_config]` or `[auth]`: `auth_provider_command`,
  `oidc`, `oauth2`, `grok_ws_url` or `grok_ws_origin`, or either
  section as something other than a table;
- a non-empty `[endpoints]` table;
- an `[auth_provider.<name>]` command table;
- in a `[model_providers.<id>]` or `[model.<id>]` table, or in
  `[toolset.web_search]`: `api_key`, `env_key`, `auth_provider`,
  `auth`, `base_url`, `api_base_url` or `mtls_cert_dir`, or a non-empty
  `extra_headers`, `env_http_headers` or `query_params`;
- a non-empty `[models].extra_headers`.

Each of these is refused at the top level of a file and inside any
`[[version_overrides]]` or `[[campaigns]]` entry, whatever its version
bounds. A file that cannot be read or does not parse refuses too,
because clawpatrol cannot confirm it is safe.

It also reads two caches grok keeps in `$GROK_HOME`:

- `settings_cache.json`: refused when a campaign in it sets any of the
  keys above, or when the file does not have the shape grok writes
  (including a repeated JSON key).
- `models_cache.json`: refused when a cached model sets `api_key`,
  `env_key`, `auth_provider` or `mtls_cert_dir`; sets a non-empty
  `extra_headers`, `query_params` or `env_http_headers`; has a
  `base_url` or `api_base_url` that is not `https` on
  `cli-chat-proxy.grok.com`, `x.ai` or a subdomain of `x.ai` (port 443,
  no user info); or when the file does not parse.

Deleting either cache file is safe: grok fetches it again.

With neither `GROK_HOME` nor `HOME` set (`env -i`, some service
units), clawpatrol cannot tell which home grok will read and refuses to
start grok; set one of them.

A grok config that points a model at its own provider or key, or adds
its own headers or query parameters to model requests, cannot run
under `clawpatrol run grok`. Route that provider through a gateway
endpoint instead, and let the gateway inject its credential.

The check runs only when the wrapped binary is named exactly `grok`
(the file name, case-sensitive). A wrapped launch that starts grok
later (`clawpatrol run bash`) gets the environment cleanup and grok's
shim, but not this check.

#### Root and `sudo` inside `clawpatrol run` (Linux)

`clawpatrol run` builds the network namespace one of two ways,
depending on whether the invoking user has **passwordless `sudo`**:

- **Passwordless `sudo` available (preferred).** clawpatrol uses it to
  set up the net + mount namespace as real root, then drops back to
  your own user before exec'ing the command. Inside the wrapper you
  are your normal uid, root (uid 0) exists in the namespace, and
  `sudo` works — a command that needs to elevate can just call `sudo`
  as it would anywhere. The wrapped command can't tell it was launched
  this way: clean environment, normal uid, no leftover `SUDO_*` vars.
- **No passwordless `sudo` (or `CLAWPATROL_NO_SUDO=1`).** clawpatrol
  falls back to an unprivileged user namespace. As a consequence of
  how Linux user namespaces work, that namespace has no mapped root:
  your own uid is the only one mapped in, host root (uid 0) is not. So
  commands that need real root won't work — `sudo` fails with messages
  like:

  ```
  sudo: /etc/sudo.conf is owned by uid 65534, should be 0
  sudo: The "no new privileges" flag is set, which prevents sudo from running as root.
  ```

  The first is the namespace mapping root-owned files to "nobody"
  (65534); the second is the `no_new_privileges` flag clawpatrol sets
  to install its unprivileged seccomp filter. This isn't a deliberate
  restriction — it falls out of running unprivileged, and the host's
  own `sudo` is unaffected outside the wrapper.

Gaining root inside the wrapper doesn't bypass the gateway's purpose:
real secrets never leave the gateway, so a process that steps around
the tunnel only reaches the network with placeholder credentials that
mean nothing upstream. The namespace makes the gateway the path of
least resistance, not an escape-proof jail.

If you're on the unprivileged path and a command needs to act as root:

- **Install the tooling on the host first**, then launch — e.g.
  `sudo apt-get install -y postgresql-client && clawpatrol run -- psql …`.
  Many tools can also be unpacked into a local prefix (e.g.
  `dpkg-deb -x`) without root at all.
- **Use `--whole-machine`** (see `clawpatrol join --whole-machine`).
  It routes traffic at the host level instead of per-process, so the
  command runs in the normal host environment where `sudo` works —
  you run it directly, not through `clawpatrol run`.

#### Ubuntu 24.04 and AppArmor

Ubuntu 24.04 ships with `kernel.apparmor_restrict_unprivileged_userns=1`,
which denies unprivileged user namespaces to any program that has no
AppArmor profile granting them. `clawpatrol run` then prints a
warning and, without passwordless `sudo`, fails to build its
namespace. Two ways to run without turning that protection off for
the whole system:

- **Passwordless `sudo` for the invoking user.** clawpatrol uses the
  privileged setup path described above and never creates a user
  namespace. This is the simplest option on a single-user machine.
- **An AppArmor profile for the clawpatrol binary.** This is the
  mechanism Ubuntu uses for its own browsers. The profile attaches
  by path, and whatever sits at that path runs with the `userns`
  grant, so put the binary somewhere only root can write (for
  example `/usr/local/bin/clawpatrol`) and name that exact path; a
  glob over home directories would hand the grant to any file a
  user drops there. Create `/etc/apparmor.d/clawpatrol`:

  ```
  abi <abi/4.0>,
  include <tunables/global>

  profile clawpatrol /usr/local/bin/clawpatrol flags=(unconfined) {
    userns,
    include if exists <local/clawpatrol>
  }
  ```

  then load it with `sudo apparmor_parser -r /etc/apparmor.d/clawpatrol`.
  The profile is unconfined apart from granting `userns`, so it
  changes nothing else about how clawpatrol runs; it has to be
  reloaded if the binary moves. The warning prints the path of the
  binary that is running.

Setting `kernel.apparmor_restrict_unprivileged_userns=0` also works
but removes the restriction for every program on the host, which is
what it exists to prevent.

### `clawpatrol test`

Replay recorded gateway actions against a candidate HCL policy and
report verdict drift.

```bash
clawpatrol test <config.hcl> <fixture.json | fixture-dir>
```

See [Testing](clawpatrol-test) for the fixture format and
CI integration. Exit 0 = all match, 1 = drift, 2 = usage/config
error.

### `clawpatrol validate`

Parse and compile a gateway HCL config, then exit. Use it in CI to
catch typos before they hit production.

```bash
clawpatrol validate <config.hcl>
```

`validate` runs the same load path the daemon does, so any
[external plugin](plugins) referenced from the file is spawned and
its manifest is checked. Beyond the HCL pipeline it also runs a
schema-only pass that exercises every plugin-declared facet’s CEL
env and resolves every plugin endpoint’s `Family` against the
facet registry — catches authoring bugs (typo’d Family, invalid
identifier in a facet name, …) the operator’s HCL didn’t happen to
exercise. The success line names what loaded:

```
ok: gateway.hcl — 7 endpoints across 3 profile(s)
  plugin "example" v0.1: 2 facet(s), 1 credential type(s), 1 tunnel type(s), 3 endpoint type(s)
```

### `clawpatrol plugins`

Manage external plugins — download GitHub-sourced plugins, pin them in
`clawpatrol.lock.hcl`, and approve permission grants. The running gateway
only ever loads the locked version and never downloads on its own; these
are the explicit, reviewable steps.

```bash
clawpatrol plugins install <config.hcl> [name...]   # download + pin the locked version
clawpatrol plugins update  <config.hcl> [name...]   # re-pin to the newest matching release
clawpatrol plugins lock    <config.hcl> [name...]   # record every platform's binary hash
clawpatrol plugins info    <config.hcl> [name...]   # show required privileges (no download)
clawpatrol plugins approve <config.hcl> [name...]   # approve a pending permission escalation
```

`info` reads each GitHub plugin's signed static manifest — without
downloading the binary — and prints its types and the network / egress /
privileged grants it requests. `approve` records a plugin's requested
grants in the lockfile after a manifest escalation held it closed (a new
version that wants more than the lockfile recorded). Local (`./path`)
sources skip the download but still pin a binary hash. See
[Plugins](/docs/plugins/) for the `source` / `version` syntax and the
trust model.

### `clawpatrol status`

Report device install state — whether `join`/`login` ran, whether
the CA is trusted, whether the WG conf or tailnet membership is
healthy.

```bash
clawpatrol status
```

### `clawpatrol uninstall`

Tear down everything `join` / `login` put on this machine — stops
the macOS Network Extension, brings down the WG interface, removes
the CA from system trust, drops per-user state dirs, strips the
shell-rc.

```bash
clawpatrol uninstall [-y] [--keep-ca] [--keep-conf]
```

### `clawpatrol env`

Print the shell exports clawpatrol injects when wrapping a command
(`SSL_CERT_FILE`, credential-placeholder env vars). Source from
your shell rc if you need them outside `clawpatrol run`.

```bash
eval "$(clawpatrol env)"
```

### `clawpatrol version`

Print the version. Also accepts `-v` and `--version`.

## Environment variables

Most configuration lives in `gateway.hcl` on the gateway side. A few
device-side knobs:

| Variable | Effect |
|---|---|
| `CLAWPATROL_RUN_CONF` | Override the WG conf path `clawpatrol run` reads |
| `CLAWPATROL_DEBUG` | Print the relay / auto-expose diagnostic lines, which are otherwise silent |
| `CLAWPATROL_PLUGIN_LOG` | Raise the external-plugin subprocess log level (`trace`/`debug`/`info`/`warn`/`error`/`off`); at `trace`/`debug` surfaces a sandboxed plugin's own stderr, useful when a plugin dies before the handshake completes |
| `CLAWPATROL_NO_ENV` | Skip the env pushdown (`SSL_CERT_FILE`, placeholders) when wrapping a command. Competing credential variables are still removed (see [Agent credentials in the environment](#agent-credentials-in-the-environment)) |
| `CLAWPATROL_CLAUDE_OAUTH_SHIM` | `1` opts in to the Claude Code OAuth shim, which enables `/remote-control` when an Anthropic OAuth credential is bound (see [Agent credentials in the environment](#agent-credentials-in-the-environment)) |
| `CLAWPATROL_NO_SUDO` | Force the unprivileged user-namespace path even when passwordless `sudo` is available (see [Root and `sudo` inside `clawpatrol run`](#root-and-sudo-inside-clawpatrol-run-linux)); `sudo` won't work inside the wrapper |
| `CLAWPATROL_TELEMETRY` | `0` to disable telemetry (same as `DO_NOT_TRACK=1`) |
| `DO_NOT_TRACK` | Standard opt-out, honored |
| `TS_AUTHKEY` | Used by `clawpatrol login` to authenticate to Tailscale non-interactively |

## Data directories

Where state lives, by role:

**Gateway host** — the operator picks the location; nothing is
hardcoded. A typical layout under `/opt/clawpatrol/`:

```
gateway.hcl              HCL config (operator-edited)
state/clawpatrol.db      SQLite — everything else
```

`state_dir` in the HCL points at the sqlite directory. The DB holds
the CA cert + key, WireGuard server key, SSH host keys, sessions,
audit log, telemetry UUID, and DNS-VIP allocations.

**Device** (set up by `join` / `login`):

```
~/.clawpatrol/
  ca.crt                  Fetched gateway CA
~/.config/clawpatrol/
  wg.conf                 Per-device WireGuard config (join path)
```
