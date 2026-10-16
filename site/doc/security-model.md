# Security Model

Claw Patrol is a forward proxy that intercepts outbound traffic
(HTTPS, SSH, Postgres, …), injects credentials on behalf of the
agent, and enforces policy. The agent — an AI tool, a script, a
batch job, anything we won’t hand raw secrets to — sees the result
of the authenticated operation but never the credential.

This page describes how Claw Patrol stops a hostile agent from
reading injected credentials, using another agent’s credentials, or
reaching Claw Patrol’s own administrative surfaces.

The agent must not be able to:

- read any injected credential,
- use credentials assigned to a different agent,
- read Claw Patrol’s state files (SQLite DB, policy, registrations),
- modify the Claw Patrol binary,
- call Claw Patrol’s HTTP API or reach its dashboard.

Two deployment modes: **remote** (agent and Claw Patrol on
separate hosts, isolated by a network) and **local** (same host,
isolated by UNIX users). Remote is strictly stronger.

## Remote mode

Agent host and Claw Patrol host are separate. The agent host
initiates a WireGuard tunnel during onboarding; the tunnel stays
up for the life of the registration.

### Registration

Starts on the agent host, finishes with a human approving in the
Claw Patrol dashboard:

1. Agent host calls Claw Patrol with its public IPv4 + IPv6
   addresses.
2. Claw Patrol records them and issues a **join credential** —
   the only Claw-Patrol-issued secret the agent host ever holds.
3. Agent host brings up the WireGuard tunnel. Tunnel up,
   registration *unapproved*: zero traffic forwarded.
4. Operator approves in the dashboard and assigns one or more
   profiles. Traffic begins flowing.

A leaked registration endpoint is worthless on its own: no human
approval, no credentials, no traffic.

### What lives where

| Host | Holds |
|---|---|
| Agent host | The join credential. Nothing else of value to Claw Patrol. |
| Claw Patrol host | All injected credentials, the state DB, the policy, the dashboard, the HTTP API. |

Because injected credentials never reach the agent host, **the
agent can have root on its own host and still not compromise Claw
Patrol.** This is the strongest property remote mode buys you.

### Traffic flow

Per protocol:

- **HTTPS** — Claw Patrol terminates TLS with a local CA whose
  root was installed in the agent’s trust store at onboarding.
  Decrypted, the request is inspected, the credential injected,
  the request re-encrypted with the destination’s real cert, then
  forwarded.
- **SSH / Postgres / other authenticated protocols** — Claw Patrol
  completes the upstream authentication handshake with the real
  credential, then proxies the authenticated session back to the
  agent. The agent never participates in auth and never sees the
  credential.
- **Non-credentialled traffic** (public web, DNS) — forwarded
  unchanged, with one exception: UDP/443 (QUIC) is refused for every
  destination, because HTTP/3 cannot be inspected and would carry an
  intercepted host's traffic past its rules. The refusal is an ICMP
  port unreachable, so clients see a connection refused and fall back
  to TCP/443 immediately. The refusal is keyed on port 443 only: an
  `https` endpoint whose authority names another port (`host:8443`)
  is intercepted on TCP/8443, but UDP to that port is relayed like
  any other UDP, so an origin that advertises HTTP/3 on the same
  alternate port (an HTTPS DNS record with `alpn=h3`, or `Alt-Svc`
  on a connection the gateway does not terminate) could be reached
  over QUIC there without inspection.

Non-credentialled traffic is outside the security surface. If the
agent bypasses the tunnel, it gets the same internet it would have
without Claw Patrol — no credential leaks, just no protection.

`defaults.unknown_host` decides what happens to HTTPS whose SNI
matches no declared endpoint: `passthrough` (default) splices it
unchanged, `deny` hangs up at the ClientHello, and `inspect`
terminates TLS with the same local CA and runs the request through
the rules of a declared `endpoint "https" "unknown"`. Inspect is a
policy choice, not a credential path: no credential can be bound to
`https.unknown` (the compiler rejects it), so an inspected request
is always forwarded exactly as the agent sent it, and the agent's
traffic to every unmatched host becomes visible in the action log
and body captures. Connections the gateway cannot read as HTTP/1.1
over the minted certificate (no SNI, ECH outer names it cannot
serve, h2-only ALPN, non-HTTP protocols on 443) are closed.

### Agent login hosts

Coding agents that log in to a subscription account (Claude Code,
Codex, Grok Build) are logged in by the gateway, from the dashboard
(see [Credentials › Agent account logins](/docs/credentials/#agent-account-logins)).
The agent must not be able to log in, refresh, or mint a key by
itself, because the token it got back would be real and would never
pass through the gateway's control.

#### What is gated

Every provider auth host is answered by the gateway and never
forwarded, whatever `defaults.unknown_host` or an endpoint block says:

| Agent | Auth hosts |
|---|---|
| Claude Code | `console.anthropic.com` |
| Codex | `auth.openai.com` |
| Grok Build | `auth.x.ai`, `accounts.x.ai` |

The gateway terminates TLS for these hosts with its own CA and answers
each request itself: with 403 and the text "login for … is managed by
clawpatrol; connect it in the dashboard", or, for the one request
Codex needs to succeed (its agent-task registration), a fixed stub.
The first gated request from an agent adds a hint to the request log
that login moved to the dashboard. The gateway's own login and refresh
calls do not pass through this gate, so connecting and refreshing
credentials from the dashboard keeps working.

Claude Code also logs in on hosts it uses for documentation and
inference, so on those hosts only the login paths are gated:

- `platform.claude.com`: `/v1/oauth/` and `/oauth/`
- `claude.com`: `/cai/oauth/`
- `claude.ai`: `/v1/oauth/` and `/oauth/`
- `api.anthropic.com`: `/v1/oauth/`
- `/api/oauth/claude_cli/create_api_key` on `api.anthropic.com`,
  `platform.claude.com`, `claude.ai` and `claude.com`

A request on one of these paths is answered with 403 before any
credential is resolved, and the connection is closed after the
answer. There is one exception: `GET` or `HEAD
platform.claude.com/v1/oauth/hello`, Claude Code's first-run
connectivity check, is answered locally with an empty 200, and is
still never forwarded. The path is matched after decoding, cleaning
and lowercasing, so `/v1/../oauth/token`, `//oauth/token` and
`/OAuth/token` are gated too. Documentation and inference requests on
these hosts are forwarded as before.

#### Scope

- The host gate keys on the TLS SNI of connections the gateway handles
  as HTTPS: port 443, or a port an endpoint claims for interception.
- On every other port, the relay reads the agent's first TLS record
  and refuses a ClientHello whose SNI is a provider auth host,
  forwarding nothing. It reassembles a ClientHello split across TLS
  records, gates the second ClientHello after a HelloRetryRequest (and
  refuses one whose SNI changed), and refuses a TLS handshake it cannot
  parse rather than relaying it. A relay sees no request paths, so it
  also refuses TLS whose SNI is a host with login path rules
  (`platform.claude.com`, `claude.com`, `claude.ai`,
  `api.anthropic.com`) on any port other than 443, whole host and all.
  Reach those hosts on 443.
- A spliced 443 connection (`unknown_host = "passthrough"`) gets the
  same strict ClientHello check, so an auth host named only in a
  mixed or repeated `server_name` list, or only in the second
  ClientHello, is refused too.
- The relay does not see STARTTLS upgrades, and it cannot see the real
  SNI under Encrypted Client Hello, on any port. An agent that presents
  a false SNI under `unknown_host = "passthrough"` is not inspected;
  `inspect` or `deny` closes that.
- Login path rules apply only to connections the gateway already
  inspects: an endpoint claims the host, or `unknown_host =
  "inspect"`. Under the default `passthrough`, an unclaimed
  `platform.claude.com`, `claude.com`, `claude.ai` or
  `api.anthropic.com` is spliced and its login paths are not gated.
  Claim each of these hosts with an endpoint so their login paths are
  gated (`api.anthropic.com` is normally claimed already, by the
  endpoint that carries the Anthropic credential).

#### Signing in on a joined machine

The gate applies to all traffic the gateway handles, not only to
`clawpatrol run` children. On a `--whole-machine` device, a person
signing in to ChatGPT or Codex, the Anthropic Console, or xAI in a
browser on that machine gets the gateway's 403 page for those login
hosts, and Claude login pages on an inspected `platform.claude.com` or
`claude.com` get it too. Sign in from a machine that does not route
through the gateway, or connect the credential from the dashboard.

#### When a refresh is rejected

If the provider rejects the gateway's refresh of an agent login, the
dashboard marks the credential as needing re-authorization. Agent
requests then carry only the placeholder, and upstream answers 401
until someone reconnects the credential from the dashboard. The agent
is never given a way to log in again by itself.

#### Response secret scrub

On provider API hosts (`api.anthropic.com`, `chatgpt.com` and its
subdomains, `api.openai.com`, `cli-chat-proxy.grok.com`), and on any
host for a credential type an agent provider owns
(`anthropic_oauth_subscription`, `anthropic_manual_key`,
`openai_codex_oauth`, `grok_oauth`), the gateway replaces a real
secret it holds for that request with `clawpatrol-redacted-secret`
before the response reaches the agent. It scrubs response bodies, SSE
streams, WebSocket text messages and close, ping and pong payloads,
response header values, trailer values, and the WebSocket upgrade
response. To keep responses scannable it asks upstream for
uncompressed bodies and turns off WebSocket compression on these
connections. It decodes gzip, and answers 502 for any other
content encoding and for a non-WebSocket protocol switch. A compressed
WebSocket message that arrives anyway closes the connection. None of
those can be scanned, so none of them reach the agent.

Out of scope:

- binary WebSocket frames;
- encoded forms of a secret (base64, URL encoding, a secret split
  across header lines), and a secret used as a header name;
- secondary values shorter than 16 bytes (such as user names); the
  injected secret itself is scrubbed at any length;
- WebSocket frames a conforming client rejects (reserved opcodes, a
  fragmented control frame, an orphan continuation frame), which are
  forwarded unchanged and fail the client's connection.

A WebSocket text message over 16 MiB on a scrubbed connection closes
the connection rather than pass unscanned.

`llm_approver` no longer puts the judge's error body in the verdict
reason the agent sees. The reason reads `llm http <status>: judge
response withheld (see the gateway log)`, and the gateway log has the
body, with the values the judge call carried redacted.

#### Credential sources clawpatrol cannot strip

`clawpatrol run` removes the credential environment variables each
agent is known to read (listed in [CLI › Agent credentials in the
environment](/docs/cli/#agent-credentials-in-the-environment)), and
checks grok's config files before `clawpatrol run grok` (see
[CLI › `clawpatrol run grok`](/docs/cli/#clawpatrol-run-grok)). It
cannot reach every credential an agent reads. Keep the following
empty or unset on agent machines; if one holds a real credential, the
agent can use it without the gateway:

- **Claude Code files.** Claude Code's `apiKeyHelper` setting (a
  command that prints a key) and an `env` block in any of its settings
  files, including a project `.claude/settings*.json` the agent can
  write itself; its own login in `~/.claude`; and an Anthropic SDK
  profile in `~/.config/anthropic` (or `$XDG_CONFIG_HOME/anthropic`)
  holding a login. A base URL pointed at a credentialed relay already
  running on localhost bypasses the gateway the same way.
- **Codex files.** `~/.codex/auth.json`.
- **Grok files.** `~/.grok/auth.json` (a `grok login` made outside
  clawpatrol). Under `clawpatrol run`, grok's own login reads the
  managed store instead, but the file is still reachable: grok's local
  workspace feature (in builds that include it) reads
  `$GROK_HOME/auth.json` directly, whatever `GROK_AUTH_PATH` says, and
  the agent's shell tools can read it like any other file.
- **Codex variables without a pushdown.** `CODEX_ACCESS_TOKEN` and
  `CODEX_AGENT_IDENTITY` are not stripped. An `openai_codex_https`
  endpoint pushes its own values for them, which replace the shell's;
  with no such endpoint (or with `CLAWPATROL_NO_ENV=1`), a value set in
  the shell reaches codex. Keep them unset in the shell that runs
  `clawpatrol run`.
- **Claude Code variables that are not stripped.**
  `CLAUDE_CODE_HOST_CREDS_FILE`, `CLAUDE_CODE_HOST_AUTH_ENV_VAR` and
  `CLAUDE_CODE_HFI_BEARER_TOKEN`; keep them unset in the shell that
  runs `clawpatrol run`. These names are not model credentials and
  are left alone: `CLAUDE_TRUSTED_DEVICE_TOKEN`,
  `CCR_AGENT_PROXY_TOKEN_FILE_DESCRIPTOR`, `AGENT_PROXY_AUTH_TOKEN`,
  `CLAUDE_BG_SOCKET_TOKENS_PATH`, `CLAUDE_BG_RV_AUTH`,
  `CLAUDE_BG_PTY_AUTH`, `CLAUDE_BG_CLAIM_AUTH`,
  `ANTHROPIC_ENVIRONMENT_KEY`, `CLAUDE_CODE_MCP_SERVE_AUTH_TOKEN`,
  `CLAUDE_CODE_MEMORY_API_TOKEN`, `CLAUDE_CODE_MESSAGING_TOKEN`,
  `CLAUDE_CODE_SLACK_TAG_TOKEN`, `CLAUDE_CODE_ARTIFACTS_API_TOKEN`,
  `CLAUDE_CODE_CLIENT_KEY`, `CLAUDE_CODE_CLIENT_KEY_PASSPHRASE`,
  `CLAUDE_CODE_CUSTOM_OAUTH_URL`, `CLAUDE_CODE_OAUTH_CLIENT_ID`, and
  `CLAUDE_CODE_CLIENT_CERT` (the public half of the mTLS pair whose
  key, `CLAUDE_CODE_CLIENT_KEY`, is listed above). Names that only
  move a path or URL are left alone too: `CLAUDE_CONFIG_DIR`,
  `CLAUDE_CODE_MANAGED_SETTINGS_PATH`,
  `CLAUDE_CODE_REMOTE_SETTINGS_PATH`,
  `CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST`, `CLAUDE_CODE_API_BASE_URL`,
  `CLAUDE_BRIDGE_BASE_URL`, `CLAUDE_BRIDGE_SESSION_INGRESS_URL`,
  `CLAUDE_REMOTE_TOOLS_BRIDGE_URL`, `CLAUDE_CODE_GB_BASE_URL`, and the
  `CLAUDE_LOCAL_OAUTH_*` names, which current Claude Code builds do not
  read.
- **Claude Code on macOS.** When you set `CLAUDE_CONFIG_DIR` to a
  directory that already has a real Claude `/login` in the keychain,
  Claude Code uses that keychain token rather than the shim's
  placeholder file. Leave `CLAUDE_CONFIG_DIR` unset, or point it at a
  directory with no login, on agent machines.
- **Shared telemetry and proxy variables.** `OTEL_EXPORTER_OTLP_*`
  (your own collector's settings, read by Claude Code and grok alike),
  `HTTP_PROXY`, `HTTPS_PROXY` and `GROK_WEB_FETCH_PROXY` are not
  stripped. They carry no provider credential, and the agent's traffic
  still crosses the gateway.
- **grok, outside the preflight.** The preflight runs only when
  `clawpatrol run`'s wrapped binary is named exactly `grok` (the file
  name, case-sensitive). A wrapped launch (`clawpatrol run bash`) that
  later starts grok, `clawpatrol run GROK` on a case-insensitive
  volume, or a versioned binary name gets no preflight. When no
  `grok_oauth` credential is bound, or the pushdown is disabled with
  `CLAWPATROL_NO_ENV=1`, such a launch also gets no grok shim and no
  managed `GROK_AUTH_PATH`, so grok can use a login in
  `~/.grok/auth.json`.
- **grok config the preflight does not read.** Project
  `.grok/config.toml` files and macOS MDM requirements are not read.
  Campaigns that reach grok in a live settings fetch from
  `cli-chat-proxy.grok.com` are xAI's own and are not checked; only
  the on-disk settings cache is. The staged managed config
  (`$GROK_HOME/staged/managed_config_refresh.json`) is applied when
  grok starts, after the preflight; it is signed by xAI and is not
  checked.
- **grok keys the preflight allows.** A settings-cache
  `web_fetch_proxy` and a `[toolset.web_fetch] proxy_endpoint` route
  grok's web fetches and carry no credential. A models-cache
  `info.auth_scheme` only chooses whether grok sends its placeholder
  in `Authorization` or `x-api-key`.

The preflight reads `$GROK_HOME`, else `$HOME/.grok`. With both unset
or empty (a scrubbed environment such as `env -i` or a service unit),
it refuses to start grok rather than guess, because grok itself would
fall back to the home directory in the password database.

### Leaked join credential

The join credential can leak: from a backup, shell history, a
compromised process on the agent host. To bound the damage, Claw
Patrol pins each join credential to the **exact** IPv4/IPv6 pair
the agent host presented at registration. A request from a
deviating pair — different v4, different v6, or v6 on a host that
registered with v4 only — blocks the credential in the state DB
and tears down the tunnel. Restoring access takes explicit
re-approval.

Two caveats: IPv6 privacy extensions rotate the source address —
disable them or deploy a stable prefix scheme. And an attacker on
the same NAT shares the public v4, so pinning isn’t a standalone
defense; it’s a blast-radius limiter for credentials that have
already escaped.

## Local mode

Agent and Claw Patrol on the same host. No network between them,
so the boundary moves into the OS.

**Local mode is strictly weaker than remote.** In remote mode,
nothing on the agent host can hurt Claw Patrol. In local mode,
injected credentials sit on the same physical machine as the
agent, separated only by UNIX permissions.

### UNIX user separation

Two accounts:

- The **agent user** — the agent runs here, normally the primary
  interactive user on a desktop install.
- The **Claw Patrol user** — an unprivileged service account
  created at onboarding; the Claw Patrol process runs here.

The agent user can’t read the state DB (owned by the Claw Patrol
user), can’t replace the binary (owned by root or the Claw Patrol
user), and can’t read the dashboard’s access token. Recovering the
token uses `sudo clawpatrol get-token`, which requires a password
the agent can’t supply.

### Host preconditions

Two properties must hold; Claw Patrol can’t enforce them itself:

- The agent user is not root-equivalent.
- The agent user cannot use `sudo` without a password.

Passwordless `sudo` for the agent user defeats the entire model.

### Defense in depth

Claw Patrol’s proxy listener, HTTP API, and dashboard all bind to
loopback only in local mode. UNIX user separation is doing the
real work; loopback bind closes accidental network exposure.

### Pre-existing secrets on the host

A local install lands on a host that likely already contains
credentials the agent user can read — shell dotfiles, credential
helpers, cloud CLI configs, SSH keys. These are outside Claw
Patrol’s control. Onboarding offers to import recognized
credentials and delete the originals; anything not recognized or
not migrated stays readable to the agent.

### Secrets at rest

Everything the gateway needs across restarts lives in `state_dir`,
mostly in `clawpatrol.db`. That file holds, in plaintext: the MITM CA
private key, the WireGuard server key, OAuth access and refresh
tokens, and every credential value pasted into the dashboard. The
dashboard root password and per-device API tokens are stored as
hashes. There is no application-level encryption; file permissions
are the defense. The gateway creates `state_dir` mode `0700` and
warns at startup when it finds it looser.

Consequences for operators:

- Anyone who can read `state_dir` as the gateway user or root holds
  every injected credential and can mint certificates the agents
  trust. Run the gateway under a dedicated user with no other role.
- Backups, disk snapshots, and copies of `clawpatrol.db` are as
  sensitive as the live file. Encrypt them, or exclude the state
  directory and re-enter credentials after a restore.
- Full-disk encryption on the gateway host covers the stolen-disk
  case; it does not help against a process running as the gateway
  user.

Encrypting the sensitive columns with an operator-held key is a
possible future hardening; it would move the problem to where that
key lives rather than remove it, which is why it has not been
prioritized over the controls above.

## Dashboard and management API

Everything the agent must not reach — credential storage, profile
assignment, human-in-the-loop decisions, registration approval —
sits behind the dashboard’s HTTP API. Network reachability alone
must never grant access to it.

### App-layer auth, on every bind

The dashboard refuses to serve any management endpoint until an
operator credential has been established at the app layer. Network-
layer reachability is treated as cheap defense in depth, never as
the trust boundary. This is non-negotiable: an agent that finds
its way onto the same network as the gateway — including the
tailnet that the gateway joined — must still be denied.

Why we cannot rely on network reachability:

- `clawpatrol join` persists a Tailscale node identity (machine key
  + node key) under `~/.config/clawpatrol/tsnet-client/`. Anyone
  who can read that directory can stand up a tsnet server and
  rejoin the tailnet as the same peer, indefinitely.
- That tailnet peer can route to the gateway’s tailnet IP. Without
  app-layer auth, "I’m on the tailnet" would silently equal "I am
  an operator." It must not.

### Cross-site request forgery

The session cookie is `SameSite=Lax`, so a cross-site request never
carries it. That is not on its own a defense: without the cookie the
request falls through to the tailnet path, which attributes an
identity from the peer address of the connection — so stripping the
cookie is what routes a forged request onto the gate that does not
ask for one. A dedicated origin check therefore wraps both gates,
outside them, and refuses every non-GET request that a browser
reports as cross-site.

`Sec-Fetch-Site` rejects outright anything a browser reports as other
than same-origin. Beyond that, the request's `Origin` must identify
this dashboard, which either `public_url` or the request's own `Host`
can establish.

`public_url` is the operator's declaration of where the dashboard is
reached, so it holds for a deployment fronted by a proxy whatever
`Host` that proxy forwards; it declares a scheme too, so the scheme is
compared. Otherwise the `Origin` must equal the request's `Host` in
full, port included, and that `Host` must name something the gateway
serves the dashboard on: a loopback name, an IP literal, the
`public_url` host, the bind hostname, or the tsnet node's MagicDNS
name.

Comparisons are between canonical origins — scheme, host, and the port
with the scheme's default folded away — so `https://gw:443` and
`https://gw` are one origin while `https://gw:9999` is not. Matching
the port is what refuses a page the agent serves on another port of the
operator's own machine, the cheapest forgery available to it and one a
hostname-only comparison accepts. Requiring the `Host` to be one of the
gateway's own is what refuses a rebound name, which agrees with
`Origin` by construction; that is also why `Sec-Fetch-Site:
same-origin` is not sufficient alone, since a rebound page genuinely is
same-origin with the dashboard and reports itself that way.

On the `Host` half the scheme is compared whenever something proves
one. A TLS request cannot have been initiated by a plaintext page on
the same name, so `http://` is refused there. Failing that, a
`public_url` naming the same host is authoritative about that host's
scheme, which is what covers a proxy that terminates TLS and preserves
the external `Host` — the request reaches the gateway in plaintext, so
it proves nothing on its own. Only the scheme is pinned that way; the
same host on another port is still the dashboard.

A host with neither of those keeps both schemes, since a plain-HTTP
dashboard and a TLS-terminating proxy are indistinguishable at that
point. Anyone able to forge a page on the gateway's own name over
plaintext is already astride that same plaintext request and needs no
forgery.

`public_url` is read from the live configuration, so a hot reload that
retires or replaces it retires the origin with it.

Endpoints whose callers are not browsers are exempt, because they
send no origin headers and prove themselves per request instead:
credential webhooks under `/api/cred/` (a provider signature, such
as Slack's v0 HMAC), the HITL operation-status paths (a per-operation
token), and the device-flow handshakes `clawpatrol join` drives.

The login form is not among them. Its `POST` sets the root password on
a gateway that has none, so a cross-site submission would choose the
operator's password for them, and `SameSite=Lax` does not help because
first-run setup presents no cookie to withhold. `GET` still renders the
form for anyone.

Because the check does not apply to `GET`, a `GET` must not change
anything: `/api/tailscale/connect`, which starts a login and holds a
tunnel open past the response, is `POST`-only, and its polling
counterpart `/api/tailscale/status` reports a parked login URL without
force-acquiring anything.

### First-run root password

On a fresh install the dashboard has no operator yet. The first
request — from anywhere — is redirected to a "set password" form;
the chosen password becomes the bcrypt-hashed `root` row in
`clawpatrol.db`. Logging in with that password mints an opaque
session token, held in the `HttpOnly`, `SameSite=Lax` `cp_session`
cookie and stored only as a SHA-256 in `dashboard_sessions`;
subsequent requests are authenticated by that cookie.

The first-run window is benign by construction: the dashboard is
the only path that creates credentials / profile assignments /
HITL decisions, and all of those endpoints sit behind the same gate
the first-run flow protects. So no sensitive state can predate the
root password — losing the first-run race to an attacker means
they hold an empty dashboard. Recover with
`clawpatrol gateway --reset-dashboard-password`.

To skip the web first-run entirely, set the password from the CLI
before the dashboard ever serves a request:

```
clawpatrol gateway --set-dashboard-password '<pw>' gateway.hcl
```

### Tailnet operator allowlist (tailscale block)

When the `tailscale {}` block is declared the gateway can additionally
accept requests on the strength of a Tailscale whois identity, gated
by an explicit allowlist inside the same block:

```hcl
tailscale {
  authkey   = "{{secret:TS_AUTHKEY}}"
  operators = ["alice@example.com", "*@example.com"]
}
```

The gateway pulls the whois login directly off the tsnet socket
(`LocalClient.WhoIs`), so this is a kernel-attested per-peer
identity, not a forgeable header. Tagged devices — the shape
operators use for agent service accounts (`tag:cp-agent`) — return
their tag name from whois, not a user login, so a `*@example.com`
wildcard never matches an agent.

Allowlist auth composes with password auth: either gets a request
in. The first-run password is still mandatory, so an operator can
always fall back to it (and tests / break-glass paths don’t depend
on a working tailnet).

### Untagged-key prohibition

A subtle failure mode worth calling out: if the gateway ever minted
a Tailscale auth key with an empty `tags` list, the resulting node
would be "owner-associated" — whois on its requests would return
the OAuth client owner’s user login, not a tag. With
`tailscale { operators = ["*@example.com"] }` configured, that node
would silently match the allowlist and inherit operator powers.

The auth-key minting path
(`onboard.go` → `mintTailscaleAuthKey`) refuses to call Tailscale’s
create-key API with an empty tag list — it both defaults to
`tag:client` and errors out if the default is somehow stripped.
Treat the comment block at that call site as load-bearing.

### Out of band

`/api/onboard/{start,poll,claim}`, `/info`, `/ca.crt`, and the
plugin webhook prefix (`/api/cred/...`) are intentionally
reachable without the dashboard password — they carry their own
auth (signed onboarding handshake; webhook signature header) or
need to be reachable before any credential exists (CA fingerprint
fetch, fresh client onboarding). The full route table lives in
`web.go:routes()`; every other path is gated.

## Isolation between agents

One Claw Patrol instance can serve many agents, each with its own
credentials. A hostile agent must not be able to make Claw Patrol
inject credentials assigned to a different agent.

Claw Patrol enforces this by scoping injection to the originating
registration. Each registration is assigned one or more
**profiles**; each profile names a set of credentials. The
originating registration is identified from the channel the request
arrived on — the WireGuard peer (remote) or the authenticated local
channel (local) — not from anything the agent can claim. From there:

- Only credentials from the originating registration’s profiles can
  be injected.
- A request for a service whose credentials live only in another
  registration’s profile is treated like a request for a service
  Claw Patrol has no credentials for — forwarded without injection
  or rejected by policy, never signed with the wrong agent’s key.

Default-profile auto-assignment is a UX convenience for fresh
registrations; the security-relevant property is the scoping rule
above.

On a tailnet the registration is the device row, and the row is bound
to the node's control-plane StableID (`ts_node_id`) — not to its
hostname, which the node asserts itself and which the control plane
frees once the node is gone. A peer reaching the gateway from an
address its row does not carry is folded onto the row only through
that binding. The binding is recorded where the caller holds an
approval for the address (onboard claim, tsnet register) and where a
WhoIs names an unbound row's address among the node's own. Rows that
predate the column are bound at boot to the node the control plane
reports holding the row's address — the same node that is already
served the row's profile on that address — and rows no node holds are
logged so the operator can delete them.

## Plugins are untrusted

External plugins (`plugin "<name>" { source = "..." }`) extend the
gateway with new credential, endpoint, and tunnel types. They run as
subprocesses inside the gateway's process tree, and the gateway holds
the secrets a plugin must never reach: the state database (CA private
key, stored credential material), the WireGuard / Tailscale keys, and
the `CLAWPATROL_SECRET_*` environment variables. A planned
Terraform-style distribution mechanism would let operators fetch
plugins they did not write — so plugins are treated as a supply-chain
attack surface, not trusted gateway code.

Two mechanisms contain a malicious or compromised plugin:

- **Scrubbed environment.** A plugin inherits **none** of the
  gateway's environment — only `PATH`, `HOME` and `TMPDIR` (a private
  scratch dir) and its gateway socket path. This holds even with
  `sandbox = "off"`.
- **OS sandbox, on by default.** Every plugin runs inside an OS
  sandbox: Linux user/mount/pid (and, with `network = "none"`,
  network) namespaces over a deny-by-default mount tree; Landlock
  where unprivileged user namespaces are blocked; macOS seatbelt. The
  sandbox hides the filesystem (the plugin sees only its own binary,
  system libraries, and explicitly granted paths) and, by default,
  the network. If no sandbox can be established the plugin **fails to
  load** unless the operator explicitly sets `sandbox = "off"`. A plugin
  that genuinely cannot run sandboxed (it must exec helper tools and read
  the user's tool configs) can declare the **privileged** capability,
  which runs it unsandboxed — but, because that is full host access, the
  gateway holds it closed until the operator approves it explicitly (it
  is never trust-on-first-use), and an upgrade re-pends that approval.

Because the default `network = "none"` cuts a plugin off from the
network entirely, an endpoint plugin that receives credential secrets
(to inject them into an upstream request) cannot exfiltrate them: its
only channel is the gateway socket, and its upstream connections are
opened *by the gateway* through the [brokered
dial](plugins.md#brokered-upstream-dial), restricted to the targets the
endpoint's `hosts`/`dial` HCL or the plugin's manifest-declared egress
set sanctions and audited on every attempt. That egress set is recorded
trust-on-first-use like the network grant, and an upgrade that broadens
it fails closed until re-approved. Tunnel plugins keep the same posture:
they open their *own* transport (the socket to a SOCKS proxy, a bastion)
through the gateway's brokered transport dial, so they also default to
`network = "none"`. `outbound` is the exception, not the rule — only a
plugin that genuinely dials out itself (one that execs helper tools, or a
credential plugin doing its own token exchange) requests it, and that
grant is per-plugin, so it does not loosen the plugins beside it.

Network is **declared by the plugin** in its manifest and recorded,
trust-on-first-use, in a committed lockfile (`clawpatrol.lock.hcl`).
The threat this addresses is the supply-chain one: a benign plugin's
next version silently gaining a network leak path. An upgrade (a
changed binary hash) that requests more than the lockfile recorded
**fails config load** until an operator re-approves it — the loud,
reviewable moment a malicious update would otherwise slip through.
Because the lockfile is committed, the approval is also a diff in code
review. Filesystem and `sandbox = "off"` grants are never
plugin-declarable; they are operator-only and explicit (below).

For a GitHub-distributed plugin the declared capability comes from the
release's **signed static manifest** — verified (checksum + provenance)
before the binary is downloaded — so the gateway never runs the
unapproved binary to discover what it wants. When the binary then runs,
its manifest is cross-checked against that signed declaration and the
load **fails closed** if they disagree: the binary must do what its
published manifest claims. A local plugin, or a release that ships no
static manifest, falls back to reading the manifest from a throwaway,
network-denied probe spawn.

When a plugin's `source` is a GitHub repo, the same lockfile pins the
resolved release version and the binary's hash, and distribution is
gated three ways: the download must match the release's `SHA256SUMS`;
the binary's hash is trusted-on-first-use and re-checked (fail-closed)
on every later load; and, when the release carries a [GitHub
build-provenance attestation](plugins.md#verification-and-trust),
clawpatrol verifies through Sigstore that the binary was built by *that
repo's* Actions workflow — the `github.com/owner/repo` named in the
config is the trust anchor, closing the first-download gap. The
attestation also binds the binary to the source commit it was built
from, which the lockfile pins (`commit`) as an immutable reference; a
re-pointed tag whose attestation names a different commit is rejected.
Provenance is tracked trust-on-first-use like the network grant: the
lockfile records whether the pinned version was attested, and a binary
that loses provenance across a re-download or upgrade fails closed until
the operator re-approves it — the loud, reviewable moment a malicious
update that strips its attestation would otherwise slip through. The
per-plugin `provenance` field (`warn` default, `require`, `off`) sets
how a *first*, never-attested release is treated.
The gateway loads only the locked version and never upgrades on its own;
moving to a newer release is the operator's explicit `clawpatrol plugins
update`.

The sandbox is defense-in-depth, not a capability wall around the
gateway as a whole. The grants form a deliberate risk ladder:

- `network = "outbound"` is a bounded *leak path* — a network-enabled
  plugin can exfiltrate only the secrets it is actually handed,
  because the sandbox still confines its filesystem.
- `read_paths` is a *host read hole* — fine for inert files, but
  catastrophic when pointed at credential-bearing paths, so the
  gateway refuses any that overlaps the state dir (the secret store).
- There is **no host-write grant**. Host write is a
  code-execution-as-the-gateway-user primitive (plant a payload in
  `~/.bashrc`, cron, a `$PATH` dir; it runs later as the user, reads
  the state DB, and exfiltrates over the user's own network), and no
  denylist of active locations can be complete — so the only way to
  get host write is `sandbox = "off"`.
- `sandbox = "off"` is the single **full-trust** knob: full host read,
  write, and exec (the environment scrub still applies). A plugin run
  this way can read every credential in the state DB; use it only for
  plugins you fully trust.

Grant the minimum a plugin needs, and prefer the brokered dial over
`network = "outbound"` for anything that handles secrets.

## Egress interception is best-effort

Routing the agent’s traffic through the gateway is what lets Claw
Patrol inject credentials and apply policy — it is **not** a
containment wall, and intercepting every packet the agent emits is not
part of the guarantee. Per-process `clawpatrol run` confines the
wrapped process as well as the platform allows (a kernel network
namespace on Linux; a PPID-chain match in the macOS Network
Extension), but neither is airtight: on macOS an agent that detaches
from its session — double-fork + `setsid` to reparent under launchd —
no longer matches and egresses untunneled, and even the Linux
namespace can be left by an agent with enough privilege (passwordless
`sudo`). Whole-machine mode routes at the host level and sidesteps the
question.

This does not weaken the guarantee, because credentials and policy
share one chokepoint: traversing the gateway is what earns a request a
real credential *and* what subjects it to policy. A flow that escapes
interception is therefore *uncredentialed* — an anonymous client
holding only placeholders, with no access to any privileged system,
not a credentialed-but-unpoliced path. What this does **not** prevent
is a hostile process exfiltrating data it can already read locally,
over a side channel it opens outside the tunnel; if that is in your
threat model, use whole-machine mode or an external network egress
control.

The same holds for everything else on the client host. `clawpatrol
run` is not a sandbox: the wrapped process runs as your OS user and
can read whatever that user can read — files, the environment of the
shell it was launched from, other processes, keychains and credential
helpers. Apart from removing the credential environment variables
coding agents are known to read, and checking grok's config before
`clawpatrol run grok` (see [Credential sources clawpatrol cannot
strip](#credential-sources-clawpatrol-cannot-strip)), Claw Patrol does
not try to strip or hide any of that from the wrapped process, because
it could not do so reliably, and a partial measure would only suggest
a boundary that is not there. Keep real secrets out of the shell you
launch agents from; put them in the gateway, where the agent only ever
sees placeholders.

## Out of scope

Claw Patrol does not defend against:

- physical access to the Claw Patrol host;
- compromise of the Claw Patrol host or user — any attacker with
  those privileges holds every injected credential;
- a kernel or hypervisor compromise that bypasses UNIX user
  separation;
- supply-chain compromise of the binary or its build toolchain;
- cross-user side channels (shared-CPU timing, etc.);
- exfiltration of locally-readable data by a process that bypasses
  per-process egress interception (see [Egress interception is
  best-effort](#egress-interception-is-best-effort));
- anything the wrapped process's OS user can already read on the
  client host, including secrets in the launching shell's environment
  (`clawpatrol run` is not a sandbox).
