# Claude Code OAuth & `/remote-control` env pushdown

## Problem

`/remote-control` (and other OAuth-only Claude Code features) does not
work in Claude Code sessions launched through `clawpatrol run` when
clawpatrol provides credentials via `ANTHROPIC_AUTH_TOKEN` env
pushdown. Claude Code detects the session as bearer/API-token auth and
refuses to register a remote-control session — even though the
operator's gateway-stored credential is a full-scope claude.ai
subscription OAuth token.

## How Claude Code picks its auth mode

Claude Code resolves credentials in a fixed precedence order (highest
first):

1. Cloud provider creds (`CLAUDE_CODE_USE_BEDROCK` / `_VERTEX` / `_FOUNDRY`)
2. `ANTHROPIC_AUTH_TOKEN` → `Authorization: Bearer` (LLM-gateway/proxy mode)
3. `ANTHROPIC_API_KEY` → `x-api-key`
4. `apiKeyHelper` script output
5. `CLAUDE_CODE_OAUTH_TOKEN` (long-lived `claude setup-token`, inference-only)
6. Subscription OAuth from `/login` (Pro/Max/Team) — stored in
   `.credentials.json` under a `claudeAiOauth` object

Sources:
- <https://code.claude.com/docs/en/authentication>
- <https://code.claude.com/docs/en/remote-control.md>

Modes #2–#5 put Claude Code into "API-key/bearer auth", which the
`/remote-control` feature explicitly rejects. Only mode #6 (a stored
subscription OAuth credential carrying the `user:sessions:claude_code`
scope) is eligible.

## The gate is **local**, not upstream

Verified by inspecting the shipped Claude Code binary (v2.1.156). Two
facts matter:

1. The eligibility reason-builder returns, verbatim, when
   `process.env.ANTHROPIC_AUTH_TOKEN` is set:

   > Remote Control requires claude.ai subscription auth.
   > `ANTHROPIC_AUTH_TOKEN` is set, so this session is using API-key
   > auth — unset it (or run in a shell without it) to use Remote
   > Control.

   The same builder rejects `ANTHROPIC_API_KEY` and `apiKeyHelper`
   the same way.

2. The scope check reads `scopes` off the **local** `.credentials.json`
   (`claudeAiOauth.scopes`), not the upstream `Authorization` header,
   and looks for `user:sessions:claude_code`.

Because the gate fires before any network request, a gateway that
swaps the `Authorization` header at MITM time **cannot** satisfy it:
Claude Code bails locally. This rules out the "keep pushing
`ANTHROPIC_AUTH_TOKEN`, just grant the upstream OAuth scope" approach.

Related upstream issues (all confirm bearer/long-lived tokens are
inference-only and cannot do remote control):
- anthropics/claude-code#33105 — setup-token lacks `user:sessions:claude_code`
- anthropics/claude-code#35407 — `CLAUDE_CODE_OAUTH_TOKEN` not eligible
- anthropics/claude-code#48378 — Desktop-injected token breaks `/remote-control`

## What clawpatrol does

For SDK clients (Python, Node, the raw Anthropic SDKs) the
`anthropic_oauth_subscription` plugin keeps pushing
`ANTHROPIC_AUTH_TOKEN` — that's the shape those clients expect, and the
gateway rewrites the header upstream so the placeholder never reaches
Anthropic.

For the `claude` CLI, `clawpatrol run` can install a small shim
(`Shim`, `internal/config/plugins/agents/claude/shim.go`, run by
`prepareAgentEnv` in `cmd/clawpatrol/agent_env.go`) just before the
wrapped command starts. The shim and its notice apply to any
`clawpatrol run` whose environment received the Anthropic placeholder
(`ANTHROPIC_AUTH_TOKEN`, pushed by an `anthropic_oauth_subscription`
credential), not only to `clawpatrol run claude`: a wrapper such as
`clawpatrol run bash` can start Claude Code too. **It is opt-in** (R&D decision,
2026-06-03): rewriting the worker's environment and config dir is too
invasive to do silently — pointing `CLAUDE_CONFIG_DIR` at a
clawpatrol-managed dir shadows the worker's existing `~/.claude` (skills,
memory, MCP servers, project state), and writing into an operator's dir
touches files clawpatrol doesn't own. So by default the shim only prints
a notice telling the operator how to turn it on; it changes nothing.

Opt in per invocation:

```
CLAWPATROL_CLAUDE_OAUTH_SHIM=1 clawpatrol run claude ...
```

Once opted in, the shim:

- Synthesizes a `.credentials.json` in a `CLAUDE_CONFIG_DIR` with the
  `claudeAiOauth` shape Claude Code's `/login` writes — placeholder
  access/refresh tokens, a far-future `expiresAt` (so Claude Code never
  tries to refresh), and a `scopes` list including
  `user:sessions:claude_code`. The refresh token is a placeholder, so
  the agent cannot exchange it, and `console.anthropic.com` (the
  gateway's token endpoint) is a gated auth host that the gateway
  answers itself and never forwards.
- Strips `ANTHROPIC_AUTH_TOKEN` from the child's environment so
  Claude Code drops out of precedence #2 and falls through to
  subscription OAuth (#6).

To keep the worker's `~/.claude` (skills/memory/MCP) intact while opting
in, set `CLAUDE_CONFIG_DIR` to your own dir first — the shim writes into
it rather than carving out a managed one (see below).

The gateway still rewrites the `Authorization` header at MITM time
using the operator's gateway-stored OAuth bearer, so the placeholder
bytes never reach Anthropic. That bearer must itself carry
`user:sessions:claude_code` for the upstream session-register call to
succeed — which is why `AnthropicOAuthSubscription.OAuthFlow()` requests
that scope (operators who connected the credential before the scope was
added must re-run the dashboard OAuth flow once).

### Scoping & opt-in

- The shim is off unless `CLAWPATROL_CLAUDE_OAUTH_SHIM=1` is set. Without
  it, `clawpatrol run` prints a one-time notice explaining why
  `/remote-control` is disabled and how to enable it, and changes nothing.
- Even when opted in, it fires only when the gateway pushed the
  Anthropic placeholder into the environment, whatever binary is
  wrapped. `ANTHROPIC_AUTH_TOKEN` is stripped from every launch first,
  so the pushed placeholder is the only value it can hold. With the
  opt-in set, a wrapped launch such as `clawpatrol run python app.py`
  also loses `ANTHROPIC_AUTH_TOKEN` and gets `CLAUDE_CONFIG_DIR`
  pointed at the managed dir; an SDK client that needs the bearer
  should run without the opt-in.
- If the operator has set `CLAUDE_CONFIG_DIR`, the shim writes the
  synthesized credentials into that dir (so Claude Code keeps its
  settings/MCP/project state) instead of overriding it. A real
  `.credentials.json` already present there is left alone when it
  parses as JSON — dropping `ANTHROPIC_AUTH_TOKEN` lets that login win
  on its own. An empty or truncated file (for example, left by a failed
  earlier write) is rewritten with the placeholder credentials. A
  failed shim write aborts `clawpatrol run`.
- Otherwise the shim carves out a clawpatrol-managed dir
  (`~/.clawpatrol/claude-config`). Note this dir becomes Claude Code's
  whole config home for the session, so the worker's `~/.claude` skills,
  memory, and MCP servers are *not* visible — set `CLAUDE_CONFIG_DIR`
  yourself if you need them.

## Login paths the gateway answers

Claude Code's own login and refresh paths are declared as `AuthPaths`
in `internal/config/plugins/agents/claude/claude.go` and answered by
the gateway in the MITM request loop, before any credential is
resolved:

- `platform.claude.com` `/v1/oauth/` and `/oauth/`, and `claude.com`
  `/cai/oauth/` (Claude Code's login and refresh);
- the alias hosts of the same handlers: `claude.ai` `/v1/oauth/` and
  `/oauth/`, and `api.anthropic.com` `/v1/oauth/`;
- `/api/oauth/claude_cli/create_api_key` on `api.anthropic.com`,
  `platform.claude.com`, `claude.ai` and `claude.com`, so an agent
  cannot mint a permanent API key through the gateway's grant.

These get 403, and the connection is closed, on any connection the
gateway MITMs (an endpoint claims the host, or `unknown_host =
"inspect"`). `GET`/`HEAD platform.claude.com/v1/oauth/hello`, Claude
Code's first-run connectivity check, is answered locally with an empty
200 (the rule sits ahead of the `/v1/oauth/` prefix; first match wins);
it is never forwarded either. Docs and inference requests on these
hosts are forwarded as before.

Under the default `unknown_host = "passthrough"`, an unclaimed
`platform.claude.com` or `claude.com` is spliced, and these paths are
not gated: the gateway never sees them. Operators should claim the
Claude login hosts with an endpoint. Non-443 relays refuse TLS to any
of these hosts outright, because a relay sees no paths.

## Credential env vars `clawpatrol run` strips

Every `clawpatrol run` removes these Claude Code credential sources
from the child's environment, whatever binary is wrapped, before the
env pushdown (`Launcher.CompetingEnv` in `claude.go`, plus
`ANTHROPIC_API_KEY` from the generic list in
`cmd/clawpatrol/agent_env.go`):

`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`,
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

An operator who set one of these for another purpose loses it inside
`clawpatrol run`, including the Remote Control and background-session
names (`CLAUDE_BG_AUTH_SNAPSHOT_PATH`,
`CLAUDE_SESSION_INGRESS_TOKEN_FILE`, `CLAUDE_SECURESTORAGE_CONFIG_DIR`,
`CLAUDE_BRIDGE_OAUTH_TOKEN`) and the SDK profile and header names
(`ANTHROPIC_CONFIG_DIR`, `ANTHROPIC_PROFILE`,
`ANTHROPIC_CUSTOM_HEADERS`, …). The only value a stripped name can hold
afterwards is a gateway pushdown placeholder. The names deliberately
left alone are listed in `claudeDocumentedResiduals`
(`claude_test.go`) and in the operator docs
(`site/doc/security-model.md`, "Credential sources clawpatrol cannot
strip").

## Caveat: macOS Keychain

On macOS, an interactive `claude /login` stores credentials in the
Keychain rather than `.credentials.json`. The shim writes a file and
points `CLAUDE_CONFIG_DIR` at it, which Claude Code reads on all
platforms; clawpatrol's primary target (Linux workers) uses the file
store natively. macOS operators who rely on a pre-existing Keychain
login should simply leave the shim off (it is off by default) and rely on
that login.
