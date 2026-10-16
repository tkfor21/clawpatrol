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

For the `claude` CLI specifically, `clawpatrol run` can install a small
shim (`installClaudeCodeOAuthShim`, `cmd/clawpatrol/integrations.go`)
just before the wrapped command starts. **It is opt-in** (R&D decision,
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
  tries to refresh against the un-intercepted
  `console.anthropic.com`), and a `scopes` list including
  `user:sessions:claude_code`.
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
  it, `clawpatrol run claude` prints a one-time notice explaining why
  `/remote-control` is disabled and how to enable it, and changes nothing.
- Even when opted in, it only fires when the wrapped binary is `claude`
  and `ANTHROPIC_AUTH_TOKEN` is set. Non-claude clients are untouched.
- If the operator has set `CLAUDE_CONFIG_DIR`, the shim writes the
  synthesized credentials into that dir (so Claude Code keeps its
  settings/MCP/project state) instead of overriding it. A real
  `.credentials.json` already present there is left alone — dropping
  `ANTHROPIC_AUTH_TOKEN` lets that login win on its own.
- Otherwise the shim carves out a clawpatrol-managed dir
  (`~/.clawpatrol/claude-config`). Note this dir becomes Claude Code's
  whole config home for the session, so the worker's `~/.claude` skills,
  memory, and MCP servers are *not* visible — set `CLAUDE_CONFIG_DIR`
  yourself if you need them.

## Gateway opt-in: `remote_control` (worker token)

The shim gets Claude Code to *start* a remote-control session. Keeping
it up also needs the gateway's opt-in on the credential:

```hcl
credential "anthropic_oauth_subscription" "claude" {
  endpoint       = https.anthropic
  remote_control = true   # default false
}
```

Why: after `POST /v1/code/sessions/<id>` (OAuth), Claude Code calls
`POST /v1/code/sessions/<id>/bridge`, which returns a session-scoped
`worker_jwt`. Every later `/v1/code/sessions/<id>/worker…` call carries
that token, not the OAuth bearer. Without special handling, credential
injection would overwrite it and Anthropic would answer 403 (#25).

With `remote_control = true` (invariant I15, `cmd/clawpatrol/session_tokens.go`):

- The gateway forwards `/bridge` with its OAuth bearer and
  `Accept-Encoding: identity`, and rewrites the response: `worker_jwt`
  becomes a random placeholder (`clawpatrol-session-token-<32 hex>`).
  The real token stays in gateway memory, keyed to the agent device,
  profile, credential, host and session, for `expires_in` seconds (at
  most 24 h, at most 32 per owner). It never reaches the agent or the
  dashboard's stored records.
- On the canonical path `/v1/code/sessions/<id>/worker[/...]` of that
  same session, a request whose only `Authorization` header is exactly
  `Bearer <placeholder>` from the same owner gets the real token put
  back. Every other request, including a placeholder from another
  session or device, a non-canonical spelling of the path, or a token
  the agent supplies itself, gets ordinary OAuth injection, which the
  upstream refuses.
- The `/bridge` body is never forwarded as upstream bytes. A 2xx must
  be one JSON object with exactly one top-level string `worker_jwt`, a
  positive `expires_in` and no repeated top-level key; the agent gets a
  canonical re-encoding of the placeholder, `expires_in`,
  `api_base_url`, `worker_epoch` and `mcp_config` only (their values
  are still upstream content, re-encoded). A non-2xx keeps its status
  with its JSON body re-encoded; any other body is dropped. Status and
  headers are forwarded once they pass the checks below.
- A response that fails any of these checks is answered with 502 and
  not forwarded: an encoded body, one over 64 KiB, headers over 8 KiB
  per value or 32 KiB in all, invalid UTF-8 or a surrogate escape, or a
  header, trailer or forwarded string (any depth) that holds the token,
  anything JWT-shaped, or (for a non-2xx) the name `worker_jwt`. "Holds"
  covers the token raw, with whitespace removed, percent-encoded
  (lenient, up to three layers), base64 (standard or URL, any
  alignment, line-wrapped) or hex, and decoded base64/hex runs are
  checked again, JSON inside included. The scan has a work budget per
  response; running out counts as a failed check.
- These are checks for known spellings, not a proof. A token split
  across fields, re-encoded some other way (UTF-16, reversed, …) or
  otherwise transformed by the upstream is not detected.
- A `/bridge` whose credential is reconnected, revoked or cleared, or
  that sees a config reload, after the request arrived (a human
  approval wait included) is answered with 502 instead of issuing a
  placeholder.
- Requests whose target isn't a `/path` (an opaque `scheme:path`) are
  refused before any gate (see the MITM loop).

With it off (the default), the gateway answers `/bridge` itself with
403 in every spelling its matcher normalizes (escapes and up to three
decoding layers, case, dot segments, backslashes, matrix parameters,
fullwidth and zero-width characters, trailing junk on the last
segment), so no worker token
is minted through `/bridge` with the gateway's credential, and worker
paths get ordinary OAuth injection.

Placeholders are bound to the agent's device, not its process: in
`join` mode every process on a host shares one identity. Connecting,
reconnecting, revoking or clearing the credential retires its
placeholders (an OAuth refresh doesn't), and a config reload keeps them
only for credentials still opted in.

Not covered, in either mode: `claude remote-control` server/runner
mode, which gets its worker credential from
`/v1/environments/<id>/work/poll` and `/worker/register` instead of
`/bridge`. Those paths are forwarded with ordinary OAuth injection as
before this change; see the follow-up issue.

## Caveat: macOS Keychain

On macOS, an interactive `claude /login` stores credentials in the
Keychain rather than `.credentials.json`. The shim writes a file and
points `CLAUDE_CONFIG_DIR` at it, which Claude Code reads on all
platforms; clawpatrol's primary target (Linux workers) uses the file
store natively. macOS operators who rely on a pre-existing Keychain
login should simply leave the shim off (it is off by default) and rely on
that login.
