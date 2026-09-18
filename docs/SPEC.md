# Safe Router — v0 Specification

Status: **PHASE 0 ACCEPTED 2026-08-13.** Written 2026-08-14.

Derived from a research pass on LLM-router threat literature and an independent
skeptical review (`safe_router_design_review.md`, repo root). Where this spec departs
from that review, the departure is marked and reasoned.

---

## 1. What this is

A headless single-user daemon on macOS that accepts OpenAI-compatible inference
requests from local clients and dispatches them to local or remote model
backends according to a static policy bound to the requesting client's key.

**Why it exists, in one sentence:** so that a designated set of clients on this
machine can be *structurally* incapable of sending their traffic to a
third-party inference provider, while the remaining clients get consolidated key
custody, uniform cost logging, and declared multi-provider failover.

### What it is not

- Not a gateway. No multi-tenancy, no teams, no user management, no admin
  surface. Every one of those features is a CVE class this project exists to
  not have.
- Not a router in the "intelligently pick the best model" sense. Selection is
  deterministic and policy-bound. There is no classifier and no learned
  component anywhere in the request path.
- Not a defense against local code execution. See §3.

---

## 2. The invariant

> **Traffic presented under a safe-plane key is served by a local backend or it
> is not served at all.**

Everything in this document is either that sentence, a mechanism enforcing it,
or an explicitly-scoped exception to it.

## 3. The boundary — what this does NOT protect

Stating this precisely is what makes the in-scope claim honest. The invariant
covers **the inference hop only.**

- **Upstream is out of scope.** Anything arriving via a channel that already
  transited a third party (a chat gateway, email, a hosted webhook) was exposed
  before the router saw its first byte. Each such channel is an accepted risk
  that gets recorded per deployment, with its content profile and the change
  that would force a rethink — a channel described as "mostly non-sensitive" is
  exactly the scope that erodes the first time someone pastes a document into a
  thread. Instances live in the operator's `docs/DEPLOYMENT.md` (§11), not in
  this spec. Audit every inbound channel on the same terms before adding it.
- **Downstream is out of scope.** The router cannot stop a client from leaking
  what it *receives*. A compromised MCP server or agent tool holding a
  legitimate safe-plane key gets the model's answer and can relay it anywhere it
  has its own connectivity. The guarantee is "traffic through me obeys the
  floor," not "this machine does not leak."
- **Local code execution defeats this by definition.** Anything running as your
  user — a hostile npm postinstall, a malicious dependency — does not need to
  attack the router. It can read configs, or simply call a provider API directly
  with its own key. The router's only obligations against local malware are:
  don't make it worse (no plaintext key files, Keychain-only, signed binary),
  and leave usable forensics.
- **Model provenance is unverifiable.** No provider cryptographically binds a
  response to the model that produced it. v0 logs requested-vs-returned `model`
  and counts mismatches; the safe plane additionally refuses to relay a
  response whose *reported* model is off-allowlist (matrix row 12). That is
  enforcement on an honest signal — detection, not provenance — and it is the
  ceiling until provider attestation exists.
- **(Amended 2026-08-14) Tailnet bind adds a dependency the loopback
  deployment did not have.** With `[server] bind` on a `100.64.0.0/10`
  address, the guarantee now also rests on **Tailscale's ACLs and on every
  tailnet peer being trusted.** A compromised tailnet device holding a valid
  safe-plane key is inside the boundary — the router cannot tell a
  legitimate Mac Mini client from a compromised one on the same tailnet;
  both present the same bearer key over the same transport. *Accepted risk,
  mitigations required, not optional:* a Tailscale ACL restricting
  `:8787`/`:8788` to named devices, and LM Studio bound to loopback on
  **every** tailnet node, not only the router's own machine. Both recorded
  in `docs/DEPLOYMENT.md` and re-verified per Step 1 of PLAN.md.

---

## 4. Architecture

### 4.1 Split-plane

Two processes, one binary, two configs.

| | Safe plane | Escalation plane |
|---|---|---|
| Binds | `127.0.0.1:8787` | `127.0.0.1:8788` |
| Backends | local only | remote (+ local, optional) |
| Provider credentials | **none in config, none in Keychain scope** | Keychain, restricted to the signed binary |
| Keys served | safe-plane keys only | escalation keys only |
| Failure of policy logic | cannot reach a remote provider — there is no credential and no backend defined | worst case: wrong remote provider |

This is the load-bearing decision. It converts "no path degrades into a remote
call" from a code-correctness claim into a process-property claim: a policy bug
in the safe plane cannot spend credentials that do not exist in its address
space.

It also produces the auditable artifact that matters commercially — *"here is
the entire config of the process your data talks to; observe that it contains no
remote anything."*

**Startup validation:** the loader refuses to start if any key hash appears in
both planes' configs, or if the safe plane's config contains any backend whose
transport is not loopback/tailnet-local.

**(Amended 2026-08-14) "Tailnet-local," precisely:** a literal IPv4 address in
`100.64.0.0/10` (Tailscale's CGNAT range). **MagicDNS names (`*.ts.net`) are
not accepted as a safe-plane backend `base_url`** — a name resolves wherever
DNS says it does at request time, which turns a structural, config-time check
into a trust-the-resolver check at every request. Names are accepted only on
the *inbound* side (`[server] allowed_hosts`), where an incoming `Host` header
is compared against the configured string, never resolved.

*Later hardening, not v0:* run the safe plane as a dedicated UNIX user with a PF
egress rule permitting loopback only.

### 4.2 Request path

```
client ──bearer key──▶ [admission] ──▶ [route resolution] ──▶ backend
                            │                                    │
                            │                              response bytes
                            ▼                                    │
                      metadata log  ◀────────────────────────────┘
```

Admission is the only security-relevant decision and it happens **before the
first upstream byte**, using only: the bearer key, the `model` field, `stream`,
and whether `tools` is present. The body is otherwise not interpreted.

### 4.3 What the daemon is made of

Rust. tokio + axum/hyper, rustls, serde. No GUI, no WebView, no npm. A dashboard,
if it ever exists, is a separate process with read-only access to the log
(see §8).

---

## 5. Policy model

### 5.1 Keys are policy identity, not authentication

Every OpenAI-compatible client already sends a bearer key, which makes this the
only classification mechanism that requires zero cooperation from clients.
Policy binds to the key. There is no content inspection anywhere in the
admission path — nothing an attacker writes inside a prompt can influence where
that prompt is sent.

Keys are stored as argon2id hashes. Comparison is constant-time. The plaintext
key exists only at issuance, when it is written into one client's config.

### 5.2 Route aliases and the substitution rule

A client may name either:

- **a concrete model id** — served by that model or the request errors. No
  substitution under any circumstance.
- **a route alias** — a named, ordered chain. Naming the alias *is* the
  client's consent to substitution within that chain.

This is how declared multi-provider failover coexists with invariant #6. The
response always reports the model that actually served, and the log records
which rung of the chain answered.

**Chains never cross planes.** A chain is resolved entirely within one plane's
config. There is no chain that begins local and ends remote — that shape cannot
be expressed in the config schema.

### 5.3 Config schema

`~/.safe-router/safe.toml`

```toml
# The safe plane. Note what is absent: no [provider] block, no credentials,
# no remote backend. That absence IS the guarantee.

[server]
bind = "127.0.0.1:8787"
plane = "safe"

[[backend]]
id       = "lmstudio-local"
base_url = "http://127.0.0.1:1234/v1"
dialect  = "openai"

[[route]]
name  = "local-workhorse"
chain = ["lmstudio-local/llama-3.3-70b"]

[[key]]
id      = "hermes-client-work"
hash    = "$argon2id$v=19$..."
allow   = ["local-workhorse", "lmstudio-local/qwen2.5-72b"]
# Dense models only for agentic clients. MoE safety alignment is brittle under
# routing manipulation (arXiv 2602.04448, 2602.08621) — see §10.
```

`~/.safe-router/escalation.toml`

```toml
[server]
bind  = "127.0.0.1:8788"
plane = "escalation"

[[provider]]
id            = "openai"
base_url      = "https://api.openai.com/v1"
dialect       = "openai"          # native; Anthropic joins in v1 via Messages dialect
keychain_item = "safe-router/openai"

[[provider]]
id            = "qwen"
base_url      = "https://..."
dialect       = "openai"
keychain_item = "safe-router/qwen"

[[provider]]
id            = "moonshot"
base_url      = "https://..."
dialect       = "openai"
keychain_item = "safe-router/moonshot"

[[route]]
name     = "frontier"
chain    = ["openai/gpt-5"]
on_error = "fail"                 # single rung; named model semantics

[[route]]
name     = "frontier-cheap"
chain    = ["qwen/qwen3.8-max", "moonshot/kimi-k3"]
on_error = "next"                 # substitution in scope — the alias says so
# NOT client-adjacent. Both are non-US providers; data-residency tier 3.
# See §10, "provider tiering".

[[key]]
id    = "claude-code"
hash  = "$argon2id$v=19$..."
allow = ["frontier", "frontier-cheap"]
```

### 5.4 Provider tiering

Three rungs, not two. The tier is a property of the provider and constrains
which keys may reach it:

1. **local** — LM Studio on this machine (v1: on the tailnet).
2. **remote first-party** — the model vendor's own API, with retention controls
   where offered. The only remote tier permitted for client-adjacent work.
3. **remote aggregator / non-domestic** — OpenRouter, Kie.ai, and non-US
   frontier providers. Personal and experimental traffic only. Never
   client-adjacent, even when the specific request is non-sensitive.

Rung 3 exists because an aggregator is precisely the unaccountable intermediary
this project's source literature measures; routing client-adjacent traffic there
partially undoes the premise.

### 5.5 Key hygiene

The residual problem after keys-as-policy is not classification — it is custody.

- **One key per client**, named for the client. Never share a key across two
  clients; the log's `key_id` is the only attribution you get.
- **Default-deny issuance.** A new key is safe-plane until explicitly promoted.
  Promotion is a config edit with a comment stating why.
- **Escalation-capable keys are few and individually named.** If the list grows
  past what you can recite from memory, something has gone wrong.
- **Plaintext exists once**, at issuance. It goes into exactly one client
  config. It is never stored in this repo, in notes, or in a password manager
  shared with anything else.
- **Rotation triggers:** suspected client compromise, contractor offboarding,
  any key pasted into the wrong config, and a standing quarterly pass.
- **The failure mode to fear is human:** pasting an escalation-capable key into
  a client that handles client work. Nothing in the system can catch this.
  Mitigate by keeping escalation keys few, named, and obviously distinct in
  their prefix.

### 5.6 Multi-account failover (same provider) *(Added 2026-09-04)*

`ProviderConfig` never required `base_url` uniqueness across `[[provider]]`
entries. Two entries may point at the same provider's `base_url` with
different `id` and different `keychain_item` — each names a distinct
Keychain-sourced credential, i.e. a distinct account. This is not new schema;
it is an existing degree of freedom, documented here so it is a sanctioned
pattern rather than a rediscovered one.

Chain accounts like any other multi-rung route:

```toml
[[provider]]
id            = "openai-work"
base_url      = "https://api.openai.com/v1"
dialect       = "openai"
keychain_item = "safe-router/openai-work"

[[provider]]
id            = "openai-personal"
base_url      = "https://api.openai.com/v1"
dialect       = "openai"
keychain_item = "safe-router/openai-personal"

[[route]]
name     = "frontier"
chain    = ["openai-work/gpt-5", "openai-personal/gpt-5"]
on_error = "next"
```

Matrix row 5 (§6) already implements "keep working after one account is
rate-limited" — 429/5xx/connect-fail advances one rung, same as any other
chain. No new dispatch logic. Naming convention: suffix the provider `id`
with the account label so `backend` stays attributable per §8's log schema.

**Explicit non-features — this amendment covers failover only:**

- **No cross-plane or cross-dialect account chains.** Same restriction as any
  other chain (§5.2, matrix row 21): rungs resolve within one plane's config,
  one dialect.
- **No rate-limit remaining/reset tracking or display.** Nothing in the
  router parses response headers today; a "reset countdown" feature would
  need its own amendment, since it requires reading response headers the
  router currently never inspects (§4.2, §7).
- **No usage-aware account selection.** Chain order is static and
  operator-set. The router never picks a rung based on observed quota state —
  that would be adequacy/cascade logic in the router, a permanent non-goal
  (§9).

**Reason:** raised 2026-09-04 comparing against a competitor's per-account
rate-limit hot-swap feature. Verified the failover half is already
expressible with zero code or schema changes via existing `[[provider]]` +
`[[route]] on_error = "next"` (src/policy.rs `ProviderConfig`/`RouteConfig`;
src/proxy.rs `is_retryable_status`). The visibility half (remaining/reset
display) is explicitly NOT covered by this amendment and remains unbuilt.

---

## 6. The one rule, and the failure matrix

> **Every failure is terminal within the tier the key authorizes. The router
> never re-dispatches across the local→remote boundary for any reason — not on
> error, not on timeout, not on overflow, not on quota. Escalation exists only
> as a fresh client request under an escalation-capable key. Silent model
> substitution never happens in any direction.**

Everything below is that rule applied. **This table is the v0 integration test
list — one named test per row.**

| # | Failure mode | Required behavior |
|---|---|---|
| 1 | Local backend down / connection refused | 502, well-formed OpenAI error JSON. No fallback, no retry elsewhere. |
| 2 | Requested model unknown / not loaded | Surface the backend error verbatim. Alias resolution is a static map; aliases never cross tiers. |
| 3 | Context overflow on a local model | Pass the 400 through. **Never retry on a larger remote model.** Most tempting violation in the system. |
| 4 | Stream stalls mid-generation (idle timeout) | Terminate the SSE with a proper error event. No re-dispatch. |
| 5 | Remote 429 / quota / 5xx on an escalated request | If the route is an alias with `on_error = "next"`, advance one rung and log `chain_pos`. Otherwise pass through. **Never downgrade to local.** |
| 6 | Router crash mid-stream | Client sees a dropped connection. On restart: no replay, no persisted request state. |
| 7 | Config invalid at startup | **Refuse to start.** Never start with defaults — a default is a policy you didn't write. |
| 8 | Config reload (SIGHUP) invalid | Keep the old config. Log loudly. Set a degraded flag. |
| 9 | Unknown or revoked key | 401. Constant-time compare. No detail about which part failed. |
| 10 | Safe-plane key requests a remote model or alias | 403 with a **distinct machine-readable code**. Agent clients loop on ambiguous errors; a policy denial must read as permanent. |
| 11 | Log write failure / disk full | Traffic continues, buffer in memory, set a visible degraded flag. Availability beats log completeness for one user — and the transparency claim is weakened while this flag is set. |
| 12 | Reported `model` ≠ resolved target / outside key's allowlist | **Safe plane: terminal.** Non-streaming → 502 with a distinct code, body discarded. Streaming → inspect the first chunk's `model` before forwarding any bytes; on mismatch, error event and terminate. Log + mismatch counter either way. **Escalation plane: pass through, log, count** — detection only. *(Amended 2026-08-13: safe plane was pass-and-log; fail closed is the plane's entire premise, so a response reported from an off-allowlist model must not be relayed. Enforcement on an honest signal — provenance itself stays unverifiable, §3.)* *(Amended 2026-08-14: byte shape differs per dialect, semantics unchanged. OpenAI non-streaming/streaming per above, rows 12a/12b. Anthropic Messages non-streaming → top-level `"model"` in the response object, same `model_from_json_object` path (row 12c). Anthropic streaming → the model is nested at `message.model` inside the first SSE event, `message_start` (row 12d); the terminal error event on mismatch is Anthropic-shaped, not the OpenAI-shaped constant, same for the idle-timeout event of row 4 on this route.)* |
| 13 | TLS / certificate failure to a remote backend | Fail closed. No plaintext retry. No pinning-bypass flag exists. |
| 14 | Client disconnects mid-request | Cancel the upstream request. Log partial usage. |
| 15 | Cross-plane confusion | Safe plane receives an escalation request → 403. Escalation plane receives a safe-plane key → 401, because that key does not exist there. That is the point of the split. |
| 16 | Same key hash present in both plane configs | Startup validation failure. Refuse to start (both planes). |
| 17 | Inbound `Host` not loopback and not in `allowed_hosts` | 403 `policy_bad_host`, logged as `denied_auth`. Comparison only — the router never resolves a name to decide this. *(2026-08-14)* |
| 18 | `[server] bind` is `0.0.0.0`, LAN, or public | **Refuse to start.** Distinct message naming the offending address. *(2026-08-14)* |
| 19 | Safe-plane backend `base_url` on the tailnet vs on the LAN | `100.64.0.0/10` literal accepted; LAN, public, and `*.ts.net` names refused at startup. *(2026-08-14)* |
| 20 | `/v1/messages` resolves to an openai-dialect chain (or `/v1/chat/completions` to an anthropic one) | 403 `policy_dialect_mismatch`, before any upstream byte. Permanent-reading, same as row 10. *(2026-08-14)* |
| 21 | A route chain whose rungs span two dialects | **Refuse to start.** Advancing a rung must never change wire protocol mid-request. *(2026-08-14)* |
| 22 | Client sends `x-api-key` / `Authorization` to `/v1/messages` | Consumed by the router as its own key; never forwarded upstream (invariant #9). Upstream sees only the Keychain-sourced provider credential. *(2026-08-14)* |
| 23 | Daemon restart mid-log | Chain continues across the restart: the first post-restart row's `prev_hash` equals the last pre-restart row's `row_hash`. *(2026-08-14)* |
| 24 | A row is edited directly in the DB | `verify-log` names the first divergent row and exits non-zero; `anchor` refuses to publish a head over a broken chain. *(2026-08-14)* |
| 25 | Log-write failure period (row 11) then recovery | Buffered rows never enter the chain. The chain stays internally valid across the gap; the gap itself is visible (degraded flag + `id` discontinuity), never papered over. *(2026-08-14)* |

---

## 7. Protocol scope

v0 speaks **one inbound dialect**: OpenAI chat completions.

- Endpoints: `POST /v1/chat/completions`, `GET /v1/models`.
- Backends must speak it natively. No translation layer exists in v0 and none is
  planned for v1.
- The router parses the request body only for admission (§4.2). Response bytes
  stream through byte-for-byte.
- **Token counting is not a policy input.** It requires per-model tokenizers,
  drifts with model versions, and buys nothing that `max_tokens` + tools-presence
  + key identity don't already provide. Cut.
- **Claude Code stays pointed directly at Anthropic in v0.** It is the least
  sensitive client, already frontier-bound by nature, and it speaks Anthropic
  Messages. It joins in v1 via a second *passthrough* dialect (Messages in →
  Anthropic out, bytes through, admission at the front) — the same trick, not a
  translation.
- **Cross-dialect translation is a permanent non-goal.** Per-dialect passthrough
  scales linearly; translation scales combinatorially. This is the attrition
  death predicted for this project, and everything of security value survives
  without it.

### 7.1 Second inbound dialect: Anthropic Messages *(added 2026-08-14)*

v1 adds **`POST /v1/messages`** on the escalation plane, passthrough only —
the same trick as §7's OpenAI dialect, not a translation layer. Admission
reads the same four facts (bearer key, `model`, `stream`, presence of
`tools`) from Anthropic's body, which uses the same field names; the
admission middleware itself stays dialect-unaware.

- **Endpoints covered:** `POST /v1/messages` only. `GET /v1/models` is
  unchanged (first configured backend/provider for the plane), with
  credentials attached in that target's dialect style.
- **Explicitly not covered, this phase or any future one without a written
  amendment:** `/v1/messages/count_tokens`, `/v1/messages/batches`, the
  Files API. Token counting as a policy input remains cut (§7); batching and
  file upload are surface this router has no reason to intermediate.
- **Inbound key extraction widens for this route only.** Claude Code sends
  the router's key as `x-api-key` (when configured via `ANTHROPIC_API_KEY`)
  or `Authorization: Bearer` (via `ANTHROPIC_AUTH_TOKEN`). Either is accepted
  as the router's own key; whichever header it arrives in, it is consumed by
  the router and never forwarded upstream (invariant #9, matrix row 22).
- **A route chain must not mix dialects** (matrix row 21): all rungs of a
  chain resolve to backends/providers of the same dialect, or the daemon
  refuses to start. **The inbound endpoint's dialect must match the resolved
  chain's dialect** (matrix row 20): `/v1/messages` → anthropic rungs only,
  `/v1/chat/completions` → openai rungs only. Mismatch is 403
  `policy_dialect_mismatch`, before any upstream byte.
- **Outbound auth is derived from the provider's dialect**, not hardcoded
  per-route: `openai` → `Authorization: Bearer <secret>` (unchanged);
  `anthropic` → `x-api-key: <secret>` plus `anthropic-version` (forwarded
  verbatim from the client when present, defaulted otherwise) and
  `anthropic-beta` (forwarded verbatim when present). That is the entire
  forwarded-header allowlist for this dialect — no general header
  passthrough, and the client's own `Authorization`/`x-api-key` is never
  among the forwarded set.
- **Error envelope:** `/v1/messages` errors render Anthropic-shaped —
  `{"type":"error","error":{"type":<anthropic type>,"message":<msg>,
  "router_code":<our code>}}`. Anthropic's `type` values are a fixed set
  clients switch on, so the router's own machine-readable code rides
  alongside in `router_code` rather than displacing it. The codes themselves
  are unchanged and shared across dialects — one `ApiError`, two renderers.
- Row 12's model-mismatch behavior applies unchanged to this dialect; see
  the dialect note on row 12 in §6.

---

## 8. The metadata log — and the Logic Loop interface

Append-only SQLite at `~/.safe-router/log.db`. **Metadata only. No prompt or
response content**, ever, for safe-plane keys — both because a plaintext prompt
log is a liability the hosted alternative didn't hand you, and because client
data obligations may include deletion, which hashed metadata survives and stored
prompts do not.

```sql
CREATE TABLE requests (
  id           INTEGER PRIMARY KEY,
  ts           TEXT    NOT NULL,   -- RFC3339 UTC
  plane        TEXT    NOT NULL,   -- 'safe' | 'escalation'
  key_id       TEXT    NOT NULL,   -- client identity; never the key or its hash
  route        TEXT,               -- alias requested, NULL if a concrete model
  model_req    TEXT    NOT NULL,
  model_served TEXT,               -- as reported by the backend; NULL on failure
  backend      TEXT,
  chain_pos    INTEGER,            -- which rung of an alias chain served
  disposition  TEXT    NOT NULL,   -- served|denied_policy|denied_auth|backend_error|client_cancel
  status       INTEGER,            -- HTTP status returned to the client
  err_code     TEXT,
  tokens_in    INTEGER,
  tokens_out   INTEGER,
  latency_ms   INTEGER,
  stream       INTEGER NOT NULL,   -- 0/1
  tools        INTEGER NOT NULL,   -- 0/1, request carried tool definitions
  mismatch     INTEGER NOT NULL,   -- model_served != model_req outside an alias
  client_tag   TEXT,               -- opaque passthrough of X-Safe-Router-Tag
  prev_hash    TEXT,               -- (added 2026-08-14) chain: prior row's row_hash
  row_hash     TEXT                -- (added 2026-08-14) sha256(prev_hash || "\n" || canonical_fields)
);
```

**(Added 2026-08-14)** Existing `log.db` files migrate via idempotent
`ALTER TABLE ADD COLUMN`, guarded by `PRAGMA user_version` (0 → 1).
Pre-migration rows keep NULL hashes; the chain starts at the first
post-migration row — a documented, verifiable starting point beats
back-filling hashes over rows nobody chained. `canonical_fields` joins the
row's columns in fixed schema order with a separator that cannot appear in a
value (NUL bytes; `client_tag` already rejects control characters, §8.1).
Computed inside the same write transaction that inserts the row, under the
log's single writer — a property that was already true (§4.3) and must stay
true for the chain's ordering to mean anything.

**Observability amendment (2026-09-13, explicitly requested by the user).**
The router may read bounded metadata from the two supported response dialects
to fill the existing nullable `tokens_in`/`tokens_out` fields: OpenAI chat
completions `usage.prompt_tokens`/`completion_tokens`, and Anthropic Messages
`usage.input_tokens`/`output_tokens`. For SSE it observes complete bounded
events after the response's existing model gate; it forwards the original
bytes unchanged and never persists content. It does not alter requests to
solicit usage. Missing or malformed counters remain NULL, while a reported
zero is 0. This is logging only, never policy or tokenization. `v_requests_v1`
is frozen; `v_requests_v2` adds a derived `usage_state` describing recorded
counter completeness, with a transactional `PRAGMA user_version` 1 → 2 view
migration. No table field, canonical hash input, or anchor changes. Reason:
the existing v1 view is independently useful, but its implementation omitted
Anthropic and streaming usage, making a consumer misread unknown values as
zero. No provider rate-limit reset or account-switch semantics are added;
those require a separate provider-specific contract and, for header
inspection, a further explicit amendment to §4.2/§7. Static on-error
failover remains the only account failover behavior.

### 8.1 `client_tag` — why it's here

*(Amended 2026-08-13: generalized from `X-Logic-Loop-Tab`/`tab_id` to a
tool-agnostic fixed header, and bounded. Reason: the router is
consumer-agnostic; any client-side tool that wants join-ability stamps the
header itself. The reader owns the join, not the writer.)*

Any client may send `X-Safe-Router-Tag: <opaque string>`. The router records it
verbatim in `client_tag`, enabling external tools to join router rows to their
own session/task identifiers **with no machinery in the router**. The header
name is **fixed, not configurable** — a configurable name is config-validation
surface for no benefit, and a user-supplied header name (e.g. `Authorization`)
would log credentials verbatim into the database.

**Constraints, all mandatory:**

- `client_tag` is an **opaque label with no policy meaning**. It must never
  influence routing, admission, or plane selection. It is a client-controlled
  string; treating it as policy input would hand routing control to the caller.
- **Untrusted and bounded.** Max 128 bytes; values containing control
  characters are dropped (logged as NULL); inserted via parameterized SQL only.
  Any downstream renderer (dashboards, panels) must escape it on render.

### 8.2 Integrity

Hash-chaining the log proves internal consistency and nothing else: on a single
machine, anything that can write the log can rewrite the chain and recompute
every hash. **Either push the chain head off-box on an interval** (the Mac Mini,
or a private git remote — a chain head is a hash, not client data), **or call it
"a log" and claim nothing more.** Do not use the phrase "tamper-evident" without
the anchor.

Anchoring is a v1 item. In v0 this is a plain log.

**(Amended 2026-08-14 — v1 lands the chain and the anchor.)** With an anchor in
place, the honest claim is **"tamper-evident against edits made before the
last anchor push"** and nothing broader — a row inserted and then edited
between two anchor runs is undetectable by this mechanism alone; only the
interval bounds the exposure. The anchor itself is a separate offline
process (`safe-router anchor` / `safe-router verify-log`), never the daemon:
the daemon's guarantee is a process property (no remote backend, no remote
credential in its address space — invariants #2, #9), and giving it an
outbound git/ssh path and a credential to use it trades that property for a
convenience. `anchor` refuses to publish a head over a chain that
`verify-log` finds broken — publishing a head that certifies tampered
history is worse than publishing nothing.

Row 11's interaction with the chain: rows buffered in memory during a
log-write failure never enter the chain at all (they were never written).
The chain stays internally valid across the gap; the gap itself — a
degraded-flag window plus a discontinuity in `id` — is a **recorded gap**,
not a hole the chain can silently paper over (matrix row 25).

---

## 9. Build plan

**Phase 0 — this document.** Accept or amend before any code.

**Phase 1 — v0, in work order:**

1. Daemon skeleton: axum, loopback bind, bearer-key auth (argon2id hashes from
   static TOML, constant-time compare), `Host`/`Origin` validation.
2. Passthrough SSE proxy to LM Studio — same dialect, byte-level — with
   backpressure and cancellation.
3. Admission policy: key → (plane, allowed routes/models), distinct 401/403
   codes. Config loader with the §4.1 startup validations.
4. Escalation plane: same binary, second config, one remote first-party
   provider, credential from Keychain.
5. Route aliases and chain advancement (§5.2).
6. Failure matrix rows 1–16 implemented, each with a named integration test.
7. Metadata log; requested-vs-returned model diff; `client_tag` capture.
8. Sign + notarize; `cargo-audit`/`cargo-deny` in CI; pinned lockfile; launchd
   plists for both planes.

Estimated one to two focused part-time weeks. **If it trends meaningfully past
that, v1 features have leaked in — stop and identify which.**

**Phase 2 — v1:** tailnet bind so Mac Mini clients can reach it (LM Studio moves
to loopback everywhere; the router becomes the only off-box listener); Anthropic
Messages as a second passthrough dialect; log-head anchoring; Logic Loop reads
the log as a panel.

**Phase 3 — only if earned by an actual incident or a client requirement:**
tool-call buffering and response screening; the downgrade-only PII tripwire;
adaptive selection *within* the local tier.

**Permanent non-goals** (revisit only with a written reason): cross-dialect
translation; any runtime-mutable policy surface; auto-update; multi-user
anything; cascade/adequacy logic in the router; behavioral fingerprinting of
providers; token counting as a policy input.

---

## 10. Notes carried from the research pass

- **Adaptive routing was rejected for the floor decision, not universally.**
  Learned selection *among local-only models* cannot cause disclosure — worst
  case is quality or availability manipulation. Deterministic-everywhere is
  still the right v0 call on simplicity grounds, but the accurate statement is:
  *the floor stays dumb; the shelf may get smart later.*
- **MoE local models and agentic clients.** Safety alignment on MoE models is
  brittle under routing manipulation, and naive safety fine-tuning can mask
  rather than repair it. Encode this as key→model allowlists: agentic clients
  driving tools get dense local models by default; MoE is the deliberate
  efficiency exception, not the default.
- **Model files are untrusted input.** Pinned sources, checksums, prefer
  safetensors/MLX, never pickle-adjacent formats. Weights-file parsers in the
  llama.cpp family have a CVE history. This is procurement discipline, not a
  router feature — but the allowlist above is where it gets enforced.
- **The four risk classes compose in failure.** Router-as-software compromise
  collapses directly into router-as-adversary: a compromised router is the
  perfect intermediary. That is why the supply-chain items in CLAUDE.md are
  invariants rather than "later."

---

## 11. Open questions — resolved 2026-08-13

1. **Client → plane assignment.** Operator decision, not spec content. The
   spec's rule is §5.5 default-deny; per-deployment assignments live in
   `docs/DEPLOYMENT.md` (not part of the published spec).
2. **Inbound-channel risk acceptances.** Same: §3's rule ("audit every inbound
   channel on the same terms") is the spec; each deployment records its own
   acceptances in `docs/DEPLOYMENT.md`.
3. **Ports.** `8787`/`8788` confirmed free on the reference machine and are
   TOML-configurable defaults. Kept.
4. **v1 log-head anchor target.** Any operator-controlled append-only remote;
   reference implementation: a private git remote. (v1 item; nothing in v0.)
5. **Anthropic OpenAI-compatibility layer.** Verified 2026-08-13: tool calling
   is supported, but the layer is documented as test-grade ("not a
   production-ready solution"), silently ignores unsupported fields, and hoists
   system messages — it mutates request structure, which conflicts with
   passthrough fidelity. **Decision: v0 escalation plane starts with OpenAI
   direct (remote first-party); Anthropic joins in v1 via the Messages
   passthrough dialect.**
