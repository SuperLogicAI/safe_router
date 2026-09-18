# PLAN.md — Phase 1 (v0 daemon)

Status: **PHASE 1 PLAN APPROVED 2026-08-13.** Prerequisites met: PHASE 0
ACCEPTED 2026-08-13, SPEC §11 resolved 2026-08-13.

## Step status

Running dashboard — update the checkbox + one-liner as each step lands.
Detail lives in `docs/TESTING.md` (manual verification) and `cargo test`
(automated); this is a pointer to that, not a duplicate of it — don't let
it drift from reality.

- [x] **Step 1 — Skeleton + auth.** Bearer auth (argon2id), Host/Origin
      validation, `hash-key` CLI. Verified 2026-08-13.
- [x] **Step 2 — Passthrough proxy.** Byte-passthrough SSE/JSON, idle
      timeout, client-disconnect cancels upstream. Verified against real
      LM Studio 2026-08-13.
- [x] **Step 3 — Admission + config validation.** Key→allowlist admission,
      safe-plane loopback check, cross-plane key-hash collision check, live
      SIGHUP reload. Verified against the real binary 2026-08-13.
- [x] **Step 4 — Escalation plane.** Keychain-sourced provider credentials,
      held in memory only. Fail-closed path verified against real
      `/usr/bin/security`; live OpenAI request still an optional manual
      step — needs a go-ahead before creating the real Keychain item.
- [x] **Step 5 — Route aliases + chain advancement.** Real chain
      resolution/dispatch, `<backend_id>/<model>` composite ids, advances
      only on 429/5xx/connect-fail. Verified against real LM Studio
      (dead rung → live rung) plus 6 automated tests.
- [x] **Step 6 — Failure matrix.** 16/16 rows automated (row 11 landed with
      Step 7 below; row 6 is a documented manual step, not automatable).
      Manual `kill -9` row-6 step not yet run.
- [x] **Step 7 — Metadata log.** SQLite `requests` table (SPEC §8 schema),
      single flush point in `guard`, in-memory default for tests + real
      `~/.safe-router/log.db` in production, degraded flag on write failure
      (matrix row 11), `client_tag` bounds enforced. 15 automated tests
      (`tests/metadata_log.rs` + row 11). Manual real-LM-Studio verification
      not yet run.
- [x] **Step 8 — Ship hygiene.** CI workflow (clippy, test, cargo-audit,
      cargo-deny) on `macos-latest`, `deny.toml` (verified locally: both
      checks clean), launchd plists for both planes written (not loaded),
      signing/notarization + install commands documented in TESTING.md. Not
      yet run: signing (needs Developer ID cert), launchd load (needs
      go-ahead), CI not yet pushed to GitHub.

Current: 91 tests passing (unit + integration, all binaries),
`cargo clippy --all-targets -- -D warnings` clean.

This plan is written to be executed by a smaller model. Everything needed is in
this file, `CLAUDE.md`, and `docs/SPEC.md`. Read both fully before any code.

---

## Rules for the executing model — read first, re-read when tempted

1. The 9 architecture invariants in CLAUDE.md are non-negotiable. If a step
   appears to require violating one, **stop and report** — the step is wrong.
2. Never add fallback, retry-elsewhere, or substitution logic, even where it
   looks obviously helpful. Failure matrix row 3 (context overflow → pass the
   400 through) is the named trap.
3. No dependencies beyond the list below without a one-line justification in
   the commit message.
4. Merge gates before reporting any step done:
   `cargo clippy --all-targets -- -D warnings` clean, `cargo test` green.
5. Steps a machine can't verify (Keychain, signing, launchd, LM Studio) go in
   `docs/TESTING.md` as numbered manual steps, and are listed in the step report.
6. No system-level side effects without asking: nothing written outside the
   repo and `~/.safe-router/`, no launchd load, no Keychain writes except
   items named `safe-router/*` and only in step 4.
7. Work the steps in order. One step per session/PR is fine. Do not start
   step N+1 with step N's checks unmet.

---

## Crate layout

Single binary crate `safe-router`.

```
Cargo.toml            # lockfile committed
src/main.rs           # CLI (--config <path>, hash-key subcommand), startup, serve
src/policy.rs         # TOML parse + ALL validation + admission evaluation.
                      #   Pure functions, no I/O (SPEC requirement). Input:
                      #   config string + request facts (key hash match, model,
                      #   stream, tools). Output: routing decision or typed error.
src/auth.rs           # argon2id verify (the argon2 crate's verify is the
                      #   constant-time compare), key lookup by prefix scan
src/proxy.rs          # byte-passthrough HTTP + SSE proxy: backpressure,
                      #   client-cancel → upstream cancel, idle timeout
src/errors.rs         # OpenAI-shaped error JSON, distinct machine-readable
                      #   codes (401 auth_unknown_key, 403 policy_denied_plane,
                      #   502 backend_unreachable, etc. — one code per matrix row
                      #   that returns an error)
src/log.rs            # rusqlite append to ~/.safe-router/log.db, schema SPEC §8,
                      #   in-memory buffer + degraded flag on write failure
tests/matrix.rs       # one named integration test per failure-matrix row
tests/support.rs      # tiny axum-based mock backend (no new dep) that can:
                      #   refuse connections, return 400/429/5xx, stream SSE,
                      #   stall mid-stream, report a wrong `model` field
docs/TESTING.md       # manual verification steps, appended per phase step
```

## Dependencies (closed list)

| Crate | Why |
|---|---|
| tokio | runtime (SPEC-named) |
| axum | server (SPEC-named) |
| reqwest (`rustls-tls`, `stream`, no default features) | upstream client; vetted, avoids hand-rolling hyper client + pooling; rustls per SPEC |
| serde, serde_json, toml | config + error JSON (SPEC-named) |
| argon2 | key hashes, constant-time verify (invariant 8) |
| rusqlite (`bundled`) | metadata log |
| tracing, tracing-subscriber | daemon logging |
| thiserror | typed internal errors |
| futures-util | stream plumbing for SSE passthrough |

Keychain: **no crate** — shell out to
`/usr/bin/security find-generic-password -s <item> -w`.
`# ponytail: zero-dep shell-out; swap to security-framework crate if flaky.`

---

## Work order

Mirrors SPEC §9. Each step ends with its check passing and a 5-line-max report.

### Step 1 — Skeleton + auth
- `cargo init`, deps, `main.rs` loads config path from `--config`, reads file,
  hands string to `policy.rs`.
- `hash-key` subcommand: reads a key from stdin, prints argon2id hash. Offline
  CLI only — this is how the user authors TOML; it is not a runtime policy
  surface (invariant 3 intact).
- Bearer auth on all routes; `Host`/`Origin` validation (reject non-loopback
  Host, reject any Origin header — no browser client exists).
- Endpoints stubbed: `POST /v1/chat/completions`, `GET /v1/models` return 502
  until step 2.
- **Check:** unit tests — bad key 401 (well-formed JSON, distinct code), good
  key reaches stub; `hash-key` output verifies against itself.

### Step 2 — Passthrough proxy
- `proxy.rs`: stream request body up, response bytes down untouched. Both
  streaming (SSE) and non-streaming. Client disconnect cancels upstream
  (matrix 14). Idle timeout terminates SSE with proper error event (matrix 4).
- Parse `model` from the response (first SSE chunk before forwarding any
  bytes; response body otherwise) — feeds logging, and on the safe plane the
  matrix-row-12 terminal check. Peek-then-stream, not full buffering.
- `/v1/models` proxied verbatim.
- **Check:** integration test against mock backend (echo + SSE). Manual step in
  TESTING.md: real request through to LM Studio, streamed and not.

### Step 3 — Admission + config validation
- `policy.rs` complete: key → (plane, allowed routes/models); concrete-model
  vs alias distinction; admission parses only bearer key, `model`, `stream`,
  `tools` presence (invariant 5).
- Startup validation per SPEC §4.1: refuse if key hash in both plane configs
  (matrix 16), refuse if safe-plane backend transport non-loopback, refuse any
  invalid TOML (matrix 7). SIGHUP reload: full validation, keep old config on
  invalid, log loudly, degraded flag (matrix 8).
- **Check:** unit tests for every validator, each refusal case; 403 with
  distinct permanent-reading code for safe-key-requests-remote (matrix 10).

### Step 4 — Escalation plane
- Same binary, `escalation.toml`, one remote first-party provider: **OpenAI
  direct** (SPEC §11 Q5 resolved). Credential fetched from Keychain at
  startup, held in memory, never logged, never in config.
- **Check:** unit test with fake `security` binary on PATH. Manual TESTING.md
  step: real Keychain item, real request. **Ask the user before creating the
  Keychain item.**

### Step 5 — Route aliases + chain advancement
- Alias = ordered chain within one plane (schema cannot express cross-plane —
  enforce by construction: chains validated against same-file backends only).
- `on_error = "next"` advances one rung on 429/5xx/connect-fail, logs
  `chain_pos`. `on_error = "fail"` passes through. Response reports the model
  that actually served.
- **Check:** integration tests: rung 1 down → rung 2 serves, `chain_pos` = 2;
  concrete model name never substitutes.

### Step 6 — Failure matrix, rows 1–10 + 12–16 (15 named tests; row 11 deferred to Step 7)
- **Revision from the original "all 16 rows" text (stated per CLAUDE.md
  process rules, not silent):** row 11 is "log write failure / disk full →
  buffer in memory, degraded flag." There is no log to fail-write yet —
  `log.rs`/SQLite land in Step 7. Testing row 11 now would mean building a
  throwaway degraded-flag mechanism disconnected from the real log, then
  redoing it in Step 7. Row 11's named test (`matrix_row_11_log_write_failure`)
  moves to Step 7's checklist, next to the log it's actually about. SPEC §9's
  own build order (rows 1–16 in step 6, log in step 7) already has this
  wrinkle baked in — not introducing it, just not pretending around it.
- Row 6 (router crash mid-stream): **documented manual step in
  docs/TESTING.md, not an automated test.** Reasoning: invariant #1 means
  there's no persisted request state to assert *against* on restart (nothing
  survives, full stop — that's the entire content of the requirement), and
  the only thing a process-kill integration test could verify is that a TCP
  connection drops when its owning process dies, which is OS behavior, not
  safe-router logic. A `kill -9` + curl manual step demonstrates the same
  fact without adding a flaky process-spawn test for zero incremental
  coverage.
- `tests/matrix.rs`: one test per remaining row, named `matrix_row_NN_<slug>`
  (e.g. `matrix_row_03_context_overflow_passthrough`). Row 12 splits by
  plane: `matrix_row_12a_safe_mismatch_terminal` (502 / stream terminated, no
  body relayed) and `matrix_row_12b_escalation_mismatch_passthrough`
  (relayed, logged, counted). Reuses `tests/support.rs` mock backends
  (`spawn_mock_backend`, `spawn_status_backend`, `spawn_slow_drip_backend`)
  plus new fixtures as needed (a backend that returns a body with a
  different `model` than requested, for row 12).
- **Row 12 needs real enforcement code, not just a test** — nothing today
  compares the response's `model` field to what was resolved.
  - Non-streaming: buffer the full response body (small, single JSON object;
    no framing concern), compare its `model` to the serving rung's
    `rung.model`. Safe plane mismatch → discard the body, `502
    model_mismatch` (new `ApiError` variant). Escalation plane mismatch →
    relay the buffered bytes unchanged, just log + count.
  - Streaming: peek the *first* SSE chunk's `model` before forwarding any
    bytes (this is why row 12 says "before forwarding any bytes" — it's
    already the shape `relay()`'s first-chunk peek was built for in Step 5,
    just needs to gate instead of only log). Safe plane mismatch → emit an
    error event, terminate, forward nothing further. Escalation plane
    mismatch → forward normally, log + count.
  - Mismatch counter: an `AtomicU64` on `AppState` (both planes increment on
    mismatch), not a SQLite write — Step 7 wires it into the real log's
    counter column. Tests read it directly off the in-process `AppState`
    handle (not over the network — no admin API, invariant #3 intact).
- Row 13 (TLS/cert failure, escalation plane only): no cert-generation crate
  is on the closed dependency list, and adding one for one test isn't
  justified. Point a provider's `base_url` at `https://127.0.0.1:<port>`
  where `<port>` is one of the existing **plain-HTTP** mock backends — the
  TLS handshake itself fails (the peer never speaks TLS), which exercises
  the real "fail closed, no plaintext retry" path with zero new
  dependencies: if the router *did* silently retry in plaintext, this test
  would observe a successful response instead of `backend_unreachable`.
- **Check:** all 15 named tests in `tests/matrix.rs` exist and pass;
  `docs/TESTING.md` has the row-6 manual step; row 11 is listed as deferred
  (not silently dropped) in this file's Step 7 entry.

### Step 7 — Metadata log
- `log.rs`: SPEC §8 schema verbatim. Metadata only — assert nothing
  body-derived is stored beyond the admission fields. `client_tag` = verbatim
  `X-Safe-Router-Tag` (fixed name, never configurable), opaque, never read by
  policy (grep the codebase: header name appears in exactly one file, `log.rs`).
  Bounds per SPEC §8.1: max 128 bytes, drop values with control characters
  (store NULL), parameterized insert only — unit test each. Mismatch counter
  (matrix 12).
  Write failure → in-memory buffer + degraded flag, traffic continues
  (matrix 11, deferred here from Step 6 — see that step's note).
- **Check:** integration test asserts a row per request with correct
  disposition for served/denied_policy/denied_auth/backend_error/client_cancel;
  `tests/matrix.rs::matrix_row_11_log_write_failure` (readonly log dir) keeps
  serving and sets the degraded flag.

**Design detail (stated before building, per CLAUDE.md process rules — SPEC
§8's schema doesn't map onto the current middleware chain 1:1, these fill the
gaps):**

- **Scope: `/v1/chat/completions` only.** `model_req TEXT NOT NULL` and
  SPEC §4.2's request-path diagram (admission → route resolution → backend)
  are chat-completions concepts; `/v1/models` has no model to log and never
  runs `admission`. `guard` checks `req.uri().path()` and skips the logging
  machinery entirely for anything else.
- **One flush point.** `guard` (already the outermost layer) gains a
  `finish()` helper that every exit path — its own 3 pre-auth rejections
  (bad host/origin/key) and the `next.run(req).await` result — funnels
  through, instead of scattering log calls through `admission`/`proxy.rs`.
  `finish()`:
  - **Build note:** axum doesn't set `Content-Length` on the in-memory
    `Response` for either `Json::into_response` or `relay`'s buffered
    branch — hyper fills it in later, at wire-encoding time, invisible to
    anything inspecting the `Response` object beforehand. Both now set it
    explicitly (`errors.rs::ApiError::into_response`, `proxy.rs::relay`'s
    non-SSE branch) — load-bearing for the classification below, not
    cosmetic.
  - If the response has a `Content-Length` (never true for a streamed
    relay — only for `ApiError` JSON and non-streaming completions):
    buffer it, look for a top-level `error.code`; a match against the
    router's own fixed `ApiError` codes sets `disposition`/`err_code` from a
    static table (below), a miss (a backend's own error body, e.g. matrix
    row 2) or a 2xx defaults to `served`. Rebuild the response from the
    buffered bytes (same buffer-then-rebuild shape Step 6 already uses for
    row 12) and log immediately — the full response already exists
    server-side by this point, so there's no "client disconnected before it
    finished" to detect.
  - Otherwise (chunked/streaming — exclusively backend-relayed content,
    never a router `ApiError`): tag `disposition = served` optimistically
    and wrap the body stream in a small `Drop` guard. If the stream is
    dropped before it ever reaches its own natural end — client walked away
    mid-stream, matrix row 14 — the guard overwrites `disposition` to
    `client_cancel` before flushing. This is the only way to catch that case
    correctly: `next.run()` returns as soon as the handler hands back a
    `Response`, which for a streaming body is long before the bytes are
    actually (or not) fully sent.
  - `ApiError` code → `disposition` table: `auth_unknown_key` /
    `bad_host` / `origin_rejected` → `denied_auth`; `invalid_request_body` /
    `policy_denied_model` → `denied_policy`; `backend_unreachable` /
    `backend_not_configured` / `route_unresolvable` / `model_mismatch` →
    `backend_error`. Everything else (including a backend's own passthrough
    error status) → `served`. `err_code` is set only alongside a non-`served`
    disposition; `status` is always the real HTTP status returned.
- **`key_id`/`model_req` sentinel: `"unknown"`.** Both columns are
  `NOT NULL`, but a pre-auth rejection (bad host/origin/key) happens before
  either is ever determined — admission (which parses `model`) runs *after*
  auth. `"unknown"` satisfies the constraint without ever echoing any part
  of a presented (possibly fat-fingered-real) credential into the log.
- **`route`/`model_req`/`stream`/`tools` set by `admission`**, which already
  parses the body once; **`backend`/`chain_pos`/`model_served`/`mismatch`
  set by `proxy::chat_completions`**, which already knows which rung served.
  Both write into a per-request `Arc<Mutex<LogFields>>` inserted into request
  extensions by `guard` before `next.run()` — the same "annotate as you go,
  flush once at the end" shape Step 6's `MismatchGate` already established
  the model for, just widened to the handful of fields only those two layers
  know.
- **`tokens_in`/`tokens_out`: best-effort, not real tokenization.** Read the
  backend's own `usage.prompt_tokens`/`usage.completion_tokens` from a
  buffered non-streaming response when present; `NULL` otherwise. SPEC §7
  cuts token counting as a *policy input* — this is purely observational
  logging of a number the backend already computed, zero cost, never read by
  admission.
- **`AppState` defaults to an in-memory log** (`rusqlite::Connection::
  open_in_memory()`, effectively infallible) so the ~80 existing tests that
  call `AppState::new(config)` need zero changes. `main.rs` explicitly points
  production at the real `~/.safe-router/log.db` via a new
  `AppState::with_log_path`. New tests that need to inspect rows use the
  in-memory default and a `Log::last_row()` accessor.
- **Degraded flag: reused, not duplicated.** A log-write failure sets the
  *same* `AppState.degraded` AtomicBool as a failed SIGHUP reload — SPEC
  doesn't call for a flag per failure mode, and nothing reads this flag over
  the network either way (invariant #3, no admin API).
- **In-memory overflow buffer on write failure is unbounded.**
  `# ponytail: unbounded Vec; add a cap + drop-oldest if a disk-full period
  is ever long enough on a single-user local daemon to matter.`

### Step 8 — Ship hygiene
- CI (GitHub Actions): clippy, test, `cargo-audit`, `cargo-deny`. Lockfile
  committed. `deny.toml` minimal.
- Signing + notarization + launchd plists for both planes: **write the files
  and document the commands in TESTING.md; do not load or sign without the
  user** (needs Apple ID / cert, and launchd is a system-level side effect).
- **Check:** CI green on the repo. TESTING.md complete.

---

## Definition of done (Phase 1)

- All 16 matrix tests green; clippy `-D warnings` clean; `cargo test` green.
- Both planes start from the SPEC §5.3 example configs (hashes swapped in) and
  serve a real request end-to-end (manual, TESTING.md).
- No dependency outside the closed list without recorded justification.
- Phase report lists every manual TESTING.md step still unverified.
- Then stop. Wait for `PHASE 1 ACCEPTED`.

## Explicitly out of scope (v1+ leak detector)

Tailnet bind, Anthropic Messages dialect, log-head anchoring, any dashboard,
cross-dialect translation, token counting, screening/tripwire, adaptive
selection. If any of these appears in a diff, the phase has drifted.

`logo.py` is not Phase 1 work and never enters the daemon (Rust only,
invariant 4). If the project open-sources later, port the ASCII art as a
`const &str` banner behind `--version`/`--help` in `main.rs` — cosmetic,
zero-dep, decide then.
