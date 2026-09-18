# PLAN.md — Phase 2 (v1)

## Approved follow-on sprint — provider usage in the versioned log (2026-09-13)

The user explicitly approved building this focused router-side sprint on
2026-09-13, superseding the earlier roadmap candidate. **Implemented on
`feature/observability-log-v2`; `cargo test` and clippy pass.** This is a Phase 2 log
contract follow-on, not authorization for Phase 3 screening, live deployment,
or an account-switching surface. The existing Phase 2 plan remains below.

1. Freeze and test `v_requests_v1`'s exact columns and existing meaning. Keep
   `X-Safe-Router-Tag` fixed, opaque, untrusted, bounded to 128 bytes, and
   excluded from every policy decision. Validate the header contract in both
   dialects.
2. Normalize only supported response usage: OpenAI chat completions
   `usage.prompt_tokens` / `completion_tokens`; Anthropic Messages
   `usage.input_tokens` / `output_tokens`. For SSE, collect complete bounded
   `data:` events across arbitrary transport chunks and inspect only OpenAI
   terminal usage and Anthropic `message_start` / `message_delta` usage.
   Never alter upstream requests to solicit usage; an OpenAI stream without
   a usage event remains unknown. Reject malformed, negative, or oversized
   metadata; preserve every response byte and incremental delivery. Record
   each counter independently as NULL when not reported, including on
   incomplete streams; zero is a reported zero, not a stand-in for missing.
3. Add no table columns: existing nullable `tokens_in` / `tokens_out` already
   carry the normalized counters. Add `v_requests_v2` with the v1 columns in
   the same order plus a derived `usage_state` (`complete`, `partial`,
   `not_recorded`). `not_recorded` describes the log, not provider behavior;
   historical NULLs may reflect the old extractor. Keep v1 SQL unchanged.
   Migrate schema version 1 → 2 transactionally when creating v2. Because
   no stored field or canonical hash input changes, old and new rows retain
   the same hash formula and existing anchors remain valid.
4. Rate-limit remaining/reset is deferred: provider header families, quota
   units, and reset time formats need a separate cross-provider contract and
   SPEC amendment. Static `on_error = "next"` is existing failover, not a
   runtime account switch. Add no mutable policy, cost, or pricing logic.
5. Update SPEC and LOG_CONTRACT with the generic read-only consumer contract,
   field nullability and provenance, schema/version detection, older or
   missing DB behavior, trust limits, WAL, and integrity claim. Document
   Logic Loop's independent work: prove client header emission and build its
   own read-only panel; the router cannot read `LOGIC_LOOP_TAB_ID` from an
   agent's environment.
6. Focused tests: both dialects buffered and SSE, split/coalesced events,
   missing and zero usage, byte-for-byte passthrough and incremental stream,
   tag acceptance/rejection/non-policy behavior, v1/v2 migration and
   read-only access, hash verification before/after migration and tampering.
   Run `cargo test` and `cargo clippy --all-targets -- -D warnings`. Record
   only manual checks that cannot be automated in `docs/TESTING.md`.

No live config, Keychain, launchd, global client settings, deployed binary,
GUI, or Logic Loop code is in scope.

Status: **PHASE 2 ACCEPTED 2026-08-14.** Build in progress: Step 0 done,
Step 1 next. Phase 1's plan is archived verbatim at `docs/PLAN-phase1.md`;
this file is the current phase only, per CLAUDE.md.

Baseline at draft time: 91 tests passing, `cargo clippy --all-targets -D
warnings` clean, all 16 v0 failure-matrix rows have named tests.

This plan is written to be executed by a smaller model. Everything needed is in
this file, `CLAUDE.md`, and `docs/SPEC.md`. Read both fully before any code.

---

## What Phase 2 is

SPEC §9's four v1 items, plus the ship-hygiene tail Phase 1 left open:

1. **Tailnet bind** — the router becomes the only off-box listener; LM Studio
   is loopback everywhere; Mac Mini clients reach the router over Tailscale.
2. **Anthropic Messages as a second *passthrough* dialect** — `POST
   /v1/messages` in, Anthropic out, bytes through, admission at the front.
   Claude Code moves behind the escalation plane. No translation (invariant #5).
3. **Log-head anchoring** — hash-chained rows plus an off-box head push, so
   SPEC §8.2's "tamper-evident" claim becomes sayable.
4. **Logic Loop panel read contract** — a documented, versioned, read-only view
   of `log.db`. The panel itself lives in Logic Loop's repo (invariant #4).
5. **Carry-over:** CI now runs (pushed 2026-08-14, one bug fixed — see Step
   5 below), signing is blocked on a Developer ID cert, launchd is
   uninstalled.

Everything else is Phase 3 or a permanent non-goal. See the leak detector at
the bottom.

---

## Rules for the executing model — read first, re-read when tempted

Same rules as Phase 1, unchanged. Repeated because they are the point:

1. The 9 architecture invariants in CLAUDE.md are non-negotiable. If a step
   appears to require violating one, **stop and report** — the step is wrong.
2. Never add fallback, retry-elsewhere, or substitution logic, even where it
   looks obviously helpful. Matrix row 3 (context overflow → pass the 400
   through) is the named trap; **Phase 2 adds a second one: an Anthropic
   request failing on the escalation plane must never fall back to a local
   OpenAI-dialect backend, and vice versa. Chains never cross dialects, for
   the same reason they never cross planes.**
3. No dependencies beyond Phase 1's closed list plus the one addition below,
   without a one-line justification in the commit message.
4. Merge gates before reporting any step done:
   `cargo clippy --all-targets -- -D warnings` clean, `cargo test` green.
5. Steps a machine can't verify (Tailscale, Keychain, signing, launchd, real
   LM Studio, real Anthropic) go in `docs/TESTING.md` as numbered manual steps
   and are listed in the step report.
6. No system-level side effects without asking: nothing written outside the
   repo and `~/.safe-router/`, no launchd load, no `tailscale` state changes,
   no Keychain writes except items named `safe-router/*`, no `git push` to any
   remote other than `origin` and not without asking.
7. Work the steps in order. Do not start step N+1 with step N's checks unmet.
8. **Phase 2 changes the security boundary.** Step 0's SPEC amendments land
   *before* any code that depends on them. An amendment written after the fact
   is a rationalization, not a decision.

### Dependency additions (one)

| Crate | Why |
|---|---|
| `sha2` | SHA-256 for the log hash chain (Step 3). RustCrypto, tiny, no transitive weight. `ring` is already in the tree via rustls and could be used instead with zero new crates, but that pins us to reqwest's current TLS backend choice — if it switches to `aws-lc-rs`, `ring` vanishes from the tree and the log chain breaks for an unrelated reason. One small explicit dep beats a load-bearing accident. |

No CIDR crate for the tailnet check: `std::net::Ipv4Addr` + an octet
comparison is four lines (`# ponytail:` comment at the site).

---

## Step status

Update the checkbox + one-liner as each step lands. Detail lives in
`docs/TESTING.md` and `cargo test`; this is a pointer, not a duplicate.

- [x] **Step 0 — SPEC amendments + two hygiene fixes.** 0b (error codes
      carried, not re-parsed) and 0c (WAL) landed 2026-08-14; 95 tests
      passing, clippy clean. **0a landed 2026-08-14** (PHASE 2 ACCEPTED same
      day): docs/SPEC.md §3, §4.1, §6 (rows 17–25 + row 12 dialect note),
      §7.1 (new), §8/§8.2 amended.
- [x] **Step 1 — Tailnet bind.** Landed 2026-08-14: `allowed_hosts` config
      field, `validate_bind_address`/`validate_allowed_hosts`, widened
      `validate_safe_plane_backends`, `check_host` widened to accept
      `allowed_hosts` matches. 113 tests passing (was 95), clippy clean.
      Manual tailnet/ACL verification not yet run (docs/TESTING.md Step 9).
- [x] **Step 2 — Anthropic Messages dialect.** Landed 2026-08-14:
      `POST /v1/messages` route, `x-api-key`/`Authorization` key extraction
      widened for that route only, `validate_chain_dialects` (row 21),
      request-time dialect-match check (row 20), `apply_credential` per
      target dialect (`anthropic-version`/`anthropic-beta` forwarded,
      client's own key never forwarded), `ApiError::into_response_for`
      (Anthropic envelope, `router_code` alongside the fixed `type` set),
      Anthropic-shaped SSE idle-timeout/mismatch events. 130 tests passing
      (was 113), clippy clean. Manual real-Claude-Code verification not yet
      run (docs/TESTING.md Step 10 — needs a go-ahead, spends real credit).
- [x] **Step 3 — Log hash chain + off-box anchor.** Landed 2026-08-14:
      `prev_hash`/`row_hash` columns (idempotent migration guarded by
      `PRAGMA user_version`), `row_hash = sha256(prev_hash || "\n" ||
      canonical_fields)` computed inside the same write transaction as the
      insert. `Log::verify_chain` (recomputes, reports first divergence),
      `safe-router verify-log` / `safe-router anchor` offline subcommands —
      `anchor` refuses to publish over a broken chain. Off-box push (shell
      script + launchd) is documented, not built — the daemon must never
      make that connection itself (invariants #2/#9). `sha2` added, the
      only new dependency for the phase. 142 tests passing (was 130),
      clippy clean, `cargo deny check`/`cargo audit` clean with `sha2` in
      the tree. Manual real-log anchor run, tamper test, push script, and
      launchd interval job **done and verified 2026-09-03** (docs/TESTING.md
      Step 11) — real commits landing at `github.com/SuperLogicAI/
      log-anchor`, job confirmed firing via `launchctl start`.
- [x] **Step 4 — Panel read contract.** Landed 2026-08-14: `v_requests_v1`
      view (explicit column list, created at daemon startup alongside the
      table), `docs/LOG_CONTRACT.md` (columns, the `file:…?mode=ro` +
      `PRAGMA query_only=1` connection string, `client_tag`'s untrusted
      status, the "no HTTP interface, ever" statement, and integrity
      caveats matching §8.2's amended claim). No daemon changes beyond the
      view — no read endpoint, no socket, no IPC. 143 tests passing (was
      142), clippy clean.
- [~] **Step 5 — Ship hygiene carry-over.** CI push + fix done 2026-08-14
      (see below). launchd load done 2026-08-14 (safe plane running,
      escalation blocked on missing Keychain item). Signing still blocked
      on cert. PF egress lock scoped and deferred — bigger than planned
      (LaunchDaemon + ownership restructuring), not part of the TCB.

---

## Step 0 — SPEC amendments + two hygiene fixes

No feature work. This step exists because Steps 1–3 each move something the
spec currently states differently, and CLAUDE.md requires the amendment to be
written, dated, and reasoned *first*.

### 0a. `docs/SPEC.md` amendments (dated 2026-08-14)

- **§3 (the boundary) — new accepted risk.** Tailnet bind adds a dependency
  the loopback deployment did not have: **the guarantee now also rests on
  Tailscale's ACLs and on every tailnet peer being trusted.** A compromised
  tailnet device with a valid safe-plane key is inside the boundary. State it
  in the same voice as the existing exclusions. Record the mitigations that
  are actually required (not optional): a Tailscale ACL restricting
  `:8787`/`:8788` to named devices, and LM Studio bound to loopback on *every*
  tailnet node — not just this one.
- **§4.1 — define "tailnet-local" precisely.** The existing sentence already
  permits safe-plane backends on "loopback/tailnet-local" transport; it never
  says what that means. Define it as: a literal IPv4 address in
  `100.64.0.0/10` (Tailscale's CGNAT range). **MagicDNS names are not
  accepted as a safe-plane backend `base_url`** — a name resolves wherever
  DNS says it does, which turns a structural check into a trust-the-resolver
  check. Names are accepted only on the *inbound* side (`allowed_hosts`),
  where they are compared, never resolved.
- **§6 — new failure-matrix rows 17–24**, plus a dialect note on row 12. Table
  below; it is the Phase 2 test plan the same way rows 1–16 were Phase 1's.
- **§7 — second inbound dialect.** `POST /v1/messages`, passthrough only. Also
  record the error-envelope decision (0b below) and the endpoints explicitly
  *not* covered (`/v1/messages/count_tokens`, `/v1/messages/batches`, the
  Files API).
- **§8 — schema gains `prev_hash`/`row_hash`.** §8.2 gets the honest claim
  wording: with an anchor in place, the claim is *"tamper-evident against
  edits made before the last anchor push"* and nothing broader. Also record
  the row-11 interaction: rows buffered in memory during a log-write failure
  never enter the chain, so a degraded period is a **recorded gap**, not a
  hole the chain can paper over.

### 0b. Hygiene fix 1 — error codes are carried, not re-parsed (real bug)

`lib.rs::disposition_for_code` matches `"bad_host"` / `"origin_rejected"`, but
`errors.rs` emits `"policy_bad_host"` / `"policy_origin_rejected"`. Effect
today: a Host- or Origin-rejected `/v1/chat/completions` request logs
`disposition = "served"` with a NULL `err_code` and a 403 status. Wrong row in
the security log for the two rejections that most want to be visible.

Fix the string mismatch, **and remove the class of bug**: `ApiError` inserts
its own `&'static str` code into the response's extensions
(`resp.extensions_mut().insert(ErrCode(self.code))`); `finish` reads it from
there instead of re-parsing the JSON body it just serialized. `classify_buffered`
keeps its *other* job (reading a backend's `model` / `usage` out of a buffered
response) and loses the router-error branch entirely. This also removes the
"how do I classify an Anthropic-shaped error body" question from Step 2 before
it can be asked.

- **Check (met, landed 2026-08-14):** three new tests in
  `tests/metadata_log.rs` — `logs_denied_auth_for_a_non_loopback_host`,
  `logs_denied_auth_for_an_origin_header`, and
  `logs_served_when_a_backend_error_body_mimics_a_router_code` (the
  regression test for the class: a backend error body carrying
  `"code":"policy_denied_model"` is relayed verbatim and must still log
  `served`, since the router produced no error of its own). The first two
  were confirmed failing against the old code — both logged
  `disposition = "served"` — before the fix went in.

### 0c. Hygiene fix 2 — WAL mode on the log

`Log::open_file` sets `PRAGMA journal_mode=WAL`. Needed by Step 4 (a reader
process while the daemon writes), harmless before it.

**Landed 2026-08-14, and it was not one line — recorded here because it moved
a matrix row's mechanism:**

- **It broke matrix row 11.** That test injected a log-write failure by
  denying write permission on the log *directory*, which worked only because
  the rollback journal creates a new `-journal` file per transaction. WAL
  appends to a single `-wal` file opened at startup, so nothing new is ever
  created and the permission check never fires. Reworked to hold the write
  lock from a second connection instead: the INSERT fails at the same layer a
  real disk-full does (`execute` returns `Err`), which is the entire behavior
  row 11 specifies. Assertions unchanged — traffic continues, row buffered,
  degraded flag set.
- **The log connection's busy timeout is now 0.** rusqlite defaults to 5s;
  under that default the failing INSERT silently *waited* instead of failing,
  which would have hidden row 11's path behind a 5-second stall of a
  blocking-pool thread. This daemon is the log's only writer and WAL readers
  never block writers, so a lock worth waiting on doesn't exist here.

- **Check (met):** existing log tests green; new
  `a_read_only_connection_can_query_while_the_writer_is_open` asserts a
  read-only connection queries during active writes, sees rows written after
  it connected, and cannot itself write.

---

## Step 1 — Tailnet bind

### Config surface (static TOML, startup-validated — invariant #3 intact)

```toml
[server]
bind          = "100.x.y.z:8787"          # tailnet IP, or loopback as before
allowed_hosts = ["100.x.y.z", "mac-studio.tailXXXX.ts.net"]
```

`allowed_hosts` defaults to empty. Empty means **loopback only** — exactly
today's behavior, so an unmodified v0 config keeps its v0 semantics. Fail
closed by default; the widening is opt-in and written down.

### Validation (all at startup and on SIGHUP; refuse to start on failure)

1. `bind` host must be loopback **or** a literal `100.64.0.0/10` address.
   `0.0.0.0`, `::`, LAN, and public addresses are refused with a distinct
   message. This is the midnight-config-edit landmine from CLAUDE.md — the
   check exists to catch *you*, not an attacker.
2. Every `allowed_hosts` entry must be a loopback name/IP, a literal
   `100.64.0.0/10` address, or a `*.ts.net` name. Nothing else.
3. If `bind` is non-loopback, its host must itself appear in `allowed_hosts`
   (otherwise the daemon listens on an address no request can pass Host
   validation for — silently dead, the worst failure shape).
4. `validate_safe_plane_backends` widens from loopback-only to loopback **or**
   literal `100.64.0.0/10`. Names still refused (see §4.1 amendment).

### Request path

`check_host` accepts loopback (as today) plus any exact `allowed_hosts` match,
port stripped before comparison. Nothing else changes: no per-peer identity
check, no `tailscaled` LocalAPI whois, no new auth path. Invariant #8 says
authentication is boring; a Tailscale identity lookup in the admission path is
an IPC dependency and a second auth mechanism, for a machine-identity signal
the bearer key already covers. **Rejected — do not add it.**

- **Check (automated):** matrix rows 17, 18, 19 below. Plus a unit test per
  refused bind form (`0.0.0.0`, `192.168.x.x`, a public IP, a `.ts.net` name
  as a *bind*).
- **Check (manual, `docs/TESTING.md`):**
  1. Tailscale ACL restricting 8787/8788 to named devices, applied and pasted
     into `docs/DEPLOYMENT.md`.
  2. From the Mac Mini: request succeeds over the tailnet with a valid key.
  3. From a LAN-only host (same Wi-Fi, not on the tailnet): connection
     refused — the router is not listening on the LAN interface at all.
  4. LM Studio re-verified loopback on **every** tailnet node. `--bind` is not
     persisted by the LM Studio GUI (DEPLOYMENT.md already records this) —
     confirm after every restart/upgrade, on each machine.
  5. `Host: evil.example.com` against the tailnet listener → 403
     `policy_bad_host`.

---

## Step 2 — Anthropic Messages dialect

Second **passthrough** dialect. Same trick as v0, not a translation: bytes in,
bytes out, admission at the front on the same four facts.

### Routing

- New route `POST /v1/messages`, behind the same `guard` + `admission`
  middleware. Anthropic's body uses the same field names admission already
  reads (`model`, `stream`, `tools`) — **the admission middleware needs no
  dialect awareness at all.** Do not add any.
- **Inbound key extraction widens for this route only:** Claude Code sends
  `x-api-key` when configured with `ANTHROPIC_API_KEY` and `Authorization:
  Bearer` when configured with `ANTHROPIC_AUTH_TOKEN`. Accept the router's own
  key from either header. Whichever it arrives in, it is consumed by the
  router and **never forwarded upstream** (invariant #9).
- `/v1/models` stays as-is (first configured backend/provider for the plane)
  but must attach credentials in that target's dialect style — see below.

### Config

```toml
[[provider]]
id            = "anthropic"
base_url      = "https://api.anthropic.com"
dialect       = "anthropic"
keychain_item = "safe-router/anthropic"
```

- `validate_dialects` widens from `{openai}` to `{openai, anthropic}`.
- **New validation: a route chain must not mix dialects.** All rungs of a
  chain resolve to backends/providers of the same dialect, or the daemon
  refuses to start (row 21). Advancing a rung must never change the wire
  protocol mid-request.
- **New admission-time check: the inbound endpoint's dialect must match the
  resolved chain's dialect.** `/v1/messages` → anthropic rungs only;
  `/v1/chat/completions` → openai rungs only. Mismatch is a **403
  `policy_dialect_mismatch`**, before any upstream byte (row 20). It reads as
  permanent because it is: it is a config error, not a transient failure.

### Outbound

`Target` gains an auth style derived from the dialect:

- `openai` → `Authorization: Bearer <secret>` (today's behavior, unchanged).
- `anthropic` → `x-api-key: <secret>` + `anthropic-version`.
  `anthropic-version` is forwarded verbatim from the client when present;
  when absent, a single `const ANTHROPIC_VERSION_DEFAULT` is injected.
  `anthropic-beta` is forwarded verbatim when present. **That is the entire
  forwarded-header allowlist** — no general header passthrough, and the
  client's `Authorization`/`x-api-key` is never among them.
- Path: `{base_url}/v1/messages`. Note the escalation config's OpenAI provider
  carries `/v1` in its `base_url` while Anthropic's does not; keep the join
  explicit per dialect rather than inventing a normalization rule.

### Row 12 (model mismatch) in the Messages dialect

Same semantics, different byte shapes — safe plane terminal, escalation plane
detect-and-relay:

- Non-streaming: top-level `"model"` in the response object. The existing
  `model_from_json_object` works unchanged.
- Streaming: the first SSE event is `message_start`, with the model nested at
  `message.model`. `extract_model_field`'s substring scan finds it as-is —
  **verify this with a real captured `message_start` chunk in the test
  fixture, do not assume it.**
- The terminal SSE event emitted on a safe-plane mismatch must be
  Anthropic-shaped (`event: error` + `{"type":"error","error":{…}}`), not the
  OpenAI-shaped constant. Same for the idle-timeout event (matrix row 4).

### Error envelope

`/v1/messages` errors render Anthropic-shaped:
`{"type":"error","error":{"type":<anthropic type>,"message":<msg>,"router_code":<our code>}}`.
Anthropic's `type` values are a fixed set clients switch on, so the router's
own machine-readable code rides alongside in `router_code` rather than
displacing it. Codes themselves are unchanged and shared across dialects — one
`ApiError`, two renderers. (Step 0b already moved log classification off the
serialized body, so this costs the log nothing.)

- **Check (automated):** matrix rows 20, 21, 12c, 22 below; a test that no
  client-supplied `x-api-key`/`Authorization` reaches the mock upstream; a
  test that `anthropic-version` is forwarded when present and defaulted when
  absent.
- **Check (manual, `docs/TESTING.md`):** real Claude Code pointed at the
  escalation plane (`ANTHROPIC_BASE_URL=http://127.0.0.1:8788`,
  `ANTHROPIC_AUTH_TOKEN=<router key>`), one streaming and one tool-using
  turn. **Requires creating Keychain item `safe-router/anthropic` and spends
  real Anthropic credit — ask before doing either.** Update
  `docs/DEPLOYMENT.md`'s client→plane table (Claude Code moves from "none
  (direct)" to escalation).

---

## Step 3 — Log hash chain + off-box anchor

### Chain

- Schema gains `prev_hash TEXT` and `row_hash TEXT`. Existing `log.db` files
  are migrated with idempotent `ALTER TABLE ADD COLUMN` guarded by
  `PRAGMA user_version` (0 → 1). Pre-migration rows keep NULL hashes and the
  chain starts at the first post-migration row — a documented, verifiable
  starting point beats back-filling hashes over rows nobody chained.
- `row_hash = sha256(prev_hash || "\n" || canonical_fields)` where
  `canonical_fields` is the row's columns joined in fixed schema order with a
  separator that cannot appear in a value (NULs; `client_tag` already rejects
  control characters, §8.1). Computed inside the same `spawn_blocking` insert
  that writes the row, under the existing connection mutex, so ordering is the
  DB's ordering. **Single writer only — that is already true and must stay
  true.**

### Anchor: a separate process, never the daemon

`safe-router anchor` and `safe-router verify-log` — offline subcommands next
to `hash-key`, reading the DB read-only.

- `verify-log` recomputes the chain and reports the first divergence (row id +
  expected vs stored hash), exit non-zero on divergence.
- `anchor` verifies first, then writes `{id, ts, row_hash}` for the newest row
  to a file (default `~/.safe-router/anchor/head.json`). **It refuses to write
  a head over a broken chain** — publishing a head that certifies tampered
  history is worse than publishing nothing.
- Pushing that file off-box is a **shell script + launchd job** (`docs/
  DEPLOYMENT.md`, SPEC §11 Q4's private git remote), not daemon code.

**Why the daemon must not do the push:** the safe plane's guarantee is a
process property — no remote backend, no remote credential in its address
space (invariant #2, #9). Giving it an outbound git/ssh path and a credential
to use it trades the load-bearing property for a convenience. A separate
short-lived process reading a file the daemon happens to have written keeps
the daemon exactly as inert as it is today. **If a step seems to require the
daemon making an off-box connection, that step is wrong.**

- **Check (automated):** rows 23, 24, 25 below.
- **Check (manual, `docs/TESTING.md`):** run `anchor` against the real
  `~/.safe-router/log.db`; hand-edit one row in a *copy* of the DB and confirm
  `verify-log` names that row and exits non-zero; confirm the launchd interval
  job produces a new head file and that the git push is a one-line hash, no
  client data.

---

## Step 4 — Panel read contract

Invariant #4: the panel is a separate process, reads the log, cannot write
policy. This repo's deliverable is the **contract**, not the panel.

- `Log::open_file` creates a view `v_requests_v1` with an explicit, stable
  column list (never `SELECT *` — a schema addition must not silently change
  the panel's shape). Future schema growth adds `v_requests_v2`; v1 stays.
- `docs/LOG_CONTRACT.md`: the view's columns and meanings, the required
  reader-side connection string (`file:…?mode=ro` + `PRAGMA query_only=1`),
  the rule that `client_tag` is untrusted, client-controlled text that
  **must be escaped on render** (§8.1), and the explicit statement that there
  is no HTTP interface and will not be one.
- No daemon changes beyond the view. **No read endpoint, no socket, no IPC.**
  The panel opens a file.

- **Check:** a test that a read-only connection can query `v_requests_v1`
  while the writer is active, and that a write attempt through a `query_only`
  connection fails. `docs/LOG_CONTRACT.md` exists and matches the view.

---

## Step 5 — Ship hygiene carry-over

- [x] Push to `origin` and confirm CI is actually green. **Done 2026-08-14**
  (with go-ahead): first-ever CI run caught a real bug — `deny` ran on
  `macos-latest`, but `cargo-deny-action` is a Linux-only container action.
  Fixed (moved to `ubuntu-latest`), pushed again — `test`/`audit`/`deny` all
  green.
- [x] Re-run `cargo audit` / `cargo deny check` with `sha2` added. Done in
  Step 3 (local) and now in CI (above) — both clean.
- Sign + notarize: still blocked on a Developer ID cert. If one exists by
  then, run the documented commands; if not, keep it documented and blocked —
  do not ship an unsigned binary to a second machine, because Step 1 just made
  "a second machine" a real deployment target.
- launchd: **partially done 2026-08-14** (with go-ahead). Safe plane loaded
  as a `LaunchAgent`, running (`127.0.0.1:8787` LISTEN). Escalation plane
  loaded but refuses to start — no Keychain item `safe-router/openai` on
  this machine, invariant #1 fail-closed working as designed. Needs a real
  OpenAI key stored under that item before it will come up; not fabricated
  here (real credential). Anchor interval job **loaded and verified
  2026-09-03** — push script + off-box remote now built (docs/TESTING.md
  Step 11). See docs/TESTING.md Step 8 §2.
- Safe-plane PF egress lock (SPEC.md:120-121): **scoped 2026-08-14, deferred.**
  Turns out to be more than "add a PF rule": `_saferouter` is a headless
  system account with no login session, so the safe plane would have to move
  from its current `LaunchAgent` to a `LaunchDaemon` (root's launchd,
  `UserName` key) — which means `~/.safe-router/{bin,safe.toml,log.db}`
  ownership/permissions need to change for a second local user, on top of
  the PF anchor + `/etc/pf.conf` edit + a boot-time enable. Real risk of
  misconfiguring the host firewall or breaking the now-working safe plane's
  file access. SPEC.md:121 already frames this as "later hardening, not
  v0" — not part of the TCB, pure defense-in-depth against side-exit egress
  (dependency telemetry, crash reporters, DNS) that invariant #2's keyless
  config doesn't stop (CLAUDE.md Known landmines). Left documented-but-not-
  built; revisit as its own scoped step, not folded into Step 5.
  **System-level side effect — needs an explicit go-ahead when picked up.**
  Re-checked 2026-08-20 against outside pentester-perspective input claiming
  "two rules, 20 minutes" (own user, block out on that user, pass on lo0):
  the PF rules themselves are that cheap, but *this* project's cost is the
  `LaunchAgent`→`LaunchDaemon` migration + file ownership restructuring
  above, which his framing assumes is already done. Scope estimate stands.
  Once that dedicated user exists, also `launchctl bootout`/unload
  `com.apple.ReportCrash` for it in the same step (CLAUDE.md Known
  landmines) — same prerequisite, no reason to split into a second
  system-level go-ahead.

---

## New failure-matrix rows (SPEC §6, added by Step 0a)

Same discipline as rows 1–16: **one named integration test per row.** A row
without a test is an unimplemented requirement.

| # | Failure mode | Required behavior |
|---|---|---|
| 17 | Inbound `Host` not loopback and not in `allowed_hosts` | 403 `policy_bad_host`, logged as `denied_auth`. Comparison only — the router never resolves a name to decide this. |
| 18 | `[server] bind` is `0.0.0.0`, LAN, or public | **Refuse to start.** Distinct message naming the offending address. |
| 19 | Safe-plane backend `base_url` on the tailnet vs on the LAN | `100.64.0.0/10` literal accepted; LAN, public, and `*.ts.net` names refused at startup. |
| 20 | `/v1/messages` resolves to an openai-dialect chain (or `/v1/chat/completions` to an anthropic one) | 403 `policy_dialect_mismatch`, before any upstream byte. Permanent-reading. |
| 21 | A route chain whose rungs span two dialects | **Refuse to start.** Advancing a rung must never change wire protocol. |
| 22 | Client sends `x-api-key` / `Authorization` to `/v1/messages` | Consumed by the router as its own key; never forwarded. Upstream sees only the Keychain-sourced provider credential. |
| 23 | Daemon restart mid-log | Chain continues across the restart: the first post-restart row's `prev_hash` equals the last pre-restart row's `row_hash`. |
| 24 | A row is edited directly in the DB | `verify-log` names the first divergent row and exits non-zero; `anchor` refuses to publish a head. |
| 25 | Log-write failure period (row 11) then recovery | Buffered rows never enter the chain. The chain stays internally valid across the gap, and the gap is visible (degraded flag + `id` discontinuity), never papered over. |

Row 12 gains a dialect note and two named tests: `matrix_row_12c_messages_
safe_mismatch_terminal`, `matrix_row_12d_messages_escalation_passthrough`.

---

## Definition of done (Phase 2)

- Rows 17–25 green, row 12c/12d green, rows 1–16 still green; clippy
  `-D warnings` clean; `cargo test` green.
- Both planes start from amended example configs and serve real traffic:
  safe plane over the tailnet from the Mac Mini, escalation plane serving real
  Claude Code over `/v1/messages` (manual, TESTING.md).
- `verify-log` passes over the real `log.db`; one anchor head pushed off-box.
- `docs/LOG_CONTRACT.md` written; `docs/DEPLOYMENT.md` updated (Tailscale ACL,
  Claude Code's plane move, anchor remote).
- Only `sha2` added to the dependency list, justified in its commit.
- Phase report lists every manual TESTING.md step still unverified.
- Then stop. Wait for `PHASE 2 ACCEPTED`.

## Explicitly out of scope (Phase 3+ leak detector)

Response screening, the PII tripwire, adaptive selection within the local
tier, cross-dialect translation, any runtime-mutable policy surface, token
counting as a policy input, an HTTP read endpoint for the log, the Logic Loop
panel's own UI, multi-user anything, per-peer Tailscale identity in the
admission path, a Bedrock/Vertex Anthropic variant, Anthropic's
`count_tokens`/batches/Files endpoints. If any of these appears in a diff, the
phase has drifted.

---

## Decisions this plan makes that you may want to overrule

Listed so approval is informed rather than implied:

1. **The daemon never pushes the anchor** (Step 3). A separate offline
   subcommand + launchd job does. Costs one more moving part; keeps the safe
   plane's "no off-box path, no credential" process property intact.
2. **No Tailscale peer identity in admission** (Step 1). Bearer key remains
   the only identity. Invariant #8.
3. **MagicDNS names are inbound-only** (Step 1). A safe-plane backend must be
   a literal tailnet IP.
4. **`allowed_hosts` defaults to loopback-only** (Step 1), so a v0 config
   keeps v0 behavior and the widening is always explicit.
5. **`/v1/messages` errors are Anthropic-shaped** with the router's code in
   `router_code` (Step 2), rather than one OpenAI-shaped envelope everywhere.
6. **Step order puts the boring hygiene first** (Step 0). The error-code bug
   it fixes is small; the response-extension change it makes is what keeps
   Step 2's second error shape from costing anything.
