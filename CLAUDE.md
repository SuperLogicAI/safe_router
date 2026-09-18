# CLAUDE.md — Safe Router

Headless single-user model router for macOS. Sits on loopback, accepts
OpenAI-compatible requests from local clients, and structurally guarantees that
traffic from designated clients cannot reach a third-party inference provider.
Full spec: docs/SPEC.md

## Process rules (non-negotiable)

- **Phase boundaries are hard stops.** Do not begin phase N+1 work until the
  user writes the literal token `PHASE N ACCEPTED`. Absence of objection is not
  approval. If waiting, say so and stop.
- Before each phase: write/update PLAN.md for that phase only, get approval,
  then build. Plan revisions mid-phase must be stated explicitly, never silent.
- **Changing an architecture invariant below requires an explicit written
  amendment in docs/SPEC.md with a date and a reason.** Do not soften one in
  passing while implementing something else. If a task seems to require
  violating an invariant, stop and say so — that is the signal that the task is
  wrong, not the invariant.
- Manual test steps a machine can't verify go in docs/TESTING.md and are called
  out at the end of the phase report.
- **No system-level side effects without asking first**: installing toolchains,
  modifying anything in `~` outside `~/.safe-router/`, changing global config,
  writing launchd plists, touching Keychain entries other than this app's own.

## Architecture invariants (decided — do not revisit)

1. **Fail closed.** Every failure is terminal within the tier the requesting key
   authorizes. Invalid config means the daemon refuses to start. There is no
   default, no fallback, no degraded mode.
   *This is the opposite of Logic Loop's invariant #2 (fail open). If you have
   Logic Loop's conventions in context, do not import that habit here. Logic
   Loop breaking costs a panel; this breaking costs a confidentiality guarantee.*
2. **Split-plane.** Two processes from one binary. The safe plane's config
   contains no remote backends and no remote credentials — the local-only floor
   is a property of what the process *has*, not of a branch in the code. A key
   authorized for one plane must not exist in the other; startup validation
   fails if a key hash appears in both.
3. **No runtime-mutable policy.** Policy is static TOML loaded at startup.
   SIGHUP reloads with full validation and keeps the old config on invalid. No
   admin API, no config endpoint, no settings UI in the daemon, no policy write
   path over the network. Ever.
4. **No GUI, no WebView, no npm, no Tauri in the daemon.** Headless Rust only.
   Any dashboard is a separate process that reads the log and cannot write
   policy.
5. **Passthrough only.** The router parses the request body only enough for
   admission (bearer key, `model`, `stream`, presence of `tools`). Response
   bytes stream through untouched. No cross-dialect translation — not now, not
   in v1. Per-dialect passthrough scales linearly; translation scales
   combinatorially and is how this project dies.
6. **No silent substitution, in any direction.** A request naming a concrete
   model gets that model or an error. Substitution occurs only when the client
   names a *route alias*, which is itself the consent. Remote→local downgrade is
   as forbidden as local→remote escalation: the first is an integrity violation,
   the second a confidentiality violation. Both are bugs.
7. **Backends are unreachable except through the router.** A guarantee about
   traffic through the chokepoint is void if the backend has a second door.
   LM Studio binds loopback; the router is the only advertised path.
8. **Authentication must be boring.** Constant-time comparison against argon2id
   hashes loaded from a static file. No database, no query language, no parser,
   no dynamic dispatch anywhere near the auth path. LiteLLM's CVE-2026-42208 was
   SQL injection in exactly this position.
9. **The client never holds a remote credential.** Provider keys exist in
   exactly one process, sourced from Keychain. This is the single largest
   security gain of the project; do not build a feature that erodes it.

## Code conventions

- Rust only in the daemon. Minimal, mainstream dependency set: tokio,
  hyper/axum, rustls, serde. Adding a dependency is a decision, not a
  convenience — justify it in the PR/commit message.
- `cargo clippy --all-targets -- -D warnings` clean and `cargo test` green are
  merge gates, run before reporting done.
- `cargo-audit` and `cargo-deny` run in CI. Lockfile pinned and committed.
- **Every row of the failure matrix (docs/SPEC.md §5) has a named integration
  test.** The matrix is the test plan; a row without a test is an unimplemented
  requirement, not a documentation gap.
- Config parsing and policy evaluation live in one module with no I/O, so they
  are unit-testable without a running server.
- Errors returned to clients are well-formed OpenAI-shaped error JSON with
  distinct machine-readable codes. Agent clients retry ambiguous errors in
  loops; a policy denial must read as permanent.
- No auto-update mechanism, ever. An auto-updater is a remote code execution
  channel with a nice UI. Updates are manual, from signed builds.

## Known landmines

- **Context overflow is the most tempting invariant violation.** A local model
  rejecting an oversized request looks exactly like a case where "just retry it
  on the big remote model" is obviously correct. It is not. Pass the 400
  through. If this ever gets implemented, the floor is gone and nothing will
  visibly break to tell you.
- **Remote→local downgrade feels safe and isn't.** It leaks nothing, so it will
  pass a confidentiality review — but the client believes it received frontier
  output. Silent substitution is a bug in both directions (invariant #6).
- **LM Studio's OpenAI-compatible server is unauthenticated.** While it listens
  on a tailnet or LAN address, every control in this project is decorative:
  anything on the network can talk to the models directly. Binding it to
  loopback is a prerequisite for the guarantee, not a hardening step. Re-verify
  after any LM Studio upgrade.
- **The transparency log is not a trust anchor.** Single machine, single writer:
  anything that can write the log can rewrite the chain and recompute every
  hash. Either push the chain head off-box on an interval, or call it "a log"
  and claim nothing more. Do not ship the word "tamper-evident" without the
  anchor.
- **Anthropic's OpenAI-compatibility layer is test-grade — do not use it as a
  backend.** Verified 2026-08-13: it supports tool calling but silently ignores
  unsupported fields and hoists system messages, mutating request structure.
  Anthropic joins in v1 via the Messages passthrough dialect, never via the
  compat layer and never via a translation shim (invariant #5).
- **`X-Safe-Router-Tag` / `client_tag` is an opaque label with no policy
  meaning.** Logged verbatim for join-ability by external tools; must never
  influence routing, admission, or plane selection. It is untrusted,
  client-controlled data: max 128 bytes, control characters rejected,
  parameterized insert only, escaped on render by any consumer. The header name
  is fixed — never make it configurable (a user-supplied name like
  `Authorization` would log credentials into the database).
- **You, in a hurry, are the most probable adversary.** The likeliest cause of a
  floor violation in year one is a config edit at midnight, not an attacker.
  This is why invariant #3 exists. Resist every request to add a convenience
  that mutates policy at runtime, including from the user.
- **A keyless config stops credentialed egress, not all egress.** Invariant #2
  removes remote keys/addresses from the safe plane's config, which stops the
  router code itself from calling out. It does nothing about side exits: logs
  shipped to a collector, a crash reporter, telemetry in a dependency, DNS
  lookups. Independently flagged 2026-08-14 by an outside pentester-perspective
  review (`pentester_perspective/` — local only, untracked: not ours to
  publish) that converged on the same split-plane design from a different
  angle. Mitigation already on record, not yet built:
  PF egress lock, SPEC.md:120-121, tracked as a Phase 2 Step 5 item in
  PLAN.md.
- **Key issuance is outside the TCB.** Invariant #2 guarantees the two planes'
  key sets don't overlap, not that a given key went to the right client. Handing
  a general-plane key to a client that will handle sensitive data defeats the
  guarantee with no error, no log line, nothing to detect it — the router did
  exactly what it was configured to do. Who gets which key is a human decision
  made outside this repo, every time, correctly. Two cheap conventions shrink
  the blast radius without pretending to close the hole (flagged by outside
  pentester-perspective review, 2026-08-20): **default new clients to the safe
  plane** — moving a client to the general plane is the deliberate extra step,
  so the lazy failure mode is "client ran on a smaller model" instead of
  "client data left the building"; and **prefix keys `sp_` / `gp_`** so a
  misplaced key looks wrong sitting in the wrong config file. Neither is a
  control the router enforces — both are provisioning habit.
- **macOS crash reporting is a side exit the config audit won't find.**
  `com.apple.ReportCrash` writes a crash report to `~/Library/Logs/
  DiagnosticReports` on any panic of the safe-plane process, unconditionally —
  no opt-in in this codebase required. If analytics sharing is enabled or the
  machine is MDM-enrolled, that report can leave the box through a channel
  invariant #2's keyless config says nothing about. Flagged 2026-08-20 by the
  same outside pentester-perspective review. Mitigation: run the safe plane as
  its own dedicated user and `launchctl bootout`/unload `com.apple.ReportCrash`
  for that user — bundle into the Step 5 PF egress work, not a separate task.
- **Redeploying the binary with a plain `cp` onto a path a running
  safe-router process has open corrupts its code signature.** The kernel's
  code-signing check (independent of Gatekeeper/`spctl`) then SIGKILLs every
  future exec of that path — silently: no log line, `launchctl list` just
  shows exit `-9` forever. Discovered 2026-08-14 rebuilding for the Anthropic
  dialect test (docs/TESTING.md Step 10). Since both planes' launchd jobs
  point at the same `~/.safe-router/bin/safe-router` path, this can take out
  a plane that was fine seconds earlier, and — worse — leaves a *currently
  running* plane unable to restart if it ever needs to, which is a fail-closed
  router that can't come back up. Always redeploy via temp-file + `mv`
  (atomic rename), never a direct `cp` over the live path.
- **A plain `cp` of `log.db` while it's in WAL mode gives a silently stale
  copy, not an error.** Discovered 2026-09-03 building the Step 11 tamper
  test (docs/TESTING.md): a `cp`'d copy had 6 of the real 16 rows, all
  pre-hash-migration, and `verify-log` happily reported "chain OK" against
  data that was simply wrong rather than tamper-free — no warning anywhere.
  `sqlite3 log.db ".backup <path>"` (SQLite's backup API, which accounts for
  committed WAL content) is the only correct way to copy the live log for
  testing, inspection, or backup. Same shape of failure as the binary
  redeploy landmine above: a filesystem-level copy of something SQLite/WAL
  is still writing looks fine and isn't.

## Phase status

- Phase 0 (spec): docs/SPEC.md written 2026-08-14 — **ACCEPTED 2026-08-13**
- Phase 1 (v0 daemon): plan approved 2026-08-13, build starting (Step 1) —
  **ACCEPTED 2026-08-14**. All 8 steps built, all 16 failure-matrix rows have
  named tests, manual verification in docs/TESTING.md complete except
  Step 8's signing (blocked — no Developer ID cert configured) and launchd
  install (deferred — deploy-time action, not a test-completion checkbox).
- Phase 2 (v1: tailnet, second dialect, log anchoring, Logic Loop panel):
  plan approved 2026-08-14 (PLAN.md). Steps 0-4 built and committed
  2026-08-14 (143 tests, clippy clean). Step 5 (ship hygiene carry-over:
  push to origin, signing, launchd): pushed to origin, both plane launchd
  jobs loaded 2026-08-14; signing still blocked (no Developer ID cert); PF
  egress lock + crash-reporter unload still deferred (system-level,
  needs the dedicated-user prerequisite, PLAN.md). Manual-only verification
  tracked in docs/TESTING.md Steps 9-11: Step 10 (Anthropic Messages
  dialect) **verified 2026-08-14/15** with real Claude Code, real Keychain
  credential — DEPLOYMENT.md's client→plane table updated (Claude Code:
  escalation). Step 11 (log anchor + off-box push) **verified 2026-09-03**
  — real `anchor`/`verify-log` against the live log, push script deployed
  and pushing real commits to `github.com/SuperLogicAI/log-anchor`, anchor
  launchd job loaded and confirmed firing hourly. Step 9 (tailnet) not yet
  run — needs a second tailnet device.
- Phase 3 (screening / tripwire / local-tier adaptive selection): gated on an
  actual incident or client requirement — do not build speculatively

Update this section as phases are accepted.
