# TESTING.md — manual verification steps

## 2026-09-13 — versioned usage-log observability sprint

At implementation time, no live-system manual test was run or required for
this router-side sprint.
The automated suite uses local mock OpenAI and Anthropic backends to verify
buffered/streamed usage, byte passthrough, schema migration, read-only access,
and hash integrity. A future Logic Loop integration check must separately
prove that each supported client emits `X-Safe-Router-Tag` with its tab id;
the router cannot obtain `LOGIC_LOOP_TAB_ID` from the agent environment.
At that point, live config, Keychain, launchd, client settings, and deployed
binaries were not changed.

**Live follow-up, 2026-09-13:** Built `master` in release mode, verified its
code signature, and atomically replaced `~/.safe-router/bin/safe-router` via
a staged file in the same directory. A `launchctl kickstart -k` of each
existing job exited with `OS_REASON_CODESIGNING` even though the new binary
passed `codesign --verify` and executed directly. `launchctl bootout` then
`bootstrap` of the existing plists refreshed launchd's policy; both safe and
escalation listeners returned on `127.0.0.1:8787` and `:8788`. Future
binary redeploys should include that job reload and a listener check.

Ran the installed binary on a temporary safe-plane config at
`127.0.0.1:18787`, using a temporary key and the already-running local
LM Studio backend. No live plane config or Keychain item changed. A tagged,
non-streaming request to `nvidia/nemotron-3-nano` returned HTTP 200; a
read-only `v_requests_v2` query found `client_tag=logic-loop-smoke-tab`,
`model_served=nvidia/nemotron-3-nano`, `tokens_in=21`,
`tokens_out=7`, and `usage_state=complete`. The temporary process and
config were removed afterward. An initial request for the larger
`qwen2.5-72b-instruct` returned HTTP 400 from LM Studio's resource guard;
its log rows correctly have NULL usage and `usage_state=not_recorded`.
`verify-log` reported the chain OK after the test.

Steps a machine can't verify (real LM Studio, real Keychain, real launchd,
real signing). Numbered per phase step; append, don't renumber.

## Step 1 — Skeleton + auth

1. `echo -n "<key>" | cargo run -- hash-key` and confirm output is a
   `$argon2id$v=19$...` PHC string.
2. Write a `safe.toml` with a `[[key]]` using that hash, `cargo run --
   --config safe.toml`, confirm it binds and logs "listening".
3. `curl -H "Authorization: Bearer <key>" http://127.0.0.1:8787/v1/models`
   with no backend configured → `502 backend_not_configured`.
4. Same request with a wrong/missing key → `401 auth_unknown_key`.
5. Same request with `-H "Host: evil.example.com"` → `403 policy_bad_host`.

**Verified 2026-08-13.** All five behaved as expected.

## Step 2 — Passthrough proxy

Prerequisite: LM Studio running, bound to loopback (`docs/DEPLOYMENT.md`
checklist), at least one model loaded.

1. Add a `[[backend]]` block to `safe.toml` pointing at
   `http://127.0.0.1:1234/v1`, restart the router.
2. `curl -H "Authorization: Bearer <key>" http://127.0.0.1:8787/v1/models`
   → 200, model list matches LM Studio's own `/v1/models` output verbatim.
3. Non-streaming chat completion (`"stream": false`) through the router →
   200, full JSON body, `model` field matches the model that answered.
4. Streaming chat completion (`"stream": true`) through the router → SSE
   chunks arrive incrementally (not buffered until the end — watch `curl -N`
   output land token-by-token), terminated by `data: [DONE]`.
5. Idle timeout: not exercised against real LM Studio (nothing in the stack
   naturally stalls for 60s). Covered by unit logic only; a forced-stall
   integration test is deferred to Step 6 when `tests/support.rs` grows a
   stalling mock endpoint.
6. Client disconnect mid-stream against *real* LM Studio (optional — the
   mechanism is already covered by an automated integration test,
   `client_disconnect_cancels_upstream` in `tests/proxy_passthrough.rs`,
   against a mock backend that proves the upstream request stops advancing
   once the client drops the body). Manual variant: start a streaming
   request, `Ctrl-C` the `curl` before it finishes, confirm via LM Studio's
   own activity indicator that generation stops.

**Verified 2026-08-13** (steps 1–4). Real request end-to-end: `/v1/models`
listed `qwen/qwen3.6-35b-a3b` and others; non-streaming completion returned
200 with matching `model` field; streaming completion arrived as incremental
SSE chunks terminated by `data: [DONE]`, byte-for-byte from LM Studio.
Step 5 (idle timeout) deferred as noted — no real-backend stall to test
against yet. Step 6 (cancellation) verified automatically instead of
manually; the real-LM-Studio variant is optional and not yet run.

## Step 3 — Admission + config validation

1. Config with a `[[backend]]` `base_url` pointing off-loopback (e.g.
   `http://192.168.1.50:1234/v1`) on a `plane = "safe"` config → process
   exits 1, `refusing to start: safe-plane backend '<id>' has non-loopback
   base_url ...`.
2. Two config files in the same directory, named `safe.toml` and
   `escalation.toml`, sharing one key hash → starting against either one
   exits 1 with `key hash appears in both plane configs ...`, naming the
   peer file.
3. Start with a valid config, `curl` a `model` outside the key's `allow`
   list → `403 policy_denied_model`. A `model` inside `allow` → passes
   admission (502/whatever the backend does, not 403).
4. Edit the running config's `allow` list, `kill -HUP <pid>`, re-`curl` →
   new list takes effect immediately (old entries now denied, new ones
   admitted) with no restart.
5. Break the config file (invalid TOML), `kill -HUP <pid>` again → daemon
   keeps serving the *previous* valid config; logs an `ERROR` naming the
   parse failure.

**Verified 2026-08-13**, all five, against the real binary (not mocks):
non-loopback backend and cross-plane collision both refused to start with
the expected message and exit code 1. Live SIGHUP reload flipped a key's
allowed model from `model-v1` to `model-v2` with zero downtime — `model-v2`
went 403→502 (admitted) and `model-v1` went 502→403 (revoked) across the
same running process. A second SIGHUP with deliberately-broken TOML kept
serving the `model-v2` config and logged the parse error instead of
crashing or blocking.

## Step 4 — Escalation plane

1. `[[provider]]` config with a `keychain_item` that doesn't exist yet →
   process exits 1, `refusing to start: cannot fetch credential for
   provider '<id>' ...`, quoting the real `security` CLI's error.
2. **Requires the user's go-ahead before this one** — creates a real
   Keychain item: `security add-generic-password -a safe-router -s
   safe-router/openai -w '<real OpenAI API key>'`. Then start the
   escalation plane and send a real chat completion through it; confirm
   OpenAI answers (200, real completion) and that `ps`/`lsof`/process
   inspection shows the key exists only in this daemon's memory, never in
   `escalation.toml` or the client's own config.
3. Confirm a safe-plane request's logs/headers never show an
   `Authorization` header reaching the local backend (already covered by
   an automated test against a mock backend; this is the real-LM-Studio
   sanity check).

**Verified 2026-08-13** (step 1): real `/usr/bin/security` lookup against a
nonexistent item correctly refused to start, quoting
`SecKeychainSearchCopyNext: The specified item could not be found`.

**Verified 2026-08-14** (step 2, with go-ahead): real `safe-router/openai`
Keychain item added, escalation plane started against it (`~/.safe-router/
escalation.toml`, route `frontier-cheap-test` → `openai/gpt-4o-mini`), and a
real chat completion request was sent through it with a fresh test key
(`manual-test-escalation-1`). The account had no OpenAI billing/quota
configured, so the response was a real, passed-through `429
insufficient_quota` rather than a 200 — accepted as sufficient per user
decision, since a 429 vs 200 doesn't change what this step verifies (the
key is valid and reaches OpenAI; the router relays whatever comes back
untouched). Process inspection (`ps`, `ps eww`, config file contents)
confirmed the credential existed only in the running daemon's memory: no
key material in the process command line, environment, or
`escalation.toml` (which holds only the `keychain_item` pointer). Test
Keychain item deleted immediately after (`security delete-generic-password`,
confirmed gone via a follow-up `find-generic-password` failure). The
OpenAI key itself still needs revoking/rotating on the user's end — deleting
the local Keychain entry doesn't invalidate the key.

Step 3 (safe-plane request never leaks an `Authorization` header to the
local backend) not run manually — already covered by an automated test
against a mock backend; the real-LM-Studio variant remains optional per the
original note above.

## Step 5 — Route aliases + chain advancement

Note for concrete-model/alias requests: the client-facing `model` field must
now be either a route alias name, or a `<backend_id>/<model>` composite
matching a configured `[[backend]]`/`[[provider]]` id (SPEC §5.3's own
example format) — a bare LM Studio model id with no prefix no longer
resolves to anything (`502 route_unresolvable`). This is Step 5 finishing
real dispatch; Steps 2–4's ad hoc bare-name testing happened to work only
because backend selection was still a stub.

1. Two-rung alias chain, rung 1 pointed at a genuinely dead backend
   (connection refused), rung 2 at real LM Studio → response is a real
   completion from rung 2; logs show `chain_pos=1` failed/advancing then
   `chain_pos=2` served.
2. **LM Studio does not validate the `model` field** — an unknown model
   name still gets 200'd by whatever's currently loaded. This means you
   *cannot* exercise the "bad model name → advance" path against real LM
   Studio; it only demonstrates via a truly-down backend (connection
   refused) or the automated tests (`tests/chain_advancement.rs`), which use
   a controllable mock to return 429/5xx on demand.
3. Concrete model via composite id (`lmstudio-local/qwen/qwen3.6-35b-a3b`)
   dispatches directly, no chain involved.

**Verified 2026-08-13**, all three, against the real binary: rung-1-dead →
rung-2-real-LM-Studio chain advancement confirmed via response content and
log lines (`chain_pos=1` connect-failed-advancing, `chain_pos=2` served,
200). Concrete composite-id dispatch confirmed with a real answer. The
429/5xx/`on_error=fail`/never-advance-on-400 paths are covered by the 6
automated tests in `tests/chain_advancement.rs`, not re-verified manually
here (real LM Studio has no easy way to produce a controlled 429/5xx).

## Step 6 — Failure matrix

All 16 rows have a named automated test in `tests/matrix.rs` (row 11 landed
with Step 7's metadata log — see below). Row 6 (router crash mid-stream) is
the one row that's a manual step instead of an automated test — invariant #1
means there's
nothing app-specific to assert against on restart (no persisted request
state, full stop, that's the entire content of the requirement), so the
only thing an automated process-kill test could verify is that a TCP
connection drops when its owning process dies, which is OS behavior, not
safe-router logic.

1. Start the real binary against a working config (safe plane, LM Studio
   loopback-bound per the Prework checklist above).
2. From a second terminal, start a streaming chat completion against it
   (e.g. `curl -N` with `"stream": true`) and confirm at least one SSE
   chunk arrives.
3. Find the daemon's pid (`pgrep -f safe-router` or the shell's own job
   control) and `kill -9 <pid>` mid-stream.
4. Confirm the `curl` connection drops (no hang, no partial-then-frozen
   output) — the client sees a dropped connection, not an error it could
   mistake for a policy response.
5. Restart the daemon against the same config and confirm it serves a fresh
   request normally — no crash-loop, no attempt to resume or replay the
   killed request (there's no request state anywhere to resume from).

**Verified 2026-08-14** against the real binary + real LM Studio
(`qwen2.5-72b-instruct`, safe plane, `~/.safe-router/safe.toml`). A
streaming completion was started (`curl -N`); first SSE chunk confirmed on
disk (cold model load took ~30s to first token — not a router issue) before
`kill -9`'ing the daemon mid-stream. The `curl` process exited immediately
with no hang and no partial-then-frozen output; the streamed file stopped
growing at the moment of the kill. Restarted the daemon against the same
config and it served a fresh non-streaming request normally (200,
`"pong"`) — no crash-loop, no resume attempt.

## Step 7 — Metadata log

15 named automated tests cover the mechanics: `tests/metadata_log.rs`
(5 tests — one row per request, correct `disposition` for
served/denied_auth/denied_policy/backend_error/client_cancel) plus
`tests/matrix.rs::matrix_row_11_log_write_failure`. Both use the in-memory
default `AppState::new` gives every test — nothing here exercises the real
`~/.safe-router/log.db` file path (`AppState::with_log_path`, wired up in
`main.rs`) end-to-end against a real backend.

1. Start the real binary against a working config (safe plane, LM Studio
   loopback-bound). Confirm `~/.safe-router/log.db` gets created on startup
   (`ls -la ~/.safe-router/`).
2. Make one real chat completion through it (streaming and non-streaming,
   one each).
3. `sqlite3 ~/.safe-router/log.db "SELECT ts, plane, key_id, model_req, model_served, disposition, status, latency_ms FROM requests ORDER BY id DESC LIMIT 5;"`
   — confirm a row landed per request, `ts` is a real RFC3339 timestamp,
   `disposition = 'served'`, `model_served` matches what LM Studio actually
   ran, `latency_ms` is a plausible number.
4. Send a request with `X-Safe-Router-Tag: manual-test-1` and confirm
   `client_tag` shows up verbatim in the row.
5. Send one request with a bad key (401) and one for a model outside the
   key's `allow` list (403); confirm both land as
   `denied_auth`/`denied_policy` rows with `key_id = 'unknown'` for the
   first (no credential material logged) and the real key id for the
   second.

**Verified 2026-08-14** against the real binary, real LM Studio, and real
`~/.safe-router/log.db` (confirmed created on startup). One streaming and
one non-streaming completion both landed as `served` rows with correct
`model_served` (`qwen2.5-72b-instruct`) and plausible `latency_ms`. A
request with `X-Safe-Router-Tag: manual-test-1` logged `client_tag`
verbatim; the untagged requests logged it empty. A bad-key request against
`/v1/chat/completions` logged `denied_auth` with `key_id = 'unknown'` (no
credential material logged) — note this must go to `/v1/chat/completions`,
not `/v1/models`, since `/v1/models` is intentionally out of scope for the
log (see `tests/metadata_log.rs`'s header comment); the first attempt used
`/v1/models` by mistake and produced no row, which is correct behavior, not
a bug. A model-outside-allow-list request logged `denied_policy` with the
real key id retained.

## Step 8 — Ship hygiene

CI (`.github/workflows/ci.yml`) runs clippy + `cargo test` + `cargo audit` +
`cargo deny check` on every push/PR, `macos-latest` (the daemon shells out to
`/usr/bin/security` and targets macOS deployment — matching the runner to the
real OS beats a green build that never ran on it). `deny.toml` allow-lists the
license set actually present in the lockfile (checked 2026-08-13 via `cargo
metadata`), not a generic template — re-check when a new dependency lands.
Both `cargo deny check` and `cargo audit` were run locally against the real
lockfile during this step (not just left for CI to discover): `cargo deny
check` → `advisories ok, bans ok, licenses ok, sources ok`, exit 0; `cargo
audit` → `Scanning Cargo.lock for vulnerabilities (216 crate dependencies)`,
zero advisories found, exit 0.

Everything below is a system-level side effect (Keychain-adjacent install
paths, launchd load, code signing) and per CLAUDE.md's process rules, none of
it runs without the user doing it by hand.

### 1. Signing + notarization

Requires an Apple Developer ID (Application) certificate in this machine's
Keychain and an app-specific password or a stored `notarytool` credential
profile. Not run — no cert configured yet.

```sh
# Release build
cargo build --release
# target/release/safe-router

# Sign with hardened runtime (required for notarization)
codesign --sign "Developer ID Application: <Your Name/Org> (<TEAMID>)" \
  --options runtime --timestamp \
  target/release/safe-router

# One-time: store notarization credentials in Keychain (interactive, asks
# for an app-specific password from appleid.apple.com)
xcrun notarytool store-credentials "safe-router-notary" \
  --apple-id "<apple-id-email>" --team-id "<TEAMID>"

# Notarize (zip a single binary — notarytool requires an archive)
ditto -c -k --keepParent target/release/safe-router safe-router.zip
xcrun notarytool submit safe-router.zip \
  --keychain-profile "safe-router-notary" --wait

# Stapling a bare Mach-O binary is not supported by `stapler` (only
# .app/.pkg/.dmg bundles) — Gatekeeper re-checks online instead, which is
# fine for a binary that never leaves this machine.

# Verify
codesign --verify --deep --strict --verbose=2 target/release/safe-router
spctl --assess --type execute -vv target/release/safe-router
```

### 2. Install layout + launchd

Plists live in `launchd/` in this repo (source of truth); loading copies them
to `~/Library/LaunchAgents/` (**agents, not `/Library/LaunchDaemons`** — a
LaunchDaemon runs as root before login and would not inherit the user's
unlocked login Keychain, which the escalation plane needs for
`/usr/bin/security` at startup; see the escalation plist's comment).

```sh
mkdir -p ~/.safe-router/bin ~/.safe-router/logs
cp target/release/safe-router ~/.safe-router/bin/
# safe.toml / escalation.toml already live at ~/.safe-router/ from earlier steps

cp launchd/com.superlogicai.safe-router.safe.plist ~/Library/LaunchAgents/
cp launchd/com.superlogicai.safe-router.escalation.plist ~/Library/LaunchAgents/

launchctl load ~/Library/LaunchAgents/com.superlogicai.safe-router.safe.plist
launchctl load ~/Library/LaunchAgents/com.superlogicai.safe-router.escalation.plist

launchctl list | grep safe-router   # both jobs listed, PID present
curl -H "Authorization: Bearer <key>" http://127.0.0.1:8787/v1/models  # 200

# Stop:
launchctl unload ~/Library/LaunchAgents/com.superlogicai.safe-router.safe.plist
launchctl unload ~/Library/LaunchAgents/com.superlogicai.safe-router.escalation.plist
```

Recall (KeepAlive is `false` on purpose, per both plists' comments): a
refused startup (bad config, unfetchable Keychain credential) exits non-zero
by design (invariant #1) and launchd cannot distinguish that from a crash —
`KeepAlive` would turn a deliberate fail-closed refusal into a silent
respawn loop. Restart is a human running `launchctl load` again after fixing
the cause.

**Signing/notarization: not yet run** — still blocked, no Developer ID
certificate configured.

**launchd load: done 2026-08-14** (with go-ahead). `~/.safe-router/bin/`
+ `~/.safe-router/logs/` created, unsigned release binary copied in, both
plists copied to `~/Library/LaunchAgents/`, both `launchctl load`ed.

- Safe plane: **running.** `launchctl list` shows PID with last exit 0;
  `lsof` confirms `127.0.0.1:8787` LISTEN.
- Escalation plane: **refused to start, as designed.** Exit code 1;
  `escalation.err.log`: `refusing to start: cannot fetch credential for
  provider 'openai' (Keychain item 'safe-router/openai'): security exited
  with status exit status: 44: ... item could not be found in the
  keychain.` No Keychain item `safe-router/openai` exists on this machine
  yet — invariant #1 (fail closed) doing exactly its job: keyless rather
  than a silent unauthenticated escalation plane. Needs a real OpenAI key
  stored via `security add-generic-password` (or equivalent) under that
  item name before this plane will start; not done here since it requires
  a real credential and CLAUDE.md forbids fabricating one.
- `curl`-with-bearer-key verification (step 3 in the block above) not run:
  the plaintext test key was never recorded anywhere (correctly — only its
  argon2id hash lives in `safe.toml`), so `lsof`/`launchctl list` stood in
  as the "is it actually up" check instead.

**CI (updated 2026-08-14):** pushed to `origin` for the first time as part
of Phase 2 — first real run caught a genuine bug: the `deny` job ran on
`macos-latest`, but `cargo-deny-action` is a Docker container action, which
GitHub Actions only supports on Linux runners (`X Container action is only
supported on Linux`). Fixed by moving `deny` to `ubuntu-latest` — it has no
macOS-specific behavior to verify, unlike `test`/`audit`, which stay on
`macos-latest` for the real `/usr/bin/security` shell-out. Re-run after the
fix: `test`, `audit`, `deny` all green
(github.com/SuperLogicAI/safe_router/actions).

## Step 9 — Tailnet bind (Phase 2 Step 1)

Matrix rows 17-19 have automated tests (`tests/matrix.rs`). Everything below
needs a second real tailnet device (the Mac Mini) and a Tailscale ACL, so it
stays manual.

1. Apply a Tailscale ACL restricting `:8787`/`:8788` to named devices; paste
   the applied ACL JSON into `docs/DEPLOYMENT.md`.
2. Set `[server] bind = "100.x.y.z:8787"` (this machine's tailnet IP) and
   `allowed_hosts = ["100.x.y.z"]` in `safe.toml`, restart the router.
3. From the Mac Mini (a tailnet peer): `curl -H "Authorization: Bearer <key>"
   -H "Host: 100.x.y.z:8787" http://100.x.y.z:8787/v1/models` → 200.
4. From a LAN-only host on the same Wi-Fi but **not** on the tailnet: the
   same request → connection refused (the router isn't listening on the LAN
   interface at all — this is a TCP-level refusal, not a 403).
5. `curl -H "Host: evil.example.com" ...` against the tailnet listener → 403
   `policy_bad_host`.
6. Re-verify LM Studio is bound to loopback on **every** tailnet node
   (`docs/DEPLOYMENT.md`'s checklist) — confirm after every restart/upgrade,
   on each machine, not just this one.

**Not yet run** — needs a second tailnet device and a live Tailscale ACL
change; ask before applying an ACL that affects other tailnet traffic.

## Step 10 — Anthropic Messages dialect (Phase 2 Step 2)

Matrix rows 20-22, 12c/12d have automated tests (`tests/anthropic_dialect.rs`).
The one thing that needs a real Claude Code + real Anthropic credit stays
manual:

1. Create Keychain item `safe-router/anthropic` with a real Anthropic API
   key.
2. Add an `[[provider]] dialect = "anthropic"` block to `escalation.toml`
   pointing at `https://api.anthropic.com`, plus a route/key allowing it.
3. Point Claude Code at the escalation plane: `ANTHROPIC_BASE_URL=
   http://127.0.0.1:8788`, `ANTHROPIC_AUTH_TOKEN=<router key>`.
4. One streaming turn, one tool-using turn — confirm both work end to end
   and that the response is indistinguishable from talking to Anthropic
   directly.
5. Update `docs/DEPLOYMENT.md`'s client→plane table (Claude Code moves from
   "none (direct)" to escalation) once this is actually done — not before.

**Verified 2026-08-14/15** (with go-ahead), real `safe-router/anthropic` Keychain
item (short-lived test key, expires ~2026-08-21 — rotate/delete after), real
Claude Code session. `[[provider]] dialect = "anthropic"` added to
`escalation.toml` alongside the existing `openai` provider; route named
`claude-sonnet-5` (chain `["anthropic/claude-sonnet-5"]`) — named to match
Claude Code's real outbound `model` field exactly, not an arbitrary alias, so
admission is a literal-match, not a substitution (invariant #6 stays clean).
`ANTHROPIC_BASE_URL=http://127.0.0.1:8788` + `ANTHROPIC_AUTH_TOKEN=<test key>`
pointed a real Claude Code session at the escalation plane. One plain turn,
one tool-invoking turn (directory listing — real `LS` executed and reasoned
over), and one long-answer turn all confirmed working through the router;
the long-answer turn streamed incrementally (not buffered-then-dumped),
confirming SSE passthrough on the Anthropic dialect the same way Step 2
confirmed it on the OpenAI dialect. `docs/DEPLOYMENT.md`'s client→plane table
updated: Claude Code moved from "none (direct)" to escalation.

Two real issues surfaced and are worth keeping on record:

1. **A `cp` redeploy over a live-mapped binary corrupts its code signature.**
   Rebuilding and `cp`-ing a new `safe-router` binary directly onto
   `~/.safe-router/bin/safe-router` — the same path the already-running
   safe-plane process (from Step 8's launchd load) had open — produced a
   binary that the kernel refused to exec at all: `load code signature error
   2`, `AppleSystemPolicy: Security policy would not allow process`, SIGKILL
   before any app code ran (`launchctl list` showed exit `-9`, zero log
   output). Gatekeeper/`spctl` was a red herring chased first (its assessment
   also said "rejected," and toggling "Allow apps from anywhere" did nothing
   — confirmed by re-testing with Gatekeeper back to normal afterward and
   the binary still working fine). The actual fix was deploying atomically:
   `cp` to a temp file in the same directory, then `mv` (atomic rename) onto
   the live path, which never disturbs a process still mapped from the old
   inode. **Every future manual redeploy must use temp-file + `mv`, never a
   direct `cp` onto a path a running safe-router process has open** — this
   is now the standard redeploy step, not a one-off workaround.
2. **A bare client-sent model name only resolves via an exact route-alias
   match (Step 5's rule, re-confirmed here).** Claude Code sends its own
   real model id (`claude-sonnet-5`) with no dialect/backend prefix. The
   route was initially named `claude-test`, which doesn't match that string,
   so admission correctly 403'd (`denied_policy`) — Claude Code's UI
   surfaced this as a generic "Please run /login" prompt, which is
   misleading (it's a router policy denial, not an auth/session problem);
   `sqlite3 log.db` showing `disposition = denied_policy` was what actually
   confirmed the cause. Fixed by naming the route exactly `claude-sonnet-5`
   to match — since the alias name equals the real backing model, this is a
   literal pass-through, not a substitution, so invariant #6 holds.

## Step 11 — Log hash chain + off-box anchor (Phase 2 Step 3)

Matrix rows 23-25 have automated tests (`tests/log_chain.rs`), including
`verify-log`/`anchor` against the real binary on synthetic logs. What's left
needs the real `~/.safe-router/log.db` and a real off-box remote:

1. `safe-router anchor` against the real log — confirm it writes
   `~/.safe-router/anchor/head.json` and prints the anchored row id.
2. Hand-edit one row in a **copy** of the real `log.db` (never the live
   file) and confirm `safe-router verify-log --log <copy>` names that row
   and exits non-zero.
3. Write the push script (`docs/DEPLOYMENT.md`, SPEC §11 Q4's private git
   remote) and a launchd interval job calling `anchor` then the push script.
   Confirm a run produces a new head file and that the git push is a
   one-line hash — no client data in the commit.
4. Load the launchd job and confirm it fires on interval.

**Verified 2026-09-03** (with go-ahead), against the real `log.db` and a real
off-box remote (`docs/DEPLOYMENT.md`).

1. `safe-router anchor` against the real log wrote `~/.safe-router/anchor/
   head.json` (`{"id": 16, "ts": "2026-08-15T03:49:28Z", "row_hash": ...}`)
   and printed `anchored row 16 ...`.
2. Tamper test on a **copy** confirmed `verify-log` names the exact edited
   row and exits non-zero: `UPDATE requests SET disposition = 'tampered'
   WHERE id = 8` on a copy produced `chain diverges at row 8: expected
   prev_hash/row_hash '...', stored Some("...")`, exit code 1.
   - **Gotcha:** a plain `cp` of `log.db` while it's in WAL mode gives a
     silently *stale* copy — the first attempt copied only 6 of 16 rows,
     all pre-hash-migration (`row_hash` NULL), and `verify-log` reported
     "chain OK" against data that was simply wrong, not tamper-free. No
     error, no warning. Fixed by copying with `sqlite3 log.db ".backup
     <path>"` instead, which goes through SQLite's backup API and picks up
     committed WAL content. **Any future manual copy of `log.db` — for
     testing, inspection, backup — must use `.backup`, never `cp`.** Same
     family of failure as the binary code-signature landmine (CLAUDE.md):
     a tool that looks fine on a live SQLite/WAL file silently isn't.
3. Push script `scripts/anchor-push.sh` written, deployed to
   `~/.safe-router/bin/anchor-push.sh` (same temp-file-then-`mv` convention
   as the binary). Runs `anchor`, clones/pulls the local mirror of the
   off-box remote at `~/.safe-router/anchor-repo`, copies `head.json` in,
   and commits+pushes only if it changed. First real run produced a real
   commit (hash + row id + timestamp only — no client data) at
   `github.com/SuperLogicAI/log-anchor@3cb9cc9`; a second run correctly
   no-op'd since nothing had changed.
   - **Bug caught during this verification:** the no-op check originally
     used `git diff --quiet -- head.json`, which does not detect an
     **untracked** file — the very first push (repo had no `head.json` yet)
     silently skipped, reporting "unchanged" for a file that didn't exist
     yet. Fixed to `git status --porcelain -- head.json`, which catches
     untracked/modified/staged alike. Re-verified: first run now pushes,
     repeat runs correctly no-op.
4. Launchd job (`launchd/com.superlogicai.safe-router.anchor.plist`,
   `StartInterval` 3600s, no `RunAtLoad`) copied to `~/Library/LaunchAgents/`
   and loaded. Confirmed via `launchctl start` (forced, not waiting an hour)
   that the real launchd-triggered run matches the manual run exactly —
   `anchor.out.log`/`anchor.err.log` show the same anchor id and correct
   no-op (nothing had changed since the manual verification run above).
