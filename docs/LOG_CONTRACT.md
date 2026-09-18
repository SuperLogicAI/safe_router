# LOG_CONTRACT.md — the versioned metadata-log read surface

Invariant #4: any dashboard is a separate process that reads the log and
cannot write policy. This file is the contract for any independent reader.
The optional Logic Loop panel lives in Logic Loop's repo, not this one.

**There is no HTTP interface for the log, and there will not be one.** No
read endpoint, no socket, no IPC. A panel gets at this data by opening the
SQLite file directly, the same way any other read-only tool would.

---

## The view: `v_requests_v1`

`~/.safe-router/log.db` has a table (`requests`, SPEC §8's schema, the
router's own write surface — not part of this contract and not guaranteed
stable) and versioned views, created by the daemon itself at
startup (`Log::open_file` / `Log::open_in_memory`, `src/log.rs`).

**Read a versioned view, never `requests` directly.** The view is the
contract; the table is an implementation detail that can and will grow new
columns as the router grows. `v_requests_v1` is defined with an explicit
column list — never `SELECT *` — so a future schema addition to `requests`
does not silently change what a v1 reader sees. If the row shape ever needs
to change or grow, that lands in a new view; `v_requests_v1` keeps its
current meaning.

### Columns

| Column | Type | Meaning |
|---|---|---|
| `id` | INTEGER | Monotonic row id. Gaps are meaningful (SPEC §6 row 11/25: a gap is a buffered-and-lost row during a log-write failure, not an error in the view). |
| `ts` | TEXT | RFC3339 UTC, set by SQLite at insert time. |
| `plane` | TEXT | `'safe'` or `'escalation'`. |
| `key_id` | TEXT | Client identity — **never** the key or its hash. |
| `route` | TEXT or NULL | Alias name, if the client named one; NULL for a concrete `<backend_id>/<model>` request. |
| `model_req` | TEXT | What the client asked for (route alias or concrete model). |
| `model_served` | TEXT or NULL | What actually answered, as reported by the backend. NULL on a failure that never reached a backend. |
| `backend` | TEXT or NULL | Which configured backend/provider id served the request. |
| `chain_pos` | INTEGER or NULL | Which rung of an alias chain served (1-indexed). |
| `disposition` | TEXT | One of `served`, `denied_policy`, `denied_auth`, `backend_error`, `client_cancel`. |
| `status` | INTEGER or NULL | HTTP status returned to the client. |
| `err_code` | TEXT or NULL | The router's own machine-readable code, when the router (not the backend) produced the response. |
| `tokens_in` / `tokens_out` | INTEGER or NULL | Best-effort, read from the backend's own `usage` object — not real tokenization (SPEC §7 cuts token counting as a policy input; this is logging only). |
| `latency_ms` | INTEGER | Request duration as observed by the router. |
| `stream` | INTEGER (0/1) | Request carried `"stream": true`. |
| `tools` | INTEGER (0/1) | Request carried a `tools` array. |
| `mismatch` | INTEGER (0/1) | `model_served` differed from what was dispatched to, outside an alias chain's own substitution. |
| `client_tag` | TEXT or NULL | **Untrusted, client-controlled.** See below — do not skip this. |
| `prev_hash` / `row_hash` | TEXT or NULL | SPEC §8.2's hash chain. NULL on a pre-migration row (never chained) or before Phase 2 shipped at all. See "Integrity" below before treating these as a security feature. |

### `v_requests_v2` (schema `user_version` 2)

V2 exposes the same v1 columns in the same order, then one trailing TEXT
column: `usage_state`. It is `complete` if both token counters are non-NULL,
`partial` if one is non-NULL, and `not_recorded` if both are NULL. This
describes what the log recorded, **not** whether the provider omitted usage.
Historical NULLs may reflect the older extractor. A reported zero is stored
as integer 0, never NULL. V1's columns and meaning remain unchanged.

For OpenAI chat completions, `tokens_in`/`tokens_out` map to reported
`usage.prompt_tokens`/`completion_tokens`; for Anthropic Messages they map
to `usage.input_tokens`/`output_tokens`. In streams, the router reads bounded
SSE metadata events: OpenAI usage events and Anthropic `message_start` /
`message_delta`. OpenAI usage is often absent unless the client requests it
with `stream_options.include_usage`; the router does not add that option.
Malformed, negative, or missing counters remain NULL, independently. Partial
usage may be recorded on a canceled stream.

V2 adds no table columns. The 1 → 2 migration creates the view and updates
`user_version` transactionally; it does not rewrite rows or change the
hash-chain formula or existing anchors.

### `client_tag` is not policy input, and it is not trusted

`client_tag` is the verbatim value of a client-supplied `X-Safe-Router-Tag`
header (SPEC §8.1) — capped at 128 bytes, control characters rejected, but
otherwise **exactly what the client sent, unescaped, un-sanitized for any
particular rendering context.** The router never interprets it; it exists
purely so an external tool (this panel included) can join router rows to
its own session/task identifiers.

**Any consumer of this view — this panel included — must escape `client_tag`
on render**, the same as any other untrusted string reaching a UI, a log
line, or a query built from user input. Treat it as hostile input, because
it is: any client that can reach the router can put (almost) anything it
wants in that header.

---

## Opening the database

Read-only, at both the connection-flag level and the pragma level. Two
layers because either one alone is defense-in-depth, not a guarantee — a
`PRAGMA query_only` can in principle be reset by a connection that also has
write access to the file's journal; a `SQLITE_OPEN_READ_ONLY` flag is
enforced by the OS-level file descriptor. Together, a bug in the panel
cannot become a write to this database.

```
file:/Users/<you>/.safe-router/log.db?mode=ro
```

opened with `SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_URI`, followed by:

```sql
PRAGMA query_only = 1;
```

The daemon runs the log in WAL mode specifically so a reader connection can
query while the daemon is actively writing (`src/log.rs`'s `open_file`) —
the two don't take turns. `src/log.rs`'s own test suite
(`a_query_only_connection_can_read_v_requests_v1_but_never_write`) is the
executable version of this contract: it opens the view with exactly this
connection string while the daemon is writing, confirms a read succeeds,
and confirms a write attempt through either the view or the raw table
fails.

Check file existence, `PRAGMA user_version`, and the requested view before
querying. A missing database must not be created by the reader. A version-1
database can still be read through `v_requests_v1`; a v2 reader should treat
an absent v2 view as unavailable. Missing, locked, unreadable, or incompatible
files must leave a panel unavailable without blocking other reader functions.
Never migrate or query the underlying `requests` table from a consumer.

---

## Integrity — what the hash chain does and doesn't buy you

`prev_hash`/`row_hash` (SPEC §8.2) prove **internal consistency of this
file**, and nothing else on their own: on a single machine, anything that
can write the log file can rewrite the chain and recompute every hash. The
reference deployment began pushing an anchor off-box on 2026-09-03
(`docs/TESTING.md` Step 11). Where a deployment pushes an anchor, the honest
claim becomes **"tamper-evident
against edits made before the last anchor push"** — nothing broader.

If this panel ever wants to *display* an integrity status, the correct
source of truth is running `safe-router verify-log` (or re-implementing its
exact recomputation) against the file, not merely checking that
`row_hash`/`prev_hash` columns are non-NULL. A NULL-vs-not-NULL check only
tells you whether a row predates the migration; it says nothing about
whether the chain still verifies.

---

## What this contract does not include

- No HTTP interface, no socket, no IPC — covered above, repeated because
  it's the point.
- No write path of any kind. The panel does not create keys, does not
  change routes, does not set the degraded flag. Policy is static TOML,
  loaded by the daemon at startup and on SIGHUP only (invariant #3); this
  view cannot touch that even in principle, since it's read-only at the
  connection level before it's read-only by convention.
- No guarantee about `requests` (the underlying table) — only about the
  versioned views.
- No prompt or response content, ever, for either plane (SPEC §8) — there
  is nothing here to accidentally over-expose in the first place.
- No cost or pricing calculation. Consumers own any pricing table and the
  interpretation of missing usage or provider billing semantics.
- No rate-limit remaining/reset or account-switch command. Static
  `on_error = "next"` failover is not an interactive account switch.

Logic Loop must prove that each supported client sends the fixed
`X-Safe-Router-Tag` header with its intended tab identifier. Safe Router
cannot infer `LOGIC_LOOP_TAB_ID` from an agent's environment. Logic Loop owns
the read-only panel, join logic, and escaping untrusted tags.
