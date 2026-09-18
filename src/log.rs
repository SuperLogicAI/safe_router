//! Append-only metadata log (SPEC §8). Metadata only — never prompt or
//! response content, for either plane. `record()` never blocks the request
//! path on disk I/O (the write happens in a `spawn_blocking` task) and never
//! fails the request: a write error buffers the row in memory and sets the
//! shared `degraded` flag (matrix row 11) instead.
//!
//! `ts` is filled in by SQLite's own `strftime('%Y-%m-%dT%H:%M:%SZ','now')`
//! at insert time, not computed in Rust — RFC3339 UTC formatting needs
//! correct calendar math (leap years etc.), and SQLite already has a
//! well-tested implementation built in. Avoids hand-rolling it and avoids
//! a new dependency (`chrono`/`time`) for one column.

use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS requests (
  id           INTEGER PRIMARY KEY,
  ts           TEXT    NOT NULL,
  plane        TEXT    NOT NULL,
  key_id       TEXT    NOT NULL,
  route        TEXT,
  model_req    TEXT    NOT NULL,
  model_served TEXT,
  backend      TEXT,
  chain_pos    INTEGER,
  disposition  TEXT    NOT NULL,
  status       INTEGER,
  err_code     TEXT,
  tokens_in    INTEGER,
  tokens_out   INTEGER,
  latency_ms   INTEGER,
  stream       INTEGER NOT NULL,
  tools        INTEGER NOT NULL,
  mismatch     INTEGER NOT NULL,
  client_tag   TEXT
);
";

const INSERT_SQL: &str = "
INSERT INTO requests (
  ts, plane, key_id, route, model_req, model_served, backend, chain_pos,
  disposition, status, err_code, tokens_in, tokens_out, latency_ms,
  stream, tools, mismatch, client_tag, prev_hash
) VALUES (
  strftime('%Y-%m-%dT%H:%M:%SZ','now'),
  ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18
)
";

/// SPEC §8 / docs/LOG_CONTRACT.md (Phase 2 Step 4): the Logic Loop panel's
/// entire read surface — a file the panel opens itself (invariant #4: a
/// separate process, read-only, cannot write policy). An explicit, stable
/// column list, never `SELECT *` — a future schema addition must not
/// silently change what a v1 reader sees; that's what a v2 view would be
/// for. `client_tag` is untrusted, client-controlled text (SPEC §8.1); any
/// consumer of this view must escape it on render.
const VIEW_SQL: &str = "
CREATE VIEW IF NOT EXISTS v_requests_v1 AS
SELECT
  id, ts, plane, key_id, route, model_req, model_served, backend, chain_pos,
  disposition, status, err_code, tokens_in, tokens_out, latency_ms,
  stream, tools, mismatch, client_tag, prev_hash, row_hash
FROM requests;
";

/// v1 remains frozen. The final field is derived from the two nullable,
/// provider-reported counters; it does not imply the provider omitted usage.
const VIEW_V2_SQL: &str = "
CREATE VIEW IF NOT EXISTS v_requests_v2 AS
SELECT
  id, ts, plane, key_id, route, model_req, model_served, backend, chain_pos,
  disposition, status, err_code, tokens_in, tokens_out, latency_ms,
  stream, tools, mismatch, client_tag, prev_hash, row_hash,
  CASE
    WHEN tokens_in IS NOT NULL AND tokens_out IS NOT NULL THEN 'complete'
    WHEN tokens_in IS NOT NULL OR tokens_out IS NOT NULL THEN 'partial'
    ELSE 'not_recorded'
  END AS usage_state
FROM requests;
";

const SELECT_ALL_CHAINED_SQL: &str = "
SELECT id, ts, plane, key_id, route, model_req, model_served, backend, chain_pos,
       disposition, status, err_code, tokens_in, tokens_out, latency_ms,
       stream, tools, mismatch, client_tag, prev_hash, row_hash
FROM requests ORDER BY id ASC
";

/// One `requests` row. `ts` is only ever populated by reading a row back
/// (`last_row`) — `record()` ignores whatever's in it on the way in; see the
/// module doc for why.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LogRow {
    pub ts: String,
    pub plane: String,
    pub key_id: String,
    pub route: Option<String>,
    pub model_req: String,
    pub model_served: Option<String>,
    pub backend: Option<String>,
    pub chain_pos: Option<i64>,
    pub disposition: String,
    pub status: Option<i64>,
    pub err_code: Option<String>,
    pub tokens_in: Option<i64>,
    pub tokens_out: Option<i64>,
    pub latency_ms: i64,
    pub stream: bool,
    pub tools: bool,
    pub mismatch: bool,
    pub client_tag: Option<String>,
    /// SPEC §8.2 (Phase 2 Step 3). Populated by SQLite at insert time (via
    /// `record`) or on read-back (`last_row`, `verify_chain`) — never set by
    /// a caller constructing a row to log. `None` for a pre-migration row,
    /// which was never chained (the chain starts at the first post-migration
    /// row).
    pub prev_hash: Option<String>,
    pub row_hash: Option<String>,
}

pub struct Log {
    conn: Arc<Mutex<Connection>>,
    /// Rows that failed to write (matrix row 11) — availability beats log
    /// completeness for one user, so a write failure never blocks or fails
    /// the request it's describing.
    /// # ponytail: unbounded; add a cap + drop-oldest if a disk-full period
    /// is ever long enough on a single-user local daemon to matter.
    buffer: Arc<Mutex<Vec<LogRow>>>,
    degraded: Arc<AtomicBool>,
}

/// SPEC §8.2 (Step 3): idempotent `ALTER TABLE ADD COLUMN`, guarded by
/// `PRAGMA user_version` (0 → 1) so it runs exactly once per database file,
/// ever — including a brand-new one (the base `SCHEMA` above deliberately
/// doesn't declare these two columns, so there's exactly one code path that
/// adds them, not two that have to agree). Pre-migration rows keep NULL
/// `prev_hash`/`row_hash`; the chain starts at the first post-migration
/// insert, a documented starting point rather than back-filled hashes over
/// rows nobody chained.
fn migrate_add_hash_columns(conn: &Connection) -> rusqlite::Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 1 {
        conn.execute("ALTER TABLE requests ADD COLUMN prev_hash TEXT", [])?;
        conn.execute("ALTER TABLE requests ADD COLUMN row_hash TEXT", [])?;
        conn.execute("PRAGMA user_version = 1", [])?;
    }
    Ok(())
}

fn migrate_add_v2_view(conn: &Connection) -> rusqlite::Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 2 {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            conn.execute_batch(VIEW_V2_SQL)?;
            conn.execute_batch("PRAGMA user_version = 2")
        })();
        match result {
            Ok(()) => conn.execute_batch("COMMIT"),
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    } else {
        conn.execute_batch(VIEW_V2_SQL)
    }
}

impl Log {
    /// Used by `AppState::new` as the default so the many tests that don't
    /// care about logging need zero setup and never touch the filesystem.
    pub fn open_in_memory(degraded: Arc<AtomicBool>) -> Self {
        let conn = Connection::open_in_memory().expect("open in-memory sqlite connection");
        conn.execute_batch(SCHEMA).expect("create requests table");
        migrate_add_hash_columns(&conn).expect("add hash-chain columns");
        conn.execute_batch(VIEW_SQL).expect("create v_requests_v1 view");
        migrate_add_v2_view(&conn).expect("create v_requests_v2 view");
        Self {
            conn: Arc::new(Mutex::new(conn)),
            buffer: Arc::new(Mutex::new(Vec::new())),
            degraded,
        }
    }

    /// Offline, read-only access for the `anchor`/`verify-log` CLI
    /// subcommands (SPEC §8.2) — a separate process, never the daemon,
    /// reading a file the daemon happens to have written. No migration runs
    /// here: a log old enough to need one was already migrated the next
    /// time the daemon itself opened it.
    pub fn open_readonly(path: &Path) -> Result<Self, String> {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|e| format!("cannot open metadata log {} read-only: {e}", path.display()))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            buffer: Arc::new(Mutex::new(Vec::new())),
            degraded: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Production path (`main.rs`): a file that can't even be *opened* is an
    /// environment problem, same tier as an unreadable config or an
    /// unfetchable Keychain credential — invariant #1, refuse to start
    /// rather than silently degrade from the first request. A write that
    /// starts failing *after* a successful open is matrix row 11's problem,
    /// handled by `record()`, not this constructor.
    pub fn open_file(path: &Path, degraded: Arc<AtomicBool>) -> Result<Self, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("cannot create log directory {}: {e}", dir.display()))?;
        }
        let conn = Connection::open(path)
            .map_err(|e| format!("cannot open metadata log {}: {e}", path.display()))?;
        // WAL so a reader (the Logic Loop panel, invariant #4 — a separate
        // process holding a read-only connection) can query while the daemon
        // writes, instead of the two blocking each other. `PRAGMA
        // journal_mode` returns the mode it settled on, so it's a query, not
        // an execute.
        let mode: String = conn
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(|e| format!("cannot set WAL mode on {}: {e}", path.display()))?;
        if mode.to_lowercase() != "wal" {
            return Err(format!(
                "metadata log {} refused WAL mode (got '{mode}')",
                path.display()
            ));
        }
        // No busy-wait. This daemon is the log's only writer, and WAL readers
        // never block a writer — so a lock we'd have to wait on is a broken
        // situation, not a busy one. rusqlite's 5s default would park a
        // blocking-pool thread per row before reaching the same conclusion;
        // failing immediately routes it into matrix row 11 (buffer + degraded
        // flag), which is the behavior that's actually specified.
        conn.busy_timeout(std::time::Duration::from_millis(0))
            .map_err(|e| format!("cannot set busy timeout on {}: {e}", path.display()))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| format!("cannot create requests table: {e}"))?;
        migrate_add_hash_columns(&conn)
            .map_err(|e| format!("cannot migrate hash-chain columns on {}: {e}", path.display()))?;
        conn.execute_batch(VIEW_SQL)
            .map_err(|e| format!("cannot create v_requests_v1 view on {}: {e}", path.display()))?;
        migrate_add_v2_view(&conn)
            .map_err(|e| format!("cannot create v_requests_v2 view on {}: {e}", path.display()))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            buffer: Arc::new(Mutex::new(Vec::new())),
            degraded,
        })
    }

    /// Fire-and-forget: the caller never waits on disk I/O. A failed write
    /// buffers `row` in memory and sets the degraded flag instead of
    /// failing (or even slowing down) the request it's describing.
    pub fn record(&self, row: LogRow) {
        let conn = self.conn.clone();
        let buffer = self.buffer.clone();
        let degraded = self.degraded.clone();
        tokio::task::spawn_blocking(move || {
            let result = insert_chained(&conn, &row);
            if let Err(e) = result {
                tracing::error!(error = %e, "metadata log write failed, buffering in memory");
                buffer.lock().unwrap().push(row);
                degraded.store(true, Ordering::SeqCst);
            }
        });
    }

    /// Test/debug accessor: the most recently inserted row, if any.
    pub fn last_row(&self) -> Option<LogRow> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT ts, plane, key_id, route, model_req, model_served, backend, chain_pos, \
             disposition, status, err_code, tokens_in, tokens_out, latency_ms, stream, tools, \
             mismatch, client_tag, prev_hash, row_hash FROM requests ORDER BY id DESC LIMIT 1",
            [],
            |r| {
                Ok(LogRow {
                    ts: r.get(0)?,
                    plane: r.get(1)?,
                    key_id: r.get(2)?,
                    route: r.get(3)?,
                    model_req: r.get(4)?,
                    model_served: r.get(5)?,
                    backend: r.get(6)?,
                    chain_pos: r.get(7)?,
                    disposition: r.get(8)?,
                    status: r.get(9)?,
                    err_code: r.get(10)?,
                    tokens_in: r.get(11)?,
                    tokens_out: r.get(12)?,
                    latency_ms: r.get(13)?,
                    stream: r.get::<_, i64>(14)? != 0,
                    tools: r.get::<_, i64>(15)? != 0,
                    mismatch: r.get::<_, i64>(16)? != 0,
                    client_tag: r.get(17)?,
                    prev_hash: r.get(18)?,
                    row_hash: r.get(19)?,
                })
            },
        )
        .ok()
    }

    /// Test/debug accessor: how many rows are sitting in the in-memory
    /// overflow buffer because they failed to write (matrix row 11).
    pub fn buffered_count(&self) -> usize {
        self.buffer.lock().unwrap().len()
    }

    /// SPEC §8.2: recomputes the chain from row 1 and reports the first
    /// divergence — either a row whose `prev_hash` doesn't match the
    /// previous chained row's actual `row_hash` (a deleted, reordered, or
    /// re-pointed row), or a row whose own fields no longer hash to its
    /// stored `row_hash` (an edited field, or a hand-edited hash). A
    /// pre-migration row (`row_hash` NULL) is unchained by definition —
    /// skipped, and it resets the chain, since the next chained row's
    /// `prev_hash` was computed against "no prior hash" at insert time too.
    pub fn verify_chain(&self) -> Result<(), ChainDivergence> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(SELECT_ALL_CHAINED_SQL).expect("valid SQL");
        let rows = stmt
            .query_map([], row_from_columns)
            .expect("valid SQL")
            .collect::<Result<Vec<_>, _>>()
            .expect("reading already-written rows");
        drop(stmt);
        drop(conn);

        let mut last_chained_hash: Option<String> = None;
        for (id, ts, row) in rows {
            let Some(row_hash) = row.row_hash.clone() else {
                last_chained_hash = None;
                continue;
            };
            let expected_prev = last_chained_hash.clone().unwrap_or_default();
            let stored_prev = row.prev_hash.clone();
            if stored_prev.clone().unwrap_or_default() != expected_prev {
                return Err(ChainDivergence {
                    id,
                    expected: expected_prev,
                    stored: stored_prev,
                });
            }
            let recomputed = row_hash_for(&expected_prev, id, &ts, &row);
            if recomputed != row_hash {
                return Err(ChainDivergence {
                    id,
                    expected: recomputed,
                    stored: Some(row_hash.clone()),
                });
            }
            last_chained_hash = Some(row_hash);
        }
        Ok(())
    }

    /// The newest row's `(id, ts, row_hash)`, for the `anchor` subcommand.
    /// `None` if the log is empty or the newest row is somehow unchained
    /// (shouldn't happen post-migration; `anchor` treats it as "nothing to
    /// anchor" rather than guessing).
    pub fn last_row_with_hash(&self) -> Option<(i64, String, String)> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, ts, row_hash FROM requests ORDER BY id DESC LIMIT 1",
            [],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?)),
        )
        .optional()
        .expect("reading already-written rows")
        .and_then(|(id, ts, row_hash)| row_hash.map(|h| (id, ts, h)))
    }
}

/// SPEC §8.2: the first row (by `id`) at which the recomputed chain diverges
/// from what's stored — either its `prev_hash` no longer points at the
/// actual previous chained row's hash, or its own fields no longer hash to
/// its stored `row_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainDivergence {
    pub id: i64,
    pub expected: String,
    pub stored: Option<String>,
}

fn row_from_columns(r: &rusqlite::Row) -> rusqlite::Result<(i64, String, LogRow)> {
    let id: i64 = r.get(0)?;
    let ts: String = r.get(1)?;
    let row = LogRow {
        ts: ts.clone(),
        plane: r.get(2)?,
        key_id: r.get(3)?,
        route: r.get(4)?,
        model_req: r.get(5)?,
        model_served: r.get(6)?,
        backend: r.get(7)?,
        chain_pos: r.get(8)?,
        disposition: r.get(9)?,
        status: r.get(10)?,
        err_code: r.get(11)?,
        tokens_in: r.get(12)?,
        tokens_out: r.get(13)?,
        latency_ms: r.get(14)?,
        stream: r.get::<_, i64>(15)? != 0,
        tools: r.get::<_, i64>(16)? != 0,
        mismatch: r.get::<_, i64>(17)? != 0,
        client_tag: r.get(18)?,
        prev_hash: r.get(19)?,
        row_hash: r.get(20)?,
    };
    Ok((id, ts, row))
}

/// Inserts `row` as the new chain head, all inside one write transaction
/// (SPEC §8.2: "computed inside the same write transaction that inserts the
/// row, under the log's single writer, so ordering is the DB's ordering").
/// `prev_hash` is looked up first (the current head's `row_hash`, or empty
/// if there isn't one — either an empty log or a pre-migration head), then
/// the row is inserted with it, then `row_hash` is computed from the
/// now-known `id`/`ts` and written back in the same transaction.
fn insert_chained(conn: &Arc<Mutex<Connection>>, row: &LogRow) -> rusqlite::Result<()> {
    let conn = conn.lock().unwrap();
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> rusqlite::Result<()> {
        let prev_hash: String = conn
            .query_row("SELECT row_hash FROM requests ORDER BY id DESC LIMIT 1", [], |r| {
                r.get::<_, Option<String>>(0)
            })
            .optional()?
            .flatten()
            .unwrap_or_default();

        conn.execute(
            INSERT_SQL,
            rusqlite::params![
                row.plane,
                row.key_id,
                row.route,
                row.model_req,
                row.model_served,
                row.backend,
                row.chain_pos,
                row.disposition,
                row.status,
                row.err_code,
                row.tokens_in,
                row.tokens_out,
                row.latency_ms,
                row.stream as i64,
                row.tools as i64,
                row.mismatch as i64,
                row.client_tag,
                prev_hash,
            ],
        )?;
        let id = conn.last_insert_rowid();
        let ts: String = conn.query_row("SELECT ts FROM requests WHERE id = ?1", [id], |r| r.get(0))?;
        let row_hash = row_hash_for(&prev_hash, id, &ts, row);
        conn.execute("UPDATE requests SET row_hash = ?1 WHERE id = ?2", rusqlite::params![row_hash, id])?;
        Ok(())
    })();

    match result {
        Ok(()) => conn.execute_batch("COMMIT"),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

/// SPEC §8.2: `row_hash = sha256(prev_hash || "\n" || canonical_fields)`.
fn row_hash_for(prev_hash: &str, id: i64, ts: &str, row: &LogRow) -> String {
    let canonical = canonical_fields(id, ts, row);
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(b"\n");
    hasher.update(canonical.as_bytes());
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The row's columns, in fixed schema order, joined with a NUL separator —
/// a byte that can't appear in any of these values (`client_tag` already
/// rejects control characters, §8.1; everything else is either numeric or a
/// router-controlled enum string). `None` renders as an empty segment;
/// position in the join is what disambiguates fields, not the separator
/// alone.
fn canonical_fields(id: i64, ts: &str, row: &LogRow) -> String {
    let opt_i64 = |v: Option<i64>| v.map(|n| n.to_string()).unwrap_or_default();
    let opt_str = |v: &Option<String>| v.clone().unwrap_or_default();
    [
        id.to_string(),
        ts.to_string(),
        row.plane.clone(),
        row.key_id.clone(),
        opt_str(&row.route),
        row.model_req.clone(),
        opt_str(&row.model_served),
        opt_str(&row.backend),
        opt_i64(row.chain_pos),
        row.disposition.clone(),
        opt_i64(row.status),
        opt_str(&row.err_code),
        opt_i64(row.tokens_in),
        opt_i64(row.tokens_out),
        row.latency_ms.to_string(),
        (row.stream as i64).to_string(),
        (row.tools as i64).to_string(),
        (row.mismatch as i64).to_string(),
        opt_str(&row.client_tag),
    ]
    .join("\0")
}

/// SPEC §8.1: `client_tag` is opaque, untrusted, and bounded. `None` (stored
/// as SQL NULL) if the value is oversized or contains control characters —
/// never truncated or escaped, just dropped, since a mangled tag is worse
/// for join-ability than a missing one.
pub fn sanitize_client_tag(raw: &str) -> Option<String> {
    if raw.len() > 128 || raw.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(raw.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_log() -> Log {
        Log::open_in_memory(Arc::new(AtomicBool::new(false)))
    }

    fn sample_row() -> LogRow {
        LogRow {
            plane: "safe".into(),
            key_id: "test".into(),
            model_req: "b/model-a".into(),
            disposition: "served".into(),
            status: Some(200),
            stream: false,
            tools: false,
            mismatch: false,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn record_then_last_row_round_trips() {
        let log = test_log();
        log.record(sample_row());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let row = log.last_row().expect("a row was inserted");
        assert_eq!(row.plane, "safe");
        assert_eq!(row.key_id, "test");
        assert_eq!(row.model_req, "b/model-a");
        assert_eq!(row.disposition, "served");
        assert_eq!(row.status, Some(200));
        assert!(!row.ts.is_empty(), "ts should be populated by SQLite, not empty");
    }

    /// WAL's reason for existing here: the Logic Loop panel is a separate
    /// process holding a read-only connection (invariant #4), and it must be
    /// able to read while the daemon writes rather than the two taking turns.
    #[tokio::test]
    async fn a_read_only_connection_can_query_while_the_writer_is_open() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "safe-router-log-wal-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log.db");

        let log = Log::open_file(&path, Arc::new(AtomicBool::new(false))).expect("log opens");
        log.record(sample_row());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let reader = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .expect("read-only connection opens while the writer holds its own");
        let count: i64 = reader
            .query_row("SELECT count(*) FROM requests", [], |r| r.get(0))
            .expect("reader can query while the writer is open");
        assert_eq!(count, 1);

        // ...and the writer is still a writer afterwards.
        log.record(sample_row());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let count: i64 = reader.query_row("SELECT count(*) FROM requests", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 2, "reader sees rows written after it connected");

        assert!(
            reader.execute("DELETE FROM requests", []).is_err(),
            "a read-only connection must not be able to write the log"
        );

        drop(reader);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn chained_rows_link_prev_hash_to_prior_row_hash() {
        let log = test_log();
        log.record(sample_row());
        log.record(sample_row());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let conn = log.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, prev_hash, row_hash FROM requests ORDER BY id ASC").unwrap();
        let rows: Vec<(i64, Option<String>, Option<String>)> =
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(|r| r.unwrap()).collect();
        drop(stmt);
        drop(conn);

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].1, Some(String::new()), "first row's prev_hash is the empty genesis value");
        assert!(rows[0].2.as_ref().is_some_and(|h| !h.is_empty()));
        assert_eq!(rows[1].1, rows[0].2, "second row's prev_hash must equal the first row's row_hash");
        assert_ne!(rows[1].2, rows[0].2, "distinct rows must not hash to the same value");
    }

    #[tokio::test]
    async fn verify_chain_passes_on_an_untampered_log() {
        let log = test_log();
        log.record(sample_row());
        log.record(sample_row());
        log.record(sample_row());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert!(log.verify_chain().is_ok());
    }

    #[tokio::test]
    async fn verify_chain_detects_a_hand_edited_field() {
        let log = test_log();
        log.record(sample_row());
        log.record(sample_row());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let conn = log.conn.lock().unwrap();
        conn.execute("UPDATE requests SET disposition = 'denied_policy' WHERE id = 1", []).unwrap();
        drop(conn);

        let err = log.verify_chain().expect_err("a hand-edited field must be detected");
        assert_eq!(err.id, 1);
    }

    #[tokio::test]
    async fn verify_chain_detects_a_deleted_row() {
        let log = test_log();
        log.record(sample_row());
        log.record(sample_row());
        log.record(sample_row());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let conn = log.conn.lock().unwrap();
        conn.execute("DELETE FROM requests WHERE id = 2", []).unwrap();
        drop(conn);

        let err = log.verify_chain().expect_err("a deleted row must break the chain at the next surviving row");
        assert_eq!(err.id, 3);
    }

    #[tokio::test]
    async fn verify_chain_skips_unchained_pre_migration_rows_and_resumes() {
        let log = test_log();
        // Simulate a pre-migration row: inserted directly, no hash columns.
        {
            let conn = log.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO requests (ts, plane, key_id, model_req, disposition, status, latency_ms, stream, tools, mismatch) \
                 VALUES ('2020-01-01T00:00:00Z', 'safe', 'k', 'm', 'served', 200, 0, 0, 0, 0)",
                [],
            )
            .unwrap();
        }
        log.record(sample_row());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        assert!(log.verify_chain().is_ok(), "an unchained pre-migration row must not itself count as a divergence");
    }

    #[tokio::test]
    async fn last_row_with_hash_returns_newest_chained_row() {
        let log = test_log();
        log.record(sample_row());
        log.record(sample_row());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let (id, ts, row_hash) = log.last_row_with_hash().expect("a chained row exists");
        assert_eq!(id, 2);
        assert!(!ts.is_empty());
        assert!(!row_hash.is_empty());
        assert_eq!(log.last_row().unwrap().row_hash, Some(row_hash));
    }

    #[test]
    fn last_row_with_hash_is_none_on_an_empty_log() {
        let log = test_log();
        assert!(log.last_row_with_hash().is_none());
    }

    #[tokio::test]
    async fn a_restarted_log_continues_the_chain_from_the_same_file() {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("safe-router-log-restart-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log.db");

        let degraded = Arc::new(AtomicBool::new(false));
        let log = Log::open_file(&path, degraded.clone()).unwrap();
        log.record(sample_row());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let (_, _, pre_restart_hash) = log.last_row_with_hash().unwrap();
        drop(log);

        // Matrix row 23: a fresh `Log` over the same file (simulating a
        // daemon restart) must continue the chain, not reset it.
        let restarted = Log::open_file(&path, degraded).unwrap();
        restarted.record(sample_row());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let conn = restarted.conn.lock().unwrap();
        let prev_hash: Option<String> =
            conn.query_row("SELECT prev_hash FROM requests ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).unwrap();
        drop(conn);
        assert_eq!(prev_hash, Some(pre_restart_hash), "post-restart row's prev_hash must equal the pre-restart head");
        assert!(restarted.verify_chain().is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// docs/LOG_CONTRACT.md / Phase 2 Step 4: the panel's entire read
    /// surface is `v_requests_v1`, opened via `file:…?mode=ro` +
    /// `PRAGMA query_only=1` — read-only at both the connection-flag level
    /// and the pragma level, queryable while the daemon writes (same WAL
    /// property as the raw-table test above), and unable to write through
    /// either the view or the underlying table.
    #[tokio::test]
    async fn a_query_only_connection_can_read_v_requests_v1_but_never_write() {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("safe-router-log-contract-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log.db");

        let log = Log::open_file(&path, Arc::new(AtomicBool::new(false))).unwrap();
        log.record(sample_row());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let uri = format!("file:{}?mode=ro", path.display());
        let reader = Connection::open_with_flags(
            &uri,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .expect("panel's documented connection string opens read-only");
        reader.execute_batch("PRAGMA query_only=1").unwrap();

        let (model_req, disposition): (String, String) = reader
            .query_row("SELECT model_req, disposition FROM v_requests_v1 ORDER BY id DESC LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .expect("the view is queryable while the daemon writes");
        assert_eq!(model_req, "b/model-a");
        assert_eq!(disposition, "served");

        assert!(
            reader.execute("DELETE FROM v_requests_v1", []).is_err(),
            "a query_only connection must not be able to write through the view"
        );
        assert!(
            reader.execute("DELETE FROM requests", []).is_err(),
            "a query_only connection must not be able to write the underlying table either"
        );
        let (usage_state, tokens_in, tokens_out): (String, Option<i64>, Option<i64>) = reader
            .query_row("SELECT usage_state, tokens_in, tokens_out FROM v_requests_v2 ORDER BY id DESC LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            }).unwrap();
        assert_eq!((usage_state.as_str(), tokens_in, tokens_out), ("not_recorded", None, None));
        assert!(reader.execute("DELETE FROM v_requests_v2", []).is_err());

        drop(reader);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn v2_migrates_without_changing_v1_or_existing_hashes() {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("safe-router-v2-migrate-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log.db");
        let log = Log::open_file(&path, Arc::new(AtomicBool::new(false))).unwrap();
        let mut row = sample_row();
        row.tokens_in = Some(0);
        row.tokens_out = Some(2);
        log.record(row);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let (_, _, original_hash) = log.last_row_with_hash().unwrap();
        drop(log);

        let conn = Connection::open(&path).unwrap();
        let original_v1_sql: String = conn.query_row("SELECT sql FROM sqlite_master WHERE name='v_requests_v1'", [], |r| r.get(0)).unwrap();
        conn.execute_batch("DROP VIEW v_requests_v2; PRAGMA user_version=1").unwrap();
        drop(conn);

        let reopened = Log::open_file(&path, Arc::new(AtomicBool::new(false))).unwrap();
        assert!(reopened.verify_chain().is_ok());
        assert_eq!(reopened.last_row_with_hash().unwrap().2, original_hash);
        let conn = Connection::open(&path).unwrap();
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(version, 2);
        let new_v1_sql: String = conn.query_row("SELECT sql FROM sqlite_master WHERE name='v_requests_v1'", [], |r| r.get(0)).unwrap();
        assert_eq!(new_v1_sql, original_v1_sql);
        let (tokens_in, tokens_out, state): (i64, i64, String) = conn.query_row(
            "SELECT tokens_in, tokens_out, usage_state FROM v_requests_v2 WHERE id=1", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).unwrap();
        assert_eq!((tokens_in, tokens_out, state.as_str()), (0, 2, "complete"));
        drop(conn);
        drop(reopened);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitize_client_tag_accepts_normal_string() {
        assert_eq!(sanitize_client_tag("tab-42"), Some("tab-42".to_string()));
    }

    #[test]
    fn sanitize_client_tag_rejects_oversized() {
        let too_long = "x".repeat(129);
        assert_eq!(sanitize_client_tag(&too_long), None);
    }

    #[test]
    fn sanitize_client_tag_accepts_exactly_128_bytes() {
        let exactly = "x".repeat(128);
        assert_eq!(sanitize_client_tag(&exactly), Some(exactly));
    }

    #[test]
    fn sanitize_client_tag_rejects_control_characters() {
        assert_eq!(sanitize_client_tag("tab\nwith\nnewlines"), None);
        assert_eq!(sanitize_client_tag("tab\twith\ttabs"), None);
    }
}
