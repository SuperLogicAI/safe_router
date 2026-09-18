//! Phase 2 Step 3 (SPEC §8.2): the log's hash chain and its offline
//! `anchor`/`verify-log` subcommands. Matrix rows 23-25.

use std::{
    process::Command,
    sync::{atomic::AtomicBool, Arc},
    time::{SystemTime, UNIX_EPOCH},
};

use safe_router::log::Log;

fn unique_temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("safe-router-log-chain-{label}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn sample_row() -> safe_router::log::LogRow {
    safe_router::log::LogRow {
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

// ---------------------------------------------------------------------
// Row 23 — daemon restart mid-log: the chain continues across it. A fresh
// `Log::open_file` over the same path (what `main.rs` does on every
// startup) must pick up where the previous process left off, not reset.
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_23_daemon_restart_continues_the_chain() {
    let dir = unique_temp_dir("row23");
    let path = dir.join("log.db");

    let degraded = Arc::new(AtomicBool::new(false));
    let pre_restart = Log::open_file(&path, degraded.clone()).unwrap();
    pre_restart.record(sample_row());
    pre_restart.record(sample_row());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let (_, _, head_before_restart) = pre_restart.last_row_with_hash().unwrap();
    drop(pre_restart);

    let post_restart = Log::open_file(&path, degraded).unwrap();
    post_restart.record(sample_row());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let (_, _, head_after) = post_restart.last_row_with_hash().unwrap();
    assert_ne!(head_after, head_before_restart);
    assert!(
        post_restart.verify_chain().is_ok(),
        "the chain across a daemon restart must still verify as one continuous chain"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// Row 24 — a row edited directly in the DB: `verify-log` names the first
// divergent row and exits non-zero; `anchor` refuses to publish a head over
// a broken chain. Spawns the real binary's subcommands (no in-process
// equivalent for the CLI's own arg parsing / exit codes).
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_24_hand_edited_row_fails_verify_log_and_blocks_anchor() {
    let dir = unique_temp_dir("row24");
    let path = dir.join("log.db");

    let log = Log::open_file(&path, Arc::new(AtomicBool::new(false))).unwrap();
    log.record(sample_row());
    log.record(sample_row());
    log.record(sample_row());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    drop(log);

    // Hand-edit row 2 directly, bypassing the router entirely — exactly
    // what a single-machine, single-writer chain can't stop, only detect.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE requests SET status = 999 WHERE id = 2", []).unwrap();
    }

    let verify_output = Command::new(env!("CARGO_BIN_EXE_safe-router"))
        .args(["verify-log", "--log"])
        .arg(&path)
        .output()
        .expect("spawn safe-router verify-log");
    assert!(!verify_output.status.success(), "verify-log must exit non-zero on a hand-edited row");
    let stderr = String::from_utf8_lossy(&verify_output.stderr);
    assert!(stderr.contains("row 2"), "stderr must name the divergent row: {stderr}");

    let anchor_output = Command::new(env!("CARGO_BIN_EXE_safe-router"))
        .args(["anchor", "--log"])
        .arg(&path)
        .arg("--out")
        .arg(dir.join("head.json"))
        .output()
        .expect("spawn safe-router anchor");
    assert!(!anchor_output.status.success(), "anchor must refuse to publish a head over a broken chain");
    let anchor_stderr = String::from_utf8_lossy(&anchor_output.stderr);
    assert!(anchor_stderr.contains("refusing to anchor"), "stderr: {anchor_stderr}");
    assert!(!dir.join("head.json").exists(), "no head file must be written when the chain is broken");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn verify_log_and_anchor_succeed_on_an_untampered_log() {
    let dir = unique_temp_dir("row24-clean");
    let path = dir.join("log.db");

    let log = Log::open_file(&path, Arc::new(AtomicBool::new(false))).unwrap();
    log.record(sample_row());
    log.record(sample_row());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    drop(log);

    let verify_output = Command::new(env!("CARGO_BIN_EXE_safe-router"))
        .args(["verify-log", "--log"])
        .arg(&path)
        .output()
        .expect("spawn safe-router verify-log");
    assert!(verify_output.status.success(), "verify-log must succeed on an untampered chain");

    let head_path = dir.join("head.json");
    let anchor_output = Command::new(env!("CARGO_BIN_EXE_safe-router"))
        .args(["anchor", "--log"])
        .arg(&path)
        .arg("--out")
        .arg(&head_path)
        .output()
        .expect("spawn safe-router anchor");
    assert!(anchor_output.status.success(), "anchor must succeed on an untampered chain");
    let head_bytes = std::fs::read(&head_path).expect("anchor must write a head file");
    let head: serde_json::Value = serde_json::from_slice(&head_bytes).unwrap();
    assert_eq!(head["id"], 2);
    assert!(head["row_hash"].as_str().is_some_and(|h| !h.is_empty()));

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// Row 25 — log-write failure (row 11) then recovery: buffered rows never
// enter the chain, and the chain stays internally valid across the gap —
// visible as an id discontinuity, never papered over.
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_25_write_failure_gap_leaves_chain_valid_with_visible_discontinuity() {
    let dir = unique_temp_dir("row25");
    let path = dir.join("log.db");

    let log = Log::open_file(&path, Arc::new(AtomicBool::new(false))).unwrap();
    log.record(sample_row());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let (id_before_gap, _, _) = log.last_row_with_hash().unwrap();
    assert_eq!(id_before_gap, 1);

    // Same technique as matrix_row_11_log_write_failure: hold the write
    // lock from a second connection so the next INSERT fails deterministically.
    let blocker = rusqlite::Connection::open(&path).unwrap();
    blocker.busy_timeout(std::time::Duration::from_millis(0)).unwrap();
    blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();

    log.record(sample_row()); // fails, buffered — never gets an id
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(log.buffered_count(), 1, "the failed row must be buffered, not silently dropped");

    drop(blocker);

    log.record(sample_row()); // recovery: writer works again
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let (id_after_gap, _, _) = log.last_row_with_hash().unwrap();
    assert_eq!(id_after_gap, 2, "the buffered row never entered the table — id jumps straight to 2, the gap is visible");
    assert!(
        log.verify_chain().is_ok(),
        "the chain must stay internally valid across the gap — nothing papers over the missing row"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
