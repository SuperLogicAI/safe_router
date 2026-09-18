//! The failure matrix (SPEC §6) is the v0 integration test list — one named
//! test per row. Row 6 (router crash mid-stream) is the one exception:
//! documented manual step in docs/TESTING.md instead. Invariant #1 means
//! there's no persisted state to assert against on restart, so the only
//! thing an automated process-kill test could verify is that a TCP
//! connection drops when its process dies — OS behavior, not safe-router
//! logic. Row 11 landed with Step 7 (metadata log), once there was a log to
//! fail-write.
//!
//! All other v0 rows (1-16) have a named test below. Rows 17-19 (Phase 2
//! Step 1: tailnet bind) are here too.

#[path = "support.rs"]
mod support;

use std::{
    process::Command,
    sync::atomic::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use futures_util::StreamExt;
use safe_router::{auth, build_router, policy, reload_attempt, AppState};
use serde_json::Value;
use tower::ServiceExt;

const GOOD_KEY: &str = "good-key";

fn chat_request(model: &str, stream: bool) -> Request<Body> {
    let body = format!(r#"{{"model":"{model}","stream":{stream},"messages":[]}}"#);
    Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header(header::HOST, "127.0.0.1:8787")
        .header(header::AUTHORIZATION, format!("Bearer {GOOD_KEY}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

fn models_request(host: &str, bearer: &str) -> Request<Body> {
    Request::builder()
        .uri("/v1/models")
        .header(header::HOST, host)
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap()
}

async fn error_code(resp: axum::response::Response) -> String {
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    json["error"]["code"].as_str().unwrap_or_default().to_string()
}

// ---------------------------------------------------------------------
// Row 1 — local backend down / connection refused: 502, no fallback.
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_01_backend_down_no_fallback() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let down = support::refused_connection_url().await;
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["down/some-model"]

        [[backend]]
        id = "down"
        base_url = "{down}"
        dialect = "openai"
        "#
    ))
    .unwrap();
    let app = build_router(AppState::new(config));

    let resp = app.oneshot(chat_request("down/some-model", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(error_code(resp).await, "backend_unreachable");
}

// ---------------------------------------------------------------------
// Row 2 — requested model unknown/not loaded: backend's error surfaces
// verbatim (a static alias map, never crossing tiers, is the whole story).
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_02_unknown_model_surfaces_backend_error_verbatim() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_status_backend(StatusCode::NOT_FOUND).await;
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["b/no-such-model"]

        [[backend]]
        id = "b"
        base_url = "{backend}"
        dialect = "openai"
        "#
    ))
    .unwrap();
    let app = build_router(AppState::new(config));

    let resp = app.oneshot(chat_request("b/no-such-model", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(error_code(resp).await, "mock_failure");
}

// ---------------------------------------------------------------------
// Row 3 — context overflow (400) on a local model: pass it through, never
// retry on a bigger remote model, even when the chain has one configured
// with on_error = "next".
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_03_context_overflow_never_retries_on_remote() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let local = support::spawn_status_backend(StatusCode::BAD_REQUEST).await;
    let remote = support::spawn_mock_backend().await; // would succeed if ever tried
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["workhorse"]

        [[backend]]
        id = "local"
        base_url = "{local}"
        dialect = "openai"

        [[backend]]
        id = "remote"
        base_url = "{remote}"
        dialect = "openai"

        [[route]]
        name = "workhorse"
        chain = ["local/model-a", "remote/model-b"]
        on_error = "next"
        "#
    ))
    .unwrap();
    let app = build_router(AppState::new(config));

    let resp = app.oneshot(chat_request("workhorse", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------
// Row 4 — stream stalls mid-generation: idle timeout terminates the SSE
// stream with a proper error event, no re-dispatch. `idle_timeout_ms` is set
// low so this test doesn't wait on the real 60s production default.
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_04_stream_stall_idle_timeout() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_stalling_backend().await;
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"
        idle_timeout_ms = 100

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["b/some-model"]

        [[backend]]
        id = "b"
        base_url = "{backend}"
        dialect = "openai"
        "#
    ))
    .unwrap();
    let app = build_router(AppState::new(config));

    let resp = app.oneshot(chat_request("b/some-model", true)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("stream_idle_timeout"), "expected idle-timeout SSE event, got: {text}");
}

// ---------------------------------------------------------------------
// Row 5 — remote 429/5xx on an escalated request: an alias with
// on_error = "next" advances one rung. Never downgrades to local (there is
// no local rung in this chain to downgrade to — the point is it doesn't
// invent one).
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_05_escalation_429_advances_with_alias_next() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let rung1 = support::spawn_status_backend(StatusCode::TOO_MANY_REQUESTS).await;
    let rung2 = support::spawn_mock_backend().await;
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8788"
        plane = "escalation"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["cloud"]

        [[provider]]
        id = "p1"
        base_url = "{rung1}"
        dialect = "openai"
        keychain_item = "safe-router/p1"

        [[provider]]
        id = "p2"
        base_url = "{rung2}"
        dialect = "openai"
        keychain_item = "safe-router/p2"

        [[route]]
        name = "cloud"
        chain = ["p1/model-a", "p2/model-b"]
        on_error = "next"
        "#
    ))
    .unwrap();
    let app = build_router(AppState::new(config));

    let resp = app.oneshot(chat_request("cloud", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["model"], "model-b");
}

// ---------------------------------------------------------------------
// Row 7 — invalid config at startup: refuse to start. Spawns the real
// binary (no in-process equivalent exists for `main.rs`'s startup path).
// ---------------------------------------------------------------------
#[test]
fn matrix_row_07_invalid_config_refuses_to_start() {
    let dir = unique_temp_dir("row07");
    let config_path = dir.join("bad.toml");
    std::fs::write(&config_path, "this is not valid toml [[[").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_safe-router"))
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("spawn safe-router binary");

    assert!(!output.status.success(), "binary must refuse to start on invalid config");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("refusing to start"), "stderr: {stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn safe_plane_provider_and_unknown_plane_refuse_to_start() {
    for (name, config, expected) in [
        (
            "provider",
            "[server]\nbind = \"127.0.0.1:8787\"\nplane = \"safe\"\n[[provider]]\nid = \"remote\"\nbase_url = \"https://example.com/v1\"\ndialect = \"openai\"\nkeychain_item = \"safe-router/remote\"\n",
            "must not contain [[provider]]",
        ),
        (
            "plane",
            "[server]\nbind = \"127.0.0.1:8787\"\nplane = \"sfae\"\n",
            "plane 'sfae' is invalid",
        ),
    ] {
        let dir = unique_temp_dir(name);
        let path = dir.join("safe.toml");
        std::fs::write(&path, config).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_safe-router"))
            .arg("--config")
            .arg(&path)
            .output()
            .expect("spawn safe-router binary");
        assert!(!output.status.success(), "{name} config must refuse startup");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "stderr: {stderr}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ---------------------------------------------------------------------
// Row 8 — SIGHUP reload with an invalid config: keep the old config, log
// loudly, set a degraded flag. Exercised via `reload_attempt` directly
// (the library-level primitive `main.rs`'s SIGHUP handler also calls) —
// same contract, no real process/signal needed.
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_08_sighup_reload_invalid_keeps_old_config_and_sets_degraded() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_mock_backend().await;
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["b/some-model"]

        [[backend]]
        id = "b"
        base_url = "{backend}"
        dialect = "openai"
        "#
    ))
    .unwrap();
    let state = AppState::new(config);
    let app = build_router(state.clone());

    // Proves the pre-reload config actually works, so "still works after a
    // failed reload" below means something.
    let resp = app.clone().oneshot(chat_request("b/some-model", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    reload_attempt(&state, Err("simulated invalid config".to_string())).await;
    assert!(state.degraded.load(Ordering::SeqCst), "degraded flag must be set after a failed reload");

    let resp = app.oneshot(chat_request("b/some-model", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "old config must still be serving after a failed reload");
}

// ---------------------------------------------------------------------
// Row 9 — unknown/revoked key: 401, no detail about which part failed.
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_09_unknown_key_401() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["anything"]
        "#
    ))
    .unwrap();
    let app = build_router(AppState::new(config));

    let resp = app
        .oneshot(models_request("127.0.0.1:8787", "totally-wrong-key"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(error_code(resp).await, "auth_unknown_key");
}

// ---------------------------------------------------------------------
// Row 10 — safe-plane key requests a model outside its allowlist: 403 with
// a distinct, permanent-reading code (agent clients loop on ambiguous
// errors).
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_10_key_outside_allowlist_403_distinct_code() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["b/allowed-model"]

        [[backend]]
        id = "b"
        base_url = "http://127.0.0.1:1/v1"
        dialect = "openai"
        "#
    ))
    .unwrap();
    let app = build_router(AppState::new(config));

    let resp = app.oneshot(chat_request("b/not-allowed-model", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_code(resp).await, "policy_denied_model");
}

// ---------------------------------------------------------------------
// Row 12a — safe plane: reported model != resolved target is terminal.
// Non-streaming buffers and discards the body (502, distinct code);
// streaming gates on the first chunk before any bytes reach the client.
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_12a_safe_mismatch_terminal_non_streaming() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_wrong_model_backend().await;
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["b/expected-model"]

        [[backend]]
        id = "b"
        base_url = "{backend}"
        dialect = "openai"
        "#
    ))
    .unwrap();
    let state = AppState::new(config);
    let app = build_router(state.clone());

    let resp = app.oneshot(chat_request("b/expected-model", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(error_code(resp).await, "model_mismatch");
    assert_eq!(state.mismatch_count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn matrix_row_12a_safe_mismatch_terminal_streaming() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_wrong_model_backend().await;
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["b/expected-model"]

        [[backend]]
        id = "b"
        base_url = "{backend}"
        dialect = "openai"
        "#
    ))
    .unwrap();
    let state = AppState::new(config);
    let app = build_router(state.clone());

    let resp = app.oneshot(chat_request("b/expected-model", true)).await.unwrap();
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("model_mismatch"), "expected model_mismatch SSE event, got: {text}");
    assert!(
        !text.contains("not-the-model-you-dispatched-to"),
        "backend's wrong-model content must never reach the client: {text}"
    );
    assert_eq!(state.mismatch_count.load(Ordering::Relaxed), 1);
}

// ---------------------------------------------------------------------
// Row 12b — escalation plane: same mismatch is relayed anyway (detection
// only), logged and counted.
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_12b_escalation_mismatch_passthrough() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_wrong_model_backend().await;
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8788"
        plane = "escalation"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["p/expected-model"]

        [[provider]]
        id = "p"
        base_url = "{backend}"
        dialect = "openai"
        keychain_item = "safe-router/p"
        "#
    ))
    .unwrap();
    let state = AppState::new(config);
    let app = build_router(state.clone());

    let resp = app.oneshot(chat_request("p/expected-model", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["model"], "not-the-model-you-dispatched-to");
    assert_eq!(state.mismatch_count.load(Ordering::Relaxed), 1);
}

// ---------------------------------------------------------------------
// Row 13 — TLS/certificate failure to a remote backend: fail closed, no
// plaintext retry. A plain-HTTP mock under an `https://` URL fails the TLS
// handshake outright — if the router ever fell back to plaintext, this
// would observe a 200 from the mock instead.
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_13_tls_handshake_failure_fails_closed_no_plaintext_retry() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let plain_http = support::spawn_mock_backend().await; // "http://127.0.0.1:PORT/v1"
    let addr = plain_http
        .trim_start_matches("http://")
        .trim_end_matches("/v1");
    let https_url = format!("https://{addr}/v1");
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8788"
        plane = "escalation"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["p/some-model"]

        [[provider]]
        id = "p"
        base_url = "{https_url}"
        dialect = "openai"
        keychain_item = "safe-router/p"
        "#
    ))
    .unwrap();
    let app = build_router(AppState::new(config));

    let resp = app.oneshot(chat_request("p/some-model", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(error_code(resp).await, "backend_unreachable");
}

// ---------------------------------------------------------------------
// Row 14 — client disconnects mid-request: cancel the upstream request.
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_14_client_disconnect_cancels_upstream() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let (backend, counter) =
        support::spawn_slow_drip_backend(std::time::Duration::from_millis(80)).await;
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["b/some-model"]

        [[backend]]
        id = "b"
        base_url = "{backend}"
        dialect = "openai"
        "#
    ))
    .unwrap();
    let app = build_router(AppState::new(config));

    let resp = app.oneshot(chat_request("b/some-model", true)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut body = resp.into_body().into_data_stream();
    body.next().await; // wait for the first chunk to actually arrive
    drop(body); // simulate the client walking away mid-stream

    let count_at_drop = counter.load(Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let count_after_wait = counter.load(Ordering::SeqCst);

    assert!(
        count_after_wait <= count_at_drop + 1,
        "backend kept streaming after client disconnected: {count_at_drop} -> {count_after_wait} \
         (of 20 max) — upstream request was not cancelled"
    );
}

// ---------------------------------------------------------------------
// Row 15 — cross-plane confusion: a key that doesn't exist in a plane's
// config is just an unknown key there, in both directions.
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_15_cross_plane_confusion_401_both_directions() {
    const SAFE_KEY: &str = "safe-only-key";
    const ESCALATION_KEY: &str = "escalation-only-key";
    let safe_hash = auth::hash_key(SAFE_KEY).unwrap();
    let escalation_hash = auth::hash_key(ESCALATION_KEY).unwrap();

    let safe_config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "safe-key"
        hash = "{safe_hash}"
        allow = ["anything"]
        "#
    ))
    .unwrap();
    let escalation_config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8788"
        plane = "escalation"

        [[key]]
        id = "escalation-key"
        hash = "{escalation_hash}"
        allow = ["anything"]
        "#
    ))
    .unwrap();

    let safe_app = build_router(AppState::new(safe_config));
    let escalation_app = build_router(AppState::new(escalation_config));

    let resp = safe_app
        .oneshot(models_request("127.0.0.1:8787", ESCALATION_KEY))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "safe plane must not accept an escalation-only key");

    let resp = escalation_app
        .oneshot(models_request("127.0.0.1:8788", SAFE_KEY))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "escalation plane must not accept a safe-only key");
}

// ---------------------------------------------------------------------
// Row 16 — same key hash in both plane configs: startup validation
// failure. Spawns the real binary against a `safe.toml`/`escalation.toml`
// pair (the peer-file-discovery naming convention `main.rs` relies on).
// ---------------------------------------------------------------------
#[test]
fn matrix_row_16_same_key_hash_both_planes_refuses_start() {
    let dir = unique_temp_dir("row16");
    let hash = auth::hash_key("shared-key").unwrap();

    std::fs::write(
        dir.join("safe.toml"),
        format!(
            r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"

            [[key]]
            id = "shared"
            hash = "{hash}"
            allow = ["anything"]
            "#
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("escalation.toml"),
        format!(
            r#"
            [server]
            bind = "127.0.0.1:8788"
            plane = "escalation"

            [[key]]
            id = "shared"
            hash = "{hash}"
            allow = ["anything"]
            "#
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_safe-router"))
        .arg("--config")
        .arg(dir.join("safe.toml"))
        .output()
        .expect("spawn safe-router binary");

    assert!(!output.status.success(), "binary must refuse to start on a cross-plane key collision");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("both plane configs"), "stderr: {stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// Row 11 — log write failure / disk full: traffic continues, buffered in
// memory, degraded flag set. Opens a real file-backed log successfully,
// then makes the file read-only (simulating a write failure that starts
// *after* a successful open, not "can't even start" — matrix row 11's
// specific scenario) and confirms serving continues.
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_11_log_write_failure() {
    let dir = unique_temp_dir("row11");
    let log_path = dir.join("log.db");

    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_mock_backend().await;
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["b/some-model"]

        [[backend]]
        id = "b"
        base_url = "{backend}"
        dialect = "openai"
        "#
    ))
    .unwrap();
    let state = AppState::new(config).with_log_path(&log_path).expect("log opens fine while writable");

    // Injecting the failure: this used to deny write permission on the
    // *directory*, which forced SQLite's rollback journal to fail creating
    // its per-transaction `-journal` file. That stopped working when the log
    // moved to WAL — WAL appends to a single `-wal` file opened at startup,
    // so no new file is ever created and permission checks (which happen at
    // open() time, not per write to an already-open fd) never fire again.
    // A second connection holding the write lock fails the next INSERT
    // instead: deterministic, and it surfaces at exactly the layer a real
    // disk-full or EIO does — `execute` returns Err, which is the entire
    // behavior row 11 is about.
    let blocker = rusqlite::Connection::open(&log_path).expect("second connection to the same log");
    blocker.busy_timeout(std::time::Duration::from_millis(0)).unwrap();
    blocker.execute_batch("BEGIN EXCLUSIVE").expect("hold the write lock");

    let app = build_router(state.clone());
    let resp = app.oneshot(chat_request("b/some-model", false)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "traffic must continue despite a log write failure");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert!(state.degraded.load(Ordering::SeqCst), "degraded flag must be set after a failed log write");
    assert!(state.log.buffered_count() > 0, "the failed row must be buffered in memory, not dropped");

    drop(blocker);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// Row 17 — inbound Host not loopback and not in allowed_hosts: 403
// policy_bad_host, comparison only. A Host matching an allowed_hosts entry
// passes; loopback still works even once allowed_hosts is set (v0 behavior
// preserved for an unmodified config).
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_17_host_outside_allowed_hosts_403_bad_host() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "100.64.1.2:8787"
        plane = "safe"
        allowed_hosts = ["100.64.1.2"]

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["anything"]
        "#
    ))
    .unwrap();
    let app = build_router(AppState::new(config));

    let resp = app
        .clone()
        .oneshot(models_request("evil.example.com", GOOD_KEY))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(error_code(resp).await, "policy_bad_host");

    let resp = app.oneshot(models_request("100.64.1.2:8787", GOOD_KEY)).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a Host matching allowed_hosts must pass Host validation"
    );
}

// ---------------------------------------------------------------------
// Row 18 — `[server] bind` is 0.0.0.0, LAN, or public: refuse to start with
// a distinct message naming the offending address. Spawns the real binary
// (no in-process equivalent for `main.rs`'s startup path).
// ---------------------------------------------------------------------
#[test]
fn matrix_row_18_wildcard_bind_refuses_to_start() {
    let dir = unique_temp_dir("row18-wildcard");
    let config_path = dir.join("safe.toml");
    std::fs::write(
        &config_path,
        r#"
        [server]
        bind = "0.0.0.0:8787"
        plane = "safe"
        "#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_safe-router"))
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("spawn safe-router binary");

    assert!(!output.status.success(), "binary must refuse to start with a wildcard bind");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("100.64.0.0/10"), "stderr: {stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn matrix_row_18_lan_bind_refuses_to_start() {
    let dir = unique_temp_dir("row18-lan");
    let config_path = dir.join("safe.toml");
    std::fs::write(
        &config_path,
        r#"
        [server]
        bind = "192.168.1.50:8787"
        plane = "safe"
        "#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_safe-router"))
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("spawn safe-router binary");

    assert!(!output.status.success(), "binary must refuse to start with a LAN bind");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("100.64.0.0/10"), "stderr: {stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// Row 19 — safe-plane backend base_url on the tailnet vs on the LAN:
// 100.64.0.0/10 literal accepted, LAN/public/*.ts.net refused at startup.
// ---------------------------------------------------------------------
#[test]
fn matrix_row_19_safe_plane_lan_backend_refuses_to_start() {
    let dir = unique_temp_dir("row19-lan");
    let config_path = dir.join("safe.toml");
    std::fs::write(
        &config_path,
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[backend]]
        id = "local"
        base_url = "http://192.168.1.50:1234/v1"
        dialect = "openai"
        "#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_safe-router"))
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("spawn safe-router binary");

    assert!(!output.status.success(), "binary must refuse to start with a LAN safe-plane backend");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("non-loopback base_url"), "stderr: {stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn matrix_row_19_safe_plane_tailnet_literal_backend_passes_config_validation() {
    let dir = unique_temp_dir("row19-tailnet");
    let config_path = dir.join("safe.toml");
    // `bind` targets port 1 (privileged, permission denied for an
    // unprivileged process) so the binary fails fast at the bind step
    // instead of successfully serving forever — the only thing under test
    // here is that config validation itself lets a tailnet-literal backend
    // through, which happens before the bind attempt.
    std::fs::write(
        &config_path,
        r#"
        [server]
        bind = "127.0.0.1:1"
        plane = "safe"

        [[backend]]
        id = "local"
        base_url = "http://100.64.1.2:1234/v1"
        dialect = "openai"
        "#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_safe-router"))
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("spawn safe-router binary");

    assert!(!output.status.success(), "port 1 bind must fail for an unprivileged process");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("non-loopback base_url"),
        "a tailnet-literal (100.64.0.0/10) backend must pass safe-plane validation: {stderr}"
    );
    assert!(
        stderr.contains("cannot bind"),
        "must fail at the bind step, not at config validation: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn unique_temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("safe-router-matrix-{label}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
