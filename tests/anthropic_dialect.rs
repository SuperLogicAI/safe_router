//! Phase 2 Step 2 (SPEC §7.1): `POST /v1/messages`, the Anthropic Messages
//! passthrough dialect. Same trick as v0's OpenAI dialect, not a
//! translation — this file exercises what's specific to it: key extraction
//! from `x-api-key`, the forwarded-header allowlist, dialect-mismatch
//! admission (matrix row 20), the mixed-dialect-chain startup refusal (row
//! 21), and row 12's dialect note (12c/12d).

#[path = "support.rs"]
mod support;

use std::process::Command;

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use safe_router::{auth, build_router, policy, AppState};
use serde_json::Value;
use tower::ServiceExt;

const GOOD_KEY: &str = "good-key";

fn messages_request(auth_header: (&'static str, String), model: &str, stream: bool) -> Request<Body> {
    let body = format!(r#"{{"model":"{model}","stream":{stream},"messages":[{{"role":"user","content":"hi"}}]}}"#);
    Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header(header::HOST, "127.0.0.1:8788")
        .header(auth_header.0, auth_header.1)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

async fn json_body(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn escalation_config_with_anthropic_provider(hash: &str, backend_url: &str) -> policy::Config {
    policy::parse_config(&format!(
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
        base_url = "{backend_url}"
        dialect = "anthropic"
        keychain_item = "safe-router/p"
        "#
    ))
    .unwrap()
}

// ---------------------------------------------------------------------
// Basic passthrough: non-streaming and streaming, both dialects' bodies
// pass through untouched (bytes in, bytes out — no translation).
// ---------------------------------------------------------------------
#[tokio::test]
async fn messages_non_streaming_passthrough() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_anthropic_backend(None).await;
    let config = escalation_config_with_anthropic_provider(&hash, &backend);
    let state = AppState::new(config);
    let app = build_router(state.clone());

    let resp = app
        .oneshot(messages_request(
            (header::AUTHORIZATION.as_str(), format!("Bearer {GOOD_KEY}")),
            "p/expected-model",
            false,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["model"], "expected-model");
    assert_eq!(json["type"], "message");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let row = state.log.last_row().unwrap();
    assert_eq!((row.tokens_in, row.tokens_out), (Some(4), Some(2)));
}

#[tokio::test]
async fn messages_streaming_passthrough() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_anthropic_backend(None).await;
    let config = escalation_config_with_anthropic_provider(&hash, &backend);
    let state = AppState::new(config);
    let app = build_router(state.clone());

    let mut request = messages_request(
            (header::AUTHORIZATION.as_str(), format!("Bearer {GOOD_KEY}")),
            "p/expected-model",
            true,
        );
    request.headers_mut().insert("x-safe-router-tag", "anthropic-tab".parse().unwrap());
    let resp = app.oneshot(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let expected = concat!(
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"expected-model\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n",
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
        "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    );
    assert_eq!(text, expected, "the usage observer must not change any Anthropic SSE byte");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let row = state.log.last_row().unwrap();
    assert_eq!((row.tokens_in, row.tokens_out), (Some(1), Some(2)));
    assert_eq!(row.client_tag.as_deref(), Some("anthropic-tab"));
}

// ---------------------------------------------------------------------
// Matrix row 22 — inbound key extraction widens for this route only:
// x-api-key or Authorization: Bearer, either accepted as the router's own
// key, and never forwarded upstream. Upstream sees only the
// Keychain-sourced provider credential.
// ---------------------------------------------------------------------
#[tokio::test]
async fn messages_accepts_x_api_key_header() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_anthropic_backend(None).await;
    let config = escalation_config_with_anthropic_provider(&hash, &backend);
    let app = build_router(AppState::new(config));

    let resp = app
        .oneshot(messages_request(("x-api-key", GOOD_KEY.to_string()), "p/expected-model", false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn messages_wrong_x_api_key_is_401() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_anthropic_backend(None).await;
    let config = escalation_config_with_anthropic_provider(&hash, &backend);
    let app = build_router(AppState::new(config));

    let resp = app
        .oneshot(messages_request(("x-api-key", "totally-wrong".to_string()), "p/expected-model", false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let json = json_body(resp).await;
    assert_eq!(json["type"], "error");
    assert_eq!(json["router_code"], "auth_unknown_key");
}

#[tokio::test]
async fn messages_client_key_never_forwarded_upstream() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_anthropic_backend(None).await;
    let config = escalation_config_with_anthropic_provider(&hash, &backend);
    let app = build_router(AppState::new(config));

    // Via x-api-key.
    let resp = app
        .clone()
        .oneshot(messages_request(("x-api-key", GOOD_KEY.to_string()), "p/expected-model", false))
        .await
        .unwrap();
    let json = json_body(resp).await;
    assert_ne!(json["_received_x_api_key"], GOOD_KEY, "client's own key must never reach the backend");
    assert!(json["_received_x_api_key"].is_null(), "no provider credential configured — backend must see none");
    assert!(json["_received_authorization"].is_null());

    // Via Authorization: Bearer.
    let resp = app
        .oneshot(messages_request(
            (header::AUTHORIZATION.as_str(), format!("Bearer {GOOD_KEY}")),
            "p/expected-model",
            false,
        ))
        .await
        .unwrap();
    let json = json_body(resp).await;
    assert_ne!(json["_received_x_api_key"], GOOD_KEY);
    assert!(json["_received_authorization"].is_null(), "client's Authorization must never reach the backend");
}

// ---------------------------------------------------------------------
// anthropic-version / anthropic-beta: forwarded verbatim from the client
// when present, versioned defaulted otherwise. The entire forwarded-header
// allowlist for this dialect.
// ---------------------------------------------------------------------
#[tokio::test]
async fn anthropic_version_defaulted_when_absent() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_anthropic_backend(None).await;
    let config = escalation_config_with_anthropic_provider(&hash, &backend);
    let app = build_router(AppState::new(config));

    let resp = app
        .oneshot(messages_request(
            (header::AUTHORIZATION.as_str(), format!("Bearer {GOOD_KEY}")),
            "p/expected-model",
            false,
        ))
        .await
        .unwrap();
    let json = json_body(resp).await;
    assert_eq!(json["_received_anthropic_version"], "2023-06-01");
    assert!(json["_received_anthropic_beta"].is_null());
}

#[tokio::test]
async fn anthropic_version_and_beta_forwarded_when_present() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_anthropic_backend(None).await;
    let config = escalation_config_with_anthropic_provider(&hash, &backend);
    let app = build_router(AppState::new(config));

    let mut req = messages_request(
        (header::AUTHORIZATION.as_str(), format!("Bearer {GOOD_KEY}")),
        "p/expected-model",
        false,
    );
    req.headers_mut().insert("anthropic-version", "2024-01-01".parse().unwrap());
    req.headers_mut().insert("anthropic-beta", "tools-2024-01-01".parse().unwrap());

    let resp = app.oneshot(req).await.unwrap();
    let json = json_body(resp).await;
    assert_eq!(json["_received_anthropic_version"], "2024-01-01");
    assert_eq!(json["_received_anthropic_beta"], "tools-2024-01-01");
}

// ---------------------------------------------------------------------
// Row 20 — the inbound endpoint's dialect must match the resolved chain's
// dialect, before any upstream byte, in both directions.
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_20_messages_resolving_to_openai_chain_is_dialect_mismatch() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
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
        base_url = "https://api.openai.com/v1"
        dialect = "openai"
        keychain_item = "safe-router/p"
        "#
    ))
    .unwrap();
    let app = build_router(AppState::new(config));

    let resp = app
        .oneshot(messages_request(
            (header::AUTHORIZATION.as_str(), format!("Bearer {GOOD_KEY}")),
            "p/some-model",
            false,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = json_body(resp).await;
    assert_eq!(json["router_code"], "policy_dialect_mismatch");
}

#[tokio::test]
async fn matrix_row_20_chat_completions_resolving_to_anthropic_chain_is_dialect_mismatch() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let config = escalation_config_with_anthropic_provider(&hash, "https://api.anthropic.com");
    let app = build_router(AppState::new(config));

    let body = r#"{"model":"p/expected-model","stream":false,"messages":[]}"#;
    let req = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header(header::HOST, "127.0.0.1:8788")
        .header(header::AUTHORIZATION, format!("Bearer {GOOD_KEY}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["error"]["code"], "policy_dialect_mismatch");
}

// ---------------------------------------------------------------------
// Row 21 — a route chain whose rungs span two dialects: refuse to start.
// Spawns the real binary (config validation is a startup-time path).
// ---------------------------------------------------------------------
#[test]
fn matrix_row_21_mixed_dialect_chain_refuses_to_start() {
    let dir = unique_temp_dir("row21");
    let config_path = dir.join("escalation.toml");
    std::fs::write(
        &config_path,
        r#"
        [server]
        bind = "127.0.0.1:8788"
        plane = "escalation"

        [[provider]]
        id = "openai-p"
        base_url = "https://api.openai.com/v1"
        dialect = "openai"
        keychain_item = "safe-router/openai-p"

        [[provider]]
        id = "anthropic-p"
        base_url = "https://api.anthropic.com"
        dialect = "anthropic"
        keychain_item = "safe-router/anthropic-p"

        [[route]]
        name = "mixed"
        chain = ["openai-p/model-a", "anthropic-p/model-b"]
        on_error = "next"
        "#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_safe-router"))
        .arg("--config")
        .arg(&config_path)
        .output()
        .expect("spawn safe-router binary");

    assert!(!output.status.success(), "binary must refuse to start with a mixed-dialect chain");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("mixes dialects"), "stderr: {stderr}");

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// Row 12c/12d — row 12's dialect note. Safe plane: terminal, Anthropic-shaped
// error. Escalation: passthrough, detection only.
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_12c_messages_safe_mismatch_terminal() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_anthropic_backend(Some("not-the-model-you-dispatched-to")).await;
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
        dialect = "anthropic"
        "#
    ))
    .unwrap();
    let app = build_router(AppState::new(config));

    let resp = app
        .oneshot(messages_request(
            (header::AUTHORIZATION.as_str(), format!("Bearer {GOOD_KEY}")),
            "b/expected-model",
            false,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let json = json_body(resp).await;
    assert_eq!(json["router_code"], "model_mismatch");
}

#[tokio::test]
async fn matrix_row_12d_messages_escalation_passthrough() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_anthropic_backend(Some("not-the-model-you-dispatched-to")).await;
    let config = escalation_config_with_anthropic_provider(&hash, &backend);
    let app = build_router(AppState::new(config));

    let resp = app
        .oneshot(messages_request(
            (header::AUTHORIZATION.as_str(), format!("Bearer {GOOD_KEY}")),
            "p/expected-model",
            false,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["model"], "not-the-model-you-dispatched-to");
}

// ---------------------------------------------------------------------
// Streaming half of row 12c: the model lives at `message.model`, nested
// inside the first SSE event (`message_start`), not top-level. Verifies
// `extract_model_field`'s substring scan finds it as-is, against a real
// captured-shape fixture, and that the terminal SSE event on mismatch is
// Anthropic-shaped.
// ---------------------------------------------------------------------
#[tokio::test]
async fn matrix_row_12c_messages_safe_mismatch_terminal_streaming() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend = support::spawn_anthropic_backend(Some("not-the-model-you-dispatched-to")).await;
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
        dialect = "anthropic"
        "#
    ))
    .unwrap();
    let app = build_router(AppState::new(config));

    let resp = app
        .oneshot(messages_request(
            (header::AUTHORIZATION.as_str(), format!("Bearer {GOOD_KEY}")),
            "b/expected-model",
            true,
        ))
        .await
        .unwrap();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.starts_with("event: error"), "expected an Anthropic-shaped error event, got: {text}");
    assert!(text.contains("\"type\":\"error\""), "got: {text}");
    assert!(
        !text.contains("not-the-model-you-dispatched-to"),
        "backend's wrong-model content must never reach the client: {text}"
    );
}

fn unique_temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("safe-router-anthropic-{label}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
