//! Step 7 check: one metadata-log row per `/v1/chat/completions` request,
//! with the correct `disposition` for each of the five values SPEC §8's
//! schema supports (served, denied_policy, denied_auth, backend_error,
//! client_cancel). `/v1/models` is out of scope — see PLAN.md's Step 7 note.

#[path = "support.rs"]
mod support;

use std::time::Duration;

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use futures_util::StreamExt;
use safe_router::{auth, build_router, policy, AppState};
use tower::ServiceExt;

const GOOD_KEY: &str = "good-key";

fn chat_request(auth_header: &str, model: &str, stream: bool) -> Request<Body> {
    let body = format!(r#"{{"model":"{model}","stream":{stream},"messages":[]}}"#);
    Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header(header::HOST, "127.0.0.1:8787")
        .header(header::AUTHORIZATION, auth_header)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn logs_served_for_a_successful_completion() {
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

    let resp = app
        .oneshot(chat_request(&format!("Bearer {GOOD_KEY}"), "b/some-model", false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let row = state.log.last_row().expect("a row was logged");
    assert_eq!(row.disposition, "served");
    assert_eq!(row.plane, "safe");
    assert_eq!(row.key_id, "test");
    assert_eq!(row.model_req, "b/some-model");
    assert_eq!(row.backend.as_deref(), Some("b"));
    assert_eq!(row.status, Some(200));
    assert!(!row.stream);
    assert!(!row.mismatch);
    assert_eq!((row.tokens_in, row.tokens_out), (Some(7), Some(0)));
}

#[tokio::test]
async fn openai_stream_usage_and_tag_are_logged_without_changing_sse_bytes() {
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
    )).unwrap();
    let state = AppState::new(config);
    let app = build_router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header(header::HOST, "127.0.0.1:8787")
        .header(header::AUTHORIZATION, format!("Bearer {GOOD_KEY}"))
        .header("x-safe-router-tag", "<tab&42>")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"model":"b/some-model","stream":true,"stream_options":{"include_usage":true},"messages":[]}"#))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();
    let expected = concat!(
        "data: {\"id\":\"mock-1\",\"object\":\"chat.completion.chunk\",\"model\":\"some-model\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
        "data: {\"id\":\"mock-1\",\"object\":\"chat.completion.chunk\",\"model\":\"some-model\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":0}}\n\n",
        "data: [DONE]\n\n",
    );
    assert_eq!(body, expected, "the usage observer must not alter any SSE byte");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let row = state.log.last_row().unwrap();
    assert_eq!((row.tokens_in, row.tokens_out), (Some(7), Some(0)));
    assert_eq!(row.client_tag.as_deref(), Some("<tab&42>"));
    assert_eq!(row.disposition, "served");
    assert!(state.log.verify_chain().is_ok());
}

#[tokio::test]
async fn openai_stream_without_usage_keeps_null_counters_and_drops_oversized_tag() {
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
    )).unwrap();
    let state = AppState::new(config);
    let app = build_router(state.clone());
    let mut req = chat_request(&format!("Bearer {GOOD_KEY}"), "b/some-model", true);
    req.headers_mut().insert("x-safe-router-tag", "x".repeat(129).parse().unwrap());
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "tag must not affect policy");
    let _ = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let row = state.log.last_row().unwrap();
    assert_eq!((row.tokens_in, row.tokens_out), (None, None));
    assert_eq!(row.client_tag, None);
    assert!(state.log.verify_chain().is_ok());
}

#[tokio::test]
async fn logs_denied_auth_for_an_unknown_key() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["b/some-model"]
        "#
    ))
    .unwrap();
    let state = AppState::new(config);
    let app = build_router(state.clone());

    let resp = app
        .oneshot(chat_request("Bearer totally-wrong-key", "b/some-model", false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let row = state.log.last_row().expect("a row was logged");
    assert_eq!(row.disposition, "denied_auth");
    // Rejected before a key was ever matched — no credential material, real
    // or presented-and-wrong, ever gets echoed into the log.
    assert_eq!(row.key_id, "unknown");
    assert_eq!(row.err_code.as_deref(), Some("auth_unknown_key"));
}

/// A pre-auth rejection: `guard` refuses the Host before any key is looked
/// up. The two rejections that most want to be visible in a security log
/// were the two `disposition_for_code` had the wrong strings for — this row
/// logged `served`/NULL with a 403 status until that was fixed.
#[tokio::test]
async fn logs_denied_auth_for_a_non_loopback_host() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["b/some-model"]
        "#
    ))
    .unwrap();
    let state = AppState::new(config);
    let app = build_router(state.clone());

    let mut req = chat_request(&format!("Bearer {GOOD_KEY}"), "b/some-model", false);
    req.headers_mut()
        .insert(header::HOST, "evil.example.com".parse().unwrap());
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let row = state.log.last_row().expect("a row was logged");
    assert_eq!(row.disposition, "denied_auth");
    assert_eq!(row.err_code.as_deref(), Some("policy_bad_host"));
    assert_eq!(row.status, Some(403));
    // Rejected before auth and before admission — neither is known yet.
    assert_eq!(row.key_id, "unknown");
    assert_eq!(row.model_req, "unknown");
}

#[tokio::test]
async fn logs_denied_auth_for_an_origin_header() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["b/some-model"]
        "#
    ))
    .unwrap();
    let state = AppState::new(config);
    let app = build_router(state.clone());

    let mut req = chat_request(&format!("Bearer {GOOD_KEY}"), "b/some-model", false);
    req.headers_mut()
        .insert(header::ORIGIN, "http://evil.example.com".parse().unwrap());
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let row = state.log.last_row().expect("a row was logged");
    assert_eq!(row.disposition, "denied_auth");
    assert_eq!(row.err_code.as_deref(), Some("policy_origin_rejected"));
}

/// The router relays a backend's own error body verbatim (matrix rows 2/3),
/// including a `code` field that may collide with one of the router's own.
/// Classification reads what the *router* produced (an `ErrCode` extension),
/// never the body — so this stays `served`: the router did exactly its job.
#[tokio::test]
async fn logs_served_when_a_backend_error_body_mimics_a_router_code() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let backend =
        support::spawn_mimic_error_backend(StatusCode::FORBIDDEN, "policy_denied_model").await;
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

    let resp = app
        .oneshot(chat_request(&format!("Bearer {GOOD_KEY}"), "b/some-model", false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "backend status passes through");

    tokio::time::sleep(Duration::from_millis(200)).await;
    let row = state.log.last_row().expect("a row was logged");
    assert_eq!(row.disposition, "served");
    assert_eq!(row.err_code, None);
    assert_eq!(row.status, Some(403));
}

#[tokio::test]
async fn logs_denied_policy_for_a_model_outside_the_allowlist() {
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
        "#
    ))
    .unwrap();
    let state = AppState::new(config);
    let app = build_router(state.clone());

    let resp = app
        .oneshot(chat_request(&format!("Bearer {GOOD_KEY}"), "b/not-allowed", false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let row = state.log.last_row().expect("a row was logged");
    assert_eq!(row.disposition, "denied_policy");
    assert_eq!(row.key_id, "test");
    assert_eq!(row.model_req, "b/not-allowed");
    assert_eq!(row.err_code.as_deref(), Some("policy_denied_model"));
}

#[tokio::test]
async fn logs_backend_error_for_an_unreachable_backend() {
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
    let state = AppState::new(config);
    let app = build_router(state.clone());

    let resp = app
        .oneshot(chat_request(&format!("Bearer {GOOD_KEY}"), "down/some-model", false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let row = state.log.last_row().expect("a row was logged");
    assert_eq!(row.disposition, "backend_error");
    assert_eq!(row.err_code.as_deref(), Some("backend_unreachable"));
}

#[tokio::test]
async fn logs_client_cancel_when_client_disconnects_mid_stream() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let (backend, _counter) = support::spawn_slow_drip_backend(Duration::from_millis(80)).await;
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

    let resp = app
        .oneshot(chat_request(&format!("Bearer {GOOD_KEY}"), "b/some-model", true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut body = resp.into_body().into_data_stream();
    body.next().await; // let the first chunk actually arrive
    drop(body); // client walks away before the stream naturally ends

    tokio::time::sleep(Duration::from_millis(500)).await;
    let row = state.log.last_row().expect("a row was logged");
    assert_eq!(row.disposition, "client_cancel");
    assert!(row.stream);
}
