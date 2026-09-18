//! Step 4 check: escalation-plane dispatch attaches the Keychain-sourced
//! credential; safe-plane dispatch never does. Credentials are injected
//! directly via `AppState::with_credentials` here — this exercises the
//! dispatch/header logic without touching the real Keychain (that's
//! `keychain::tests`, against a fake `security` binary).

#[path = "support.rs"]
mod support;

use std::collections::HashMap;

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use safe_router::{auth, build_router, policy, AppState};
use tower::ServiceExt;

const GOOD_KEY: &str = "good-key";

fn chat_request(body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header(header::HOST, "127.0.0.1:8788")
        .header(header::AUTHORIZATION, format!("Bearer {GOOD_KEY}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn escalation_plane_attaches_keychain_credential_to_upstream_request() {
    let base_url = support::spawn_mock_backend().await;
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8788"
        plane = "escalation"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["openai/openai-model"]

        [[provider]]
        id = "openai"
        base_url = "{base_url}"
        dialect = "openai"
        keychain_item = "safe-router/openai"
        "#
    ))
    .unwrap();

    let mut credentials = HashMap::new();
    credentials.insert("openai".to_string(), "sk-injected-test-secret".to_string());
    let app = build_router(AppState::new(config).with_credentials(credentials));

    let body = r#"{"model":"openai/openai-model","stream":false,"messages":[]}"#;
    let resp = app.oneshot(chat_request(body)).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        json["_received_authorization"],
        "Bearer sk-injected-test-secret"
    );
}

#[tokio::test]
async fn safe_plane_never_attaches_a_credential() {
    let base_url = support::spawn_mock_backend().await;
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["local/local-model"]

        [[backend]]
        id = "local"
        base_url = "{base_url}"
        dialect = "openai"
        "#
    ))
    .unwrap();

    // No credentials injected at all — proves the safe plane doesn't even
    // look for one (invariant #2: no remote credential in this process'
    // reachable state, let alone attached to an outbound request).
    let app = build_router(AppState::new(config));

    let req = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header(header::HOST, "127.0.0.1:8787")
        .header(header::AUTHORIZATION, format!("Bearer {GOOD_KEY}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"model":"local/local-model","stream":false,"messages":[]}"#.to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["_received_authorization"].is_null());
}

#[tokio::test]
async fn escalation_plane_without_matching_credential_sends_no_bearer() {
    // Provider configured but its keychain_item id has no entry in the
    // credentials map (e.g. a startup edge case) — must not crash or send a
    // garbage header, just proceed unauthenticated (the backend will reject
    // it, which is the honest outcome).
    let base_url = support::spawn_mock_backend().await;
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8788"
        plane = "escalation"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["openai/openai-model"]

        [[provider]]
        id = "openai"
        base_url = "{base_url}"
        dialect = "openai"
        keychain_item = "safe-router/openai"
        "#
    ))
    .unwrap();

    let app = build_router(AppState::new(config)); // no credentials at all

    let resp = app
        .oneshot(chat_request(
            r#"{"model":"openai/openai-model","stream":false,"messages":[]}"#,
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["_received_authorization"].is_null());
}
