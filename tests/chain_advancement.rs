//! Step 5 check: `on_error = "next"` advances past 429/5xx/connect-fail to
//! the next rung; `on_error = "fail"` (or unset) never does; a concrete
//! model never substitutes to a different backend, even when one is
//! available in config.

#[path = "support.rs"]
mod support;

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use safe_router::{auth, build_router, policy, AppState};
use tower::ServiceExt;

const GOOD_KEY: &str = "good-key";

async fn router_with_two_backends(
    rung1_url: &str,
    rung2_url: &str,
    on_error: &str,
) -> Router {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["chained"]

        [[backend]]
        id = "rung1"
        base_url = "{rung1_url}"
        dialect = "openai"

        [[backend]]
        id = "rung2"
        base_url = "{rung2_url}"
        dialect = "openai"

        [[route]]
        name = "chained"
        chain = ["rung1/model-a", "rung2/model-b"]
        on_error = "{on_error}"
        "#
    ))
    .unwrap();
    build_router(AppState::new(config))
}

fn chained_request() -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header(header::HOST, "127.0.0.1:8787")
        .header(header::AUTHORIZATION, format!("Bearer {GOOD_KEY}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"model":"chained","stream":false,"messages":[]}"#.to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn advances_past_connect_refused_to_next_rung() {
    let rung1 = support::refused_connection_url().await;
    let rung2 = support::spawn_mock_backend().await;
    let app = router_with_two_backends(&rung1, &rung2, "next").await;

    let resp = app.oneshot(chained_request()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // rung2's chain entry is "rung2/model-b" — the router must have stripped
    // the backend-id prefix before dispatch, so the mock (and thus the
    // response) sees the bare model name.
    assert_eq!(json["model"], "model-b");
}

#[tokio::test]
async fn advances_past_5xx_to_next_rung() {
    let rung1 = support::spawn_status_backend(StatusCode::INTERNAL_SERVER_ERROR).await;
    let rung2 = support::spawn_mock_backend().await;
    let app = router_with_two_backends(&rung1, &rung2, "next").await;

    let resp = app.oneshot(chained_request()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["model"], "model-b");
}

#[tokio::test]
async fn advances_past_429_to_next_rung() {
    let rung1 = support::spawn_status_backend(StatusCode::TOO_MANY_REQUESTS).await;
    let rung2 = support::spawn_mock_backend().await;
    let app = router_with_two_backends(&rung1, &rung2, "next").await;

    let resp = app.oneshot(chained_request()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["model"], "model-b");
}

#[tokio::test]
async fn on_error_fail_never_advances_even_with_a_healthy_rung_2() {
    let rung1 = support::spawn_status_backend(StatusCode::INTERNAL_SERVER_ERROR).await;
    let rung2 = support::spawn_mock_backend().await; // would succeed if ever tried
    let app = router_with_two_backends(&rung1, &rung2, "fail").await;

    let resp = app.oneshot(chained_request()).await.unwrap();
    // rung1's 500 is passed straight through, not advanced past.
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn never_advances_on_400_even_with_on_error_next() {
    // The named trap (CLAUDE.md landmine): a 400 looks exactly like "just
    // try the next rung" would be obviously fine, and it is never fine —
    // matrix row 3, context overflow must pass through, not retry elsewhere.
    let rung1 = support::spawn_status_backend(StatusCode::BAD_REQUEST).await;
    let rung2 = support::spawn_mock_backend().await; // would succeed if ever tried
    let app = router_with_two_backends(&rung1, &rung2, "next").await;

    let resp = app.oneshot(chained_request()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn concrete_model_never_substitutes_to_another_configured_backend() {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let down = support::refused_connection_url().await;
    let healthy = support::spawn_mock_backend().await;
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = ["down-backend/some-model"]

        [[backend]]
        id = "down-backend"
        base_url = "{down}"
        dialect = "openai"

        [[backend]]
        id = "healthy-backend"
        base_url = "{healthy}"
        dialect = "openai"
        "#
    ))
    .unwrap();
    let app = build_router(AppState::new(config));

    let req = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header(header::HOST, "127.0.0.1:8787")
        .header(header::AUTHORIZATION, format!("Bearer {GOOD_KEY}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"model":"down-backend/some-model","stream":false,"messages":[]}"#.to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    // A concrete model names exactly one backend. Even though a second,
    // healthy backend is configured, the request gets that backend or an
    // error — never a silent switch (invariant #6).
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], "backend_unreachable");
}
