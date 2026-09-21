//! Step 2 check: integration tests against a mock backend (echo + SSE).

#[path = "support.rs"]
mod support;

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    routing::post,
    Router,
};
use futures_util::StreamExt;
use safe_router::{auth, build_router, policy, AppState};
use tower::ServiceExt;

const GOOD_KEY: &str = "good-key";

async fn router_with_backend(base_url: &str) -> Router {
    router_with_backend_and_allow(base_url, &["mock/echo-model", "mock/stream-model", "mock/x"]).await
}

async fn router_with_backend_and_allow(base_url: &str, allow: &[&str]) -> Router {
    let hash = auth::hash_key(GOOD_KEY).unwrap();
    let allow_toml = allow
        .iter()
        .map(|m| format!("\"{m}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let config = policy::parse_config(&format!(
        r#"
        [server]
        bind = "127.0.0.1:8787"
        plane = "safe"

        [[key]]
        id = "test"
        hash = "{hash}"
        allow = [{allow_toml}]

        [[backend]]
        id = "mock"
        base_url = "{base_url}"
        dialect = "openai"
        "#
    ))
    .unwrap();
    build_router(AppState::new(config))
}

fn authed_request(method: &str, uri: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "127.0.0.1:8787")
        .header(header::AUTHORIZATION, format!("Bearer {GOOD_KEY}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .unwrap()
}

#[tokio::test]
async fn list_models_passthrough() {
    let base_url = support::spawn_mock_backend().await;
    let app = router_with_backend(&base_url).await;

    let resp = app
        .oneshot(authed_request("GET", "/v1/models", Body::empty()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"][0]["id"], "mock-model");
}

#[tokio::test]
async fn chat_completions_non_streaming_passthrough() {
    let base_url = support::spawn_mock_backend().await;
    let app = router_with_backend(&base_url).await;

    let req_body = r#"{"model":"mock/echo-model","stream":false,"messages":[]}"#;
    let resp = app
        .oneshot(authed_request(
            "POST",
            "/v1/chat/completions",
            Body::from(req_body),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["model"], "echo-model");
}

#[tokio::test]
async fn ollama_style_tagged_model_id_passes_safe_plane_model_gate() {
    let base_url = support::spawn_mock_backend().await;
    let app = router_with_backend_and_allow(&base_url, &["mock/llama3.2:latest"]).await;

    let req_body = r#"{"model":"mock/llama3.2:latest","stream":false,"messages":[]}"#;
    let resp = app
        .oneshot(authed_request(
            "POST",
            "/v1/chat/completions",
            Body::from(req_body),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["model"], "llama3.2:latest");
}

#[tokio::test]
async fn safe_plane_does_not_follow_backend_redirect() {
    let redirected_hits = Arc::new(AtomicUsize::new(0));
    let hits = redirected_hits.clone();
    let destination = Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let hits = hits.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        }),
    );
    let destination_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination_addr = destination_listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(destination_listener, destination).await.unwrap() });

    let location = format!("http://{destination_addr}/v1/chat/completions");
    let redirector = Router::new().route(
        "/v1/chat/completions",
        post(move || {
            let location = location.clone();
            async move { (StatusCode::TEMPORARY_REDIRECT, [(header::LOCATION, location)]) }
        }),
    );
    let source_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let source_addr = source_listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(source_listener, redirector).await.unwrap() });

    let app = router_with_backend(&format!("http://{source_addr}/v1")).await;
    let response = app
        .oneshot(authed_request(
            "POST",
            "/v1/chat/completions",
            Body::from(r#"{"model":"mock/echo-model","messages":[]}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert!(response.headers().get(header::LOCATION).is_none());
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], "backend_redirect_rejected");
    assert_eq!(redirected_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn large_buffered_response_is_not_dropped_by_metadata_limit() {
    let base_url = support::spawn_large_body_backend().await;
    let app = router_with_backend_and_allow(&base_url, &["mock/x"]).await;
    let resp = app.oneshot(authed_request(
        "POST", "/v1/chat/completions",
        Body::from(r#"{"model":"mock/x","stream":false,"messages":[]}"#),
    )).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let expected = format!("{{\"model\":\"x\",\"choices\":[{{\"message\":{{\"content\":\"{}\"}}}}]}}", "z".repeat(25 * 1024 * 1024));
    assert_eq!(&bytes[..], expected.as_bytes());
}

#[tokio::test]
async fn chat_completions_streaming_passthrough() {
    let base_url = support::spawn_mock_backend().await;
    let app = router_with_backend(&base_url).await;

    let req_body = r#"{"model":"mock/stream-model","stream":true,"messages":[]}"#;
    let resp = app
        .oneshot(authed_request(
            "POST",
            "/v1/chat/completions",
            Body::from(req_body),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(content_type.contains("text/event-stream"));

    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("stream-model"));
    assert!(text.contains("data: [DONE]"));
}

#[tokio::test]
async fn backend_unreachable_returns_502_with_distinct_code() {
    // Bind then immediately drop: guarantees "connection refused" on the
    // returned port without racing a real listener.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let base_url = format!("http://{addr}/v1");

    let app = router_with_backend(&base_url).await;
    let resp = app
        .oneshot(authed_request("GET", "/v1/models", Body::empty()))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], "backend_unreachable");
}

#[tokio::test]
async fn client_disconnect_cancels_upstream() {
    // matrix row 14: dropping the client's read of the response body must
    // drop the upstream request too, not let it run to completion server-side.
    let (base_url, counter) = support::spawn_slow_drip_backend(Duration::from_millis(80)).await;
    let app = router_with_backend(&base_url).await;

    let req_body = r#"{"model":"mock/x","stream":true,"messages":[]}"#;
    let resp = app
        .oneshot(authed_request(
            "POST",
            "/v1/chat/completions",
            Body::from(req_body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let mut body = resp.into_body().into_data_stream();
    body.next().await; // wait for the first chunk to actually arrive
    drop(body); // simulate the client walking away mid-stream

    let count_at_drop = counter.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let count_after_wait = counter.load(Ordering::SeqCst);

    assert!(
        count_after_wait <= count_at_drop + 1,
        "backend kept streaming after client disconnected: {count_at_drop} -> {count_after_wait} \
         (of 20 max) — upstream request was not cancelled"
    );
}
