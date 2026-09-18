//! Shared mock backend for integration tests. Step 2 only needs echo + SSE;
//! Step 6 extends this same file with the rest of the failure-matrix shapes
//! (refuse connections, 400/429/5xx, stall mid-stream, wrong `model`).
//!
//! This file is pulled in via `#[path = "support.rs"] mod support;` by
//! several test binaries, each of which uses a different subset of its
//! helpers — so any one binary's compilation sees some functions as
//! "unused." (Cargo also auto-discovers this file as its own top-level,
//! zero-test binary, which sees the same thing.) Allowed at module level
//! rather than piecemeal.
#![allow(dead_code)]

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{
    body::{Body, Bytes},
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use futures_util::{stream, StreamExt};
use serde_json::{json, Value};

/// A URL that guarantees connection-refused: bind an ephemeral port, then
/// drop the listener before anything ever accepts on it.
pub async fn refused_connection_url() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}/v1")
}

/// Starts a mock OpenAI-compatible backend on an ephemeral loopback port and
/// returns its base URL (e.g. `http://127.0.0.1:54321/v1`).
pub async fn spawn_mock_backend() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    let app = Router::new()
        .route("/v1/models", get(models))
        .route("/v1/chat/completions", post(chat_completions));

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock backend serve");
    });

    format!("http://{addr}/v1")
}

async fn models() -> Response {
    Json(json!({
        "object": "list",
        "data": [{"id": "mock-model", "object": "model"}]
    }))
    .into_response()
}

async fn chat_completions(headers: HeaderMap, Json(body): Json<Value>) -> Response {
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("mock-model")
        .to_string();
    let stream = body
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // Echoed back so tests can assert what credential (if any) the router
    // actually attached — e.g. escalation-plane requests must carry the
    // Keychain-fetched secret; safe-plane requests must carry none.
    let received_authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    if stream {
        let usage_event = if body.pointer("/stream_options/include_usage").and_then(Value::as_bool) == Some(true) {
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":0}}\n\n"
        } else {
            ""
        };
        let sse = format!(
            "data: {{\"id\":\"mock-1\",\"object\":\"chat.completion.chunk\",\"model\":\"{model}\",\"choices\":[{{\"delta\":{{\"content\":\"hi\"}}}}]}}\n\n\
             data: {{\"id\":\"mock-1\",\"object\":\"chat.completion.chunk\",\"model\":\"{model}\",\"choices\":[{{\"delta\":{{}},\"finish_reason\":\"stop\"}}]}}\n\n\
             {usage_event}data: [DONE]\n\n"
        );
        (
            [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
            Bytes::from(sse),
        )
            .into_response()
    } else {
        Json(json!({
            "id": "mock-1",
            "object": "chat.completion",
            "model": model,
            "choices": [{"message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 0},
            "_received_authorization": received_authorization
        }))
        .into_response()
    }
}

/// A backend whose `/v1/chat/completions` always answers with the given
/// status and a minimal OpenAI-shaped error body — for exercising chain
/// advancement (Step 5: rung fails with 429/5xx → next rung tried) without
/// needing a real flaky backend.
pub async fn spawn_status_backend(status: StatusCode) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || async move {
            (
                status,
                Json(json!({"error": {"message": "mock failure", "code": "mock_failure"}})),
            )
        }),
    );

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock backend serve");
    });

    format!("http://{addr}/v1")
}

/// A response larger than the metadata parser cap; the router must relay
/// its bytes even though usage extraction deliberately gives up.
pub async fn spawn_large_body_backend() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    let payload = format!("{{\"model\":\"x\",\"choices\":[{{\"message\":{{\"content\":\"{}\"}}}}]}}", "z".repeat(25 * 1024 * 1024));
    let app = Router::new().route("/v1/chat/completions", post(move || {
        let payload = payload.clone();
        async move { ([(axum::http::header::CONTENT_TYPE, "application/json")], Bytes::from(payload)) }
    }));
    tokio::spawn(async move { axum::serve(listener, app).await.expect("mock backend serve"); });
    format!("http://{addr}/v1")
}

/// A backend whose error body carries a `code` the *router* also uses. The
/// router relays that body verbatim (matrix rows 2/3), so the metadata log
/// must classify the row by what the router itself produced — nothing — and
/// not by reading a code out of someone else's JSON.
pub async fn spawn_mimic_error_backend(status: StatusCode, code: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    let app = Router::new().route(
        "/v1/chat/completions",
        post(move || async move {
            (
                status,
                Json(json!({"error": {"message": "upstream says no", "code": code}})),
            )
        }),
    );

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock backend serve");
    });

    format!("http://{addr}/v1")
}

/// A backend that yields one SSE chunk every `interval`, up to 20 chunks,
/// incrementing the returned counter just before each send. Lets a test
/// assert cancellation actually reached the backend (matrix row 14) instead
/// of just trusting that dropping a `Body` drops the stream feeding it.
pub async fn spawn_slow_drip_backend(interval: Duration) -> (String, Arc<AtomicUsize>) {
    let counter = Arc::new(AtomicUsize::new(0));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    let app = Router::new()
        .route("/v1/chat/completions", post(slow_drip))
        .with_state((counter.clone(), interval));

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock backend serve");
    });

    (format!("http://{addr}/v1"), counter)
}

async fn slow_drip(State((counter, interval)): State<(Arc<AtomicUsize>, Duration)>) -> Response {
    let stream = stream::unfold(0usize, move |i| {
        let counter = counter.clone();
        async move {
            if i >= 20 {
                return None;
            }
            tokio::time::sleep(interval).await;
            counter.store(i + 1, Ordering::SeqCst);
            let chunk = Bytes::from(format!("data: {{\"chunk\":{i}}}\n\n"));
            Some((Ok::<_, std::io::Error>(chunk), i + 1))
        }
    });
    (
        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
        Body::from_stream(stream),
    )
        .into_response()
}

/// Sends one SSE chunk immediately, then never sends another byte and never
/// closes the connection — matrix row 4 (idle timeout mid-stream), which
/// only makes sense as a stall *after* some data, not a stall before any.
pub async fn spawn_stalling_backend() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    let app = Router::new().route(
        "/v1/chat/completions",
        post(|| async {
            let first = stream::once(async {
                Ok::<_, std::io::Error>(Bytes::from_static(b"data: {\"chunk\":0}\n\n"))
            });
            let stalled = first.chain(stream::pending());
            (
                [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                Body::from_stream(stalled),
            )
                .into_response()
        }),
    );

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock backend serve");
    });

    format!("http://{addr}/v1")
}

/// Starts a mock Anthropic-compatible backend (`POST /v1/messages`) on an
/// ephemeral loopback port. Echoes the requested `model` (or `fixed_model`
/// when given, for matrix row 12c/12d) and the headers it actually
/// received, so tests can assert what the router attached (or didn't —
/// matrix row 22: the client's own key must never reach here).
pub async fn spawn_anthropic_backend(fixed_model: Option<&'static str>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    let app = Router::new()
        .route("/v1/messages", post(move |headers, body| anthropic_messages(headers, body, fixed_model)));

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock anthropic backend serve");
    });

    // No trailing /v1 — SPEC §7.1: the router joins `/v1/messages` itself.
    format!("http://{addr}")
}

async fn anthropic_messages(headers: HeaderMap, Json(body): Json<Value>, fixed_model: Option<&'static str>) -> Response {
    let requested_model = body.get("model").and_then(Value::as_str).unwrap_or("mock-model").to_string();
    let model = fixed_model.map(str::to_string).unwrap_or(requested_model);
    let stream = body.get("stream").and_then(Value::as_bool).unwrap_or(false);

    let received_x_api_key = headers.get("x-api-key").and_then(|v| v.to_str().ok()).map(str::to_string);
    let received_authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let received_anthropic_version = headers.get("anthropic-version").and_then(|v| v.to_str().ok()).map(str::to_string);
    let received_anthropic_beta = headers.get("anthropic-beta").and_then(|v| v.to_str().ok()).map(str::to_string);

    if stream {
        let sse = format!(
            "event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"{model}\",\"content\":[],\"usage\":{{\"input_tokens\":1,\"output_tokens\":0}}}}}}\n\n\
             event: content_block_start\ndata: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"text\",\"text\":\"\"}}}}\n\n\
             event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"hi\"}}}}\n\n\
             event: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"end_turn\"}},\"usage\":{{\"output_tokens\":2}}}}\n\n\
             event: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n"
        );
        (
            [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
            Bytes::from(sse),
        )
            .into_response()
    } else {
        Json(json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 4, "output_tokens": 2},
            "_received_x_api_key": received_x_api_key,
            "_received_authorization": received_authorization,
            "_received_anthropic_version": received_anthropic_version,
            "_received_anthropic_beta": received_anthropic_beta,
        }))
        .into_response()
    }
}

/// Always answers with a fixed `model` field regardless of what was
/// requested — matrix row 12 (reported model != resolved target). Streams
/// or not, per the request's own `stream` field, same as `chat_completions`.
pub async fn spawn_wrong_model_backend() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    async fn handler(Json(body): Json<Value>) -> Response {
        let stream = body.get("stream").and_then(Value::as_bool).unwrap_or(false);
        const WRONG_MODEL: &str = "not-the-model-you-dispatched-to";
        if stream {
            let sse = format!(
                "data: {{\"id\":\"mock-1\",\"object\":\"chat.completion.chunk\",\"model\":\"{WRONG_MODEL}\",\"choices\":[{{\"delta\":{{\"content\":\"hi\"}}}}]}}\n\n\
                 data: [DONE]\n\n"
            );
            (
                [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                Bytes::from(sse),
            )
                .into_response()
        } else {
            Json(json!({
                "id": "mock-1",
                "object": "chat.completion",
                "model": WRONG_MODEL,
                "choices": [{"message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}]
            }))
            .into_response()
        }
    }

    let app = Router::new().route("/v1/chat/completions", post(handler));

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("mock backend serve");
    });

    format!("http://{addr}/v1")
}
