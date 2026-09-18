//! Byte-passthrough HTTP/SSE proxy (SPEC §4.2, §7). `/v1/models` uses
//! whichever backend/provider is configured first (no per-request model to
//! resolve there); `/v1/chat/completions` resolves the admitted model/alias
//! to a real dispatch chain (SPEC §5.2, §6 — Step 5) and advances on
//! 429/5xx/connect-fail only when the route says to. Response bytes are
//! forwarded untouched except for two inspections of the `model` field:
//! logging (best-effort, SPEC §8 lands the actual metadata log in Step 7)
//! and the row-12 mismatch gate (SPEC §6 — Step 6), which is enforcement,
//! not logging, on the safe plane.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{
    body::{Body, Bytes},
    extract::{Extension, State},
    http::{
        header::{AUTHORIZATION, CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING},
        response::Builder as ResponseBuilder,
        HeaderMap, StatusCode,
    },
    response::{IntoResponse, Response},
};
use futures_util::{
    stream::{self, BoxStream},
    StreamExt,
};
use tokio::time::timeout;

use crate::{
    errors::{ApiError, Dialect},
    policy, AppState, RequestedModel,
};

const SSE_IDLE_TIMEOUT_EVENT: &[u8] =
    b"data: {\"error\":{\"message\":\"idle timeout waiting for backend\",\"type\":\"api_error\",\"param\":null,\"code\":\"stream_idle_timeout\"}}\n\ndata: [DONE]\n\n";
const SSE_MODEL_MISMATCH_EVENT: &[u8] =
    b"data: {\"error\":{\"message\":\"backend response reported a different model than the one dispatched to\",\"type\":\"api_error\",\"param\":null,\"code\":\"model_mismatch\"}}\n\ndata: [DONE]\n\n";

/// SPEC §7.1: Anthropic-shaped terminal SSE events — `event: error` plus an
/// Anthropic-typed error object, not the OpenAI-shaped constants above.
const ANTHROPIC_SSE_IDLE_TIMEOUT_EVENT: &[u8] =
    b"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"idle timeout waiting for backend\"},\"router_code\":\"stream_idle_timeout\"}\n\n";
const ANTHROPIC_SSE_MODEL_MISMATCH_EVENT: &[u8] =
    b"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"backend response reported a different model than the one dispatched to\"},\"router_code\":\"model_mismatch\"}\n\n";

/// SPEC §7.1: default `anthropic-version` when the client doesn't send one.
const ANTHROPIC_VERSION_DEFAULT: &str = "2023-06-01";

struct Target {
    base_url: String,
    /// `"openai"` or `"anthropic"` — decides which auth headers `dispatch`
    /// attaches (SPEC §7.1: outbound auth is derived from dialect, not
    /// hardcoded per-route).
    dialect: String,
    /// Present only on the escalation plane, fetched from Keychain at
    /// startup (invariant #9: the client never holds this — it's attached
    /// here, server-side, per outbound request, and never logged).
    credential: Option<String>,
}

/// Attaches outbound credentials in the target's own dialect style (SPEC
/// §7.1). `anthropic_version`/`anthropic_beta` are the *client's* request
/// headers, forwarded verbatim when present — the entire forwarded-header
/// allowlist for this dialect; the client's own `Authorization`/`x-api-key`
/// is never among them (matrix row 22).
fn apply_credential(
    mut req: reqwest::RequestBuilder,
    target: &Target,
    anthropic_version: Option<&str>,
    anthropic_beta: Option<&str>,
) -> reqwest::RequestBuilder {
    match target.dialect.as_str() {
        "anthropic" => {
            if let Some(cred) = &target.credential {
                req = req.header("x-api-key", cred);
            }
            req = req.header("anthropic-version", anthropic_version.unwrap_or(ANTHROPIC_VERSION_DEFAULT));
            if let Some(beta) = anthropic_beta {
                req = req.header("anthropic-beta", beta);
            }
            req
        }
        _ => {
            if let Some(cred) = &target.credential {
                req = req.header(AUTHORIZATION, format!("Bearer {cred}"));
            }
            req
        }
    }
}

/// Matrix row 12 gating. Only `chat_completions` builds one — `list_models`
/// has no per-request model to check a response against. `enforce` is
/// `true` on the safe plane (mismatch is terminal) and `false` on
/// escalation (mismatch is relayed anyway — logged and counted, detection
/// only; SPEC §6 row 12).
struct MismatchGate {
    expected_model: String,
    enforce: bool,
    counter: Arc<AtomicU64>,
    /// Step 7: the same per-request log accumulator `chat_completions`
    /// writes `route`/`backend`/`chain_pos` into — `model_served`/`mismatch`
    /// belong here since only the mismatch check itself ever learns them.
    fields: crate::SharedLogFields,
}

/// `/v1/models` has no per-request model to resolve — it lists whatever the
/// first configured backend/provider for this plane has.
fn resolve_target(config: &policy::Config, credentials: &HashMap<String, String>) -> Option<Target> {
    if config.server.plane == "escalation" {
        let provider = config.providers.first()?;
        Some(Target {
            base_url: provider.base_url.clone(),
            dialect: provider.dialect.clone(),
            credential: credentials.get(&provider.id).cloned(),
        })
    } else {
        let backend = config.backends.first()?;
        Some(Target {
            base_url: backend.base_url.clone(),
            dialect: backend.dialect.clone(),
            credential: None,
        })
    }
}

pub async fn list_models(State(state): State<AppState>) -> Response {
    let (target, idle_timeout, safe_plane) = {
        let config = state.config.read().await;
        (
            resolve_target(&config, &state.credentials),
            Duration::from_millis(config.server.idle_timeout_ms),
            config.server.plane == "safe",
        )
    };
    let Some(target) = target else {
        return ApiError::backend_not_configured().into_response();
    };
    let url = format!("{}/models", target.base_url.trim_end_matches('/'));

    let req = apply_credential(state.http_client.get(&url), &target, None, None);

    match req.send().await {
        Ok(resp) if safe_plane && resp.status().is_redirection() => {
            ApiError::backend_redirect_rejected().into_response()
        }
        Ok(resp) => relay(resp, false, None, idle_timeout, Dialect::OpenAi).await,
        Err(e) => {
            tracing::warn!(error = %e, %url, "backend unreachable");
            ApiError::backend_unreachable().into_response()
        }
    }
}

/// Resolves one chain rung's backend/provider id to a dispatch target —
/// same lookup `resolve_target` does for the plane's first entry, but by id
/// instead of "whichever is first," since a chain names exactly which one.
fn resolve_rung_target(
    config: &policy::Config,
    rung: &policy::Rung,
    credentials: &HashMap<String, String>,
) -> Option<Target> {
    if let Some(backend) = config.backends.iter().find(|b| b.id == rung.backend_id) {
        return Some(Target {
            base_url: backend.base_url.clone(),
            dialect: backend.dialect.clone(),
            credential: None,
        });
    }
    if let Some(provider) = config.providers.iter().find(|p| p.id == rung.backend_id) {
        return Some(Target {
            base_url: provider.base_url.clone(),
            dialect: provider.dialect.clone(),
            credential: credentials.get(&provider.id).cloned(),
        });
    }
    None
}

/// Swaps the outbound `model` field for the bare name the backend actually
/// expects (chain entries are `<backend_id>/<model>`; the backend has never
/// heard of our backend-id prefix). This is routing-address resolution
/// within the one dialect the router speaks, not the cross-dialect
/// translation invariant #5 forbids — SPEC's own chain syntax only makes
/// sense if the router strips the prefix before forwarding. The *response*
/// stays untouched either way.
fn rewrite_model_field(body: &Bytes, model: &str) -> Bytes {
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(mut map)) => {
            map.insert("model".to_string(), serde_json::Value::from(model));
            match serde_json::to_vec(&serde_json::Value::Object(map)) {
                Ok(v) => Bytes::from(v),
                Err(_) => body.clone(),
            }
        }
        _ => body.clone(),
    }
}

fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

/// Matrix row 20: the inbound endpoint's dialect must match the resolved
/// chain's dialect, checked before any upstream byte. `validate_chain_dialects`
/// (startup) already guarantees every rung in a chain shares one dialect
/// (row 21), so the first rung speaks for the whole chain. A rung whose
/// backend/provider id can't be found has already failed elsewhere
/// (`resolve_rung_target` returns `None` for it); treated as a match here so
/// that failure surfaces as `backend_not_configured`, not a misleading
/// dialect-mismatch.
fn chain_matches_dialect(config: &policy::Config, chain: &policy::ResolvedChain, expected: &str) -> bool {
    match chain.rungs.first() {
        Some(rung) => policy::dialect_for_id(config, &rung.backend_id).is_none_or(|d| d == expected),
        None => true,
    }
}

pub async fn chat_completions(
    State(state): State<AppState>,
    Extension(RequestedModel(requested)): Extension<RequestedModel>,
    Extension(fields): Extension<crate::SharedLogFields>,
    body: Bytes,
) -> Response {
    let (chain, plane, idle_timeout, route_name, dialect_ok) = {
        let config = state.config.read().await;
        let route_name = config.routes.iter().find(|r| r.name == requested).map(|r| r.name.clone());
        let chain = policy::resolve_chain(&config, &requested);
        let dialect_ok = chain
            .as_ref()
            .is_none_or(|c| chain_matches_dialect(&config, c, "openai"));
        (
            chain,
            config.server.plane.clone(),
            Duration::from_millis(config.server.idle_timeout_ms),
            route_name,
            dialect_ok,
        )
    };
    let Some(chain) = chain else {
        return ApiError::route_unresolvable().into_response();
    };
    if !dialect_ok {
        return ApiError::dialect_mismatch().into_response();
    }
    // SPEC §8's log schema: `route` is Some(name) only for a named alias,
    // NULL for a bare <backend_id>/<model> composite.
    fields.lock().unwrap().route = route_name;
    let is_sse = wants_stream(&body);
    let last_rung_idx = chain.rungs.len() - 1;
    // Matrix row 12: only the safe plane treats a mismatch as terminal.
    let enforce_mismatch = plane == "safe";

    for (idx, rung) in chain.rungs.iter().enumerate() {
        let chain_pos = idx + 1;
        let is_last = idx == last_rung_idx;

        let target = {
            let config = state.config.read().await;
            resolve_rung_target(&config, rung, &state.credentials)
        };
        let Some(target) = target else {
            if chain.advance_on_error && !is_last {
                tracing::warn!(chain_pos, backend = %rung.backend_id, "rung not configured, advancing");
                continue;
            }
            return ApiError::backend_not_configured().into_response();
        };

        let url = format!("{}/chat/completions", target.base_url.trim_end_matches('/'));
        let rewritten_body = rewrite_model_field(&body, &rung.model);

        let req = apply_credential(
            state.http_client.post(&url).header(CONTENT_TYPE, "application/json"),
            &target,
            None,
            None,
        );

        match req.body(rewritten_body).send().await {
            Ok(resp) => {
                let status = resp.status();
                if plane == "safe" && status.is_redirection() {
                    return ApiError::backend_redirect_rejected().into_response();
                }
                if chain.advance_on_error && !is_last && is_retryable_status(status) {
                    tracing::warn!(chain_pos, %status, backend = %rung.backend_id, "rung failed, advancing");
                    continue;
                }
                tracing::info!(chain_pos, backend = %rung.backend_id, model = %rung.model, %status, "chain rung served");
                {
                    let mut f = fields.lock().unwrap();
                    f.backend = Some(rung.backend_id.clone());
                    f.chain_pos = Some(chain_pos as i64);
                }
                let gate = MismatchGate {
                    expected_model: rung.model.clone(),
                    enforce: enforce_mismatch,
                    counter: state.mismatch_count.clone(),
                    fields: fields.clone(),
                };
                return relay(resp, is_sse, Some(gate), idle_timeout, Dialect::OpenAi).await;
            }
            Err(e) => {
                if chain.advance_on_error && !is_last {
                    tracing::warn!(chain_pos, error = %e, backend = %rung.backend_id, "connect failed, advancing");
                    continue;
                }
                tracing::warn!(chain_pos, error = %e, %url, "backend unreachable");
                return ApiError::backend_unreachable().into_response();
            }
        }
    }

    // Unreachable: resolve_chain never returns an empty rung list, so the
    // loop above always returns on its last (or only) iteration.
    ApiError::backend_not_configured().into_response()
}

/// `POST /v1/messages` — SPEC §7.1's second passthrough dialect. Same trick
/// as `chat_completions`, not a translation: bytes in, bytes out, admission
/// already happened (the same field names, no dialect awareness needed
/// there). Differences from `chat_completions` are all in this function:
/// the outbound path (`/v1/messages`, not `/v1/chat/completions`), the
/// forwarded-header allowlist (`anthropic-version`/`anthropic-beta`), and
/// Anthropic-shaped error rendering throughout.
pub async fn messages(
    State(state): State<AppState>,
    Extension(RequestedModel(requested)): Extension<RequestedModel>,
    Extension(fields): Extension<crate::SharedLogFields>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let anthropic_version = headers.get("anthropic-version").and_then(|v| v.to_str().ok()).map(str::to_string);
    let anthropic_beta = headers.get("anthropic-beta").and_then(|v| v.to_str().ok()).map(str::to_string);

    let (chain, plane, idle_timeout, route_name, dialect_ok) = {
        let config = state.config.read().await;
        let route_name = config.routes.iter().find(|r| r.name == requested).map(|r| r.name.clone());
        let chain = policy::resolve_chain(&config, &requested);
        let dialect_ok = chain
            .as_ref()
            .is_none_or(|c| chain_matches_dialect(&config, c, "anthropic"));
        (
            chain,
            config.server.plane.clone(),
            Duration::from_millis(config.server.idle_timeout_ms),
            route_name,
            dialect_ok,
        )
    };
    let Some(chain) = chain else {
        return ApiError::route_unresolvable().into_response_for(Dialect::Anthropic);
    };
    if !dialect_ok {
        return ApiError::dialect_mismatch().into_response_for(Dialect::Anthropic);
    }
    fields.lock().unwrap().route = route_name;
    let is_sse = wants_stream(&body);
    let last_rung_idx = chain.rungs.len() - 1;
    let enforce_mismatch = plane == "safe";

    for (idx, rung) in chain.rungs.iter().enumerate() {
        let chain_pos = idx + 1;
        let is_last = idx == last_rung_idx;

        let target = {
            let config = state.config.read().await;
            resolve_rung_target(&config, rung, &state.credentials)
        };
        let Some(target) = target else {
            if chain.advance_on_error && !is_last {
                tracing::warn!(chain_pos, backend = %rung.backend_id, "rung not configured, advancing");
                continue;
            }
            return ApiError::backend_not_configured().into_response_for(Dialect::Anthropic);
        };

        let url = format!("{}/v1/messages", target.base_url.trim_end_matches('/'));
        let rewritten_body = rewrite_model_field(&body, &rung.model);

        let req = apply_credential(
            state.http_client.post(&url).header(CONTENT_TYPE, "application/json"),
            &target,
            anthropic_version.as_deref(),
            anthropic_beta.as_deref(),
        );

        match req.body(rewritten_body).send().await {
            Ok(resp) => {
                let status = resp.status();
                if plane == "safe" && status.is_redirection() {
                    return ApiError::backend_redirect_rejected().into_response_for(Dialect::Anthropic);
                }
                if chain.advance_on_error && !is_last && is_retryable_status(status) {
                    tracing::warn!(chain_pos, %status, backend = %rung.backend_id, "rung failed, advancing");
                    continue;
                }
                tracing::info!(chain_pos, backend = %rung.backend_id, model = %rung.model, %status, "chain rung served");
                {
                    let mut f = fields.lock().unwrap();
                    f.backend = Some(rung.backend_id.clone());
                    f.chain_pos = Some(chain_pos as i64);
                }
                let gate = MismatchGate {
                    expected_model: rung.model.clone(),
                    enforce: enforce_mismatch,
                    counter: state.mismatch_count.clone(),
                    fields: fields.clone(),
                };
                return relay(resp, is_sse, Some(gate), idle_timeout, Dialect::Anthropic).await;
            }
            Err(e) => {
                if chain.advance_on_error && !is_last {
                    tracing::warn!(chain_pos, error = %e, backend = %rung.backend_id, "connect failed, advancing");
                    continue;
                }
                tracing::warn!(chain_pos, error = %e, %url, "backend unreachable");
                return ApiError::backend_unreachable().into_response_for(Dialect::Anthropic);
            }
        }
    }

    ApiError::backend_not_configured().into_response_for(Dialect::Anthropic)
}

fn wants_stream(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("stream").and_then(|s| s.as_bool()))
        .unwrap_or(false)
}

enum RelayState {
    Active {
        stream: BoxStream<'static, reqwest::Result<Bytes>>,
        /// A chunk already pulled off `stream` (during row-12 gating, before
        /// any bytes were forwarded) that still needs to go out as the first
        /// yielded item. `None` once consumed or when there was nothing to
        /// gate (`list_models`, or gating already happened on a fully
        /// buffered non-streaming body).
        pending_first: Option<Bytes>,
        logged_model: bool,
        is_sse: bool,
    },
    Terminated,
}

/// Forward status + headers verbatim; stream body bytes through unmodified
/// except for an idle-timeout cutoff (matrix row 4) and a best-effort,
/// non-blocking peek at the first chunk's `model` field.
///
/// `gate` is `None` for `/v1/models` (no per-request model to check a
/// response against). When present (matrix row 12), the response's `model`
/// is compared to what was actually dispatched to *before any response
/// bytes reach the client*: the non-streaming case buffers the full body
/// first, the streaming case peeks the first chunk before the returned
/// `Response` is even constructed.
async fn relay(
    resp: reqwest::Response,
    is_sse: bool,
    gate: Option<MismatchGate>,
    idle_timeout: Duration,
    dialect: Dialect,
) -> Response {
    let (idle_timeout_event, model_mismatch_event) = match dialect {
        Dialect::OpenAi => (SSE_IDLE_TIMEOUT_EVENT, SSE_MODEL_MISMATCH_EVENT),
        Dialect::Anthropic => (ANTHROPIC_SSE_IDLE_TIMEOUT_EVENT, ANTHROPIC_SSE_MODEL_MISMATCH_EVENT),
    };
    let status = resp.status();
    let mut builder = Response::builder().status(status);
    for (name, value) in resp.headers().iter() {
        // Framing headers don't survive re-streaming through a body whose
        // final length isn't known up front (idle-timeout can shorten it) —
        // let hyper pick correct framing instead of forwarding a length that
        // might stop matching the bytes we actually send.
        if matches!(*name, CONTENT_LENGTH | TRANSFER_ENCODING | CONNECTION) {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
    }

    let Some(gate) = gate else {
        let stream: BoxStream<'static, reqwest::Result<Bytes>> = resp.bytes_stream().boxed();
        return stream_relay_body(builder, stream, is_sse, None, idle_timeout, idle_timeout_event);
    };

    if is_sse {
        let mut stream: BoxStream<'static, reqwest::Result<Bytes>> = resp.bytes_stream().boxed();
        match stream.next().await {
            Some(Ok(first)) => {
                let reported = extract_model_field(&first);
                if check_and_count_mismatch(reported.as_deref(), &gate) && gate.enforce {
                    return builder
                        .body(Body::from(model_mismatch_event))
                        .expect("response builder: only headers we copied verbatim from a valid upstream response");
                }
                stream_relay_body(builder, stream, is_sse, Some(first), idle_timeout, idle_timeout_event)
            }
            Some(Err(e)) => {
                tracing::warn!(error = %e, "upstream stream error before first chunk");
                ApiError::backend_unreachable().into_response_for(dialect)
            }
            None => builder
                .body(Body::empty())
                .expect("response builder: only headers we copied verbatim from a valid upstream response"),
        }
    } else {
        match resp.bytes().await {
            Ok(bytes) => {
                let reported = model_from_json_object(&bytes);
                if check_and_count_mismatch(reported.as_deref(), &gate) && gate.enforce {
                    return ApiError::model_mismatch().into_response_for(dialect);
                }
                // The header-copy loop above strips Content-Length (upstream's
                // value could be stale once the body's mediated through us);
                // this is the one path with the full body already in hand, so
                // set the real one back. Also lets the metadata log (Step 7)
                // tell "fully buffered" apart from "actually streaming" —
                // relay()'s streaming path never sets this.
                builder
                    .header(CONTENT_LENGTH, bytes.len())
                    .body(Body::from(bytes))
                    .expect("response builder: only headers we copied verbatim from a valid upstream response")
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed reading backend response body");
                ApiError::backend_unreachable().into_response_for(dialect)
            }
        }
    }
}

/// Returns `true` if `reported` is present and didn't match
/// `gate.expected_model`. Increments `gate.counter` as a side effect on any
/// mismatch, on either plane (SPEC row 12: "log + mismatch counter either
/// way").
fn check_and_count_mismatch(reported: Option<&str>, gate: &MismatchGate) -> bool {
    if let Some(model) = reported {
        gate.fields.lock().unwrap().model_served = Some(model.to_string());
    }
    match reported {
        Some(model) if model != gate.expected_model => {
            tracing::warn!(reported = %model, expected = %gate.expected_model, "response model mismatch");
            gate.counter.fetch_add(1, Ordering::Relaxed);
            let mut f = gate.fields.lock().unwrap();
            f.mismatch = true;
            f.mismatch_terminal = gate.enforce;
            true
        }
        _ => false,
    }
}

/// Full JSON parse of a top-level `model` field — used only for the
/// non-streaming row-12 check, where the entire body is already buffered so
/// there's no reason to settle for the streaming path's best-effort
/// substring scan (`extract_model_field`).
pub(crate) fn model_from_json_object(bytes: &[u8]) -> Option<String> {
    match serde_json::from_slice::<serde_json::Value>(bytes).ok()? {
        serde_json::Value::Object(map) => map.get("model")?.as_str().map(str::to_owned),
        _ => None,
    }
}

/// The shared idle-timeout streaming loop, used both for the ungated path
/// and for the gated-and-cleared path (streaming row 12: the first chunk
/// was already pulled and checked, so it's threaded back in via
/// `pending_first` instead of being fetched again).
fn stream_relay_body(
    builder: ResponseBuilder,
    stream: BoxStream<'static, reqwest::Result<Bytes>>,
    is_sse: bool,
    pending_first: Option<Bytes>,
    idle_timeout: Duration,
    idle_timeout_event: &'static [u8],
) -> Response {
    let initial = RelayState::Active {
        stream,
        pending_first,
        logged_model: false,
        is_sse,
    };

    let piped = stream::unfold(initial, move |state| async move {
        let RelayState::Active {
            mut stream,
            pending_first,
            logged_model,
            is_sse,
        } = state
        else {
            return None;
        };

        if let Some(bytes) = pending_first {
            let logged_model = logged_model || log_model_once(&bytes);
            return Some((
                Ok::<_, reqwest::Error>(bytes),
                RelayState::Active {
                    stream,
                    pending_first: None,
                    logged_model,
                    is_sse,
                },
            ));
        }

        match timeout(idle_timeout, stream.next()).await {
            Ok(Some(Ok(bytes))) => {
                let logged_model = logged_model || log_model_once(&bytes);
                Some((
                    Ok::<_, reqwest::Error>(bytes),
                    RelayState::Active {
                        stream,
                        pending_first: None,
                        logged_model,
                        is_sse,
                    },
                ))
            }
            Ok(Some(Err(e))) => {
                tracing::warn!(error = %e, "upstream stream error, terminating");
                None
            }
            Ok(None) => None,
            Err(_elapsed) => {
                tracing::warn!(idle_timeout_ms = idle_timeout.as_millis() as u64, "backend went idle, terminating stream");
                if is_sse {
                    Some((
                        Ok(Bytes::from_static(idle_timeout_event)),
                        RelayState::Terminated,
                    ))
                } else {
                    None
                }
            }
        }
    });

    builder
        .body(Body::from_stream(piped))
        .expect("response builder: only headers we copied verbatim from a valid upstream response")
}

/// Logs the response's `model` field the first time it's visible in a chunk.
/// Returns true if this call did the logging (caller folds that into
/// `logged_model` so it only fires once per response).
fn log_model_once(bytes: &Bytes) -> bool {
    match extract_model_field(bytes) {
        Some(model) => {
            tracing::info!(%model, "backend response model");
            true
        }
        None => false,
    }
}

/// Best-effort `"model":"..."` extraction from a raw chunk — SSE `data:`
/// lines and plain JSON bodies both contain it as a top-level string field.
/// Not a JSON parse: a value split across a raw TCP chunk boundary is simply
/// missed. Used for logging and for the *streaming* row-12 gate, where a
/// full parse of a possibly-incomplete first chunk isn't guaranteed
/// possible anyway — `model_from_json_object` below is the real parse, used
/// where the full body is already buffered.
fn extract_model_field(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let key = "\"model\":\"";
    let start = text.find(key)? + key.len();
    let rest = &text[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_model_from_plain_json() {
        let body = br#"{"id":"x","model":"llama-3.3-70b","choices":[]}"#;
        assert_eq!(extract_model_field(body).as_deref(), Some("llama-3.3-70b"));
    }

    #[test]
    fn extracts_model_from_sse_chunk() {
        let chunk = b"data: {\"id\":\"chatcmpl-1\",\"model\":\"qwen2.5-72b\",\"choices\":[]}\n\n";
        assert_eq!(extract_model_field(chunk).as_deref(), Some("qwen2.5-72b"));
    }

    #[test]
    fn missing_model_field_is_none() {
        assert_eq!(extract_model_field(b"{\"choices\":[]}"), None);
    }
}
