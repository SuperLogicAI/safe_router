pub mod auth;
pub mod errors;
pub mod keychain;
pub mod log;
pub mod policy;
pub mod proxy;
mod usage;

use std::{
    collections::HashMap,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::Instant,
};

use axum::{
    body::{to_bytes, Body},
    extract::{Extension, Request, State},
    http::header,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use futures_util::{stream, StreamExt};
use tokio::sync::RwLock;

use errors::{ApiError, Dialect, ErrCode};
use policy::{Config, KeyEntry};

/// Body size cap for the admission-time JSON peek only — not a policy
/// decision (CLAUDE.md landmine: the router never makes decisions based on
/// request size/content beyond bearer key / model / stream / tools
/// presence). Generous enough that no legitimate chat-completions payload
/// should ever hit it.
const MAX_ADMISSION_PEEK_BYTES: usize = 25 * 1024 * 1024;

/// SPEC §8.1: fixed header name, never configurable — a user-supplied name
/// (e.g. `Authorization`) would log credentials verbatim into the database.
const CLIENT_TAG_HEADER: &str = "x-safe-router-tag";

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<RwLock<Config>>,
    pub http_client: reqwest::Client,
    /// Set when a SIGHUP reload fails validation (matrix row 8). The old
    /// config keeps serving; this is purely observational until Step 7's
    /// metadata log surfaces it. No HTTP endpoint reads it (invariant #3).
    pub degraded: Arc<AtomicBool>,
    /// Escalation-plane provider secrets, keyed by provider id. Fetched from
    /// Keychain once at startup (`main.rs`) and held only in memory —
    /// invariant #9, the client never holds a remote credential, and this
    /// process is the only place the plaintext ever exists outside Keychain
    /// itself. Not part of the SIGHUP reload: rotating a credential requires
    /// a restart, since re-fetching it isn't a policy change.
    pub credentials: Arc<HashMap<String, String>>,
    /// Matrix row 12 mismatch counter: incremented whenever a response's
    /// `model` field doesn't match the rung that served it, on either plane.
    /// In-process only — the metadata log's `mismatch` column is the
    /// per-row record; this is the running total.
    pub mismatch_count: Arc<AtomicU64>,
    /// SPEC §8 metadata log. Defaults to an in-memory database (see `new`)
    /// so the many tests that don't care about logging need zero setup;
    /// `main.rs` points production at the real file via `with_log_path`.
    pub log: Arc<log::Log>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let degraded = Arc::new(AtomicBool::new(false));
        Self {
            config: Arc::new(RwLock::new(config)),
            // A validated local backend must not redirect a request to a
            // different host. Relay 3xx responses to the caller unchanged.
            http_client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("static HTTP client configuration is valid"),
            log: Arc::new(log::Log::open_in_memory(degraded.clone())),
            degraded,
            credentials: Arc::new(HashMap::new()),
            mismatch_count: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn with_credentials(mut self, credentials: HashMap<String, String>) -> Self {
        self.credentials = Arc::new(credentials);
        self
    }

    /// Production only (`main.rs`): swaps the default in-memory log for the
    /// real `~/.safe-router/log.db`. A file that can't even be opened is an
    /// environment problem, same tier as invalid config — the caller is
    /// expected to refuse to start on `Err`, not degrade from request one.
    pub fn with_log_path(mut self, path: &Path) -> Result<Self, String> {
        self.log = Arc::new(log::Log::open_file(path, self.degraded.clone())?);
        Ok(self)
    }
}

/// Swaps in an already-validated config and clears the degraded flag.
/// Validation itself happens in `main.rs` (needs file I/O to find/read the
/// peer plane's config); this is just the atomic swap primitive.
pub async fn apply_reload(state: &AppState, new_config: Config) {
    let mut guard = state.config.write().await;
    *guard = new_config;
    drop(guard);
    state.degraded.store(false, Ordering::SeqCst);
    tracing::info!("config reloaded");
}

/// SIGHUP reload outcome (matrix row 8): `Ok` swaps the new config in and
/// clears `degraded`; `Err` leaves the current config untouched — simply not
/// calling `apply_reload` is what "keep serving the old config" means — and
/// sets `degraded` instead of taking the daemon down. `main.rs`'s SIGHUP
/// handler calls this with the result of its (file-I/O-requiring)
/// `load_and_validate`; tests can call it directly with a synthetic
/// `Err(..)` without needing a real process or signal.
pub async fn reload_attempt(state: &AppState, result: Result<Config, String>) {
    match result {
        Ok(new_config) => apply_reload(state, new_config).await,
        Err(msg) => {
            state.degraded.store(true, Ordering::SeqCst);
            tracing::error!(error = %msg, "config reload failed, keeping old config");
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    let chat_completions = post(proxy::chat_completions).layer(middleware::from_fn(admission));
    let messages = post(proxy::messages).layer(middleware::from_fn(admission_anthropic));

    Router::new()
        .route("/v1/chat/completions", chat_completions)
        .route("/v1/messages", messages)
        .route("/v1/models", get(proxy::list_models))
        .route_layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// Per-request accumulator for the metadata log (SPEC §8), inserted into
/// request extensions by `guard` and shared (via `Arc<Mutex<_>>`) with
/// `admission` and `proxy::chat_completions` — each fills in the handful of
/// fields only it knows, `guard`'s `finish` flushes exactly once at the end.
/// Only ever created for `/v1/chat/completions` requests (`/v1/models` has
/// no `model_req` to log and is out of scope — see PLAN.md's Step 7 note).
#[derive(Default)]
pub struct LogFields {
    pub route: Option<String>,
    pub model_req: Option<String>,
    pub stream: bool,
    pub tools: bool,
    pub backend: Option<String>,
    pub chain_pos: Option<i64>,
    pub model_served: Option<String>,
    pub mismatch: bool,
    /// `true` only when a mismatch was *enforced* (safe plane, matrix row
    /// 12a) — as opposed to `mismatch` alone, which is also set on the
    /// escalation plane's detection-only passthrough (row 12b). `finish`
    /// needs this distinction to log `backend_error`/`model_mismatch` for
    /// the streaming safe-plane case too, where the response is a small
    /// fixed SSE event with no `error.code` for the usual classification to
    /// find (it isn't a router `ApiError`, `relay` builds it directly).
    pub mismatch_terminal: bool,
    pub tokens_in: Option<i64>,
    pub tokens_out: Option<i64>,
}

pub type SharedLogFields = Arc<StdMutex<LogFields>>;

/// Runs before every route: Host/Origin validation, then bearer auth
/// (matrix row 9). For `/v1/chat/completions` specifically, also owns the
/// metadata log's single flush point (SPEC §8, Step 7): sets up a shared
/// `LogFields` for `admission`/`proxy::chat_completions` to annotate, then
/// classifies + records exactly one row via `finish`, regardless of which
/// layer produced the final response.
async fn guard(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let allowed_hosts = state.config.read().await.server.allowed_hosts.clone();
    let path = req.uri().path();
    let dialect = if path == "/v1/messages" { Dialect::Anthropic } else { Dialect::OpenAi };
    let is_logged_route = path == "/v1/chat/completions" || path == "/v1/messages";

    if !is_logged_route {
        let key_result = match check_request_shape(&req, &allowed_hosts, dialect) {
            Ok(token) => lookup_key(&state, &token).await,
            Err(err) => Err(err),
        };
        return match key_result {
            Ok(key) => {
                req.extensions_mut().insert(key);
                next.run(req).await
            }
            Err(err) => err.into_response_for(dialect),
        };
    }

    let start = Instant::now();
    let fields: SharedLogFields = Arc::new(StdMutex::new(LogFields::default()));
    req.extensions_mut().insert(fields.clone());
    let plane = state.config.read().await.server.plane.clone();
    let client_tag = req
        .headers()
        .get(CLIENT_TAG_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(log::sanitize_client_tag);

    let key_result = match check_request_shape(&req, &allowed_hosts, dialect) {
        Ok(token) => lookup_key(&state, &token).await,
        Err(err) => Err(err),
    };
    let (key_id, resp) = match key_result {
        Ok(key) => {
            let key_id = key.id.clone();
            req.extensions_mut().insert(key);
            (key_id, next.run(req).await)
        }
        Err(err) => ("unknown".to_string(), err.into_response_for(dialect)),
    };

    finish(&state, fields, LogContext { plane, key_id, client_tag, dialect }, start, resp).await
}

/// Host/Origin validation + bearer extraction (matrix row 9's synchronous
/// half). Deliberately a plain sync fn, not async: an async fn taking
/// `&Request` captures that borrow into its generated future for the whole
/// function body, and `axum::http::Request<Body>` isn't `Sync` — that would
/// make the future (and therefore `guard`'s) non-`Send`, which
/// `route_layer` requires. Returning an owned token before anything async
/// happens sidesteps it entirely.
fn check_request_shape(
    req: &Request,
    allowed_hosts: &[String],
    dialect: Dialect,
) -> Result<String, ApiError> {
    check_host(req, allowed_hosts)?;
    check_origin(req)?;
    extract_bearer(req, dialect).ok_or_else(ApiError::unknown_key)
}

/// Bearer-key lookup (matrix row 9's async half) — only ever borrows the
/// already-extracted token, never the `Request` itself.
async fn lookup_key(state: &AppState, token: &str) -> Result<KeyEntry, ApiError> {
    let config = state.config.read().await;
    auth::authenticate(&config.keys, token)
        .cloned()
        .ok_or_else(ApiError::unknown_key)
}

/// A router-generated `ApiError` code, mapped to SPEC §8's fixed
/// `disposition` enum. Every code `errors.rs` can produce appears here; the
/// `None` arm is unreachable in practice and defaults to `served` in
/// `classify` rather than inventing a disposition. `client_cancel` is never
/// produced here; only `finish`'s streaming branch (via `LogDropGuard`) can
/// set it.
fn disposition_for_code(code: &str) -> Option<&'static str> {
    match code {
        "auth_unknown_key" | "policy_bad_host" | "policy_origin_rejected" => Some("denied_auth"),
        "invalid_request_body" | "policy_denied_model" => Some("denied_policy"),
        "backend_unreachable" | "backend_redirect_rejected" | "backend_not_configured" | "route_unresolvable"
        | "model_mismatch" => Some("backend_error"),
        _ => None,
    }
}

/// `disposition`/`err_code` for a finished response, decided by what the
/// *router* produced — an `ApiError`'s `ErrCode` extension — never by
/// parsing the response body. A response with no `ErrCode` is backend
/// content the router relayed faithfully, which is `served` even when the
/// backend's own status was an error (matrix rows 2/3): the router did its
/// job, that's not the router failing.
fn classify(
    router_code: Option<&'static str>,
    mismatch_terminal: bool,
) -> (&'static str, Option<String>) {
    // Matrix row 12a's streaming half never goes through `ApiError` —
    // `relay` builds a fixed SSE error event directly — so there's no
    // `ErrCode` to find. The non-streaming half does, and lands here with
    // the same answer either way.
    if mismatch_terminal {
        return ("backend_error", Some("model_mismatch".to_string()));
    }
    match router_code.and_then(disposition_for_code) {
        Some(disposition) => (disposition, router_code.map(str::to_owned)),
        None => ("served", None),
    }
}

/// The metadata log's single flush point (SPEC §8, Step 7). A response with
/// a `Content-Length` is never a streamed relay (only a router `ApiError` or
/// a fully-buffered completion have one) — the whole thing already exists
/// server-side, so it's buffered, classified, and logged immediately, with
/// no "client disconnected before it finished" possible. A chunked response
/// is exclusively backend-relayed content; it's wrapped in a `LogDropGuard`
/// so an early disconnect (matrix row 14) logs `client_cancel` instead of
/// `served` — `next.run()` returns as soon as the handler hands back a
/// `Response`, long before a streaming body is actually fully sent.
struct LogContext {
    plane: String,
    key_id: String,
    client_tag: Option<String>,
    dialect: Dialect,
}

async fn finish(
    state: &AppState,
    fields: SharedLogFields,
    context: LogContext,
    start: Instant,
    resp: Response,
) -> Response {
    let LogContext { plane, key_id, client_tag, dialect } = context;
    let status = resp.status();
    let has_content_length = resp.headers().contains_key(header::CONTENT_LENGTH);
    // Read before `into_parts` below moves the response apart. Present only
    // on router-generated `ApiError`s (`errors.rs`), never on relayed
    // backend content.
    let router_code = resp.extensions().get::<ErrCode>().map(|c| c.0);

    let (base, mismatch_terminal) = {
        let f = fields.lock().unwrap();
        let base = log::LogRow {
            plane,
            key_id,
            route: f.route.clone(),
            model_req: f.model_req.clone().unwrap_or_else(|| "unknown".to_string()),
            model_served: f.model_served.clone(),
            backend: f.backend.clone(),
            chain_pos: f.chain_pos,
            stream: f.stream,
            tools: f.tools,
            mismatch: f.mismatch,
            tokens_in: f.tokens_in,
            tokens_out: f.tokens_out,
            client_tag,
            status: Some(status.as_u16() as i64),
            ..Default::default()
        };
        (base, f.mismatch_terminal)
    };

    if has_content_length {
        let (parts, body) = resp.into_parts();
        // The proxy already fully buffered this branch and set Content-Length.
        // Classification has its own JSON parse cap; exceeding it must never
        // turn an otherwise valid upstream response into an empty body.
        let bytes = to_bytes(body, usize::MAX).await.unwrap_or_default();
        let (model_served, tokens_in, tokens_out) = usage::buffered(&bytes, dialect);
        let (disposition, err_code) = classify(router_code, mismatch_terminal);
        state.log.record(log::LogRow {
            model_served: base.model_served.clone().or(model_served),
            disposition: disposition.to_string(),
            err_code,
            tokens_in: base.tokens_in.or(tokens_in),
            tokens_out: base.tokens_out.or(tokens_out),
            latency_ms: start.elapsed().as_millis() as i64,
            ..base
        });
        Response::from_parts(parts, Body::from(bytes))
    } else {
        let (parts, body) = resp.into_parts();
        let inner = body.into_data_stream();
        // `router_code` is always `None` here — an `ApiError` always sets
        // Content-Length, so it takes the buffered branch above — but going
        // through the same `classify` keeps the streaming safe-plane
        // mismatch (row 12a) and everything else on one code path.
        let (initial_disposition, initial_err_code) = classify(router_code, mismatch_terminal);
        let guard = LogDropGuard {
            log: state.log.clone(),
            row: log::LogRow {
                disposition: initial_disposition.to_string(),
                err_code: initial_err_code,
                ..base
            },
            start,
            reached_end: false,
            usage: usage::SseUsage::new(dialect),
        };
        let wrapped = stream::unfold((inner, guard), |(mut inner, mut guard)| async move {
            // `guard.reached_end = true` below is read by `LogDropGuard`'s
            // `Drop::drop`, which fires when `guard` goes out of scope at
            // the end of this closure invocation — not visible to rustc's
            // simple unused-assignment dataflow analysis.
            #[allow(unused_assignments)]
            match inner.next().await {
                Some(Ok(bytes)) => {
                    guard.usage.observe(&bytes);
                    Some((Ok::<_, axum::Error>(bytes), (inner, guard)))
                }
                Some(Err(e)) => {
                    tracing::warn!(error = %e, "response stream error before natural completion");
                    None // guard drops here, reached_end still false -> client_cancel
                }
                None => {
                    guard.reached_end = true;
                    None // guard drops here, reached_end = true -> served
                }
            }
        });
        Response::from_parts(parts, Body::from_stream(wrapped))
    }
}

/// Fires exactly once, when the wrapped response-body stream is dropped —
/// whether that's because it was fully drained (`reached_end = true`) or
/// because the client walked away mid-stream and the whole `Body` got
/// dropped before ever reaching that point (matrix row 14).
struct LogDropGuard {
    log: Arc<log::Log>,
    row: log::LogRow,
    start: Instant,
    reached_end: bool,
    usage: usage::SseUsage,
}

impl Drop for LogDropGuard {
    fn drop(&mut self) {
        if !self.reached_end {
            self.row.disposition = "client_cancel".to_string();
        }
        self.row.tokens_in = self.row.tokens_in.or(self.usage.tokens_in);
        self.row.tokens_out = self.row.tokens_out.or(self.usage.tokens_out);
        self.row.latency_ms = self.start.elapsed().as_millis() as i64;
        self.log.record(std::mem::take(&mut self.row));
    }
}

/// Route-specific middleware on `POST /v1/chat/completions` only. Peeks the
/// request body just enough to read `model` (SPEC §4.2's bundled admission
/// parse), checks it against the authenticated key's allowlist (matrix row
/// 10), then reconstructs the body so the real handler can still consume it.
async fn admission_core(
    key: &KeyEntry,
    fields: &SharedLogFields,
    req: Request,
) -> Result<Request, ApiError> {
    let (parts, body) = req.into_parts();
    let bytes = to_bytes(body, MAX_ADMISSION_PEEK_BYTES)
        .await
        .map_err(|_| ApiError::invalid_request_body("could not read request body"))?;

    let parsed = serde_json::from_slice::<serde_json::Value>(&bytes).ok();
    let requested_model = parsed
        .as_ref()
        .and_then(|v| v.get("model").and_then(|m| m.as_str()).map(str::to_owned));

    let Some(requested_model) = requested_model else {
        return Err(ApiError::invalid_request_body("request body missing string `model` field"));
    };

    {
        let mut f = fields.lock().unwrap();
        f.model_req = Some(requested_model.clone());
        f.stream = parsed
            .as_ref()
            .and_then(|v| v.get("stream"))
            .and_then(|s| s.as_bool())
            .unwrap_or(false);
        f.tools = parsed.as_ref().is_some_and(|v| v.get("tools").is_some());
    }

    if policy::admit(key, &requested_model).is_err() {
        return Err(ApiError::policy_denied_model());
    }

    let mut req = Request::from_parts(parts, Body::from(bytes));
    req.extensions_mut().insert(RequestedModel(requested_model));
    Ok(req)
}

/// `POST /v1/chat/completions` admission (matrix row 10). Peeks the request
/// body just enough to read `model` (SPEC §4.2's bundled admission parse),
/// checks it against the authenticated key's allowlist, then reconstructs
/// the body so the real handler can still consume it. OpenAI-shaped errors.
async fn admission(
    Extension(key): Extension<KeyEntry>,
    Extension(fields): Extension<SharedLogFields>,
    req: Request,
    next: Next,
) -> Response {
    match admission_core(&key, &fields, req).await {
        Ok(req) => next.run(req).await,
        Err(err) => err.into_response(),
    }
}

/// `POST /v1/messages` admission — same core logic as `admission` (Anthropic's
/// body uses the same `model`/`stream`/`tools` field names, so the admission
/// check itself needs no dialect awareness at all), only the error rendering
/// differs (SPEC §7.1: Anthropic-shaped envelope).
async fn admission_anthropic(
    Extension(key): Extension<KeyEntry>,
    Extension(fields): Extension<SharedLogFields>,
    req: Request,
    next: Next,
) -> Response {
    match admission_core(&key, &fields, req).await {
        Ok(req) => next.run(req).await,
        Err(err) => err.into_response_for(Dialect::Anthropic),
    }
}

/// The admitted `model`/alias string, handed to the proxy handler so it can
/// resolve a dispatch chain (Step 5) without re-parsing the body — admission
/// already did that parse and validated the key is allowed to ask for it.
#[derive(Debug, Clone)]
pub struct RequestedModel(pub String);

/// The router's own bearer key. `Authorization: Bearer` on every route;
/// `/v1/messages` also accepts `x-api-key` (matrix row 22, SPEC §7.1) since
/// Claude Code sends the router's key there when configured via
/// `ANTHROPIC_API_KEY`. Whichever header it arrives in, only the extracted
/// token is ever used — it is never forwarded upstream (invariant #9).
fn extract_bearer(req: &Request, dialect: Dialect) -> Option<String> {
    if let Some(token) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        return Some(token.to_string());
    }
    if dialect == Dialect::Anthropic
        && let Some(token) = req.headers().get("x-api-key").and_then(|v| v.to_str().ok())
    {
        return Some(token.to_string());
    }
    None
}

/// Matrix row 17 / SPEC §4.1: loopback (as v0), plus any exact
/// `allowed_hosts` match, port stripped before comparison. Comparison
/// only — the router never resolves a name to decide this, so a
/// `*.ts.net` entry in `allowed_hosts` is matched as a literal string, not
/// looked up.
fn check_host(req: &Request, allowed_hosts: &[String]) -> Result<(), ApiError> {
    let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok());
    match host {
        Some(h) if is_loopback_host(h) => Ok(()),
        Some(h) if allowed_hosts.iter().any(|a| hosts_match(a, h)) => Ok(()),
        _ => Err(ApiError::bad_host()),
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host_only = host.split(':').next().unwrap_or(host);
    matches!(host_only, "127.0.0.1" | "localhost" | "::1" | "[::1]")
}

fn hosts_match(allowed: &str, incoming: &str) -> bool {
    let incoming_host = incoming.split(':').next().unwrap_or(incoming);
    let allowed_host = allowed.split(':').next().unwrap_or(allowed);
    allowed_host == incoming_host
}

fn check_origin(req: &Request) -> Result<(), ApiError> {
    if req.headers().contains_key(header::ORIGIN) {
        Err(ApiError::origin_rejected())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::to_bytes as body_to_bytes,
        http::{Request as HttpRequest, StatusCode},
    };
    use tower::ServiceExt;

    const GOOD_KEY: &str = "good-key";

    fn test_config() -> Config {
        let good_hash = auth::hash_key(GOOD_KEY).unwrap();
        policy::parse_config(&format!(
            r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"

            [[key]]
            id = "good"
            hash = "{good_hash}"
            allow = ["allowed-model", "some-alias"]

            [[route]]
            name = "some-alias"
            chain = ["backend/allowed-model"]
            "#
        ))
        .unwrap()
    }

    fn test_app() -> Router {
        build_router(AppState::new(test_config()))
    }

    fn models_request(auth_header: Option<&str>, host: &str) -> HttpRequest<Body> {
        let mut builder = HttpRequest::builder().uri("/v1/models").header(header::HOST, host);
        if let Some(h) = auth_header {
            builder = builder.header(header::AUTHORIZATION, h.to_string());
        }
        builder.body(Body::empty()).unwrap()
    }

    fn chat_request(auth_header: &str, body: &str) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(header::HOST, "127.0.0.1:8787")
            .header(header::AUTHORIZATION, auth_header)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn bad_key_returns_well_formed_401() {
        let resp = test_app()
            .oneshot(models_request(Some("Bearer nope"), "127.0.0.1:8787"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "auth_unknown_key");
    }

    #[tokio::test]
    async fn missing_key_returns_401() {
        let resp = test_app()
            .oneshot(models_request(None, "127.0.0.1:8787"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn good_key_with_no_backend_configured_is_502() {
        // /v1/models has no admission step (no `model` to check) — only
        // auth applies, then it's a proxy question (no backend configured).
        let resp = test_app()
            .oneshot(models_request(
                Some(&format!("Bearer {GOOD_KEY}")),
                "127.0.0.1:8787",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn non_loopback_host_rejected() {
        let resp = test_app()
            .oneshot(models_request(
                Some(&format!("Bearer {GOOD_KEY}")),
                "evil.example.com",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn origin_header_rejected() {
        let mut req = models_request(Some(&format!("Bearer {GOOD_KEY}")), "127.0.0.1:8787");
        req.headers_mut()
            .insert(header::ORIGIN, "http://evil.example.com".parse().unwrap());
        let resp = test_app().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn chat_completions_denies_model_outside_allowlist() {
        let body = r#"{"model":"not-allowed-model","stream":false,"messages":[]}"#;
        let resp = test_app()
            .oneshot(chat_request(&format!("Bearer {GOOD_KEY}"), body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = body_to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "policy_denied_model");
    }

    #[tokio::test]
    async fn chat_completions_admits_allowed_concrete_model() {
        // No backend configured, so this proves admission passed (502 from
        // the proxy, not 403 from admission).
        let body = r#"{"model":"allowed-model","stream":false,"messages":[]}"#;
        let resp = test_app()
            .oneshot(chat_request(&format!("Bearer {GOOD_KEY}"), body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn chat_completions_admits_allowed_alias() {
        let body = r#"{"model":"some-alias","stream":false,"messages":[]}"#;
        let resp = test_app()
            .oneshot(chat_request(&format!("Bearer {GOOD_KEY}"), body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn chat_completions_missing_model_field_is_400() {
        let body = r#"{"stream":false,"messages":[]}"#;
        let resp = test_app()
            .oneshot(chat_request(&format!("Bearer {GOOD_KEY}"), body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = body_to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"]["code"], "invalid_request_body");
    }

    #[tokio::test]
    async fn apply_reload_swaps_config_atomically() {
        let state = AppState::new(test_config());
        let old_allows = policy::admit(
            &state.config.read().await.keys[0].clone(),
            "allowed-model",
        );
        assert!(old_allows.is_ok());

        let new_hash = auth::hash_key(GOOD_KEY).unwrap();
        let new_config = policy::parse_config(&format!(
            r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"

            [[key]]
            id = "good"
            hash = "{new_hash}"
            allow = ["different-model"]
            "#
        ))
        .unwrap();

        state.degraded.store(true, Ordering::SeqCst);
        apply_reload(&state, new_config).await;

        assert!(!state.degraded.load(Ordering::SeqCst));
        let config = state.config.read().await;
        assert_eq!(config.keys[0].allow, vec!["different-model".to_string()]);
    }
}
