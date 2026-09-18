use axum::{
    body::Body,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;

/// The router's own machine-readable error code, attached to every
/// `ApiError` response as a typed extension. Extensions are server-side
/// only — this never reaches the wire; it exists so the metadata log can
/// classify a response by asking what the router produced, instead of
/// re-parsing the JSON body it just serialized. That also means a
/// *backend's* error body can never be mistaken for one of ours (matrix
/// rows 2/3 relay upstream error bodies verbatim, `code` field and all).
#[derive(Debug, Clone, Copy)]
pub struct ErrCode(pub &'static str);

/// SPEC §7.1: which shape a router-generated error renders as. Codes
/// themselves are unchanged and shared across dialects — one `ApiError`,
/// two renderers (`into_response` for OpenAI, `into_response_for` for
/// either).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    OpenAi,
    Anthropic,
}

/// OpenAI-shaped error response. Every client-facing failure goes through
/// this so agent clients get a distinct machine-readable `code` instead of
/// having to sniff status + prose (CLAUDE.md: "a policy denial must read as
/// permanent").
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub fn unknown_key() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "auth_unknown_key",
            "invalid API key",
        )
    }

    pub fn bad_host() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "policy_bad_host",
            "Host header must be loopback",
        )
    }

    pub fn origin_rejected() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "policy_origin_rejected",
            "Origin header is not permitted on this server",
        )
    }

    pub fn backend_unreachable() -> Self {
        Self::new(
            StatusCode::BAD_GATEWAY,
            "backend_unreachable",
            "local backend unreachable",
        )
    }

    pub fn backend_redirect_rejected() -> Self {
        Self::new(
            StatusCode::BAD_GATEWAY,
            "backend_redirect_rejected",
            "safe-plane backend returned a redirect",
        )
    }

    pub fn backend_not_configured() -> Self {
        Self::new(
            StatusCode::BAD_GATEWAY,
            "backend_not_configured",
            "no backend configured for this plane",
        )
    }

    /// Matrix row 10: distinct, permanent-reading 403 — agent clients retry
    /// ambiguous errors in loops, so this must not look like a transient
    /// failure.
    pub fn policy_denied_model() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "policy_denied_model",
            "this key is not authorized for the requested model or route",
        )
    }

    pub fn invalid_request_body(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request_body", message)
    }

    /// The requested model/alias passed admission (it's in the key's
    /// allowlist) but doesn't resolve to anything dispatchable — neither a
    /// known route name nor a well-formed `<backend_id>/<model>` composite.
    /// Distinct from `backend_not_configured`: this is a malformed `allow`
    /// entry, not an empty plane.
    pub fn route_unresolvable() -> Self {
        Self::new(
            StatusCode::BAD_GATEWAY,
            "route_unresolvable",
            "requested model/alias does not resolve to a configured backend",
        )
    }

    /// Matrix row 12, safe plane only: the response's `model` field doesn't
    /// match the rung that actually served it. Terminal — the body is
    /// discarded, never relayed (SPEC §6 row 12 amendment 2026-08-13: fail
    /// closed is the safe plane's entire premise).
    pub fn model_mismatch() -> Self {
        Self::new(
            StatusCode::BAD_GATEWAY,
            "model_mismatch",
            "backend response reported a different model than the one dispatched to",
        )
    }

    /// Matrix row 20: the inbound endpoint's dialect doesn't match the
    /// resolved chain's dialect (`/v1/messages` → an openai chain, or vice
    /// versa). Before any upstream byte — a config error, not a transient
    /// one, so it reads as permanent like row 10.
    pub fn dialect_mismatch() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "policy_dialect_mismatch",
            "this endpoint's dialect does not match the resolved route's dialect",
        )
    }

    /// Renders in the given dialect's shape. `Dialect::OpenAi` is exactly
    /// `into_response()` (kept as the `IntoResponse` impl below so every
    /// pre-Phase-2 call site needs no change); `Dialect::Anthropic` is
    /// SPEC §7.1's envelope: Anthropic's fixed `type` taxonomy for clients
    /// that switch on it, with the router's own code riding alongside in
    /// `router_code` rather than displacing it.
    pub fn into_response_for(self, dialect: Dialect) -> Response {
        match dialect {
            Dialect::OpenAi => self.into_response(),
            Dialect::Anthropic => {
                let body = json!({
                    "type": "error",
                    "error": {
                        "type": error_type(self.status),
                        "message": self.message,
                    },
                    "router_code": self.code,
                });
                let bytes = serde_json::to_vec(&body).expect("ApiError body always serializes");
                let mut response = Response::builder()
                    .status(self.status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::CONTENT_LENGTH, bytes.len())
                    .body(Body::from(bytes))
                    .expect("response builder: static status + headers + a byte body");
                response.extensions_mut().insert(ErrCode(self.code));
                response
            }
        }
    }
}

fn error_type(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED => "authentication_error",
        StatusCode::FORBIDDEN => "permission_error",
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE => "api_error",
        _ => "invalid_request_error",
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({
            "error": {
                "message": self.message,
                "type": error_type(self.status),
                "param": null,
                "code": self.code,
            }
        });
        let bytes = serde_json::to_vec(&body).expect("ApiError body always serializes");
        // Explicit, not left to `Json::into_response` (which doesn't set
        // this — hyper fills it in later, at wire-encoding time, which is
        // too late for anything inspecting the in-memory `Response`, e.g.
        // the metadata log's Step 7 buffered-vs-streaming classification).
        let mut response = Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_LENGTH, bytes.len())
            .body(Body::from(bytes))
            .expect("response builder: static status + headers + a byte body");
        response.extensions_mut().insert(ErrCode(self.code));
        response
    }
}
