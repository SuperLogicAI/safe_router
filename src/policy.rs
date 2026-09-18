//! Config parsing + admission evaluation. Pure — no I/O — so it's
//! unit-testable without a running server (CLAUDE.md: "Config parsing and
//! policy evaluation live in one module with no I/O"). File reads, SIGHUP
//! reload, and cross-plane peer-file discovery live in `main.rs`.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(rename = "key", default)]
    pub keys: Vec<KeyEntry>,
    #[serde(rename = "backend", default)]
    pub backends: Vec<BackendConfig>,
    #[serde(rename = "provider", default)]
    pub providers: Vec<ProviderConfig>,
    #[serde(rename = "route", default)]
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Deserialize)]
pub struct BackendConfig {
    pub id: String,
    pub base_url: String,
    pub dialect: String,
}

/// Escalation-plane remote provider (SPEC §5.3). `keychain_item` names a
/// Keychain entry — never a credential value; the plaintext secret is
/// fetched at startup (Step 4's `keychain` module) and never touches this
/// struct or any config file.
#[derive(Debug, Deserialize)]
pub struct ProviderConfig {
    pub id: String,
    pub base_url: String,
    pub dialect: String,
    pub keychain_item: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub bind: String,
    pub plane: String,
    /// Idle timeout for a stalled upstream response stream (matrix row 4),
    /// in milliseconds. Defaults to 60s. A config knob, not a runtime-mutable
    /// one — same static TOML, same startup-only load as everything else
    /// (invariant #3). Exists mainly so tests don't have to wait 60 real
    /// seconds to exercise this path.
    #[serde(default = "default_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// SPEC §4.1 (v1/Phase 2): inbound `Host` values accepted in addition to
    /// loopback. Defaults to empty, which means loopback-only — exactly v0's
    /// behavior, so an unmodified v0 config keeps v0 semantics. Each entry is
    /// a literal `100.64.0.0/10` tailnet address or a `*.ts.net` MagicDNS
    /// name; validated at startup/reload by `validate_allowed_hosts`.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

fn default_idle_timeout_ms() -> u64 {
    60_000
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeyEntry {
    pub id: String,
    pub hash: String,
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RouteConfig {
    pub name: String,
    pub chain: Vec<String>,
    #[serde(default)]
    pub on_error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("[server] plane '{plane}' is invalid — expected 'safe' or 'escalation'")]
    InvalidPlane { plane: String },
    #[error("safe-plane config must not contain [[provider]] entries")]
    SafePlaneProvider,
    #[error(
        "safe-plane backend '{id}' has non-loopback base_url '{base_url}' — \
         invariant #7 requires loopback-only backends on the safe plane"
    )]
    NonLoopbackSafeBackend { id: String, base_url: String },
    #[error(
        "key hash appears in both plane configs — a key authorized for one \
         plane must not exist in the other"
    )]
    CrossPlaneKeyCollision,
    #[error(
        "'{entry}' declares dialect '{dialect}' — only openai and anthropic \
         are supported passthrough dialects (invariant #5: no cross-dialect \
         translation)"
    )]
    UnsupportedDialect { entry: String, dialect: String },
    #[error("route '{route}' chain entry '{entry}' is not in <backend_id>/<model> form")]
    InvalidChainEntry { route: String, entry: String },
    #[error(
        "route '{route}' chain entry references unknown backend/provider id \
         '{backend_id}' — chains only resolve within the same plane's config"
    )]
    UnknownChainBackend { route: String, backend_id: String },
    #[error(
        "[server] bind '{bind}' is not loopback and not a literal 100.64.0.0/10 \
         tailnet address — 0.0.0.0, LAN, and public addresses are refused"
    )]
    InvalidBindAddress { bind: String },
    #[error(
        "[server] bind host '{bind_host}' is not in allowed_hosts — the daemon \
         would listen on an address no request could pass Host validation for"
    )]
    BindHostNotInAllowedHosts { bind_host: String },
    #[error(
        "allowed_hosts entry '{entry}' is not a loopback name/IP, a literal \
         100.64.0.0/10 address, or a *.ts.net name"
    )]
    InvalidAllowedHost { entry: String },
    #[error(
        "route '{route}' chain mixes dialects ('{a}' and '{b}') — advancing a \
         rung must never change wire protocol mid-request"
    )]
    MixedDialectChain { route: String, a: String, b: String },
}

pub fn parse_config(raw: &str) -> Result<Config, ConfigError> {
    Ok(toml::from_str(raw)?)
}

/// Enforce the split-plane schema before credentials are loaded or a socket
/// is bound. A safe process must have no remote provider configuration.
pub fn validate_plane(config: &Config) -> Result<(), ConfigError> {
    match config.server.plane.as_str() {
        "safe" if !config.providers.is_empty() => Err(ConfigError::SafePlaneProvider),
        "safe" | "escalation" => Ok(()),
        _ => Err(ConfigError::InvalidPlane {
            plane: config.server.plane.clone(),
        }),
    }
}

/// Invariant #7 / SPEC §4.1: the safe plane's backends must be
/// loopback or tailnet-local (a literal `100.64.0.0/10` address — never a
/// name, see `is_tailnet_literal`). A no-op on any other plane — escalation
/// legitimately has remote backends via `[[provider]]`, a separate schema
/// Step 4 adds.
pub fn validate_safe_plane_backends(config: &Config) -> Result<(), ConfigError> {
    if config.server.plane != "safe" {
        return Ok(());
    }
    for backend in &config.backends {
        let host = url_host(&backend.base_url);
        if !(is_loopback_name_or_ip(host) || is_tailnet_literal(host)) {
            return Err(ConfigError::NonLoopbackSafeBackend {
                id: backend.id.clone(),
                base_url: backend.base_url.clone(),
            });
        }
    }
    Ok(())
}

/// SPEC §4.1 (v1): `[server] bind` must be loopback or a literal tailnet
/// address. Refuses `0.0.0.0`, `::`, LAN, and public addresses — the
/// midnight-config-edit landmine CLAUDE.md names: this check exists to catch
/// *you*, not an attacker. If `bind` is non-loopback, its host must also
/// appear in `allowed_hosts`, otherwise the daemon would listen on an
/// address no request could ever pass Host validation for — silently dead,
/// the worst failure shape.
pub fn validate_bind_address(config: &Config) -> Result<(), ConfigError> {
    let host = host_without_port(&config.server.bind);
    if is_loopback_name_or_ip(host) {
        return Ok(());
    }
    if !is_tailnet_literal(host) {
        return Err(ConfigError::InvalidBindAddress { bind: config.server.bind.clone() });
    }
    if !config.server.allowed_hosts.iter().any(|a| host_without_port(a) == host) {
        return Err(ConfigError::BindHostNotInAllowedHosts { bind_host: host.to_string() });
    }
    Ok(())
}

/// SPEC §4.1 (v1): every `allowed_hosts` entry must be a loopback name/IP, a
/// literal `100.64.0.0/10` address, or a `*.ts.net` MagicDNS name. Nothing
/// else — this is the inbound `Host` allowlist, compared against verbatim
/// (`check_host` in `lib.rs`), never resolved.
pub fn validate_allowed_hosts(config: &Config) -> Result<(), ConfigError> {
    for entry in &config.server.allowed_hosts {
        let host = host_without_port(entry);
        if !(is_loopback_name_or_ip(host) || is_tailnet_literal(host) || is_ts_net_name(host)) {
            return Err(ConfigError::InvalidAllowedHost { entry: entry.clone() });
        }
    }
    Ok(())
}

/// Invariant #5: v0 speaks exactly one dialect. A config declaring anything
/// else would silently misbehave (we'd treat a non-OpenAI-shaped backend as
/// OpenAI-shaped) rather than fail loudly — refuse to start instead.
/// Plane-agnostic: applies to both `[[backend]]` and `[[provider]]`.
pub fn validate_dialects(config: &Config) -> Result<(), ConfigError> {
    for backend in &config.backends {
        if !is_supported_dialect(&backend.dialect) {
            return Err(ConfigError::UnsupportedDialect {
                entry: backend.id.clone(),
                dialect: backend.dialect.clone(),
            });
        }
    }
    for provider in &config.providers {
        if !is_supported_dialect(&provider.dialect) {
            return Err(ConfigError::UnsupportedDialect {
                entry: provider.id.clone(),
                dialect: provider.dialect.clone(),
            });
        }
    }
    Ok(())
}

fn is_supported_dialect(dialect: &str) -> bool {
    matches!(dialect, "openai" | "anthropic")
}

/// The dialect declared by whichever `[[backend]]`/`[[provider]]` owns this
/// id — `None` if the id isn't configured at all (a different validation's
/// job to catch). Also used at request time (`proxy.rs`, matrix row 20) to
/// check a resolved chain's dialect against the inbound endpoint.
pub fn dialect_for_id<'a>(config: &'a Config, backend_id: &str) -> Option<&'a str> {
    config
        .backends
        .iter()
        .find(|b| b.id == backend_id)
        .map(|b| b.dialect.as_str())
        .or_else(|| {
            config
                .providers
                .iter()
                .find(|p| p.id == backend_id)
                .map(|p| p.dialect.as_str())
        })
}

/// SPEC §7.1 / matrix row 21: a route chain must resolve entirely within one
/// dialect — advancing a rung must never change wire protocol mid-request.
/// Unknown backend ids are `validate_route_chains`'s job, not this one's;
/// entries this function can't resolve a dialect for are silently skipped.
pub fn validate_chain_dialects(config: &Config) -> Result<(), ConfigError> {
    for route in &config.routes {
        let mut first_dialect: Option<&str> = None;
        for entry in &route.chain {
            let Some(rung) = parse_rung(entry) else { continue };
            let Some(dialect) = dialect_for_id(config, &rung.backend_id) else { continue };
            match first_dialect {
                None => first_dialect = Some(dialect),
                Some(first) if first != dialect => {
                    return Err(ConfigError::MixedDialectChain {
                        route: route.name.clone(),
                        a: first.to_string(),
                        b: dialect.to_string(),
                    });
                }
                Some(_) => {}
            }
        }
    }
    Ok(())
}

/// One rung of a resolved chain: which configured backend/provider to hit,
/// and which bare model name to ask it for. `[[route]].chain` entries and
/// concrete-model requests both use the same `<id>/<model>` composite
/// string (SPEC §5.3) — split on the *first* `/` only, since model names
/// themselves can contain slashes (e.g. LM Studio's `qwen/qwen3.6-35b-a3b`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rung {
    pub backend_id: String,
    pub model: String,
}

pub fn parse_rung(entry: &str) -> Option<Rung> {
    let (backend_id, model) = entry.split_once('/')?;
    if backend_id.is_empty() || model.is_empty() {
        return None;
    }
    Some(Rung {
        backend_id: backend_id.to_string(),
        model: model.to_string(),
    })
}

/// SPEC §5.2 / PLAN Step 5: chains are validated against same-file
/// backends/providers only — a route can't reference the other plane's
/// backend because the other plane's ids simply don't exist in this config.
/// "Enforce by construction," not a runtime cross-plane check.
pub fn validate_route_chains(config: &Config) -> Result<(), ConfigError> {
    let known_ids: std::collections::HashSet<&str> = config
        .backends
        .iter()
        .map(|b| b.id.as_str())
        .chain(config.providers.iter().map(|p| p.id.as_str()))
        .collect();

    for route in &config.routes {
        for entry in &route.chain {
            let Some(rung) = parse_rung(entry) else {
                return Err(ConfigError::InvalidChainEntry {
                    route: route.name.clone(),
                    entry: entry.clone(),
                });
            };
            if !known_ids.contains(rung.backend_id.as_str()) {
                return Err(ConfigError::UnknownChainBackend {
                    route: route.name.clone(),
                    backend_id: rung.backend_id,
                });
            }
        }
    }
    Ok(())
}

/// An admitted request's model/alias, resolved to an ordered dispatch plan.
/// `advance_on_error` mirrors the route's `on_error` field (`"next"` →
/// true); a concrete model is always a single rung with no advancement —
/// invariant #6, it gets exactly that model or an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedChain {
    pub rungs: Vec<Rung>,
    pub advance_on_error: bool,
}

/// Resolves an admitted `model`/alias string to its dispatch plan. Returns
/// `None` only when the string is neither a known alias nor a well-formed
/// `<backend_id>/<model>` composite — admission already confirmed the key is
/// *allowed* to ask for this string, but that doesn't guarantee it resolves
/// to anything dispatchable (a malformed `allow` entry, for instance).
pub fn resolve_chain(config: &Config, requested: &str) -> Option<ResolvedChain> {
    if let Some(route) = config.routes.iter().find(|r| r.name == requested) {
        let rungs: Vec<Rung> = route.chain.iter().filter_map(|e| parse_rung(e)).collect();
        if rungs.is_empty() {
            return None;
        }
        let advance_on_error = route.on_error.as_deref() == Some("next");
        Some(ResolvedChain { rungs, advance_on_error })
    } else {
        let rung = parse_rung(requested)?;
        Some(ResolvedChain {
            rungs: vec![rung],
            advance_on_error: false,
        })
    }
}

/// Extracts the bare host (no scheme, no path, no port) from a `base_url`
/// like `http://127.0.0.1:1234/v1`.
fn url_host(base_url: &str) -> &str {
    let without_scheme = base_url
        .split_once("://")
        .map_or(base_url, |(_, rest)| rest);
    let host = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);
    host.rsplit_once(':').map_or(host, |(h, _)| h)
}

/// Strips a trailing `:port` from a bare `host` or `host:port` string (as
/// opposed to `url_host`, which also strips scheme/path). Used for
/// `[server] bind` and `allowed_hosts` entries, which are host[:port] pairs,
/// not URLs.
fn host_without_port(host: &str) -> &str {
    host.rsplit_once(':').map_or(host, |(h, _)| h)
}

fn is_loopback_name_or_ip(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]")
}

/// SPEC §4.1: "tailnet-local," precisely — a literal IPv4 address in
/// Tailscale's CGNAT range `100.64.0.0/10` (second octet 64-127). Never a
/// name: a name resolves wherever DNS says it does, which turns a
/// structural check into a trust-the-resolver check.
fn is_tailnet_literal(host: &str) -> bool {
    match parse_ipv4(host) {
        Some([100, second, _, _]) => (64..=127).contains(&second),
        _ => false,
    }
}

fn parse_ipv4(host: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = host.split('.');
    for octet in &mut octets {
        *octet = parts.next()?.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}

/// MagicDNS names are accepted only on the *inbound* side (`allowed_hosts`),
/// where they are compared against the `Host` header verbatim, never
/// resolved (SPEC §4.1).
fn is_ts_net_name(host: &str) -> bool {
    host.strip_suffix(".ts.net").is_some_and(|prefix| !prefix.is_empty())
}

/// SPEC §4.1 / matrix row 16: refuse to start if the same key hash is
/// authorized in both planes. Pure comparison — `main.rs` is responsible for
/// finding and loading the peer plane's config file, if any.
pub fn find_cross_plane_collision(a: &Config, b: &Config) -> Option<String> {
    a.keys
        .iter()
        .find_map(|ka| b.keys.iter().find(|kb| kb.hash == ka.hash).map(|_| ka.hash.clone()))
}

pub fn validate_no_cross_plane_collision(a: &Config, b: &Config) -> Result<(), ConfigError> {
    if find_cross_plane_collision(a, b).is_some() {
        Err(ConfigError::CrossPlaneKeyCollision)
    } else {
        Ok(())
    }
}

/// SPEC §5.2: naming a route alias *is* consent to substitution within that
/// chain; naming a concrete model gets exactly that model or an error.
/// Purely informational at v0 — the admission decision itself (below) is the
/// same membership test either way; this exists so dispatch (Step 5) and
/// logging (Step 7) can tell the two apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelKind {
    Alias,
    Concrete,
}

pub fn classify_model(config: &Config, requested: &str) -> ModelKind {
    if config.routes.iter().any(|r| r.name == requested) {
        ModelKind::Alias
    } else {
        ModelKind::Concrete
    }
}

#[derive(Debug, thiserror::Error)]
#[error("requested model/alias is not in this key's allowlist")]
pub struct AdmissionDenied;

/// SPEC §4.2 / §5.1: admission is a plain membership test against the
/// key's `allow` list — exact string match, no fuzzy resolution, no
/// reinterpretation. That's what makes invariant #6 (no silent substitution)
/// hold by construction: nothing here ever picks a *different* string than
/// what the client asked for.
pub fn admit(key: &KeyEntry, requested_model: &str) -> Result<(), AdmissionDenied> {
    if key.allow.iter().any(|a| a == requested_model) {
        Ok(())
    } else {
        Err(AdmissionDenied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let raw = r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"

            [[key]]
            id = "test-client"
            hash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$hash"
        "#;
        let config = parse_config(raw).expect("valid config parses");
        assert_eq!(config.server.bind, "127.0.0.1:8787");
        assert_eq!(config.keys.len(), 1);
        assert_eq!(config.keys[0].id, "test-client");
        assert!(validate_plane(&config).is_ok());
    }

    #[test]
    fn safe_plane_rejects_provider_entries() {
        let config = parse_config(
            r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"
            [[provider]]
            id = "remote"
            base_url = "https://example.com/v1"
            dialect = "openai"
            keychain_item = "safe-router/remote"
        "#,
        )
        .unwrap();
        assert!(matches!(
            validate_plane(&config),
            Err(ConfigError::SafePlaneProvider)
        ));
    }

    #[test]
    fn unknown_plane_is_rejected() {
        let config = parse_config(
            r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "sfae"
        "#,
        )
        .unwrap();
        assert!(matches!(
            validate_plane(&config),
            Err(ConfigError::InvalidPlane { .. })
        ));
    }

    #[test]
    fn parses_backends_and_routes() {
        let raw = r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"

            [[backend]]
            id = "lmstudio-local"
            base_url = "http://127.0.0.1:1234/v1"
            dialect = "openai"

            [[route]]
            name = "local-workhorse"
            chain = ["lmstudio-local/llama-3.3-70b"]
        "#;
        let config = parse_config(raw).expect("valid config parses");
        assert_eq!(config.backends.len(), 1);
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].name, "local-workhorse");
    }

    #[test]
    fn rejects_invalid_toml() {
        assert!(parse_config("not valid toml {{{").is_err());
    }

    #[test]
    fn safe_plane_accepts_loopback_backend() {
        let raw = r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"

            [[backend]]
            id = "local"
            base_url = "http://127.0.0.1:1234/v1"
            dialect = "openai"
        "#;
        let config = parse_config(raw).unwrap();
        assert!(validate_safe_plane_backends(&config).is_ok());
    }

    #[test]
    fn safe_plane_accepts_localhost_backend() {
        let raw = r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"

            [[backend]]
            id = "local"
            base_url = "http://localhost:1234/v1"
            dialect = "openai"
        "#;
        let config = parse_config(raw).unwrap();
        assert!(validate_safe_plane_backends(&config).is_ok());
    }

    #[test]
    fn safe_plane_rejects_lan_backend() {
        let raw = r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"

            [[backend]]
            id = "local"
            base_url = "http://192.168.1.50:1234/v1"
            dialect = "openai"
        "#;
        let config = parse_config(raw).unwrap();
        assert!(matches!(
            validate_safe_plane_backends(&config),
            Err(ConfigError::NonLoopbackSafeBackend { .. })
        ));
    }

    #[test]
    fn escalation_plane_backend_check_is_a_noop() {
        // Loopback restriction is safe-plane-specific; escalation's remote
        // reach is legitimate (via [[provider]] — Step 4).
        let raw = r#"
            [server]
            bind = "127.0.0.1:8788"
            plane = "escalation"

            [[backend]]
            id = "remote-ish"
            base_url = "http://192.168.1.50:1234/v1"
            dialect = "openai"
        "#;
        let config = parse_config(raw).unwrap();
        assert!(validate_safe_plane_backends(&config).is_ok());
    }

    #[test]
    fn parses_providers() {
        let raw = r#"
            [server]
            bind = "127.0.0.1:8788"
            plane = "escalation"

            [[provider]]
            id = "openai"
            base_url = "https://api.openai.com/v1"
            dialect = "openai"
            keychain_item = "safe-router/openai"
        "#;
        let config = parse_config(raw).expect("valid config parses");
        assert_eq!(config.providers.len(), 1);
        assert_eq!(config.providers[0].keychain_item, "safe-router/openai");
    }

    #[test]
    fn validate_dialects_accepts_openai() {
        let raw = r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"
            [[backend]]
            id = "local"
            base_url = "http://127.0.0.1:1234/v1"
            dialect = "openai"
        "#;
        let config = parse_config(raw).unwrap();
        assert!(validate_dialects(&config).is_ok());
    }

    #[test]
    fn validate_dialects_rejects_backend_unsupported_dialect() {
        let raw = r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"
            [[backend]]
            id = "local"
            base_url = "http://127.0.0.1:1234/v1"
            dialect = "gemini"
        "#;
        let config = parse_config(raw).unwrap();
        assert!(matches!(
            validate_dialects(&config),
            Err(ConfigError::UnsupportedDialect { .. })
        ));
    }

    #[test]
    fn validate_dialects_rejects_provider_unsupported_dialect() {
        let raw = r#"
            [server]
            bind = "127.0.0.1:8788"
            plane = "escalation"
            [[provider]]
            id = "p"
            base_url = "https://example.com"
            dialect = "gemini"
            keychain_item = "safe-router/p"
        "#;
        let config = parse_config(raw).unwrap();
        assert!(matches!(
            validate_dialects(&config),
            Err(ConfigError::UnsupportedDialect { .. })
        ));
    }

    #[test]
    fn detects_cross_plane_key_collision() {
        let shared_hash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$sharedhash";
        let safe = parse_config(&format!(
            r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"
            [[key]]
            id = "leaked"
            hash = "{shared_hash}"
            "#
        ))
        .unwrap();
        let escalation = parse_config(&format!(
            r#"
            [server]
            bind = "127.0.0.1:8788"
            plane = "escalation"
            [[key]]
            id = "leaked-again"
            hash = "{shared_hash}"
            "#
        ))
        .unwrap();
        assert_eq!(
            find_cross_plane_collision(&safe, &escalation),
            Some(shared_hash.to_string())
        );
        assert!(matches!(
            validate_no_cross_plane_collision(&safe, &escalation),
            Err(ConfigError::CrossPlaneKeyCollision)
        ));
    }

    #[test]
    fn no_collision_when_hashes_differ() {
        let safe = parse_config(
            r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"
            [[key]]
            id = "a"
            hash = "$argon2id$v=19$m=19456,t=2,p=1$aaaaaaaaaaaa$hashvalueaaaa"
            "#,
        )
        .unwrap();
        let escalation = parse_config(
            r#"
            [server]
            bind = "127.0.0.1:8788"
            plane = "escalation"
            [[key]]
            id = "b"
            hash = "$argon2id$v=19$m=19456,t=2,p=1$bbbbbbbbbbbb$hashvaluebbbb"
            "#,
        )
        .unwrap();
        assert!(find_cross_plane_collision(&safe, &escalation).is_none());
        assert!(validate_no_cross_plane_collision(&safe, &escalation).is_ok());
    }

    fn key_with_allow(allow: &[&str]) -> KeyEntry {
        KeyEntry {
            id: "test".to_string(),
            hash: "irrelevant-for-admission".to_string(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn admits_allowed_concrete_model() {
        let key = key_with_allow(&["lmstudio-local/qwen2.5-72b"]);
        assert!(admit(&key, "lmstudio-local/qwen2.5-72b").is_ok());
    }

    #[test]
    fn admits_allowed_alias() {
        let key = key_with_allow(&["local-workhorse"]);
        assert!(admit(&key, "local-workhorse").is_ok());
    }

    #[test]
    fn denies_model_not_in_allowlist() {
        let key = key_with_allow(&["local-workhorse"]);
        assert!(admit(&key, "some-other-model").is_err());
    }

    #[test]
    fn denies_when_allowlist_empty() {
        let key = key_with_allow(&[]);
        assert!(admit(&key, "anything").is_err());
    }

    #[test]
    fn parse_rung_splits_on_first_slash_only() {
        // Model ids can themselves contain slashes (LM Studio's own
        // convention), so only the backend-id prefix is special.
        let rung = parse_rung("lmstudio-local/qwen/qwen3.6-35b-a3b").unwrap();
        assert_eq!(rung.backend_id, "lmstudio-local");
        assert_eq!(rung.model, "qwen/qwen3.6-35b-a3b");
    }

    #[test]
    fn parse_rung_rejects_no_slash() {
        assert!(parse_rung("gpt-4").is_none());
    }

    #[test]
    fn parse_rung_rejects_empty_parts() {
        assert!(parse_rung("/model").is_none());
        assert!(parse_rung("backend/").is_none());
    }

    fn config_with_backend_and_route(chain: &[&str], on_error: Option<&str>) -> Config {
        let chain_toml = chain
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let on_error_line = on_error
            .map(|v| format!("on_error = \"{v}\"\n"))
            .unwrap_or_default();
        parse_config(&format!(
            r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"

            [[backend]]
            id = "lmstudio-local"
            base_url = "http://127.0.0.1:1234/v1"
            dialect = "openai"

            [[backend]]
            id = "lmstudio-second"
            base_url = "http://127.0.0.1:1235/v1"
            dialect = "openai"

            [[route]]
            name = "local-workhorse"
            chain = [{chain_toml}]
            {on_error_line}
            "#
        ))
        .unwrap()
    }

    #[test]
    fn resolve_chain_alias_returns_ordered_rungs() {
        let config = config_with_backend_and_route(
            &["lmstudio-local/model-a", "lmstudio-second/model-b"],
            Some("next"),
        );
        let resolved = resolve_chain(&config, "local-workhorse").unwrap();
        assert!(resolved.advance_on_error);
        assert_eq!(
            resolved.rungs,
            vec![
                Rung { backend_id: "lmstudio-local".into(), model: "model-a".into() },
                Rung { backend_id: "lmstudio-second".into(), model: "model-b".into() },
            ]
        );
    }

    #[test]
    fn resolve_chain_on_error_fail_does_not_advance() {
        let config = config_with_backend_and_route(&["lmstudio-local/model-a"], Some("fail"));
        let resolved = resolve_chain(&config, "local-workhorse").unwrap();
        assert!(!resolved.advance_on_error);
    }

    #[test]
    fn resolve_chain_missing_on_error_defaults_to_no_advance() {
        let config = config_with_backend_and_route(&["lmstudio-local/model-a"], None);
        let resolved = resolve_chain(&config, "local-workhorse").unwrap();
        assert!(!resolved.advance_on_error);
    }

    #[test]
    fn resolve_chain_concrete_model_is_single_rung_no_advance() {
        let config = config_with_backend_and_route(&["lmstudio-local/model-a"], Some("next"));
        let resolved = resolve_chain(&config, "lmstudio-local/qwen2.5-72b").unwrap();
        assert!(!resolved.advance_on_error);
        assert_eq!(
            resolved.rungs,
            vec![Rung { backend_id: "lmstudio-local".into(), model: "qwen2.5-72b".into() }]
        );
    }

    #[test]
    fn resolve_chain_unparseable_concrete_model_is_none() {
        let config = config_with_backend_and_route(&["lmstudio-local/model-a"], None);
        assert!(resolve_chain(&config, "not-a-composite-id").is_none());
    }

    #[test]
    fn validate_route_chains_accepts_known_backend_ids() {
        let config = config_with_backend_and_route(
            &["lmstudio-local/model-a", "lmstudio-second/model-b"],
            Some("next"),
        );
        assert!(validate_route_chains(&config).is_ok());
    }

    #[test]
    fn validate_route_chains_rejects_unknown_backend_id() {
        let config = config_with_backend_and_route(&["nonexistent-backend/model-a"], None);
        assert!(matches!(
            validate_route_chains(&config),
            Err(ConfigError::UnknownChainBackend { .. })
        ));
    }

    #[test]
    fn validate_route_chains_rejects_malformed_entry() {
        let config = config_with_backend_and_route(&["no-slash-here"], None);
        assert!(matches!(
            validate_route_chains(&config),
            Err(ConfigError::InvalidChainEntry { .. })
        ));
    }

    fn config_with_bind_and_hosts(bind: &str, allowed_hosts: &[&str]) -> Config {
        let hosts_toml = allowed_hosts
            .iter()
            .map(|h| format!("\"{h}\""))
            .collect::<Vec<_>>()
            .join(", ");
        parse_config(&format!(
            r#"
            [server]
            bind = "{bind}"
            plane = "safe"
            allowed_hosts = [{hosts_toml}]
            "#
        ))
        .unwrap()
    }

    #[test]
    fn allowed_hosts_defaults_to_empty() {
        let config = config_with_bind_and_hosts("127.0.0.1:8787", &[]);
        assert!(config.server.allowed_hosts.is_empty());
    }

    #[test]
    fn validate_bind_address_accepts_loopback() {
        assert!(validate_bind_address(&config_with_bind_and_hosts("127.0.0.1:8787", &[])).is_ok());
    }

    #[test]
    fn validate_bind_address_accepts_tailnet_literal_when_in_allowed_hosts() {
        let config = config_with_bind_and_hosts("100.64.1.2:8787", &["100.64.1.2"]);
        assert!(validate_bind_address(&config).is_ok());
    }

    #[test]
    fn validate_bind_address_rejects_tailnet_literal_not_in_allowed_hosts() {
        let config = config_with_bind_and_hosts("100.64.1.2:8787", &[]);
        assert!(matches!(
            validate_bind_address(&config),
            Err(ConfigError::BindHostNotInAllowedHosts { .. })
        ));
    }

    #[test]
    fn validate_bind_address_rejects_wildcard() {
        let config = config_with_bind_and_hosts("0.0.0.0:8787", &[]);
        assert!(matches!(
            validate_bind_address(&config),
            Err(ConfigError::InvalidBindAddress { .. })
        ));
    }

    #[test]
    fn validate_bind_address_rejects_lan() {
        let config = config_with_bind_and_hosts("192.168.1.50:8787", &[]);
        assert!(matches!(
            validate_bind_address(&config),
            Err(ConfigError::InvalidBindAddress { .. })
        ));
    }

    #[test]
    fn validate_bind_address_rejects_public_ip() {
        let config = config_with_bind_and_hosts("8.8.8.8:8787", &[]);
        assert!(matches!(
            validate_bind_address(&config),
            Err(ConfigError::InvalidBindAddress { .. })
        ));
    }

    #[test]
    fn validate_bind_address_rejects_ts_net_name_as_bind() {
        // `*.ts.net` names are inbound-only (allowed_hosts); a bind must be
        // a literal address, never a name.
        let config = config_with_bind_and_hosts("mac-studio.tailabcd.ts.net:8787", &[]);
        assert!(matches!(
            validate_bind_address(&config),
            Err(ConfigError::InvalidBindAddress { .. })
        ));
    }

    #[test]
    fn validate_allowed_hosts_accepts_tailnet_literal_and_ts_net_name() {
        let config =
            config_with_bind_and_hosts("127.0.0.1:8787", &["100.64.1.2", "mac-studio.tailabcd.ts.net"]);
        assert!(validate_allowed_hosts(&config).is_ok());
    }

    #[test]
    fn validate_allowed_hosts_rejects_lan_entry() {
        let config = config_with_bind_and_hosts("127.0.0.1:8787", &["192.168.1.50"]);
        assert!(matches!(
            validate_allowed_hosts(&config),
            Err(ConfigError::InvalidAllowedHost { .. })
        ));
    }

    #[test]
    fn validate_allowed_hosts_rejects_public_domain() {
        let config = config_with_bind_and_hosts("127.0.0.1:8787", &["evil.example.com"]);
        assert!(matches!(
            validate_allowed_hosts(&config),
            Err(ConfigError::InvalidAllowedHost { .. })
        ));
    }

    #[test]
    fn safe_plane_accepts_tailnet_literal_backend() {
        let raw = r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"

            [[backend]]
            id = "local"
            base_url = "http://100.64.1.2:1234/v1"
            dialect = "openai"
        "#;
        let config = parse_config(raw).unwrap();
        assert!(validate_safe_plane_backends(&config).is_ok());
    }

    #[test]
    fn safe_plane_rejects_ts_net_name_backend() {
        // Names resolve wherever DNS says at request time — a structural
        // check must not depend on the resolver (SPEC §4.1).
        let raw = r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"

            [[backend]]
            id = "local"
            base_url = "http://mac-studio.tailabcd.ts.net:1234/v1"
            dialect = "openai"
        "#;
        let config = parse_config(raw).unwrap();
        assert!(matches!(
            validate_safe_plane_backends(&config),
            Err(ConfigError::NonLoopbackSafeBackend { .. })
        ));
    }

    #[test]
    fn validate_dialects_accepts_anthropic_provider() {
        let raw = r#"
            [server]
            bind = "127.0.0.1:8788"
            plane = "escalation"
            [[provider]]
            id = "anthropic"
            base_url = "https://api.anthropic.com"
            dialect = "anthropic"
            keychain_item = "safe-router/anthropic"
        "#;
        let config = parse_config(raw).unwrap();
        assert!(validate_dialects(&config).is_ok());
    }

    fn config_with_two_provider_chain(dialect_a: &str, dialect_b: &str) -> Config {
        parse_config(&format!(
            r#"
            [server]
            bind = "127.0.0.1:8788"
            plane = "escalation"

            [[provider]]
            id = "a"
            base_url = "https://a.example.com"
            dialect = "{dialect_a}"
            keychain_item = "safe-router/a"

            [[provider]]
            id = "b"
            base_url = "https://b.example.com"
            dialect = "{dialect_b}"
            keychain_item = "safe-router/b"

            [[route]]
            name = "mixed"
            chain = ["a/model-a", "b/model-b"]
            on_error = "next"
            "#
        ))
        .unwrap()
    }

    #[test]
    fn validate_chain_dialects_accepts_uniform_chain() {
        let config = config_with_two_provider_chain("openai", "openai");
        assert!(validate_chain_dialects(&config).is_ok());
    }

    #[test]
    fn validate_chain_dialects_rejects_mixed_chain() {
        let config = config_with_two_provider_chain("openai", "anthropic");
        assert!(matches!(
            validate_chain_dialects(&config),
            Err(ConfigError::MixedDialectChain { .. })
        ));
    }

    #[test]
    fn dialect_for_id_finds_provider_dialect() {
        let config = config_with_two_provider_chain("openai", "anthropic");
        assert_eq!(dialect_for_id(&config, "a"), Some("openai"));
        assert_eq!(dialect_for_id(&config, "b"), Some("anthropic"));
        assert_eq!(dialect_for_id(&config, "nonexistent"), None);
    }

    #[test]
    fn classifies_route_name_as_alias() {
        let raw = r#"
            [server]
            bind = "127.0.0.1:8787"
            plane = "safe"
            [[route]]
            name = "local-workhorse"
            chain = ["lmstudio-local/llama-3.3-70b"]
        "#;
        let config = parse_config(raw).unwrap();
        assert_eq!(classify_model(&config, "local-workhorse"), ModelKind::Alias);
        assert_eq!(
            classify_model(&config, "lmstudio-local/llama-3.3-70b"),
            ModelKind::Concrete
        );
    }
}
