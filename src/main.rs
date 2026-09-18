use std::{
    collections::HashMap,
    io::Read,
    path::{Path, PathBuf},
    process::ExitCode,
};

use safe_router::{auth, build_router, keychain, log, policy, reload_attempt, AppState};
use tokio::signal::unix::{signal, SignalKind};

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();

    if args.get(1).map(String::as_str) == Some("hash-key") {
        return hash_key_cmd();
    }
    if args.get(1).map(String::as_str) == Some("verify-log") {
        return verify_log_cmd(&args);
    }
    if args.get(1).map(String::as_str) == Some("anchor") {
        return anchor_cmd(&args);
    }

    let Some(config_path) = config_path_arg(&args) else {
        eprintln!("usage: safe-router --config <path.toml> | hash-key | verify-log [--log <path>] | anchor [--log <path>] [--out <path>]");
        return ExitCode::from(2);
    };

    // Invariant #1: invalid config means the daemon refuses to start. No
    // default, no fallback.
    let config = match load_and_validate(Path::new(&config_path)) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("refusing to start: {msg}");
            return ExitCode::FAILURE;
        }
    };

    // Escalation-plane credentials come from Keychain, once, before we ever
    // bind — a provider we can't authenticate is as broken as invalid
    // config (invariant #1: no default, no degraded mode).
    let credentials = match fetch_escalation_credentials(&config) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("refusing to start: {msg}");
            return ExitCode::FAILURE;
        }
    };

    // SPEC §8: the real metadata log, not the in-memory default `AppState::
    // new` uses for tests. A file that can't even be opened is the same
    // tier of problem as invalid config or an unfetchable credential —
    // refuse to start rather than silently run without a log from request
    // one (invariant #1).
    let log_path = match log_db_path() {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("refusing to start: {msg}");
            return ExitCode::FAILURE;
        }
    };
    let bind = config.server.bind.clone();
    let state = match AppState::new(config).with_credentials(credentials).with_log_path(&log_path) {
        Ok(s) => s,
        Err(msg) => {
            eprintln!("refusing to start: {msg}");
            return ExitCode::FAILURE;
        }
    };
    let app = build_router(state.clone());

    spawn_sighup_reloader(state, config_path);

    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("refusing to start: cannot bind {bind}: {e}");
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(%bind, "safe-router listening");
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("server error: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

/// Reads, parses, and validates a config file — refusing (matrix row 7) on
/// invalid TOML or a non-loopback safe-plane backend (invariant #7). Also
/// best-effort cross-checks the sibling plane's config, if one exists at the
/// canonical `safe.toml`/`escalation.toml` path next to this one, for the
/// matrix-row-16 key-hash collision. A missing or unparseable peer file is
/// not itself fatal — the peer plane may simply not be deployed yet — but an
/// *actual* detected collision is.
fn load_and_validate(config_path: &Path) -> Result<policy::Config, String> {
    let raw = std::fs::read_to_string(config_path)
        .map_err(|e| format!("cannot read config {}: {e}", config_path.display()))?;
    let config = policy::parse_config(&raw).map_err(|e| format!("invalid config: {e}"))?;
    policy::validate_plane(&config).map_err(|e| e.to_string())?;
    policy::validate_bind_address(&config).map_err(|e| e.to_string())?;
    policy::validate_allowed_hosts(&config).map_err(|e| e.to_string())?;
    policy::validate_safe_plane_backends(&config).map_err(|e| e.to_string())?;
    policy::validate_dialects(&config).map_err(|e| e.to_string())?;
    policy::validate_route_chains(&config).map_err(|e| e.to_string())?;
    policy::validate_chain_dialects(&config).map_err(|e| e.to_string())?;

    if let Some(peer_path) = peer_config_path(config_path, &config.server.plane) {
        match std::fs::read_to_string(&peer_path) {
            Ok(peer_raw) => match policy::parse_config(&peer_raw) {
                Ok(peer_config) => {
                    policy::validate_no_cross_plane_collision(&config, &peer_config)
                        .map_err(|e| format!("{e} (peer config: {})", peer_path.display()))?;
                }
                Err(e) => {
                    tracing::warn!(
                        peer = %peer_path.display(),
                        error = %e,
                        "peer plane config exists but failed to parse; skipping cross-plane key check"
                    );
                }
            },
            Err(_) => {
                // No peer file yet (e.g. single-plane dev deployment) —
                // nothing to cross-check.
            }
        }
    }

    Ok(config)
}

/// Fetches every `[[provider]]`'s Keychain-held secret, keyed by provider
/// id. A no-op (empty map) on the safe plane, which has no `[[provider]]`
/// entries by construction. Fails closed: any provider whose credential
/// can't be fetched blocks startup rather than starting half-authenticated.
fn fetch_escalation_credentials(config: &policy::Config) -> Result<HashMap<String, String>, String> {
    let mut credentials = HashMap::new();
    for provider in &config.providers {
        let secret = keychain::fetch_secret(&provider.keychain_item).map_err(|e| {
            format!(
                "cannot fetch credential for provider '{}' (Keychain item '{}'): {e}",
                provider.id, provider.keychain_item
            )
        })?;
        credentials.insert(provider.id.clone(), secret);
    }
    Ok(credentials)
}

/// `~/.safe-router/log.db` — the one place the real metadata log lives.
/// Zero-dep `$HOME` lookup (matches the project's existing "shell out
/// instead of adding a crate" bias) rather than a `dirs`-style crate for one
/// path.
fn log_db_path() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME environment variable not set".to_string())?;
    Ok(PathBuf::from(home).join(".safe-router").join("log.db"))
}

fn peer_config_path(current: &Path, plane: &str) -> Option<PathBuf> {
    let dir = current.parent()?;
    let peer_name = match plane {
        "safe" => "escalation.toml",
        "escalation" => "safe.toml",
        _ => return None,
    };
    Some(dir.join(peer_name))
}

/// SIGHUP reload (matrix row 8): full re-validation, old config kept serving
/// on failure, loud log + degraded flag instead of a hard stop. Unlike
/// startup, a bad reload never takes the daemon down.
fn spawn_sighup_reloader(state: AppState, config_path: String) {
    tokio::spawn(async move {
        let mut stream = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGHUP handler; config reload unavailable");
                return;
            }
        };
        loop {
            if stream.recv().await.is_none() {
                return;
            }
            tracing::info!("SIGHUP received, reloading config");
            reload_attempt(&state, load_and_validate(Path::new(&config_path))).await;
        }
    });
}

fn config_path_arg(args: &[String]) -> Option<String> {
    value_after_flag(args, "--config")
}

fn value_after_flag(args: &[String], flag: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().cloned();
        }
    }
    None
}

/// `~/.safe-router/anchor/head.json` — the `anchor` subcommand's default
/// output path (SPEC §8.2, Step 3). Same zero-dep `$HOME` lookup as
/// `log_db_path`.
fn default_anchor_path() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME environment variable not set".to_string())?;
    Ok(PathBuf::from(home).join(".safe-router").join("anchor").join("head.json"))
}

/// Offline CLI helper, not a runtime policy surface (invariant #3): reads
/// the metadata log read-only and recomputes its hash chain, reporting the
/// first divergence. `--log <path>` overrides the default
/// `~/.safe-router/log.db` (used by tests; the real deployment never needs
/// it).
fn verify_log_cmd(args: &[String]) -> ExitCode {
    let path = match value_after_flag(args, "--log") {
        Some(p) => PathBuf::from(p),
        None => match log_db_path() {
            Ok(p) => p,
            Err(msg) => {
                eprintln!("{msg}");
                return ExitCode::FAILURE;
            }
        },
    };
    let log = match log::Log::open_readonly(&path) {
        Ok(l) => l,
        Err(msg) => {
            eprintln!("cannot open log: {msg}");
            return ExitCode::FAILURE;
        }
    };
    match log.verify_chain() {
        Ok(()) => {
            println!("chain OK");
            ExitCode::SUCCESS
        }
        Err(d) => {
            eprintln!(
                "chain diverges at row {}: expected prev_hash/row_hash '{}', stored {:?}",
                d.id, d.expected, d.stored
            );
            ExitCode::FAILURE
        }
    }
}

/// Offline CLI helper (SPEC §8.2, Step 3): verifies the chain, then writes
/// the newest row's `{id, ts, row_hash}` to a file — never over a broken
/// chain (publishing a head that certifies tampered history is worse than
/// publishing nothing). Pushing that file off-box is a separate shell
/// script + launchd job (docs/DEPLOYMENT.md), not this binary's job — see
/// CLAUDE.md's landmine on the daemon never making an off-box connection.
fn anchor_cmd(args: &[String]) -> ExitCode {
    let log_path = match value_after_flag(args, "--log") {
        Some(p) => PathBuf::from(p),
        None => match log_db_path() {
            Ok(p) => p,
            Err(msg) => {
                eprintln!("{msg}");
                return ExitCode::FAILURE;
            }
        },
    };
    let out_path = match value_after_flag(args, "--out") {
        Some(p) => PathBuf::from(p),
        None => match default_anchor_path() {
            Ok(p) => p,
            Err(msg) => {
                eprintln!("{msg}");
                return ExitCode::FAILURE;
            }
        },
    };

    let log = match log::Log::open_readonly(&log_path) {
        Ok(l) => l,
        Err(msg) => {
            eprintln!("refusing to anchor: cannot open log: {msg}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(d) = log.verify_chain() {
        eprintln!(
            "refusing to anchor: chain diverges at row {}: expected '{}', stored {:?}",
            d.id, d.expected, d.stored
        );
        return ExitCode::FAILURE;
    }
    let Some((id, ts, row_hash)) = log.last_row_with_hash() else {
        eprintln!("refusing to anchor: log is empty or has no chained rows");
        return ExitCode::FAILURE;
    };

    let head = serde_json::json!({"id": id, "ts": ts, "row_hash": row_hash});
    if let Some(dir) = out_path.parent()
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        eprintln!("cannot create anchor directory {}: {e}", dir.display());
        return ExitCode::FAILURE;
    }
    let bytes = serde_json::to_vec_pretty(&head).expect("anchor head always serializes");
    if let Err(e) = std::fs::write(&out_path, bytes) {
        eprintln!("cannot write anchor file {}: {e}", out_path.display());
        return ExitCode::FAILURE;
    }
    println!("anchored row {id} ({ts}) to {}", out_path.display());
    ExitCode::SUCCESS
}

/// Offline CLI helper, not a runtime policy surface (invariant #3). Reads a
/// plaintext key from stdin, prints its argon2id hash for the operator to
/// paste into a TOML `[[key]]` block.
fn hash_key_cmd() -> ExitCode {
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        eprintln!("failed to read key from stdin");
        return ExitCode::FAILURE;
    }
    let key = input.trim();
    if key.is_empty() {
        eprintln!("no key provided on stdin");
        return ExitCode::FAILURE;
    }
    match auth::hash_key(key) {
        Ok(hash) => {
            println!("{hash}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("hashing failed: {e}");
            ExitCode::FAILURE
        }
    }
}
