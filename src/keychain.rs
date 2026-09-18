//! Keychain access for escalation-plane provider credentials.
//!
//! CLAUDE.md dependency notes: "no crate — shell out to `/usr/bin/security
//! find-generic-password -s <item> -w`." The path is hardcoded absolute
//! (not resolved via `$PATH`) deliberately: a bare `Command::new("security")`
//! would let anything earlier on `$PATH` intercept a Keychain credential
//! fetch, which is exactly the kind of local-attacker surface invariant #9
//! (the client never holds a remote credential) exists to close off.

use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("failed to run `security`: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("security exited with status {status}: {stderr}")]
    NotFound { status: String, stderr: String },
    #[error("security returned non-UTF8 output")]
    InvalidOutput,
}

/// Fetches the plaintext password for a generic-password Keychain item.
/// Never logs the secret; the caller (`main.rs`) holds it only in memory
/// (`AppState.credentials`), never writes it to config or the metadata log.
pub fn fetch_secret(item: &str) -> Result<String, KeychainError> {
    fetch_secret_with(Command::new("/usr/bin/security"), item)
}

fn fetch_secret_with(mut cmd: Command, item: &str) -> Result<String, KeychainError> {
    let output = cmd.args(["find-generic-password", "-s", item, "-w"]).output()?;

    if !output.status.success() {
        return Err(KeychainError::NotFound {
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    String::from_utf8(output.stdout)
        .map(|s| s.trim_end_matches('\n').to_string())
        .map_err(|_| KeychainError::InvalidOutput)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    /// Zero-dep unique scratch dir under the OS temp dir — no `tempfile`
    /// crate needed for a handful of fake-binary tests.
    fn scratch_dir(label: &str) -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "safe-router-keychain-test-{}-{}-{n}",
            std::process::id(),
            label
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Writes an executable shell script named `security` into `dir`,
    /// standing in for the real macOS binary without touching the real
    /// Keychain or `$PATH` — the test points `Command::new` at this file's
    /// absolute path directly.
    fn fake_security_script(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("security");
        let mut f = fs::File::create(&path).unwrap();
        writeln!(f, "#!/bin/sh\n{body}").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[test]
    fn fetch_secret_returns_trimmed_password_on_success() {
        let dir = scratch_dir("ok");
        let script = fake_security_script(&dir, r#"echo "sk-test-secret-123""#);
        let secret = fetch_secret_with(Command::new(script), "safe-router/openai").unwrap();
        assert_eq!(secret, "sk-test-secret-123");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fetch_secret_passes_item_name_as_dash_s_argument() {
        let dir = scratch_dir("args");
        // Echoes back whichever -s argument it was given, so the test can
        // assert we're actually passing the item name through correctly.
        let script = fake_security_script(
            &dir,
            r#"
            while [ "$1" != "-s" ]; do shift; done
            echo "got:$2"
            "#,
        );
        let secret = fetch_secret_with(Command::new(script), "safe-router/openai").unwrap();
        assert_eq!(secret, "got:safe-router/openai");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fetch_secret_errors_when_item_not_found() {
        let dir = scratch_dir("notfound");
        let script = fake_security_script(
            &dir,
            r#"echo "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain." >&2
            exit 44"#,
        );
        let err = fetch_secret_with(Command::new(script), "safe-router/missing").unwrap_err();
        assert!(matches!(err, KeychainError::NotFound { .. }));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fetch_secret_errors_when_binary_missing() {
        let err = fetch_secret_with(
            Command::new("/nonexistent/path/to/security"),
            "safe-router/openai",
        )
        .unwrap_err();
        assert!(matches!(err, KeychainError::Spawn(_)));
    }
}
