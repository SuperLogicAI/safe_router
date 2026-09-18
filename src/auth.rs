//! Bearer-key authentication. Argon2id verify against static hashes loaded
//! from config (CLAUDE.md invariant 8: "no database, no query language, no
//! parser, no dynamic dispatch anywhere near the auth path").

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};

use crate::policy::KeyEntry;

/// Verify a presented bearer token against every configured key hash.
///
/// Every key is checked — the loop never returns early on a match — so a
/// request's latency does not reveal *which* key (if any) it matched.
pub fn authenticate<'a>(keys: &'a [KeyEntry], presented: &str) -> Option<&'a KeyEntry> {
    let argon2 = Argon2::default();
    let mut matched = None;
    for key in keys {
        let verified = PasswordHash::new(&key.hash)
            .map(|parsed| {
                argon2
                    .verify_password(presented.as_bytes(), &parsed)
                    .is_ok()
            })
            .unwrap_or(false);
        if verified {
            matched = Some(key);
        }
    }
    matched
}

/// Offline helper for the `hash-key` CLI subcommand — not a runtime policy
/// surface (invariant 3 stays intact: this never runs against a live config).
pub fn hash_key(plaintext: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default().hash_password(plaintext.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::KeyEntry;

    fn key(id: &str, plaintext: &str) -> KeyEntry {
        KeyEntry {
            id: id.to_string(),
            hash: hash_key(plaintext).expect("hash"),
            allow: vec![],
        }
    }

    #[test]
    fn hash_key_output_self_verifies() {
        let hash = hash_key("correct-horse-battery-staple").expect("hash");
        let parsed = PasswordHash::new(&hash).expect("parses");
        assert!(Argon2::default()
            .verify_password(b"correct-horse-battery-staple", &parsed)
            .is_ok());
    }

    #[test]
    fn authenticate_matches_correct_key() {
        let keys = vec![key("a", "secret-a"), key("b", "secret-b")];
        let matched = authenticate(&keys, "secret-b").expect("should match");
        assert_eq!(matched.id, "b");
    }

    #[test]
    fn authenticate_rejects_unknown_key() {
        let keys = vec![key("a", "secret-a")];
        assert!(authenticate(&keys, "not-a-real-key").is_none());
    }

    #[test]
    fn authenticate_rejects_against_empty_keyset() {
        assert!(authenticate(&[], "anything").is_none());
    }
}
