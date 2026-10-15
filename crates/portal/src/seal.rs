//! At-rest sealing for per-bridge secrets: AES-256-GCM under the portal KMS
//! key (PORTAL_SEAL_KEY). Layout: 12-byte IV || 16-byte tag || ciphertext.
//!
//! The layout is shared with the TypeScript portal, whose rows are already in
//! the database: changing it strands every secret sealed before the change.
//!
//! This module used to carry a keyed-HMAC `digest` alongside, for secrets the
//! database had to look up BY VALUE — /claim codes were the only such secret,
//! and they went with the claim feature. Anything needing that shape again
//! wants a length-prefixed, domain-separated label; see git history.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use anyhow::{Context, anyhow, bail};
use rand::RngCore;

const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;

pub fn seal(key_hex: &str, plaintext: &str) -> anyhow::Result<Vec<u8>> {
    let cipher = cipher_from(key_hex)?;
    let mut iv = [0u8; IV_LEN];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    let mut ct = plaintext.as_bytes().to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&iv), b"", &mut ct)
        .map_err(|_| anyhow!("seal failed"))?;
    let mut out = Vec::with_capacity(IV_LEN + TAG_LEN + ct.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn unseal(key_hex: &str, sealed: &[u8]) -> anyhow::Result<String> {
    let cipher = cipher_from(key_hex)?;
    if sealed.len() < IV_LEN + TAG_LEN + 1 {
        bail!("sealed blob too short");
    }
    let (iv, rest) = sealed.split_at(IV_LEN);
    let (tag, ct) = rest.split_at(TAG_LEN);
    let mut pt = ct.to_vec();
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(iv), b"", &mut pt, Tag::from_slice(tag))
        .map_err(|_| anyhow!("unseal failed: wrong key or tampered blob"))?;
    String::from_utf8(pt).context("sealed plaintext is not UTF-8")
}

fn cipher_from(key_hex: &str) -> anyhow::Result<Aes256Gcm> {
    if key_hex.len() != 64 || !key_hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        bail!("PORTAL_SEAL_KEY must be 64 lowercase hex chars");
    }
    let key = hex::decode(key_hex)?;
    Ok(Aes256Gcm::new_from_slice(&key)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "abababababababababababababababababababababababababababababababab";

    #[test]
    fn round_trips() {
        let sealed = seal(KEY, "nsec1secret").unwrap();
        assert_eq!(unseal(KEY, &sealed).unwrap(), "nsec1secret");
    }

    #[test]
    fn produces_distinct_ciphertexts_per_call() {
        assert_ne!(seal(KEY, "x").unwrap(), seal(KEY, "x").unwrap());
    }

    #[test]
    fn rejects_tampering_and_wrong_keys() {
        let mut sealed = seal(KEY, "payload").unwrap();
        *sealed.last_mut().unwrap() ^= 1;
        assert!(unseal(KEY, &sealed).is_err());
        assert!(unseal(&"cd".repeat(32), &seal(KEY, "payload").unwrap()).is_err());
        let err = seal("short", "x").unwrap_err();
        assert!(err.to_string().contains("PORTAL_SEAL_KEY"));
        assert!(seal(&"AB".repeat(32), "x").is_err());
    }

    #[test]
    fn rejects_short_blobs() {
        assert!(unseal(KEY, &[0u8; 28]).is_err());
    }

    /// Sealed by the TypeScript portal (`seal("11".repeat(32), "héllo")`):
    /// rows already in the database must keep unsealing.
    #[test]
    fn unseals_what_the_typescript_portal_sealed() {
        let sealed = hex::decode("f1f53da88c62ba16f26857168ff2df5d760cc884ceab8cd541973ebb35ea72d151ad").unwrap();
        assert_eq!(unseal(&"11".repeat(32), &sealed).unwrap(), "héllo");
    }
}
