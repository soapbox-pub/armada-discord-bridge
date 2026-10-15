//! Puppet identities: one deterministic Nostr keypair per Discord user
//! (following Mostr's derivation pattern).
//!
//! Nothing per-user is stored; keys are recomputed from the bridge's master
//! secret and the Discord user id, and cached. A Concord moderator can ban
//! one puppet npub without affecting the bridge or other Discord users.
//!
//! The derivation is byte-identical to the TS bridge's: changing any input to
//! the HKDF changes every existing user's puppet npub.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use hkdf::Hkdf;
use nostr::prelude::{Keys, SecretKey};
use sha2::Sha256;

const HKDF_INFO_PREFIX: &str = "armada-bridge/puppet/v1/";

/// Default number of puppets [`PuppetCache`] keeps.
pub const DEFAULT_CAP: usize = 4096;

#[derive(Clone, Debug)]
pub struct Puppet {
    pub keys: Keys,
    /// x-only pubkey, lowercase hex.
    pub pk: String,
    /// The Discord user id this puppet represents.
    pub discord_user_id: String,
}

/// Derive the puppet keypair for a Discord user. The counter suffix guards the
/// negligible (~2^-128) case where HKDF output is not a valid secp256k1
/// scalar; derivation stays deterministic because the first valid counter
/// always wins.
pub fn derive_puppet(master_secret_hex: &str, discord_user_id: &str) -> Result<Puppet> {
    if discord_user_id.is_empty() || discord_user_id.len() > 20 || !discord_user_id.bytes().all(|b| b.is_ascii_digit()) {
        bail!("Not a Discord snowflake id: {discord_user_id}");
    }
    let ikm = hex::decode(master_secret_hex).context("master secret is not hex")?;
    // No salt: HKDF then uses a hash-length block of zeros, as noble's does.
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    for counter in 0u64.. {
        let info = format!("{HKDF_INFO_PREFIX}{discord_user_id}/{counter}");
        let mut sk = [0u8; 32];
        hk.expand(info.as_bytes(), &mut sk).expect("32 bytes is a valid HKDF-SHA256 output length");
        // Out-of-range scalar: bump the counter.
        let Ok(secret) = SecretKey::from_slice(&sk) else { continue };
        let keys = Keys::new(secret);
        let pk = keys.public_key().to_hex();
        return Ok(Puppet { keys, pk, discord_user_id: discord_user_id.to_owned() });
    }
    unreachable!("u64 counter exhausted")
}

/// Bounded insertion-order cache of derived puppets, shared across tasks.
pub struct PuppetCache {
    master_secret_hex: String,
    cap: usize,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    map: HashMap<String, Puppet>,
    order: VecDeque<String>,
    by_pubkey: HashMap<String, String>,
}

impl PuppetCache {
    pub fn new(master_secret_hex: impl Into<String>) -> Self {
        Self::with_cap(master_secret_hex, DEFAULT_CAP)
    }

    pub fn with_cap(master_secret_hex: impl Into<String>, cap: usize) -> Self {
        Self { master_secret_hex: master_secret_hex.into(), cap: cap.max(1), inner: Mutex::default() }
    }

    pub fn get(&self, discord_user_id: &str) -> Result<Puppet> {
        if let Some(hit) = self.lock().map.get(discord_user_id) {
            return Ok(hit.clone());
        }
        // Derive outside the lock; a racing insert of the same id is identical.
        let puppet = derive_puppet(&self.master_secret_hex, discord_user_id)?;
        let mut inner = self.lock();
        if let Some(hit) = inner.map.get(discord_user_id) {
            return Ok(hit.clone());
        }
        if inner.map.len() >= self.cap
            && let Some(oldest) = inner.order.pop_front()
            && let Some(evicted) = inner.map.remove(&oldest)
        {
            inner.by_pubkey.remove(&evicted.pk);
        }
        inner.order.push_back(discord_user_id.to_owned());
        inner.by_pubkey.insert(puppet.pk.clone(), discord_user_id.to_owned());
        inner.map.insert(discord_user_id.to_owned(), puppet.clone());
        Ok(puppet)
    }

    /// Loop-prevention layer 2: is this pubkey one of our puppets? Only answers
    /// for puppets seen this process lifetime; the messages table is the
    /// durable check.
    pub fn is_puppet_pubkey(&self, pk: &str) -> bool {
        self.lock().by_pubkey.contains_key(pk)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // The maps are consistent after every statement, so a panic elsewhere
        // cannot leave them half-updated.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> String {
        "ab".repeat(32)
    }

    #[test]
    fn matches_the_ts_derivation() {
        // Computed by the TS bridge's derivePuppet; existing puppets must not move.
        assert_eq!(
            derive_puppet(&master(), "80351110224678912").unwrap().pk,
            "ced5a876f8ba7d9b4eb1c7b91475e5de4cc6f2ddf67d02c8b96c272818b5d14c"
        );
        assert_eq!(
            derive_puppet(&master(), "1").unwrap().pk,
            "9f1c068950167a615f5e116134bc40b31ae4dc5fde750f77820bd4fb7bc7f913"
        );
    }

    #[test]
    fn is_deterministic_per_master_and_user() {
        let a = derive_puppet(&master(), "80351110224678912").unwrap();
        let b = derive_puppet(&master(), "80351110224678912").unwrap();
        assert_eq!(a.pk, b.pk);
        assert_eq!(a.keys.secret_key(), b.keys.secret_key());
    }

    #[test]
    fn differs_across_users_and_master_secrets() {
        let a = derive_puppet(&master(), "80351110224678912").unwrap();
        let b = derive_puppet(&master(), "80351110224678913").unwrap();
        let c = derive_puppet(&"cd".repeat(32), "80351110224678912").unwrap();
        assert!(a.pk != b.pk && b.pk != c.pk && a.pk != c.pk);
    }

    #[test]
    fn produces_a_valid_xonly_pubkey() {
        let pk = derive_puppet(&master(), "1").unwrap().pk;
        assert_eq!(pk.len(), 64);
        assert!(pk.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }

    #[test]
    fn rejects_non_snowflake_ids() {
        assert!(derive_puppet(&master(), "not-a-snowflake").is_err());
        assert!(derive_puppet(&master(), "").is_err());
        assert!(derive_puppet(&master(), &"1".repeat(21)).is_err());
        assert!(PuppetCache::new(master()).get("x1").is_err());
    }

    #[test]
    fn cache_caches_and_answers_pubkey_membership() {
        let cache = PuppetCache::new(master());
        let p = cache.get("80351110224678912").unwrap();
        assert_eq!(cache.get("80351110224678912").unwrap().pk, p.pk);
        assert!(cache.is_puppet_pubkey(&p.pk));
        assert!(!cache.is_puppet_pubkey(&"00".repeat(32)));
    }

    #[test]
    fn cache_evicts_oldest_past_the_cap_but_stays_correct() {
        let cache = PuppetCache::with_cap(master(), 2);
        let a = cache.get("1").unwrap();
        cache.get("2").unwrap();
        cache.get("3").unwrap(); // evicts "1"
        assert!(!cache.is_puppet_pubkey(&a.pk));
        // Re-derivation still returns the same key material.
        assert_eq!(cache.get("1").unwrap().pk, a.pk);
    }
}
