//! Concord member personas for the Discord side: kind-0 profile lookup over the
//! community relays, TTL-cached, falling back to a shortened key handle.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use nostr::prelude::*;
use serde_json::Value;

use crate::relays::RelayLike;

const TTL: Duration = Duration::from_secs(10 * 60);
const CACHE_MAX: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub avatar_url: Option<String>,
}

#[async_trait]
pub trait ProfileResolver: Send + Sync {
    /// Display name and avatar for a Concord member.
    async fn resolve(&self, pubkey_hex: &str) -> anyhow::Result<Profile>;
}

/// The persona of a member with no usable profile: a short key handle.
pub fn fallback_profile(pk: &str) -> Profile {
    Profile { name: format!("nostr:{}", &pk[..pk.len().min(8)]), avatar_url: None }
}

pub struct Kind0ProfileResolver {
    relays: Arc<dyn RelayLike>,
    cache: Mutex<HashMap<String, (Profile, Instant)>>,
}

impl Kind0ProfileResolver {
    pub fn new(relays: Arc<dyn RelayLike>) -> Self {
        Kind0ProfileResolver { relays, cache: Mutex::default() }
    }
}

/// The persona a kind-0 content names, if it names one.
pub fn profile_from_kind0(content: &str) -> Option<Profile> {
    let meta: Value = serde_json::from_str(content).ok()?;
    let pick = |k: &str| meta.get(k).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
    let name = pick("display_name").or_else(|| pick("name"))?.to_owned();
    Some(Profile { name, avatar_url: meta.get("picture").and_then(Value::as_str).map(str::to_owned) })
}

#[async_trait]
impl ProfileResolver for Kind0ProfileResolver {
    async fn resolve(&self, pubkey_hex: &str) -> anyhow::Result<Profile> {
        if let Some((hit, at)) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).get(pubkey_hex)
            && at.elapsed() < TTL
        {
            return Ok(hit.clone());
        }
        let mut value = fallback_profile(pubkey_hex);
        // A relay or JSON failure falls back, and retries after the TTL.
        if let Ok(pk) = PublicKey::from_hex(pubkey_hex) {
            let filter = Filter::new().kind(Kind::Metadata).author(pk).limit(1);
            // Settled: this is a display name on the path of a message, and
            // no relay is worth holding the message for.
            if let Ok(events) = self.relays.query_settled(vec![filter]).await
                && let Some(newest) = events.iter().max_by_key(|e| e.created_at)
                && let Some(p) = profile_from_kind0(&newest.content)
            {
                value = p;
            }
        }
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= CACHE_MAX {
            cache.clear();
        }
        cache.insert(pubkey_hex.to_owned(), (value.clone(), Instant::now()));
        Ok(value)
    }
}
