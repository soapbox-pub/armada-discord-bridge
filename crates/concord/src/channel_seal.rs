//! A Private Channel's sealed metadata (CORD-03 §2): on the ranked Roster
//! everything but what every member needs to resolve access is NIP-44 under the
//! Channel's conversation key at the sealed epoch, naming its predecessor so it
//! can't be replayed as a newer one. A port of Armada's `channelSeal.ts`.

use serde_json::{Map, Value};

use crate::derive::channel_group_key;
use crate::nip44;
use crate::rank::is_rank_key;
use crate::roles::cut_name;
use crate::{Bytes32, is_hex64};

pub const CHANNEL_TOPIC_MAX_BYTES: usize = 1024;

/// A Private Channel's sealed form as carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedChannelMeta {
    pub epoch: u64,
    /// NIP-44 v2 payload under the Channel's conversation key at `epoch`.
    pub sealed: String,
    /// The carrying edition's predecessor hash, which the seal must name as `prev`.
    pub prev_hex: Option<String>,
}

/// What a seal opens to.
#[derive(Clone, Debug)]
pub struct OpenedChannelSeal {
    pub metadata: Map<String, Value>,
    pub creator: Option<String>,
    pub public_until: Option<u64>,
}

/// A Channel's details normalized as a reader takes them, plain or opened from
/// a seal: `name` cut and required, `custom` an object, and `position`,
/// `category` and `topic` outside their form read as absent. `None` when it
/// breaks its form.
pub fn sanitize_channel_fields(mut c: Map<String, Value>) -> Option<Map<String, Value>> {
    let name = cut_name(c.get("name")?.as_str()?);
    if name.is_empty() {
        return None;
    }
    if c.get("custom").is_some_and(|v| !v.is_object()) {
        return None;
    }
    c.insert("name".into(), Value::String(name));
    if c.get("position").is_some_and(|p| !p.as_str().is_some_and(is_rank_key)) {
        c.remove("position");
    }
    if c.get("category").is_some_and(|p| !p.as_str().is_some_and(is_hex64)) {
        c.remove("category");
    }
    if c.get("topic").is_some_and(|t| !t.as_str().is_some_and(|t| !t.is_empty() && t.len() <= CHANNEL_TOPIC_MAX_BYTES)) {
        c.remove("topic");
    }
    // Legacy `voice: true` reads as the voice view (CORD-03 §2).
    if c.get("view").is_none() && c.get("voice") == Some(&Value::Bool(true)) {
        c.insert("view".into(), Value::String("voice".into()));
    }
    Some(c)
}

/// Open a sealed head with the Channel's key at its epoch, or `None` when it
/// doesn't open as a seal naming the edition's own predecessor.
pub fn open_channel_seal(sealed: &SealedChannelMeta, key: &Bytes32, channel_id: &Bytes32) -> Option<OpenedChannelSeal> {
    let conv = channel_group_key(key, channel_id, sealed.epoch).conv_key;
    let plain: Value = serde_json::from_str(&nip44::decrypt_str(&conv, &sealed.sealed).ok()?).ok()?;
    let mut o = plain.as_object()?.clone();
    let prev = o.get("prev").and_then(Value::as_str).filter(|p| is_hex64(p) && p.bytes().all(|b| !b.is_ascii_uppercase())).map(str::to_owned);
    if prev != sealed.prev_hex {
        return None;
    }
    let creator = o.get("creator").and_then(Value::as_str).filter(|c| is_hex64(c)).map(str::to_owned);
    let public_until = o.get("public_until").and_then(Value::as_u64);
    for k in ["prev", "creator", "public_until", "private", "deleted"] {
        o.remove(k);
    }
    let mut metadata = sanitize_channel_fields(o)?;
    metadata.insert("private".into(), Value::Bool(true));
    Some(OpenedChannelSeal { metadata, creator, public_until })
}

/// Seal a Private Channel's details under its key at `epoch`, naming the
/// predecessor (CORD-03 §2). Returns the edition content.
pub fn seal_channel_metadata(
    metadata: &Map<String, Value>,
    key: &Bytes32,
    channel_id: &Bytes32,
    epoch: u64,
    prev_hex: Option<&str>,
    creator: Option<&str>,
) -> Result<String, nip44::Nip44Error> {
    let mut plain: Map<String, Value> = metadata.iter().filter(|(k, _)| !matches!(k.as_str(), "private" | "deleted")).map(|(k, v)| (k.clone(), v.clone())).collect();
    if let Some(c) = creator {
        plain.insert("creator".into(), Value::String(c.to_owned()));
    }
    plain.insert("prev".into(), prev_hex.map_or(Value::Null, |p| Value::String(p.to_owned())));
    let conv = channel_group_key(key, channel_id, epoch).conv_key;
    let sealed = nip44::encrypt_str(&conv, &Value::Object(plain).to_string())?;
    Ok(serde_json::json!({ "private": true, "epoch": epoch.to_string(), "sealed": sealed }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seal_opens_only_with_its_predecessor() {
        let (key, chan) = ([3u8; 32], [4u8; 32]);
        let mut meta = Map::new();
        meta.insert("name".into(), Value::String("secret-plans".into()));
        let prev = "ab".repeat(32);
        let content = seal_channel_metadata(&meta, &key, &chan, 1, Some(&prev), Some(&"cd".repeat(32))).unwrap();
        let v: Value = serde_json::from_str(&content).unwrap();
        let sealed = SealedChannelMeta { epoch: 1, sealed: v["sealed"].as_str().unwrap().into(), prev_hex: Some(prev) };
        let opened = open_channel_seal(&sealed, &key, &chan).unwrap();
        assert_eq!(opened.metadata["name"], "secret-plans");
        assert_eq!(opened.creator.as_deref(), Some("cd".repeat(32).as_str()));
        let replayed = SealedChannelMeta { prev_hex: None, ..sealed.clone() };
        assert!(open_channel_seal(&replayed, &key, &chan).is_none());
        assert!(open_channel_seal(&sealed, &[9; 32], &chan).is_none());
    }
}
