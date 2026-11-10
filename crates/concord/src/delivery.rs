//! Key deliveries (CORD-03 §5, CORD-06 §1): a kind-3303 rumor tagged
//! `["delivery", "<form>"]` handing keys to members who are owed them, on a
//! Channel's ACCESS PLANE. Never a rotation: it advances no epoch, and nothing
//! it omits removes anyone. A port of Armada's `delivery.ts`.
//!
//! On the ranked Roster this is how a Private Channel's key reaches a member an
//! overwrite lets in: no Direct Invite, no Role scoped to the Channel.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use nostr::prelude::{Keys, PublicKey};

use crate::channel_seal::{SealedChannelMeta, open_channel_seal};
use crate::control::FoldedControl;
use crate::derive::conversation_key;
use crate::kinds;
use crate::rekey::{Blob, MAX_REKEY_BLOBS_RECEIVED, decode_channel_blob, my_locator};
use crate::roles::perm;
use crate::rumor::Rumor;
use crate::stream::Opened;
use crate::{Bytes32, hex32, is_hex64, nip44, parse_tag_decimal};

/// Blobs per delivery event a writer sends (CORD-06 §1); readers accept 120.
pub const DELIVERY_BLOBS_PER_EVENT: usize = 80;

#[derive(Clone, Debug)]
pub struct ParsedDelivery {
    /// The deliverer's real pubkey (the seal's signer).
    pub deliverer: String,
    pub form: String,
    /// The Channel's id, or its writer, certifier or history scope.
    pub scope_hex: String,
    pub new_epoch: u64,
    /// Writer and certifier scopes: the pubkey the delivered secret derives to.
    pub writer: Option<String>,
    /// Writer certificates as carried, `(recipient, cert)`.
    pub certs: Vec<(String, String)>,
    pub blobs: Vec<Blob>,
}

fn unique_tag<'a>(r: &'a Rumor, name: &str) -> Result<Option<&'a str>, ()> {
    let mut found = None;
    for t in r.tags.iter().filter(|t| t.len() >= 2 && t[0] == name) {
        if found.is_some() {
            return Err(());
        }
        found = Some(t[1].as_str());
    }
    Ok(found)
}

/// Parse an opened 3303 as a delivery, or `None` when it isn't one.
pub fn parse_delivery(opened: &Opened) -> Option<ParsedDelivery> {
    let r = &opened.rumor;
    if r.kind != kinds::REKEY || opened.seal_kind() != kinds::SEAL_ENCRYPTED {
        return None;
    }
    let form = unique_tag(r, "delivery").ok()??.to_owned();
    // An empty form names no delivery (Armada `parseDelivery`).
    if form.is_empty() {
        return None;
    }
    let scope = unique_tag(r, "scope").ok()?.filter(|s| is_hex64(s))?;
    let new_epoch = unique_tag(r, "newepoch").ok()?.and_then(parse_tag_decimal)?;
    let writer = match unique_tag(r, "writer").ok()? {
        None => None,
        Some(w) if is_hex64(w) => Some(w.to_lowercase()),
        Some(_) => return None,
    };
    // A malformed certificate is no certificate; it never refuses the delivery it rides.
    let certs = r
        .tags
        .iter()
        .filter(|t| t.len() == 3 && t[0] == "cert" && is_hex64(&t[1]) && t[2].len() == 128 && t[2].bytes().all(|b| b.is_ascii_hexdigit()))
        .take(MAX_REKEY_BLOBS_RECEIVED)
        .map(|t| (t[1].to_lowercase(), t[2].to_lowercase()))
        .collect();
    let raw = crate::strict::parse_value(&r.content)?;
    let list = raw.as_array().filter(|a| a.len() <= MAX_REKEY_BLOBS_RECEIVED)?;
    let mut blobs = Vec::with_capacity(list.len());
    for b in list {
        if crate::strict::repeated_keys(b) {
            return None;
        }
        blobs.push(Blob { locator: b.get("locator")?.as_str()?.to_owned(), wrapped: b.get("wrapped")?.as_str()?.to_owned() });
    }
    Some(ParsedDelivery { deliverer: r.pubkey.clone(), form, scope_hex: scope.to_lowercase(), new_epoch, writer, certs, blobs })
}

/// Whether a reader adopts a Channel key `deliverer` handed over (CORD-03 §5):
/// the reader's fold entitles them, and the deliverer holds the Channel
/// (entitled, Manage Channels, or the owner) and isn't banned.
pub fn delivery_trusted(folded: &FoldedControl, channel_id_hex: &str, me: &str, deliverer: &str) -> bool {
    if folded.banned.contains(deliverer) {
        return false;
    }
    let view = |who: &str| folded.roster.channel_permissions(&folded.owner, who, channel_id_hex, true) & perm::VIEW_CHANNEL != 0;
    if !view(me) {
        return false;
    }
    deliverer == folded.owner || view(deliverer) || folded.roster.has(deliverer, perm::MANAGE_CHANNELS)
}

/// Whether an access delivery of a Channel's key at `epoch` is worth opening:
/// the epoch the sealed head names or the one after, from a trusted deliverer.
/// Nothing authenticates a key past the seal, so only the owner or a manager,
/// who could rotate to a key of their own, is taken at their word there.
pub fn access_delivery_admits(folded: &FoldedControl, sealed: Option<&SealedChannelMeta>, channel_id_hex: &str, me: &str, deliverer: &str, epoch: u64) -> bool {
    let walk = sealed.map_or(0, |s| s.epoch);
    if epoch < walk || epoch > walk + 1 {
        return false;
    }
    if !delivery_trusted(folded, channel_id_hex, me, deliverer) {
        return false;
    }
    !(sealed.is_some_and(|s| epoch > s.epoch) && !folded.roster.is_authorized(deliverer, &folded.owner, perm::MANAGE_CHANNELS))
}

/// Whether a delivered key is refuted: at the sealed head's epoch it must open
/// the seal, which is what authenticates it.
pub fn access_key_refuted(sealed: Option<&SealedChannelMeta>, channel_id: &Bytes32, epoch: u64, key: &Bytes32) -> bool {
    sealed.is_some_and(|s| s.epoch == epoch && open_channel_seal(s, key, channel_id).is_none())
}

/// Open my blob of an access delivery of a Channel's key: `(epoch, key)`.
pub fn open_access_key(d: &ParsedDelivery, me: &Keys, channel_id: &Bytes32) -> Option<(u64, Bytes32)> {
    let locator = my_locator(&d.deliverer, &me.public_key().to_hex(), &d.scope_hex, d.new_epoch)?;
    let deliverer = PublicKey::from_hex(&d.deliverer).ok()?;
    d.blobs.iter().filter(|b| b.locator.eq_ignore_ascii_case(&locator)).find_map(|b| {
        let plain = crate::rekey::open_blob(b, me.secret_key(), &deliverer).ok()?;
        Some((d.new_epoch, decode_channel_blob(&plain, channel_id, d.new_epoch).ok()?))
    })
}

/// At most this many blobs in an event that hands its recipients writer certificates.
pub const MAX_CERTIFIED_BLOBS_PER_EVENT: usize = 48;

/// What a writer-epoch delivery adds to a plain key delivery (CORD-03 §1).
#[derive(Clone, Debug, Default)]
pub struct WriterDelivery {
    /// The pubkey the delivered secret derives to: the writer address, or the certifier.
    pub writer: Option<String>,
    /// A writer certificate per recipient, `(recipient, cert)`, riding the event carrying its blob.
    pub certs: Vec<(String, String)>,
    /// Each event is a part of the epoch's minting delivery.
    pub mint: bool,
}

/// A key delivery's rumors: the key of `scope`'s `epoch`, one blob per
/// recipient, at most [`DELIVERY_BLOBS_PER_EVENT`] an event.
pub fn build_access_deliveries(deliverer: &Keys, scope: &Bytes32, epoch: u64, key: &Bytes32, recipients: &[String], at_secs: u64) -> Result<Vec<Rumor>, nip44::Nip44Error> {
    build_writer_deliveries(deliverer, scope, epoch, key, recipients, at_secs, &WriterDelivery::default())
}

/// [`build_access_deliveries`] for a writer epoch's secret or certifier
/// (Armada `buildAccessDeliveries` with `writer`, `certs`, `mint`).
pub fn build_writer_deliveries(
    deliverer: &Keys,
    scope: &Bytes32,
    epoch: u64,
    key: &Bytes32,
    recipients: &[String],
    at_secs: u64,
    w: &WriterDelivery,
) -> Result<Vec<Rumor>, nip44::Nip44Error> {
    let mut plain = Vec::with_capacity(72);
    plain.extend_from_slice(scope);
    plain.extend_from_slice(&epoch.to_be_bytes());
    plain.extend_from_slice(key);
    let plain = STANDARD.encode(plain);
    let me = deliverer.public_key().to_hex();
    let scope_hex = crate::to_hex(scope);
    let mut blobs = Vec::new();
    let mut who: Vec<&String> = Vec::new();
    for r in recipients {
        let Some(pk) = hex32(r).and_then(|b| PublicKey::from_slice(&b).ok()) else { continue };
        let conv = conversation_key(deliverer.secret_key(), &pk);
        let locator = my_locator(&me, r, &scope_hex, epoch).expect("validated hex");
        blobs.push(serde_json::json!({ "locator": locator, "wrapped": nip44::encrypt_str(&conv, &plain)? }));
        who.push(r);
    }
    let per_event = if w.certs.is_empty() { DELIVERY_BLOBS_PER_EVENT } else { MAX_CERTIFIED_BLOBS_PER_EVENT };
    let parts = blobs.len().div_ceil(per_event).max(1);
    Ok((0..parts)
        .map(|i| {
            let range = (i * per_event).min(blobs.len())..((i + 1) * per_event).min(blobs.len());
            let mut tags = vec![vec!["scope".into(), scope_hex.clone()], vec!["newepoch".into(), epoch.to_string()], vec!["delivery".into(), "access".into()]];
            if let Some(writer) = &w.writer {
                tags.push(vec!["writer".into(), writer.clone()]);
            }
            for r in &who[range.clone()] {
                if let Some((_, cert)) = w.certs.iter().find(|(recipient, _)| recipient == *r) {
                    tags.push(vec!["cert".into(), (*r).clone(), cert.clone()]);
                }
            }
            if w.mint {
                tags.push(vec!["mint".into(), (i + 1).to_string(), parts.to_string()]);
            }
            Rumor::new(kinds::REKEY, serde_json::Value::Array(blobs[range].to_vec()).to_string(), tags, &me, None, Some(at_secs))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kinds::Plane;
    use crate::stream::{StreamKey, open_plane_wrap, seal_and_wrap};

    #[test]
    fn a_built_delivery_opens_for_its_recipient_only() {
        let (owner, bob, eve) = (Keys::generate(), Keys::generate(), Keys::generate());
        let (chan, key) = ([4u8; 32], [9u8; 32]);
        let rumors = build_access_deliveries(&owner, &chan, 2, &key, &[bob.public_key().to_hex()], 1_700_000_000).unwrap();
        assert_eq!(rumors.len(), 1);
        let plane: StreamKey = (&crate::derive::channel_access_group_key(&[1; 32], &chan, 0)).into();
        let wrap = seal_and_wrap(&rumors[0], Plane::Rekey, &plane, &owner, Default::default()).unwrap();
        let d = parse_delivery(&open_plane_wrap(&wrap, &plane, Plane::Rekey).unwrap()).unwrap();
        assert_eq!(open_access_key(&d, &bob, &chan), Some((2, key)));
        assert_eq!(open_access_key(&d, &eve, &chan), None);
        assert_eq!(open_access_key(&d, &bob, &[5; 32]), None, "a blob for another channel's scope is refused");
    }
}
