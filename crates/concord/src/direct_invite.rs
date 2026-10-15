//! Direct Invites — CORD-05 §6: a standard NIP-59 giftwrap (kind-13 seal,
//! recipient-`p`-tagged 1059 with `["k","3313"]`) whose rumor carries the bundle.

use nostr::event::FinalizeEvent;
use nostr::prelude::{Event, Keys, Kind, PublicKey, Tag, Timestamp, UnsignedEvent};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::derive::conversation_key;
use crate::invite::InviteBundle;
use crate::{kinds, nip44};

/// NIP-59 backdates seals and wraps by up to two days, so their timestamps do
/// not correlate sender and recipient activity.
const MAX_BACKDATE_SECS: u64 = 2 * 24 * 60 * 60;

/// The kind-3313 rumor as Armada writes it: no `id`, and fields in this order.
/// Armada never hashes it, so requiring an `id` would refuse every real invite.
#[derive(Debug, Serialize, Deserialize)]
struct DirectInviteRumor {
    kind: u16,
    content: String,
    tags: Vec<Vec<String>>,
    created_at: u64,
    pubkey: String,
}

/// An unwrapped Direct Invite: the bundle and its verified inviter.
#[derive(Clone, Debug)]
pub struct DirectInvite {
    pub inviter: String,
    pub bundle: InviteBundle,
    pub created_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum DirectInviteError {
    #[error("bundle does not serialize: {0}")]
    Bundle(String),
    #[error(transparent)]
    Encrypt(#[from] nip44::Nip44Error),
    #[error("signing failed: {0}")]
    Sign(String),
}

fn tweaked_past() -> Timestamp {
    Timestamp::from(Timestamp::now().as_secs() - rand::thread_rng().gen_range(0..MAX_BACKDATE_SECS))
}

/// Seal and giftwrap `bundle` to `recipient` (CORD-05 §6). The seal carries the
/// inviter's real identity, which is what proves who invited; the wrap is under
/// a single-use key and carries the only identifying outer tags a Concord event
/// may: the recipient `p` and the indexing `k`.
pub fn send(bundle: &InviteBundle, inviter: &Keys, recipient: &PublicKey, expires_at_ms: Option<u64>) -> Result<Event, DirectInviteError> {
    let rumor = DirectInviteRumor {
        kind: kinds::DIRECT_INVITE,
        content: serde_json::to_string(bundle).map_err(|e| DirectInviteError::Bundle(e.to_string()))?,
        tags: vec![],
        created_at: Timestamp::now().as_secs(),
        pubkey: inviter.public_key().to_hex(),
    };
    let rumor_json = serde_json::to_string(&rumor).expect("rumors always serialize");
    let seal_content = nip44::encrypt_str(&conversation_key(inviter.secret_key(), recipient), &rumor_json)?;
    let seal = UnsignedEvent::new(inviter.public_key(), tweaked_past(), Kind::Custom(kinds::NIP59_SEAL), Vec::<Tag>::new(), seal_content)
        .finalize(inviter)
        .map_err(|e| DirectInviteError::Sign(e.to_string()))?;

    let ephemeral = Keys::generate();
    let mut tags = vec![
        Tag::parse(["p".to_string(), recipient.to_hex()]).expect("valid p tag"),
        Tag::parse(["k".to_string(), kinds::DIRECT_INVITE.to_string()]).expect("valid k tag"),
    ];
    if let Some(ms) = expires_at_ms {
        tags.push(Tag::parse(["expiration".to_string(), (ms / 1000).to_string()]).expect("valid tag"));
    }
    let content = nip44::encrypt_str(&conversation_key(ephemeral.secret_key(), recipient), &seal.as_json())?;
    UnsignedEvent::new(ephemeral.public_key(), tweaked_past(), Kind::Custom(kinds::WRAP), tags, content)
        .finalize(&ephemeral)
        .map_err(|e| DirectInviteError::Sign(e.to_string()))
}

/// Unwrap a giftwrap addressed to `me`; `None` if it is malformed, not an
/// invite, or its rumor claims an author other than the seal's signer.
///
/// The returned inviter is PROVEN, not AUTHORIZED: anyone can seal a
/// well-formed bundle to a public npub, so callers must check the inviter
/// against the roster before adopting any key it carries.
pub fn unwrap(wrap: &Event, me: &Keys) -> Option<DirectInvite> {
    if wrap.kind != Kind::Custom(kinds::WRAP) {
        return None;
    }
    let seal_json = nip44::decrypt_str(&conversation_key(me.secret_key(), &wrap.pubkey), &wrap.content).ok()?;
    let seal = Event::from_json(&seal_json).ok()?;
    if seal.kind != Kind::Custom(kinds::NIP59_SEAL) || seal.verify().is_err() {
        return None;
    }
    let rumor_json = nip44::decrypt_str(&conversation_key(me.secret_key(), &seal.pubkey), &seal.content).ok()?;
    let rumor: DirectInviteRumor = serde_json::from_str(&rumor_json).ok()?;
    if rumor.pubkey != seal.pubkey.to_hex() || rumor.kind != kinds::DIRECT_INVITE {
        return None;
    }
    let bundle: InviteBundle = serde_json::from_str(&rumor.content).ok()?;
    Some(DirectInvite { inviter: rumor.pubkey, bundle: bundle.validate().ok()?, created_at: rumor.created_at })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> InviteBundle {
        let owner = Keys::generate().public_key().to_hex();
        let salt = [7u8; 32];
        let cid = crate::derive::community_id_of(&crate::hex32(&owner).unwrap(), &salt);
        serde_json::from_value(serde_json::json!({
            "community_id": crate::to_hex(&cid), "owner": owner, "owner_salt": crate::to_hex(&salt),
            "community_root": "11".repeat(32), "root_epoch": 0,
            "channels": [{ "id": "22".repeat(32), "key": "33".repeat(32), "epoch": 0, "name": "mods" }],
            "relays": [], "name": "x",
        }))
        .unwrap()
    }

    #[test]
    fn round_trips_to_the_recipient_only() {
        let (inviter, recipient, stranger) = (Keys::generate(), Keys::generate(), Keys::generate());
        let wrap = send(&bundle(), &inviter, &recipient.public_key(), None).unwrap();
        assert_eq!(wrap.tags.iter().map(|t| t.as_slice().to_vec()).collect::<Vec<_>>()[1], vec!["k", "3313"]);
        let opened = unwrap(&wrap, &recipient).expect("recipient opens it");
        assert_eq!(opened.inviter, inviter.public_key().to_hex());
        assert_eq!(opened.bundle.channels[0].name, "mods");
        assert!(unwrap(&wrap, &stranger).is_none());
    }
}
