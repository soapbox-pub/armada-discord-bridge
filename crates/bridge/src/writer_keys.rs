//! Posting in a restricted Channel as one of its writers (CORD-03 §1): the
//! live writer epoch's secret and this member's certificate, delivered on the
//! Channel's access plane at its writer scope, and the address and tags a post
//! sends with. A port of the member side of Armada's `writerKeys.ts`
//! (`usableWriter`, `writerNeeds`, `adoptWriterDeliveries`).
//!
//! A Channel is restricted while `@everyone` can't post there, which is every
//! Channel of a Community that requires approval to post. A post at its read
//! address is held from every reader; only one signed by the live writer key
//! and carrying a certificate from the epoch's certifier stands. So a member
//! the Roster lets post still can't, until a writer delivery reaches them.
//!
//! Not ported: scoped certificates (a Locked Channel's reactions and calls),
//! taking the certifier as a manager, and minting a writer epoch. A member
//! that needs those posts nowhere it couldn't before.

use std::collections::BTreeMap;

use concord::community::Membership;
use concord::control::FoldedControl;
use concord::delivery::{open_access_key, parse_delivery};
use concord::derive::{channel_writer_group_key, writer_scope};
use concord::kinds::{self, Plane};
use concord::roles::perm;
use concord::stream::{StreamKey, open_plane_wrap};
use concord::writers::{Ledger, cert_digest, certifier_of, current_writer, stopped, verify_writer_cert};
use concord::{Bytes32, hex32, to_hex};
use nostr::prelude::*;
use serde::{Deserialize, Serialize};

use crate::relays::{RelayLike, query_all_settled};

/// What this identity holds for one writer epoch, hex: its secret and this
/// member's certificate. Either may arrive before the other.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldWriter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
}

/// Held writer epochs by [`held_id`]. Kept beside the membership: losing it
/// only means taking the deliveries again.
pub type HeldWriters = BTreeMap<String, HeldWriter>;

pub fn held_id(channel_id_hex: &str, epoch: u64) -> String {
    format!("{channel_id_hex}:{epoch}")
}

/// What a writer posts with: the epoch it commits, its certificate, and the
/// key signing its wraps (the writer address).
#[derive(Clone)]
pub struct UsableWriter {
    pub epoch: u64,
    pub cert: Option<String>,
    pub address: Keys,
}

impl UsableWriter {
    /// The tags a write at the writer address carries (Armada `writerTags`).
    pub fn tags(&self) -> Vec<Vec<String>> {
        let mut tags = vec![vec!["wepoch".to_owned(), self.epoch.to_string()]];
        if let Some(cert) = &self.cert {
            tags.push(vec!["wcert".to_owned(), cert.clone()]);
        }
        tags
    }

    /// The wrap key it sends with: its own signer, the read key's encryption.
    pub fn stream(&self, read: &StreamKey) -> StreamKey {
        StreamKey { pk: self.address.public_key(), conv_key: read.conv_key, sk: Some(self.address.secret_key().clone()), restricted: false }
    }
}

/// Whether the Channel resolves Send Messages for `me`; a legacy Roster holds
/// no such bit (Armada `sendsIn`).
fn sends_in(f: &FoldedControl, channel_id_hex: &str, me: &str) -> bool {
    !f.ranked || f.channel_permissions(me, channel_id_hex) & perm::SEND_MESSAGES != 0
}

fn secret_derives(secret_hex: &str, channel: &Bytes32, epoch: u64, pk: &str) -> Option<Bytes32> {
    let secret = hex32(secret_hex)?;
    (channel_writer_group_key(&secret, channel, epoch).pubkey().to_hex() == pk).then_some(secret)
}

fn cert_verifies(community_id: &Bytes32, ledger: &Ledger, epoch: u64, me: &str, cert: &str) -> bool {
    let (Some(certifier), Some(channel), Some(writer)) = (certifier_of(ledger, epoch), hex32(&ledger.channel), hex32(me)) else { return false };
    verify_writer_cert(&certifier, &cert_digest(community_id, &channel, epoch, &writer), cert)
}

/// The live writer key `me` may post with (Armada `usableWriter`): the Roster
/// lets them send, the secret held derives to the ledger's address, a
/// certificate the epoch's certifier signed is held where it names one, and
/// they weren't stopped.
pub fn usable_writer(f: &FoldedControl, community_id: &Bytes32, channel_id_hex: &str, me: &str, held: &HeldWriters) -> Option<UsableWriter> {
    let ledger = f.writers.get(channel_id_hex)?;
    let live = current_writer(ledger)?;
    if !sends_in(f, channel_id_hex, me) {
        return None;
    }
    let channel = hex32(channel_id_hex)?;
    let h = held.get(&held_id(channel_id_hex, live.epoch))?;
    let secret = secret_derives(h.secret.as_deref()?, &channel, live.epoch, &live.pk)?;
    let cert = h.cert.clone().filter(|c| cert_verifies(community_id, ledger, live.epoch, me, c));
    if certifier_of(ledger, live.epoch).is_some() && cert.is_none() {
        return None;
    }
    if stopped(ledger, live.epoch, me, u64::MAX) {
        return None;
    }
    Some(UsableWriter { epoch: live.epoch, cert, address: channel_writer_group_key(&secret, &channel, live.epoch).keys })
}

/// What `me` still needs for a restricted Channel's live writer epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriterNeed {
    pub epoch: u64,
    pub pk: String,
    pub key: bool,
    pub cert: bool,
}

/// Armada `writerNeeds`, for a member with Send Messages: the epoch's secret
/// unless held, and its certificate where the epoch names a certifier.
pub fn writer_needs(f: &FoldedControl, community_id: &Bytes32, channel_id_hex: &str, me: &str, held: &HeldWriters) -> Option<WriterNeed> {
    let ledger = f.writers.get(channel_id_hex)?;
    let live = current_writer(ledger)?;
    if !sends_in(f, channel_id_hex, me) {
        return None;
    }
    let channel = hex32(channel_id_hex)?;
    let h = held.get(&held_id(channel_id_hex, live.epoch)).cloned().unwrap_or_default();
    let key = h.secret.as_deref().and_then(|s| secret_derives(s, &channel, live.epoch, &live.pk)).is_none();
    let cert = certifier_of(ledger, live.epoch).is_some() && !h.cert.as_deref().is_some_and(|c| cert_verifies(community_id, ledger, live.epoch, me, c));
    (key || cert).then_some(WriterNeed { epoch: live.epoch, pk: live.pk, key, cert })
}

/// Take what the writer deliveries on each owed Channel's access plane hand
/// `identity` (Armada `adoptWriterDeliveries`), returning the epochs that
/// changed. Only deliveries naming the ledger's address for the live epoch
/// count; a certificate only if the epoch's certifier signed it, whoever
/// carried it; a secret only if it derives to that address. Those checks are
/// what make a delivery safe to take from anyone who can reach the plane: a
/// key of someone else's choosing would sign at an address no reader follows.
pub async fn intake_writer_keys(relays: &dyn RelayLike, identity: &Keys, community: &Membership, f: &FoldedControl, held: &HeldWriters) -> HeldWriters {
    let me = identity.public_key().to_hex();
    let cid = community.id();
    let owed: Vec<(String, WriterNeed, StreamKey)> = f
        .writers
        .keys()
        .filter_map(|ch| {
            let need = writer_needs(f, &cid, ch, &me, held)?;
            Some((ch.clone(), need, (&community.access_plane(&hex32(ch)?)).into()))
        })
        .collect();
    let mut changed = HeldWriters::new();
    if owed.is_empty() {
        return changed;
    }
    relays.register_auth_keys(owed.iter().filter_map(|(_, _, s)| s.sk.clone().map(Keys::new)).collect());
    // Paged: an access plane carries a delivery per approval, and a Community
    // approving members by the hundred is exactly the one that needs this.
    let filter = Filter::new().kind(Kind::Custom(kinds::WRAP)).authors(owed.iter().map(|(_, _, s)| s.pk).collect::<Vec<_>>());
    let wraps = match query_all_settled(relays, filter).await {
        Ok(w) => w,
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "reading writer deliveries failed");
            return changed;
        }
    };
    for wrap in &wraps {
        let Some((ch, need, plane)) = owed.iter().find(|(_, _, s)| s.pk == wrap.pubkey) else { continue };
        let Some(d) = open_plane_wrap(wrap, plane, Plane::Rekey).ok().and_then(|o| parse_delivery(&o)) else { continue };
        let Some(channel) = hex32(ch) else { continue };
        let scope = writer_scope(&channel);
        if d.form != "access" || d.scope_hex != to_hex(&scope) || d.new_epoch != need.epoch || d.writer.as_deref() != Some(need.pk.as_str()) {
            continue;
        }
        let Some(ledger) = f.writers.get(ch) else { continue };
        let id = held_id(ch, need.epoch);
        let mut next = changed.get(&id).or_else(|| held.get(&id)).cloned().unwrap_or_default();
        let had = next.clone();
        if need.cert
            && !next.cert.as_deref().is_some_and(|c| cert_verifies(&cid, ledger, need.epoch, &me, c))
            && let Some((_, cert)) = d.certs.iter().find(|(w, c)| *w == me && cert_verifies(&cid, ledger, need.epoch, &me, c))
        {
            next.cert = Some(cert.clone());
        }
        if need.key
            && !next.secret.as_deref().is_some_and(|s| secret_derives(s, &channel, need.epoch, &need.pk).is_some())
            && let Some((_, secret)) = open_access_key(&d, identity, &scope).filter(|(_, s)| secret_derives(&to_hex(s), &channel, need.epoch, &need.pk).is_some())
        {
            next.secret = Some(to_hex(&secret));
        }
        if next != had {
            changed.insert(id, next);
        }
    }
    changed
}
