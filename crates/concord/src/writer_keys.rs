//! Writing in a restricted Channel as one of its writers (CORD-03 §1): the live
//! writer epoch's secret and this member's certificate, whole or scoped,
//! delivered on the Channel's access plane at its writer scope, and the address
//! and tags a write sends with. The member side of Armada's `writerKeys.ts`
//! (`usableWriter`, `writerNeeds`, `adoptWriterDeliveries`); reading the access
//! plane is the caller's.
//!
//! A Channel is restricted while `@everyone` can't post there, which is every
//! Channel of a Community that requires approval to post. A post at its read
//! address is held from every reader; only one signed by the live writer key
//! and carrying a certificate from the epoch's certifier stands. In a Locked
//! Channel the same goes for reactions and deletions, and a member who may
//! react but not post holds a certificate scoped to the bits they have.
//!
//! Not here: taking the certifier as a manager, and minting a writer epoch.

use std::collections::BTreeMap;

use nostr::prelude::{Event, Keys};
use serde::{Deserialize, Serialize};

use crate::community::Membership;
use crate::control::FoldedControl;
use crate::delivery::{ParsedDelivery, open_access_key, parse_delivery};
use crate::derive::{channel_writer_group_key, writer_scope};
use crate::guestbook::{GuestbookHistory, kicked_into};
use crate::kinds::Plane;
use crate::stream::{StreamKey, open_plane_wrap};
use crate::writers::{
    Ledger, Rights, cert_digest, certifier_of, current_writer, ledger_locked, rights_of, scope_covers, scoped_cert_digest, stopped, verify_writer_cert, writer_windows,
};
use crate::{Bytes32, hex32, to_hex};

/// What an identity holds for one writer epoch, hex: its secret, that
/// member's whole certificate, or a scoped one and the bits it covers in
/// decimal. Any may arrive before the others.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldWriter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rights: Option<String>,
}

/// Held writer epochs by [`held_id`].
pub type HeldWriters = BTreeMap<String, HeldWriter>;

pub fn held_id(channel_id_hex: &str, epoch: u64) -> String {
    format!("{channel_id_hex}:{epoch}")
}

/// What a writer writes with: the epoch it commits, its certificate (whole, or
/// scoped and its bits), and the key signing its wraps (the writer address).
#[derive(Clone)]
pub struct UsableWriter {
    pub epoch: u64,
    pub cert: Option<String>,
    pub scoped: Option<(String, u64)>,
    pub address: Keys,
}

impl UsableWriter {
    /// The tags a write at the writer address carries (Armada `writerTags`):
    /// its whole certificate, else a scoped one.
    pub fn tags(&self) -> Vec<Vec<String>> {
        let mut tags = vec![vec!["wepoch".to_owned(), self.epoch.to_string()]];
        if let Some(cert) = &self.cert {
            tags.push(vec!["wcert".to_owned(), cert.clone()]);
        } else if let Some((cert, rights)) = &self.scoped {
            tags.push(vec!["rcert".to_owned(), cert.clone(), rights.to_string()]);
        }
        tags
    }

    /// The wrap key it sends with: its own signer, the read key's encryption.
    pub fn stream(&self, read: &StreamKey) -> StreamKey {
        StreamKey { pk: self.address.public_key(), conv_key: read.conv_key, sk: Some(self.address.secret_key().clone()), restricted: false }
    }
}

fn secret_derives(secret_hex: &str, channel: &Bytes32, epoch: u64, pk: &str) -> Option<Bytes32> {
    let secret = hex32(secret_hex)?;
    (channel_writer_group_key(&secret, channel, epoch).pubkey().to_hex() == pk).then_some(secret)
}

fn cert_verifies(community_id: &Bytes32, ledger: &Ledger, epoch: u64, me: &str, cert: &str) -> bool {
    let (Some(certifier), Some(channel), Some(writer)) = (certifier_of(ledger, epoch), hex32(&ledger.channel), hex32(me)) else { return false };
    verify_writer_cert(&certifier, &cert_digest(community_id, &channel, epoch, &writer), cert)
}

fn scoped_verifies(community_id: &Bytes32, ledger: &Ledger, epoch: u64, me: &str, cert: &str, rights: u64) -> bool {
    let (Some(certifier), Some(channel), Some(writer)) = (certifier_of(ledger, epoch), hex32(&ledger.channel), hex32(me)) else { return false };
    verify_writer_cert(&certifier, &scoped_cert_digest(community_id, &channel, epoch, &writer, rights), cert)
}

/// The scoped certificate held for `epoch`, when the epoch's certifier signed it.
fn held_scoped(community_id: &Bytes32, ledger: &Ledger, epoch: u64, me: &str, h: &HeldWriter) -> Option<(String, u64)> {
    let rights = crate::parse_tag_decimal(h.rights.as_deref()?)?;
    let cert = h.rcert.clone()?;
    scoped_verifies(community_id, ledger, epoch, me, &cert, rights).then_some((cert, rights))
}

fn manages(f: &FoldedControl, me: &str) -> bool {
    f.manages_channels(me)
}

/// The live writer key `me` may make a write of `kind` with (Armada
/// `usableWriter`): the Roster lets them make it, the secret held derives to
/// the ledger's address, a certificate covering it is held where the epoch
/// names a certifier, they weren't stopped, and, unless they manage, weren't
/// kicked while it held (when the Guestbook is read).
pub fn usable_writer(
    f: &FoldedControl,
    community_id: &Bytes32,
    channel_id_hex: &str,
    me: &str,
    kind: u16,
    held: &HeldWriters,
    history: Option<&GuestbookHistory>,
) -> Option<UsableWriter> {
    let ledger = f.writers.get(channel_id_hex)?;
    let live = current_writer(ledger)?;
    if f.ranked && !f.may_send_kind(me, channel_id_hex, kind) {
        return None;
    }
    let channel = hex32(channel_id_hex)?;
    let h = held.get(&held_id(channel_id_hex, live.epoch))?;
    let secret = secret_derives(h.secret.as_deref()?, &channel, live.epoch, &live.pk)?;
    let cert = h.cert.clone().filter(|c| cert_verifies(community_id, ledger, live.epoch, me, c));
    let scoped = if cert.is_none() { held_scoped(community_id, ledger, live.epoch, me, h).filter(|(_, r)| scope_covers(*r, kind)) } else { None };
    if certifier_of(ledger, live.epoch).is_some() && cert.is_none() && scoped.is_none() {
        return None;
    }
    if stopped(ledger, live.epoch, me, u64::MAX) {
        return None;
    }
    if !manages(f, me) && history.is_some_and(|h| kicked_into(h, me, live.from)) {
        return None;
    }
    Some(UsableWriter { epoch: live.epoch, cert, scoped, address: channel_writer_group_key(&secret, &channel, live.epoch).keys })
}

/// What `me` still needs for a restricted Channel's live writer epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriterNeed {
    pub epoch: u64,
    pub pk: String,
    pub key: bool,
    pub cert: bool,
}

/// Armada `writerNeeds`: the epoch's secret unless held, for a member with
/// any rights there or who manages; and a certificate covering those rights
/// where the epoch names a certifier.
pub fn writer_needs(f: &FoldedControl, community_id: &Bytes32, channel_id_hex: &str, me: &str, held: &HeldWriters) -> Option<WriterNeed> {
    let ledger = f.writers.get(channel_id_hex)?;
    let live = current_writer(ledger)?;
    let channel = hex32(channel_id_hex)?;
    let rights = if f.ranked { rights_of(f, me, channel_id_hex, ledger_locked(ledger)) } else { Some(Rights::Full) };
    let h = held.get(&held_id(channel_id_hex, live.epoch)).cloned().unwrap_or_default();
    let key = (rights.is_some() || manages(f, me)) && h.secret.as_deref().and_then(|s| secret_derives(s, &channel, live.epoch, &live.pk)).is_none();
    let whole = h.cert.as_deref().is_some_and(|c| cert_verifies(community_id, ledger, live.epoch, me, c));
    let scoped = held_scoped(community_id, ledger, live.epoch, me, &h);
    let covered = whole || rights.zip(scoped).is_some_and(|(r, (_, bits))| Rights::Scoped(bits).covers(r));
    let cert = rights.is_some() && certifier_of(ledger, live.epoch).is_some() && !covered;
    (key || cert).then_some(WriterNeed { epoch: live.epoch, pk: live.pk, key, cert })
}

/// Whether a delivery is one of a Channel's writer deliveries: an access
/// delivery at its writer scope naming the address of a window the ledger holds.
pub fn is_writer_delivery(d: &ParsedDelivery, channel_id_hex: &str, ledger: &Ledger) -> bool {
    let Some(channel) = hex32(channel_id_hex) else { return false };
    d.form == "access"
        && d.scope_hex == to_hex(&writer_scope(&channel))
        && writer_windows(ledger).iter().any(|w| w.epoch == d.new_epoch && d.writer.as_deref() == Some(w.pk.as_str()))
}

/// Open an access-plane wrap of a Channel as one of its writer deliveries.
pub fn open_writer_delivery(wrap: &Event, community: &Membership, f: &FoldedControl, channel_id_hex: &str) -> Option<ParsedDelivery> {
    let plane: StreamKey = (&community.access_plane(&hex32(channel_id_hex)?)).into();
    if wrap.pubkey != plane.pk {
        return None;
    }
    let d = parse_delivery(&open_plane_wrap(wrap, &plane, Plane::Rekey).ok()?)?;
    is_writer_delivery(&d, channel_id_hex, f.writers.get(channel_id_hex)?).then_some(d)
}

/// Take what a Channel's writer deliveries hand `identity` (Armada
/// `adoptWriterDeliveries`), returning the epochs that changed. Only deliveries
/// naming the ledger's address for the live epoch count; a certificate only if
/// the epoch's certifier signed it, whoever carried it, the widest scoped one
/// where no whole one is; a secret only if it derives to that address. Those
/// checks make a delivery safe to take from anyone who can reach the plane.
pub fn take_writer_deliveries(deliveries: &[ParsedDelivery], identity: &Keys, community_id: &Bytes32, f: &FoldedControl, channel_id_hex: &str, held: &HeldWriters) -> HeldWriters {
    let me = identity.public_key().to_hex();
    let mut changed = HeldWriters::new();
    let (Some(need), Some(ledger), Some(channel)) = (writer_needs(f, community_id, channel_id_hex, &me, held), f.writers.get(channel_id_hex), hex32(channel_id_hex)) else {
        return changed;
    };
    let scope = writer_scope(&channel);
    let id = held_id(channel_id_hex, need.epoch);
    let mut next = held.get(&id).cloned().unwrap_or_default();
    let had = next.clone();
    let named: Vec<&ParsedDelivery> = deliveries
        .iter()
        .filter(|d| d.form == "access" && d.scope_hex == to_hex(&scope) && d.new_epoch == need.epoch && d.writer.as_deref() == Some(need.pk.as_str()))
        .collect();
    if need.cert {
        let whole = named.iter().flat_map(|d| d.certs.iter()).find(|(w, c)| *w == me && cert_verifies(community_id, ledger, need.epoch, &me, c));
        if let Some((_, cert)) = whole {
            next.cert = Some(cert.clone());
        } else if let Some((_, cert, rights)) = named
            .iter()
            .flat_map(|d| d.scoped.iter())
            .filter(|(w, c, r)| *w == me && scoped_verifies(community_id, ledger, need.epoch, &me, c, *r))
            .max_by_key(|(_, _, r)| r.count_ones())
        {
            next.rcert = Some(cert.clone());
            next.rights = Some(rights.to_string());
        }
    }
    if need.key
        && let Some(secret) = named
            .iter()
            .filter_map(|d| open_access_key(d, identity, &scope))
            .map(|(_, s)| s)
            .find(|s| secret_derives(&to_hex(s), &channel, need.epoch, &need.pk).is_some())
    {
        next.secret = Some(to_hex(&secret));
    }
    if next != had {
        changed.insert(id, next);
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::FoldedChannel;
    use crate::delivery::{WriterDelivery, build_writer_deliveries};
    use crate::kinds;
    use crate::roles::{Overwrite, OverwriteTarget, perm};
    use crate::writers::{SCOPED_BITS, Spell, empty_ledger, ledger_appended_locked, sign_writer_cert};

    /// A Locked Channel where `bob` may react but not post, its writer epoch 1
    /// certified, and a delivery handing him the secret and a scoped certificate.
    #[test]
    fn a_member_who_may_only_react_takes_a_scoped_certificate_and_reacts_with_it() {
        let m = Membership::mint("t", &Keys::generate().public_key().to_hex(), vec![], 0);
        let owner = m.owner.clone();
        let chan_hex = "c1".repeat(32);
        let chan = hex32(&chan_hex).unwrap();
        let (certifier, bob, deliverer) = (Keys::generate(), Keys::generate(), Keys::generate());
        let secret = [7u8; 32];
        let address = channel_writer_group_key(&secret, &chan, 1).pubkey().to_hex();
        let mut f = FoldedControl { owner: owner.clone(), ranked: true, ..Default::default() };
        f.roster.everyone = Some(perm::VIEW_CHANNEL | perm::ADD_REACTIONS | perm::READ_MESSAGE_HISTORY);
        f.channels.insert(chan_hex.clone(), FoldedChannel { channel_id_hex: chan_hex.clone(), name: "c".into(), ..Default::default() });
        f.roster.overwrites.push(Overwrite { scope: chan_hex.clone(), target: OverwriteTarget::Everyone, allow: 0, deny: perm::SEND_MESSAGES });
        let spell = Spell::Writer { epoch: 1, pk: address.clone(), root: 0, by: owner, certifier: Some(certifier.public_key().to_hex()) };
        f.writers.insert(chan_hex.clone(), ledger_appended_locked(&empty_ledger(&chan_hex), 1_000, spell).unwrap());

        let me = bob.public_key().to_hex();
        let cid = m.id();
        let need = writer_needs(&f, &cid, &chan_hex, &me, &HeldWriters::new()).expect("owed a key and a certificate");
        assert!(need.key && need.cert);
        let rcert = sign_writer_cert(certifier.secret_key(), &scoped_cert_digest(&cid, &chan, 1, &bob.public_key().to_bytes(), SCOPED_BITS));
        let w = WriterDelivery { writer: Some(address), scoped: vec![(me.clone(), rcert, SCOPED_BITS)], ..Default::default() };
        let rumors = build_writer_deliveries(&deliverer, &writer_scope(&chan), 1, &secret, std::slice::from_ref(&me), 1_000, &w).unwrap();
        let plane: StreamKey = (&m.access_plane(&chan)).into();
        let wrap = crate::stream::seal_and_wrap(&rumors[0], Plane::Rekey, &plane, &deliverer, Default::default()).unwrap();
        let d = open_writer_delivery(&wrap, &m, &f, &chan_hex).expect("a writer delivery");
        let held = take_writer_deliveries(&[d], &bob, &cid, &f, &chan_hex, &HeldWriters::new());
        assert!(writer_needs(&f, &cid, &chan_hex, &me, &held).is_none(), "nothing more owed");
        let w = usable_writer(&f, &cid, &chan_hex, &me, kinds::REACTION, &held, None).expect("reacts as a writer");
        assert_eq!(w.tags()[1][0], "rcert");
        assert!(usable_writer(&f, &cid, &chan_hex, &me, kinds::MESSAGE, &held, None).is_none(), "but never posts");
    }
}
