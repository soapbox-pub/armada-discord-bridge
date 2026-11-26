//! What a member holds for one Community: every root epoch (current plus
//! retained priors, for history), the Control Plane pair, and private Channel
//! keys. Serializable, so a bridge can persist it. Mirrors Armada's `Community`
//! and its `channelsView`, plus the receiving half of CORD-06.

use serde::{Deserialize, Serialize};

use crate::control::{FoldedControl, cap_relays};
use crate::derive::{
    GroupKey, base_rekey_group_key, channel_group_key, channel_rekey_group_key, community_id_of, control_group_key,
    control_signer_group_key, guestbook_group_key,
};
use crate::invite::{BundleChannel, InviteBundle};
use crate::rekey::{self, Continuity, Rotation};
use crate::roles::perm;
use crate::stream::StreamKey;
use crate::{Bytes32, hex32, random32, to_hex};

/// Whether a non-owner base rotation carries a blob for everyone it must
/// (Armada `rotationCoversOwed`): the owner, and every unbanned Grant holder
/// the Rotator can't act on with BAN. One that doesn't is neither adopted nor
/// read as a removal by anyone (CORD-06 §2), or a Moderator could refound the
/// Community onto a root of their own.
fn covers_owed(set: &Rotation, folded: &FoldedControl) -> bool {
    if set.rotator == folded.owner {
        return true;
    }
    let mut owed = vec![folded.owner.clone()];
    for g in &folded.roster.grants {
        let member = g.member.to_lowercase();
        if member != set.rotator && !folded.banned.contains(&member) && !folded.roster.can_act_on_member(&set.rotator, &folded.owner, &member, perm::BAN) {
            owed.push(member);
        }
    }
    owed.iter().all(|pk| rekey::my_locator(&set.rotator, pk, &set.scope_hex, set.new_epoch).is_some_and(|l| set.find_blob(&l).is_some()))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeldRoot {
    pub epoch: u64,
    pub key: String,
    /// The epoch's Control Plane address; absent on a legacy pre-split epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_pk: Option<String>,
    /// Unix seconds of the superseding rotation: a hard read cutoff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<u64>,
    /// Whose Refounding minted this epoch (its Guestbook snapshot authority).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refounder: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PriorKey {
    pub key: String,
    pub epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateChannelKey {
    pub id: String,
    pub key: String,
    pub epoch: u64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub priors: Vec<PriorKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Membership {
    pub community_id: String,
    pub owner: String,
    pub owner_salt: String,
    pub root_epoch: u64,
    pub root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_pk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_root: Option<String>,
    /// Newest first; includes the current root.
    pub held_roots: Vec<HeldRoot>,
    #[serde(default)]
    pub private_channels: Vec<PrivateChannelKey>,
    /// channel id → the epoch whose rotation cut us out (stale bundles can't undo it).
    #[serde(default)]
    pub channel_cuts: Vec<(String, u64)>,
    pub relays: Vec<String>,
    pub name: String,
    /// When we joined (ms). A rotation predating it is history, not a removal.
    pub joined_at_ms: u64,
    /// A complete rotation excluded us at this epoch: read-only from here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excluded_at: Option<u64>,
}

/// One readable stream of a Channel.
#[derive(Clone, Debug)]
pub struct ChannelStream {
    pub epoch: u64,
    pub key: GroupKey,
    pub retired_at: Option<u64>,
}

/// One writer address of a restricted Channel (CORD-03 §1). Its wraps are
/// signed by the writer key but encrypted under the Channel's READ key, so a
/// reader opens them with each of the Channel's streams' conversation keys.
#[derive(Clone, Debug)]
pub struct WriterStream {
    pub epoch: u64,
    pub pk: nostr::prelude::PublicKey,
}

/// A Channel as the member can read it.
#[derive(Clone, Debug)]
pub struct ChannelView {
    pub id_hex: String,
    pub name: String,
    pub private: bool,
    pub forum: bool,
    pub category: Option<String>,
    pub position: Option<f64>,
    /// The rank-key position, ordering Channels on the ranked Roster (CORD-03 §2).
    pub rank: Option<String>,
    /// The Category entity it files under (CORD-03 §4).
    pub category_id: Option<String>,
    /// `"chat"`, `"forum"`, `"voice"`, or unknown (read as chat) (CORD-03 §2).
    pub view: Option<String>,
    /// Newest first; `streams[0]` is where writes go, unless a Writers ledger restricts it.
    pub streams: Vec<ChannelStream>,
    /// Every writer address the Channel's ledger names, live and retired.
    pub writers: Vec<WriterStream>,
    /// When a converted Channel went private, unix ms, from its opened seal
    /// (CORD-03 §2). Its public era reads at the root streams, cut there.
    pub public_until: Option<u64>,
}

impl ChannelView {
    pub fn current(&self) -> &ChannelStream {
        &self.streams[0]
    }
}

/// What a rekey sweep decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RekeyOutcome {
    /// Adopted a new root at this epoch.
    AdoptedRoot(u64),
    /// A complete post-join rotation by an outranking rotator carried no blob for us.
    Excluded(u64),
    Nothing,
}

impl Membership {
    /// The held key of a private Channel at `epoch`, current or prior.
    pub fn channel_key_at(&self, channel_id_hex: &str, epoch: u64) -> Option<Bytes32> {
        let h = self.private_channels.iter().find(|c| c.id.eq_ignore_ascii_case(channel_id_hex))?;
        let key = if h.epoch == epoch { Some(h.key.as_str()) } else { h.priors.iter().find(|p| p.epoch == epoch).map(|p| p.key.as_str()) };
        hex32(key?)
    }

    /// When a converted private Channel went private (unix ms), from its seal
    /// opened with the key held here (CORD-03 §2); `None` for any other.
    pub fn public_until(&self, folded: &FoldedControl, channel_id_hex: &str) -> Option<u64> {
        let ch = folded.channels.get(channel_id_hex).filter(|c| c.private && !c.deleted)?;
        let sealed = ch.sealed.as_ref()?;
        let key = self.channel_key_at(channel_id_hex, sealed.epoch)?;
        crate::channel_seal::open_channel_seal(sealed, &key, &hex32(channel_id_hex)?)?.public_until
    }

    /// Each sealed Private Channel's `creator`, opened with the keys held here
    /// (CORD-03 §2). Armada fills `roster.creators` from these on the ranked
    /// Roster, and the creator, holding Manage Channels, may view the channel
    /// with no overwrite naming them (CORD-04 §8); a reader without them
    /// resolves that member's permissions there differently from Armada.
    pub fn open_creators(&self, folded: &FoldedControl) -> std::collections::HashMap<String, String> {
        let mut out = std::collections::HashMap::new();
        if !folded.ranked {
            return out;
        }
        for ch in folded.channels.values().filter(|c| c.private && !c.deleted) {
            let Some(sealed) = &ch.sealed else { continue };
            let (Some(key), Some(id)) = (self.channel_key_at(&ch.channel_id_hex, sealed.epoch), hex32(&ch.channel_id_hex)) else { continue };
            if let Some(creator) = crate::channel_seal::open_channel_seal(sealed, &key, &id).and_then(|o| o.creator) {
                out.insert(ch.channel_id_hex.clone(), creator);
            }
        }
        out
    }
}

fn b32(s: &str) -> Bytes32 {
    hex32(s).expect("membership holds well-formed hex")
}

impl Membership {
    /// A community at its genesis epoch, as its owner (or a custodian of the
    /// owner's secrets) holds it. `control_root` is `None` for a legacy
    /// community whose Control Plane predates the write split; its control_pk
    /// is derived, never stored separately, so the two cannot disagree.
    pub fn genesis(owner: &str, owner_salt: &Bytes32, root: &Bytes32, control_root: Option<&Bytes32>, relays: Vec<String>, name: String, now_ms: u64) -> Membership {
        let owner = owner.to_lowercase();
        let id = community_id_of(&b32(&owner), owner_salt);
        let control_pk = control_root.map(|cr| control_signer_group_key(cr, &id, 0).pk_hex());
        Membership {
            community_id: to_hex(&id),
            owner,
            owner_salt: to_hex(owner_salt),
            root_epoch: 0,
            root: to_hex(root),
            control_pk: control_pk.clone(),
            control_root: control_root.map(|c| to_hex(c)),
            held_roots: vec![HeldRoot { epoch: 0, key: to_hex(root), control_pk, retired_at: None, refounder: None }],
            private_channels: vec![],
            channel_cuts: vec![],
            relays: cap_relays(relays),
            name,
            joined_at_ms: now_ms,
            excluded_at: None,
        }
    }

    /// Mint a brand-new community (CORD-02 §1): a random `owner_salt` commits the
    /// owner into the self-certifying id, and the access key and the staff write
    /// key are independent random secrets, so access can rotate while identity
    /// stays fixed. The caller publishes the genesis editions.
    pub fn mint(name: &str, owner: &str, relays: Vec<String>, now_ms: u64) -> Membership {
        Membership::genesis(owner, &random32(), &random32(), Some(&random32()), relays, name.to_owned(), now_ms)
    }

    /// The current Control Plane stream with its signing secret, or `None` when
    /// the epoch is split and this member does not hold the staff key: a wrap
    /// published without it fails the plane's signature check everywhere.
    pub fn control_write_stream(&self) -> Option<StreamKey> {
        let stream = self.current_control_stream();
        stream.sk.is_some().then_some(stream)
    }

    pub fn from_bundle(bundle: &InviteBundle, now_ms: u64) -> Membership {
        Membership {
            community_id: bundle.community_id.to_lowercase(),
            owner: bundle.owner.to_lowercase(),
            owner_salt: bundle.owner_salt.to_lowercase(),
            root_epoch: bundle.root_epoch,
            root: bundle.community_root.to_lowercase(),
            control_pk: bundle.control_pk.clone(),
            control_root: None,
            held_roots: vec![HeldRoot {
                epoch: bundle.root_epoch,
                key: bundle.community_root.to_lowercase(),
                control_pk: bundle.control_pk.clone(),
                retired_at: None,
                refounder: None,
            }],
            private_channels: bundle
                .channels
                .iter()
                .filter(|c| hex32(&c.id).is_some() && hex32(&c.key).is_some())
                .map(|c| PrivateChannelKey { id: c.id.to_lowercase(), key: c.key.to_lowercase(), epoch: c.epoch, name: c.name.clone(), priors: vec![] })
                .collect(),
            channel_cuts: vec![],
            relays: bundle.relays.clone(),
            name: bundle.name.clone(),
            joined_at_ms: now_ms,
            excluded_at: None,
        }
    }

    pub fn id(&self) -> Bytes32 {
        b32(&self.community_id)
    }

    pub fn root_key(&self) -> Bytes32 {
        b32(&self.root)
    }

    fn control_stream_for(&self, root: &HeldRoot) -> StreamKey {
        let read = control_group_key(&b32(&root.key), &self.id(), root.epoch);
        let Some(pk) = root.control_pk.as_deref().and_then(|pk| nostr::prelude::PublicKey::from_hex(pk).ok()) else {
            return (&read).into();
        };
        let signer = (root.epoch == self.root_epoch)
            .then(|| self.control_root.as_deref().and_then(hex32))
            .flatten()
            .map(|cr| control_signer_group_key(&cr, &self.id(), root.epoch))
            .filter(|g| g.pubkey() == pk);
        StreamKey { pk, conv_key: read.conv_key, sk: signer.map(|g| g.keys.secret_key().clone()), restricted: true }
    }

    /// Control Plane streams across every held epoch, newest first.
    pub fn control_streams(&self) -> Vec<StreamKey> {
        self.held_roots.iter().map(|r| self.control_stream_for(r)).collect()
    }

    pub fn current_control_stream(&self) -> StreamKey {
        let current = self.held_roots.iter().find(|r| r.epoch == self.root_epoch).cloned().unwrap_or(HeldRoot {
            epoch: self.root_epoch,
            key: self.root.clone(),
            control_pk: self.control_pk.clone(),
            retired_at: None,
            refounder: None,
        });
        self.control_stream_for(&current)
    }

    pub fn guestbook_streams(&self) -> Vec<StreamKey> {
        self.held_roots.iter().map(|r| guestbook_group_key(&b32(&r.key), &self.id(), r.epoch).into()).collect()
    }

    pub fn current_guestbook_stream(&self) -> StreamKey {
        guestbook_group_key(&self.root_key(), &self.id(), self.root_epoch).into()
    }

    /// Each held epoch's Guestbook address and the npub whose Refounding
    /// minted it, where known; and the addresses of epochs past 0 whose minter
    /// this member never saw, as a joiner holds them (CORD-02 §5).
    pub fn guestbook_authorities(&self) -> (std::collections::HashMap<String, String>, std::collections::HashSet<String>) {
        let mut known = std::collections::HashMap::new();
        let mut unrecorded = std::collections::HashSet::new();
        for r in self.held_roots.iter().filter(|r| r.epoch > 0) {
            let pk = guestbook_group_key(&b32(&r.key), &self.id(), r.epoch).pk_hex();
            match &r.refounder {
                Some(by) => {
                    known.insert(pk, by.clone());
                }
                None => {
                    unrecorded.insert(pk);
                }
            }
        }
        (known, unrecorded)
    }

    /// The npubs whose Refoundings minted held epochs (snapshot authorities).
    pub fn snapshot_authorities(&self) -> std::collections::HashSet<String> {
        self.held_roots.iter().filter(|r| r.epoch > 0).filter_map(|r| r.refounder.clone()).collect()
    }

    /// The channels this member can read (Armada `channelsView`): public ones derive
    /// from every held root; private ones need a held key; deleted ones are dropped.
    pub fn channels(&self, folded: Option<&FoldedControl>) -> Vec<ChannelView> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for def in folded.map(|f| f.channels.values()).into_iter().flatten() {
            seen.insert(def.channel_id_hex.clone());
            if def.deleted {
                continue;
            }
            let id = b32(&def.channel_id_hex);
            let root_streams: Vec<ChannelStream> = self
                .held_roots
                .iter()
                .map(|r| ChannelStream { epoch: r.epoch, key: channel_group_key(&b32(&r.key), &id, r.epoch), retired_at: r.retired_at })
                .collect();
            let held = self.private_channels.iter().find(|c| c.id == def.channel_id_hex);
            let channel_streams = held.map(|h| private_streams(h, &id)).unwrap_or_default();
            // A sealed Private Channel's details are readable only with its key
            // (CORD-03 §2): its name, and where it sits — Category, position
            // key and view all ride inside the seal, not beside it.
            let opened = def.sealed.as_ref().and_then(|sealed| {
                let key = self.channel_key_at(&def.channel_id_hex, sealed.epoch)?;
                crate::channel_seal::open_channel_seal(sealed, &key, &id)
            });
            let public_until = if def.private { opened.as_ref().and_then(|o| o.public_until) } else { None };
            let streams = if def.private {
                if held.is_none() {
                    continue;
                }
                // A converted Channel's public era stays history every key
                // holder reads, at the root streams, taking only what is dated
                // before it went private: a post arriving there later stands
                // nowhere (CORD-03 §2). Writes still go to the channel key.
                let public_era = public_until.map(|until| {
                    root_streams.into_iter().map(move |r| ChannelStream { retired_at: Some(r.retired_at.map_or(until / 1000, |t| t.min(until / 1000))), ..r })
                });
                channel_streams.into_iter().chain(public_era.into_iter().flatten()).collect()
            } else {
                // The earlier planes its metadata publishes (CORD-03 §2), last,
                // so a held plane of the same epoch sorts ahead of them.
                let mut streams: Vec<ChannelStream> = root_streams.into_iter().chain(channel_streams).collect();
                for p in published_history(&def.raw) {
                    if !streams.iter().any(|s| s.key.pubkey() == p.key.pubkey()) {
                        streams.push(p);
                    }
                }
                streams
            };
            let field = |k: &str| opened.as_ref().and_then(|o| o.metadata.get(k)).and_then(serde_json::Value::as_str).map(str::to_owned);
            let name = match (&opened, held) {
                (Some(_), _) => field("name").unwrap_or_default(),
                (None, Some(h)) if def.name.is_empty() && !h.name.is_empty() => h.name.clone(),
                // Armada shows an unopenable sealed channel by its id's first eight digits.
                (None, _) if def.name.is_empty() => def.channel_id_hex[..8].to_owned(),
                _ => def.name.clone(),
            };
            let (category_id, rank, view) = if opened.is_some() {
                (field("category").map(|c| c.to_lowercase()), field("position"), field("view"))
            } else {
                (def.category_id.clone(), def.rank.clone(), def.view.clone())
            };
            let category = if opened.is_some() {
                category_id.as_ref().and_then(|c| folded?.categories.get(c)).filter(|c| !c.deleted).map(|c| c.name.clone()).filter(|n| !n.is_empty())
            } else {
                def.category.clone()
            };
            out.push(ChannelView {
                id_hex: def.channel_id_hex.clone(),
                name,
                private: def.private,
                forum: view.as_deref() == Some("forum"),
                category,
                category_id,
                position: def.position,
                rank,
                view,
                streams,
                writers: folded
                    .and_then(|f| f.writers.get(&def.channel_id_hex))
                    .map(|l| {
                        crate::writers::writer_windows(l)
                            .into_iter()
                            .filter_map(|w| Some(WriterStream { epoch: w.epoch, pk: nostr::prelude::PublicKey::from_hex(&w.pk).ok()? }))
                            .collect()
                    })
                    .unwrap_or_default(),
                public_until,
            });
        }
        for held in &self.private_channels {
            if seen.contains(&held.id) {
                continue;
            }
            let id = b32(&held.id);
            out.push(ChannelView {
                id_hex: held.id.clone(),
                name: if held.name.is_empty() { held.id[..8].to_owned() } else { held.name.clone() },
                private: true,
                forum: false,
                category: None,
                category_id: None,
                position: None,
                rank: None,
                view: None,
                streams: private_streams(held, &id),
                writers: Vec::new(),
                public_until: None,
            });
        }
        let ranked = folded.is_some_and(|f| f.ranked);
        // On the ranked Roster position keys order Channels WITHIN a Category,
        // and Categories by their own keys, uncategorized Channels first, as a
        // Discord sidebar reads; keys restart per Category, so one flat sort by
        // channel key interleaves them.
        let category_key = |c: &ChannelView| -> (u8, Option<String>, Option<String>) {
            let cat = c.category_id.as_ref().and_then(|id| folded.and_then(|f| f.categories.get(id))).filter(|k| !k.deleted);
            match cat {
                None => (0, None, None),
                Some(k) => (if k.position.is_some() { 1 } else { 2 }, k.position.clone(), Some(k.id_hex.clone())),
            }
        };
        out.sort_by(|a, b| {
            if ranked {
                let by_category = category_key(a).cmp(&category_key(b));
                if by_category != std::cmp::Ordering::Equal {
                    return by_category;
                }
                return match (&a.rank, &b.rank) {
                    (Some(x), Some(y)) => x.cmp(y).then_with(|| a.name.cmp(&b.name)),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => a.name.cmp(&b.name),
                };
            }
            match (a.position, b.position) {
                (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.name.cmp(&b.name)),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.name.cmp(&b.name),
            }
        });
        out
    }

    /// Adopt private Channel keys from a Direct Invite on the SAME base (a role-gated
    /// key vend). A bundle may never move the base: only a rekey blob with proven
    /// continuity can. Returns the channel ids newly adopted or advanced.
    pub fn adopt_catch_up(&mut self, bundle: &InviteBundle) -> Vec<String> {
        if !bundle.community_root.eq_ignore_ascii_case(&self.root)
            || bundle.root_epoch != self.root_epoch
            || bundle.control_pk.as_deref().map(str::to_lowercase) != self.control_pk.as_deref().map(str::to_lowercase)
        {
            return vec![];
        }
        let mut adopted = vec![];
        for c in &bundle.channels {
            let id = c.id.to_lowercase();
            if hex32(&id).is_none() || hex32(&c.key).is_none() {
                continue;
            }
            // A Public Channel's entry carries the root itself (Armada `isRootKeyed`): no Private key.
            if c.key.eq_ignore_ascii_case(&bundle.community_root) {
                continue;
            }
            if self.channel_cuts.iter().any(|(cid, cut)| cid == &id && c.epoch < *cut) {
                continue;
            }
            match self.private_channels.iter_mut().find(|h| h.id == id) {
                Some(h) if c.epoch > h.epoch => {
                    h.priors.insert(0, PriorKey { key: h.key.clone(), epoch: h.epoch, retired_at: None });
                    h.key = c.key.to_lowercase();
                    h.epoch = c.epoch;
                    adopted.push(id);
                }
                Some(_) => {}
                None => {
                    let BundleChannel { key, epoch, name, .. } = c.clone();
                    self.private_channels.push(PrivateChannelKey { id: id.clone(), key: key.to_lowercase(), epoch, name, priors: vec![] });
                    adopted.push(id);
                }
            }
        }
        adopted
    }

    /// Adopt one private Channel key at `epoch` (an access delivery, CORD-03 §5):
    /// a new Channel, or a held one advancing, its old key kept as a prior for
    /// history. Never a step back, and never below a cut a rotation recorded.
    /// Returns whether anything changed.
    pub fn adopt_channel_key(&mut self, channel_id_hex: &str, epoch: u64, key: &Bytes32) -> bool {
        let id = channel_id_hex.to_lowercase();
        if self.channel_cuts.iter().any(|(cid, cut)| cid == &id && epoch < *cut) {
            return false;
        }
        match self.private_channels.iter_mut().find(|h| h.id == id) {
            Some(h) if epoch > h.epoch => {
                h.priors.insert(0, PriorKey { key: h.key.clone(), epoch: h.epoch, retired_at: None });
                h.key = to_hex(key);
                h.epoch = epoch;
                true
            }
            Some(_) => false,
            None => {
                self.private_channels.push(PrivateChannelKey { id, key: to_hex(key), epoch, name: String::new(), priors: vec![] });
                true
            }
        }
    }

    /// A Channel's access plane at the current root epoch (CORD-03 §5).
    pub fn access_plane(&self, channel_id: &Bytes32) -> GroupKey {
        crate::derive::channel_access_group_key(&self.root_key(), channel_id, self.root_epoch)
    }

    /// The address where the next base rotation would appear.
    pub fn next_base_rekey_address(&self) -> GroupKey {
        base_rekey_group_key(&self.root_key(), &self.id(), self.root_epoch + 1)
    }

    /// Addresses of upcoming private Channel rotations, under every held root,
    /// with their (channel id, epoch).
    pub fn channel_rekey_addresses(&self) -> Vec<(GroupKey, String, u64)> {
        let mut out = vec![];
        for ch in &self.private_channels {
            let id = b32(&ch.id);
            for r in &self.held_roots {
                for ahead in 1..=rekey::CHANNEL_REKEY_LOOKAHEAD {
                    out.push((channel_rekey_group_key(&b32(&r.key), &id, ch.epoch + ahead), ch.id.clone(), ch.epoch + ahead));
                }
            }
        }
        out
    }

    /// Whether a reader honors a complete base rotation off `(epoch, key)` (Armada
    /// `honoredRootRotations`): the rotator is the owner or holds BAN, unbanned,
    /// citing a satisfied Grant, continuing from exactly that key, and, unless
    /// the owner, carrying a blob for everyone it can't remove (CORD-06 §2).
    fn honors_base_rotation(&self, set: &Rotation, folded: &FoldedControl, epoch: u64, key: &Bytes32) -> bool {
        set.scope_hex == rekey::ROOT_SCOPE_HEX
            && set.new_epoch == epoch + 1
            && set.prev_epoch == epoch
            && set.is_complete()
            && !folded.banned.contains(&set.rotator)
            && folded.roster.is_authorized(&set.rotator, &folded.owner, perm::BAN)
            && folded.citation_satisfied(&self.id(), &set.rotator, set.authority.as_ref())
            && set.continues_from(epoch, key) == Continuity::Ok
            && covers_owed(set, folded)
    }

    /// Process base rotations at `root_epoch + 1` (CORD-06 §2). `rotations` must
    /// come from the next base-rekey address. Authority is the roster, never key
    /// possession. A rotation carrying no blob, or a blob at our locator that
    /// won't open, is never a removal.
    pub fn apply_base_rotations(&mut self, rotations: &[Rotation], folded: &FoldedControl, me: &nostr::prelude::Keys) -> RekeyOutcome {
        let me_hex = me.public_key().to_hex();
        let next = self.root_epoch + 1;
        let cid = self.id();
        let mut adopted: Option<(rekey::BaseBlob, String, u64)> = None;
        let mut excluded = false;
        for set in rotations {
            if !self.honors_base_rotation(set, folded, self.root_epoch, &self.root_key()) || !set.has_blobs() {
                continue;
            }
            let post_join = set.published_ms() >= self.joined_at_ms;
            let could_exclude = post_join && folded.roster.outranks_member(&set.rotator, &folded.owner, &me_hex);
            let blob = rekey::my_locator(&set.rotator, &me_hex, &set.scope_hex, set.new_epoch).and_then(|loc| set.find_blob(&loc));
            let Some(blob) = blob else {
                excluded |= could_exclude;
                continue;
            };
            let Ok(rotator) = nostr::prelude::PublicKey::from_hex(&set.rotator) else { continue };
            if let Ok(b) = rekey::open_blob(blob, me.secret_key(), &rotator).and_then(|plain| rekey::decode_base_blob(&plain, &cid, next))
                && adopted.as_ref().is_none_or(|(a, _, _)| b.new_root < a.new_root)
            {
                adopted = Some((b, set.rotator.clone(), set.published_ms()));
            }
        }
        if let Some((blob, rotator, published_ms)) = adopted {
            let retired_at = published_ms / 1000;
            for r in &mut self.held_roots {
                if r.epoch == self.root_epoch && r.retired_at.is_none() {
                    r.retired_at = Some(retired_at);
                }
            }
            self.held_roots.insert(
                0,
                HeldRoot { epoch: next, key: to_hex(&blob.new_root), control_pk: blob.control_pk.clone(), retired_at: None, refounder: Some(rotator) },
            );
            self.root = to_hex(&blob.new_root);
            self.root_epoch = next;
            self.control_pk = blob.control_pk;
            self.control_root = blob.control_root.map(|c| to_hex(&c));
            self.excluded_at = None;
            return RekeyOutcome::AdoptedRoot(next);
        }
        if excluded {
            self.excluded_at = Some(next);
            return RekeyOutcome::Excluded(next);
        }
        RekeyOutcome::Nothing
    }

    /// The address the held epoch's own Refoundings arrived at, derived from
    /// the prior root: `None` when that root isn't held (joined at this epoch).
    pub fn current_base_rekey_address(&self) -> Option<GroupKey> {
        let prior = self.held_roots.iter().find(|r| self.root_epoch > 0 && r.epoch == self.root_epoch - 1)?;
        Some(base_rekey_group_key(&b32(&prior.key), &self.id(), self.root_epoch))
    }

    /// Converge the held epoch onto a strictly lower sibling root (CORD-06 §3):
    /// an honored rotation off the same prior root whose blob opens for us,
    /// adopted with its control pair and Rotator as if taken first. Down-only,
    /// so a fetch returning only a higher sibling never re-forks a settled
    /// epoch. `rotations` come from [`Membership::current_base_rekey_address`].
    pub fn heal_base_sibling(&mut self, rotations: &[Rotation], folded: &FoldedControl, me: &nostr::prelude::Keys) -> bool {
        let Some(prior) = self.held_roots.iter().find(|r| self.root_epoch > 0 && r.epoch == self.root_epoch - 1).cloned() else { return false };
        let me_hex = me.public_key().to_hex();
        let cid = self.id();
        let mut lowest: Option<(rekey::BaseBlob, String)> = None;
        for set in rotations {
            if !self.honors_base_rotation(set, folded, prior.epoch, &b32(&prior.key)) {
                continue;
            }
            let Some(blob) = rekey::my_locator(&set.rotator, &me_hex, &set.scope_hex, set.new_epoch).and_then(|loc| set.find_blob(&loc)) else { continue };
            let Ok(rotator) = nostr::prelude::PublicKey::from_hex(&set.rotator) else { continue };
            if let Ok(b) = rekey::open_blob(blob, me.secret_key(), &rotator).and_then(|plain| rekey::decode_base_blob(&plain, &cid, self.root_epoch))
                && lowest.as_ref().is_none_or(|(l, _)| b.new_root < l.new_root)
            {
                lowest = Some((b, set.rotator.clone()));
            }
        }
        let Some((blob, rotator)) = lowest.filter(|(b, _)| b.new_root < self.root_key()) else { return false };
        self.root = to_hex(&blob.new_root);
        self.control_pk = blob.control_pk.clone();
        self.control_root = blob.control_root.map(|c| to_hex(&c));
        if let Some(r) = self.held_roots.iter_mut().find(|r| r.epoch == self.root_epoch) {
            r.key = self.root.clone();
            r.control_pk = blob.control_pk;
            r.refounder = Some(rotator);
        }
        true
    }

    /// The Private Channels `me`'s rekey walk follows that no key reached yet
    /// (Armada `walkTargets`): ones the fold lets them read, sealed, from the
    /// sealed head's epoch (CORD-03 §2). A Channel converted from public is one,
    /// and the rotation that minted it carries every reader it let in. A cut is
    /// never walked back below. `(channel id, first epoch walked)`.
    pub fn keyless_targets(&self, folded: &FoldedControl, me: &str) -> Vec<(String, u64)> {
        if !folded.ranked || folded.banned.contains(me) {
            return vec![];
        }
        folded
            .channels
            .values()
            .filter(|c| c.private && !c.deleted && c.sealed.is_some() && !self.private_channels.iter().any(|h| h.id == c.channel_id_hex))
            .filter(|c| me == folded.owner || folded.roster.channel_permissions(&folded.owner, me, &c.channel_id_hex, true) & perm::VIEW_CHANNEL != 0)
            .map(|c| {
                let sealed = c.sealed.as_ref().map_or(1, |s| s.epoch.max(1));
                let cut = self.channel_cuts.iter().filter(|(id, _)| *id == c.channel_id_hex).map(|(_, e)| *e).max().unwrap_or(0);
                (c.channel_id_hex.clone(), sealed.max(cut))
            })
            .collect()
    }

    /// [`Membership::channel_rekey_addresses`] and the addresses of the
    /// [`Membership::keyless_targets`], from their first epoch.
    pub fn channel_rekey_addresses_with(&self, folded: &FoldedControl, me: &str) -> Vec<(GroupKey, String, u64)> {
        let mut out = self.channel_rekey_addresses();
        for (ch, from) in self.keyless_targets(folded, me) {
            let id = b32(&ch);
            for r in &self.held_roots {
                for epoch in from..from + rekey::CHANNEL_REKEY_LOOKAHEAD {
                    out.push((channel_rekey_group_key(&b32(&r.key), &id, epoch), ch.clone(), epoch));
                }
            }
        }
        out
    }

    /// Process private Channel rotations (CORD-06 §2), walking each channel's
    /// epochs ascending, held ones from the epoch after their key and keyless
    /// ones from their sealed head's. Returns `(channel id, adopted epoch or
    /// None if cut)`.
    ///
    /// Adoption needs an unbroken `prevcommit` chain from the key held; a
    /// keyless walk has nothing to check, so it adopts on authority and the
    /// blob's binding, and the seal is what authenticates a key at its epoch.
    /// A rotation from the owner or a MANAGE_CHANNELS holder committing to
    /// `(n − 1, root)` is a public Channel made private, and extends the chain
    /// for a holder of an earlier private era's key too (CORD-03 §2).
    pub fn apply_channel_rotations(&mut self, rotations: &[Rotation], folded: &FoldedControl, me: &nostr::prelude::Keys) -> Vec<(String, Option<u64>)> {
        let me_hex = me.public_key().to_hex();
        let cid = self.id();
        let roots: Vec<(u64, Bytes32)> = self.held_roots.iter().map(|r| (r.epoch, b32(&r.key))).collect();
        // (channel id, key held and its epoch, first epoch walked)
        type Target = (String, Option<(Bytes32, u64)>, u64);
        let mut targets: Vec<Target> =
            self.private_channels.iter().map(|c| (c.id.clone(), Some((b32(&c.key), c.epoch)), c.epoch + 1)).collect();
        targets.extend(self.keyless_targets(folded, &me_hex).into_iter().map(|(id, from)| (id, None, from)));
        let mut changes = vec![];
        let mut cuts = vec![];
        let mut adoptions: Vec<(String, Bytes32, u64, Vec<PriorKey>)> = vec![];
        for (ch_id, held, from) in targets {
            let mut sets: Vec<&Rotation> = rotations
                .iter()
                .filter(|s| {
                    s.scope_hex == ch_id
                        && s.new_epoch >= from
                        && s.new_epoch == s.prev_epoch + 1
                        && s.is_complete()
                        && !folded.banned.contains(&s.rotator)
                        && (folded.roster.is_authorized(&s.rotator, &folded.owner, perm::BAN)
                            || folded.roster.is_authorized(&s.rotator, &folded.owner, perm::MANAGE_CHANNELS))
                        && folded.citation_satisfied(&cid, &s.rotator, s.authority.as_ref())
                })
                .collect();
            if sets.is_empty() {
                continue;
            }
            sets.sort_by_key(|s| s.new_epoch);
            let id = b32(&ch_id);
            let sealed = folded.channels.get(&ch_id).and_then(|c| c.sealed.as_ref());
            let converts = |s: &Rotation| {
                (s.rotator == folded.owner || folded.roster.is_authorized(&s.rotator, &folded.owner, perm::MANAGE_CHANNELS))
                    && roots.iter().any(|(_, k)| s.continues_from(s.prev_epoch, k) == Continuity::Ok)
            };
            let mut chain: Option<(Bytes32, u64)> = held;
            let mut adopted: Option<(Bytes32, u64)> = None;
            let mut excluded_at: Option<u64> = None;
            let mut stepped: Vec<PriorKey> = vec![];
            let mut epochs: Vec<u64> = sets.iter().map(|s| s.new_epoch).collect();
            epochs.dedup();
            for epoch in epochs {
                let mut key_here: Option<(Bytes32, u64)> = None;
                let mut addressed = false;
                for set in sets.iter().filter(|s| s.new_epoch == epoch) {
                    let Some(blob) = rekey::my_locator(&set.rotator, &me_hex, &ch_id, epoch).and_then(|l| set.find_blob(&l)) else { continue };
                    addressed = true;
                    if let Some((k, e)) = chain
                        && set.continues_from(e, &k) != Continuity::Ok
                        && !converts(set)
                    {
                        continue;
                    }
                    let Ok(rotator) = nostr::prelude::PublicKey::from_hex(&set.rotator) else { continue };
                    let Ok(k) = rekey::open_blob(blob, me.secret_key(), &rotator).and_then(|p| rekey::decode_channel_blob(&p, &id, epoch)) else { continue };
                    if chain.is_none() && crate::delivery::access_key_refuted(sealed, &id, epoch, &k) {
                        continue;
                    }
                    let at = set.published_ms();
                    key_here = Some(match key_here {
                        Some((prev, prev_at)) => (prev.min(k), prev_at.min(at)),
                        None => (k, at),
                    });
                }
                if let Some((k, at)) = key_here {
                    if let Some((ck, ce)) = chain {
                        stepped.insert(0, PriorKey { key: to_hex(&ck), epoch: ce, retired_at: Some(at / 1000) });
                    }
                    adopted = Some((k, epoch));
                    chain = Some((k, epoch));
                    continue;
                }
                if addressed || held.is_none() {
                    continue;
                }
                if sets.iter().filter(|s| s.new_epoch == epoch).any(|s| {
                    s.published_ms() >= self.joined_at_ms && folded.roster.outranks_member(&s.rotator, &folded.owner, &me_hex)
                }) {
                    excluded_at = Some(epoch);
                }
            }
            match (adopted, excluded_at) {
                (Some((k, epoch)), ex) if ex.is_none_or(|x| epoch > x) => {
                    adoptions.push((ch_id.clone(), k, epoch, stepped));
                    changes.push((ch_id, Some(epoch)));
                }
                (_, Some(x)) => {
                    cuts.push((ch_id.clone(), x));
                    changes.push((ch_id, None));
                }
                _ => {}
            }
        }
        for (id, k, epoch, mut stepped) in adoptions {
            match self.private_channels.iter_mut().find(|c| c.id == id) {
                Some(ch) => {
                    stepped.append(&mut ch.priors);
                    ch.priors = stepped;
                    ch.key = to_hex(&k);
                    ch.epoch = epoch;
                }
                None => self.private_channels.push(PrivateChannelKey { id, key: to_hex(&k), epoch, name: String::new(), priors: stepped }),
            }
        }
        for (id, epoch) in cuts {
            self.private_channels.retain(|c| c.id != id);
            self.channel_cuts.push((id, epoch));
        }
        changes
    }
}

/// At most this many published planes (CORD-03 §2).
pub const MAX_HISTORY: usize = 128;

/// The earlier planes a Public Channel's metadata publishes as `history`
/// (CORD-03 §2, Armada `publishedHistory`), each by its own secret: an entry
/// that isn't `[epoch < 2^53, "<64 hex secret>"]` names nothing.
pub fn published_history(meta: &serde_json::Value) -> Vec<ChannelStream> {
    let Some(entries) = meta.get("history").and_then(serde_json::Value::as_array) else { return vec![] };
    entries
        .iter()
        .filter_map(|e| {
            let [epoch, secret] = e.as_array()?.as_slice() else { return None };
            let epoch = epoch.as_u64().filter(|e| *e < (1 << 53))?;
            let sk = nostr::prelude::SecretKey::from_slice(&hex32(secret.as_str().filter(|s| crate::is_hex64(s))?)?).ok()?;
            Some(ChannelStream { epoch, key: GroupKey::from_secret(sk), retired_at: None })
        })
        .take(MAX_HISTORY)
        .collect()
}

fn private_streams(h: &PrivateChannelKey, id: &Bytes32) -> Vec<ChannelStream> {
    std::iter::once(ChannelStream { epoch: h.epoch, key: channel_group_key(&b32(&h.key), id, h.epoch), retired_at: None })
        .chain(h.priors.iter().filter_map(|p| {
            Some(ChannelStream { epoch: p.epoch, key: channel_group_key(&hex32(&p.key)?, id, p.epoch), retired_at: p.retired_at })
        }))
        .collect()
}

/// Whether a bundle's root is the Community's own (CORD-05 §1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootVerdict {
    Anchored,
    /// The plane answered and holds no anchor: a root of someone else's choosing.
    Forged,
    /// Nothing was read: the join waits, never waved through.
    Unread,
}

/// Authenticate a bundle's root before persisting a join (CORD-05 §1): at
/// epoch 0 the owner's genesis metadata edition (`vsk 0`, its `eid` the
/// `community_id`) opens under the delivered keys; on a rotated plane,
/// where compaction may leave no owner-signed metadata head, the
/// Community-bound metadata head and at least one owner-signed edition do.
/// `editions` are those opened at `m`'s current Control Plane address; an
/// empty read defers. Bundle fields that ride in every invite and outlive
/// removal would otherwise seat a joiner on planes an attacker controls.
pub fn authenticate_root(m: &Membership, editions: &[crate::edition::Edition]) -> RootVerdict {
    let here = m.current_control_stream().pk_hex();
    let at: Vec<&crate::edition::Edition> = editions.iter().filter(|e| e.opened.stream_pk == here).collect();
    if at.is_empty() {
        return RootVerdict::Unread;
    }
    let cid = m.id();
    let metadata = |e: &&&crate::edition::Edition| e.vsk == crate::kinds::VSK_METADATA && e.entity_id == cid;
    let anchored = if m.root_epoch == 0 {
        at.iter().any(|e| metadata(&e) && e.author == m.owner)
    } else {
        let bound = crate::derive::edition_binding(&cid);
        at.iter().any(|e| metadata(&e) && e.binding == Some(bound)) && at.iter().any(|e| e.author == m.owner)
    };
    if anchored { RootVerdict::Anchored } else { RootVerdict::Forged }
}

#[cfg(test)]
mod rotation_tests {
    use super::*;
    use crate::control::FoldedControl;
    use crate::derive::epoch_key_commitment;
    use crate::kinds::Plane;
    use crate::rekey::{group_rotations, parse_rekey};
    use crate::roles::{MemberGrant, Role, RoleScope};
    use crate::stream::{WrapOptions, open_plane_wrap, seal_and_wrap};
    use base64::Engine;
    use nostr::prelude::Keys;

    /// A base rotation by `rotator` off the held epoch, carrying each blob given
    /// as (recipient, plaintext), through a real wrap at the next base address.
    fn rotation(m: &Membership, rotator: &Keys, blobs: &[(&Keys, Vec<u8>)], prev: Option<(u64, Bytes32)>) -> Vec<Rotation> {
        rotation_citing(m, rotator, blobs, prev, None)
    }

    fn rotation_citing(m: &Membership, rotator: &Keys, blobs: &[(&Keys, Vec<u8>)], prev: Option<(u64, Bytes32)>, vac: Option<&crate::edition::Citation>) -> Vec<Rotation> {
        let (prev_epoch, prev_root) = prev.unwrap_or((m.root_epoch, m.root_key()));
        let new_epoch = prev_epoch + 1;
        let me = rotator.public_key().to_hex();
        let list: Vec<serde_json::Value> = blobs
            .iter()
            .map(|(to, plain)| {
                let conv = crate::derive::conversation_key(rotator.secret_key(), &to.public_key());
                let wrapped = crate::nip44::encrypt_str(&conv, &base64::engine::general_purpose::STANDARD.encode(plain)).unwrap();
                let locator = rekey::my_locator(&me, &to.public_key().to_hex(), rekey::ROOT_SCOPE_HEX, new_epoch).unwrap();
                serde_json::json!({ "locator": locator, "wrapped": wrapped })
            })
            .collect();
        let tags = vec![
            vec!["scope".to_string(), rekey::ROOT_SCOPE_HEX.into()],
            vec!["newepoch".into(), new_epoch.to_string()],
            vec!["prevepoch".into(), prev_epoch.to_string()],
            vec!["prevcommit".into(), to_hex(&epoch_key_commitment(prev_epoch, &prev_root))],
            vec!["chunk".into(), "1".into(), "1".into()],
        ];
        let tags = tags.into_iter().chain(vac.map(|c| c.to_tag())).collect();
        let rumor = crate::rumor::Rumor::new(crate::kinds::REKEY, serde_json::Value::Array(list).to_string(), tags, &me, Some(10_000_000), None);
        let address: StreamKey = (&base_rekey_group_key(&prev_root, &m.id(), new_epoch)).into();
        let wrap = seal_and_wrap(&rumor, Plane::Rekey, &address, rotator, WrapOptions::default()).unwrap();
        group_rotations(vec![parse_rekey(&open_plane_wrap(&wrap, &address, Plane::Rekey).unwrap()).unwrap()])
    }

    fn blob(m: &Membership, epoch: u64, root: &Bytes32, width: usize) -> Vec<u8> {
        let mut p = vec![0u8; 32];
        p.extend_from_slice(&epoch.to_be_bytes());
        p.extend_from_slice(root);
        let control_root = random32();
        p.extend_from_slice(&crate::derive::control_signer_group_key(&control_root, &m.id(), epoch).keys.public_key().to_bytes());
        p.extend_from_slice(&control_root);
        p.resize(width, 7);
        p
    }

    fn world() -> (Membership, Keys, Keys, FoldedControl) {
        let owner = Keys::generate();
        let me = Keys::generate();
        let mut m = Membership::mint("t", &owner.public_key().to_hex(), vec![], 0);
        m.joined_at_ms = 0;
        let f = FoldedControl { owner: owner.public_key().to_hex(), ..Default::default() };
        (m, owner, me, f)
    }

    #[test]
    fn a_blob_that_wont_open_or_no_blob_at_all_is_never_a_removal() {
        let (mut m, owner, me, f) = world();
        let other = Keys::generate();
        // A blob at our locator in a form we can't read.
        let junk = rotation(&m, &owner, &[(&me, vec![1, 2, 3]), (&other, blob(&m, 1, &random32(), 136))], None);
        assert_eq!(m.apply_base_rotations(&junk, &f, &me), RekeyOutcome::Nothing);
        let empty = rotation(&m, &owner, &[], None);
        assert_eq!(m.apply_base_rotations(&empty, &f, &me), RekeyOutcome::Nothing);
        // Left out of a rotation that carries blobs: that is a removal.
        let without = rotation(&m, &owner, &[(&other, blob(&m, 1, &random32(), 136))], None);
        assert_eq!(m.apply_base_rotations(&without, &f, &me), RekeyOutcome::Excluded(1));
    }

    #[test]
    fn a_wider_base_blob_is_read_by_its_prefix() {
        let (mut m, owner, me, f) = world();
        let root = random32();
        let r = rotation(&m, &owner, &[(&me, blob(&m, 1, &root, 168))], None);
        assert_eq!(m.apply_base_rotations(&r, &f, &me), RekeyOutcome::AdoptedRoot(1));
        assert_eq!(m.root, to_hex(&root));
        assert!(m.control_root.is_some(), "the 136-byte prefix still derives");
        let (mut m2, owner2, me2, f2) = world();
        let r = rotation(&m2, &owner2, &[(&me2, blob(&m2, 1, &random32(), 120))], None);
        assert_eq!(m2.apply_base_rotations(&r, &f2, &me2), RekeyOutcome::Nothing, "a width between forms is malformed");
    }

    #[test]
    fn a_moderators_rotation_that_skips_the_owner_is_neither_adopted_nor_a_removal() {
        let (mut m, owner, me, mut f) = world();
        let moderator = Keys::generate();
        let role = Role::new(&"aa".repeat(32), "Mod", 2, perm::BAN, RoleScope::Server);
        f.roster.roles.push(role.clone());
        f.roster.grants.push(MemberGrant { member: moderator.public_key().to_hex(), role_ids: vec![role.role_id.clone()], control_wrap: None });
        let eid = crate::derive::grant_locator(&m.id(), &moderator.public_key().to_bytes());
        f.heads.insert(to_hex(&eid), crate::edition::Head { version: 1, hash: [9; 32] });
        let vac = crate::edition::Citation { entity_id: eid, version: 1, edition_hash: [9; 32] };
        let rotation = |m: &Membership, r: &Keys, b: &[(&Keys, Vec<u8>)], p| rotation_citing(m, r, b, p, Some(&vac));
        let skip = rotation(&m, &moderator, &[(&me, blob(&m, 1, &random32(), 104))], None);
        assert_eq!(m.apply_base_rotations(&skip, &f, &me), RekeyOutcome::Nothing);
        let other = Keys::generate();
        let cut = rotation(&m, &moderator, &[(&other, blob(&m, 1, &random32(), 104))], None);
        assert_eq!(m.apply_base_rotations(&cut, &f, &me), RekeyOutcome::Nothing, "it can't remove anyone either");
        let full = rotation(&m, &moderator, &[(&me, blob(&m, 1, &random32(), 104)), (&owner, blob(&m, 1, &random32(), 104))], None);
        assert_eq!(m.apply_base_rotations(&full, &f, &me), RekeyOutcome::AdoptedRoot(1));
    }

    /// A public Channel converted to private: its first sealed head at epoch
    /// 1, the converter's rotation at 1 committing to (0, root).
    #[test]
    fn a_converted_channel_is_walked_keyless_and_taken_from_its_rotation() {
        let (m0, owner, me, mut f) = world();
        let mut m = m0;
        let chan_hex = "c7".repeat(32);
        let chan = b32(&chan_hex);
        let key = [5u8; 32];
        let meta = serde_json::Map::from_iter([("name".to_owned(), serde_json::Value::String("ops".into()))]);
        let content = crate::channel_seal::seal_channel_metadata(&meta, &key, &chan, 1, None, Some(&owner.public_key().to_hex())).unwrap();
        let sealed: serde_json::Value = serde_json::from_str(&content).unwrap();
        f.ranked = true;
        f.roster.everyone = Some(perm::EVERYONE_DEFAULT);
        let sealed_meta = crate::channel_seal::SealedChannelMeta { epoch: 1, sealed: sealed["sealed"].as_str().unwrap().to_owned(), prev_hex: None };
        f.channels.insert(chan_hex.clone(), crate::control::FoldedChannel { channel_id_hex: chan_hex.clone(), name: String::new(), private: true, sealed: Some(sealed_meta), ..Default::default() });
        assert!(m.keyless_targets(&f, &me.public_key().to_hex()).is_empty(), "not let in");
        f.roster.overwrites.push(crate::roles::Overwrite {
            scope: chan_hex.clone(),
            target: crate::roles::OverwriteTarget::Member(me.public_key().to_hex()),
            allow: perm::VIEW_CHANNEL,
            deny: 0,
        });
        assert_eq!(m.keyless_targets(&f, &me.public_key().to_hex()), vec![(chan_hex.clone(), 1)]);
        assert!(m.channel_rekey_addresses_with(&f, &me.public_key().to_hex()).iter().any(|(_, c, e)| *c == chan_hex && *e == 1));

        let root = m.root_key();
        let rotate = |new_key: &Bytes32| {
            let rumors = rekey::build_channel_rotation(&owner, &chan, 1, 0, &root, new_key, &[me.public_key().to_hex()], 10_000, None).unwrap();
            let address: StreamKey = (&channel_rekey_group_key(&root, &chan, 1)).into();
            let parsed = rumors.iter().map(|r| parse_rekey(&open_plane_wrap(&seal_and_wrap(r, Plane::Rekey, &address, &owner, WrapOptions::default()).unwrap(), &address, Plane::Rekey).unwrap()).unwrap()).collect();
            group_rotations(parsed)
        };
        // A key the seal doesn't open is someone's own, not the Channel's.
        assert!(m.apply_channel_rotations(&rotate(&[6; 32]), &f, &me).is_empty());
        assert_eq!(m.apply_channel_rotations(&rotate(&key), &f, &me), vec![(chan_hex.clone(), Some(1))]);
        assert_eq!(m.private_channels[0].key, to_hex(&key));
    }

    #[test]
    fn the_held_epoch_heals_down_to_a_lower_sibling_only() {
        let (mut m, owner, me, f) = world();
        let (prior_epoch, prior_root) = (m.root_epoch, m.root_key());
        let mut high = [0xffu8; 32];
        high[31] = 0xfe;
        let r = rotation(&m, &owner, &[(&me, blob(&m, 1, &high, 104))], None);
        assert_eq!(m.apply_base_rotations(&r, &f, &me), RekeyOutcome::AdoptedRoot(1));
        let address = m.current_base_rekey_address().unwrap();
        assert_eq!(address.pubkey(), base_rekey_group_key(&prior_root, &m.id(), 1).pubkey());

        let other = Keys::generate();
        let higher = rotation(&m, &other, &[(&me, blob(&m, 1, &[0xff; 32], 104))], Some((prior_epoch, prior_root)));
        assert!(!m.heal_base_sibling(&higher, &f, &me), "the rotator holds no BAN");
        let higher = rotation(&m, &owner, &[(&me, blob(&m, 1, &[0xff; 32], 104))], Some((prior_epoch, prior_root)));
        assert!(!m.heal_base_sibling(&higher, &f, &me), "never up");
        let low = [1u8; 32];
        let lower = rotation(&m, &owner, &[(&me, blob(&m, 1, &low, 104))], Some((prior_epoch, prior_root)));
        assert!(m.heal_base_sibling(&lower, &f, &me));
        assert_eq!((m.root.clone(), m.root_epoch), (to_hex(&low), 1));
        assert_eq!(m.held_roots[0].key, to_hex(&low));
        assert_eq!(m.held_roots[0].control_pk, m.control_pk);
    }
}

#[cfg(test)]
mod anchor_tests {
    use super::*;
    use crate::control::{build_metadata_edition, seal_edition};
    use crate::edition::{EditionMeta, parse_edition};
    use crate::kinds::Plane;
    use crate::stream::open_plane_wrap;
    use nostr::prelude::Keys;

    fn editions(m: &Membership, rumors: &[(&crate::rumor::Rumor, &Keys)]) -> Vec<crate::edition::Edition> {
        let w = m.control_write_stream().unwrap();
        rumors.iter().map(|(r, k)| parse_edition(open_plane_wrap(&seal_edition(r, &w, k).unwrap(), &m.current_control_stream(), Plane::Control).unwrap()).unwrap()).collect()
    }

    #[test]
    fn a_root_is_taken_only_with_the_owners_genesis_under_it() {
        let owner = Keys::generate();
        let m = Membership::mint("t", &owner.public_key().to_hex(), vec![], 0);
        let owner_hex = owner.public_key().to_hex();
        let genesis = build_metadata_edition(&m.id(), &serde_json::json!({ "name": "t" }), &EditionMeta::first(&owner_hex, None)).unwrap();
        assert_eq!(authenticate_root(&m, &[]), RootVerdict::Unread);
        assert_eq!(authenticate_root(&m, &editions(&m, &[(&genesis, &owner)])), RootVerdict::Anchored);
        // An ex-member pairs the real identity with a root of their own, and
        // re-signs a metadata edition there: not the owner's.
        let forger = Keys::generate();
        let forged = build_metadata_edition(&m.id(), &serde_json::json!({ "name": "t" }), &EditionMeta::first(&forger.public_key().to_hex(), None)).unwrap();
        assert_eq!(authenticate_root(&m, &editions(&m, &[(&forged, &forger)])), RootVerdict::Forged);
    }
}

#[cfg(test)]
mod history_tests {
    use super::*;

    #[test]
    fn a_public_channels_published_planes_are_read_after_its_own() {
        let m = Membership::mint("t", &"aa".repeat(32), vec![], 0);
        let chan = "c3".repeat(32);
        let secret = "11".repeat(32);
        let raw = serde_json::json!({ "name": "c", "private": false, "history": [[3, secret], [4, "not hex"], "junk"] });
        let mut f = FoldedControl { owner: m.owner.clone(), ..Default::default() };
        f.channels.insert(chan.clone(), crate::control::FoldedChannel { channel_id_hex: chan.clone(), name: "c".into(), raw, ..Default::default() });
        let view = m.channels(Some(&f)).into_iter().find(|c| c.id_hex == chan).unwrap();
        assert_eq!(view.streams.len(), 2, "its root plane, then the one well-formed published plane");
        assert_eq!(view.streams[1].epoch, 3);
        assert_eq!(view.current().epoch, 0, "writes still go to the root plane");
        let sk = nostr::prelude::SecretKey::from_slice(&hex32(&secret).unwrap()).unwrap();
        assert_eq!(view.streams[1].key.pubkey(), GroupKey::from_secret(sk).pubkey());
    }
}
