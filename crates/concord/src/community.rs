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
                root_streams.into_iter().chain(channel_streams).collect()
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

    /// Process base rotations at `root_epoch + 1` (CORD-06 §2). `rotations` must
    /// come from the next base-rekey address. Authority is the roster, never key
    /// possession: the rotator must be the owner or hold BAN, be unbanned, and
    /// cite a satisfied Grant.
    pub fn apply_base_rotations(&mut self, rotations: &[Rotation], folded: &FoldedControl, me: &nostr::prelude::Keys) -> RekeyOutcome {
        let me_hex = me.public_key().to_hex();
        let next = self.root_epoch + 1;
        let cid = self.id();
        let mut adopted: Option<(rekey::BaseBlob, String, u64)> = None;
        let mut excluded = false;
        for set in rotations {
            if set.scope_hex != rekey::ROOT_SCOPE_HEX
                || set.new_epoch != next
                || !set.is_complete()
                || folded.banned.contains(&set.rotator)
                || !folded.roster.is_authorized(&set.rotator, &folded.owner, perm::BAN)
                || !folded.citation_satisfied(&cid, &set.rotator, set.authority.as_ref())
                || set.continues_from(self.root_epoch, &self.root_key()) != Continuity::Ok
            {
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
            match rekey::open_blob(blob, me.secret_key(), &rotator).and_then(|plain| rekey::decode_base_blob(&plain, &cid, next)) {
                Ok(b) => {
                    if adopted.as_ref().is_none_or(|(a, _, _)| b.new_root < a.new_root) {
                        adopted = Some((b, set.rotator.clone(), set.published_ms()));
                    }
                }
                Err(_) => excluded |= could_exclude,
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

    /// Process private Channel rotations (CORD-06 §2), walking each channel's
    /// epochs ascending. Returns `(channel id, adopted epoch or None if cut)`.
    pub fn apply_channel_rotations(&mut self, rotations: &[Rotation], folded: &FoldedControl, me: &nostr::prelude::Keys) -> Vec<(String, Option<u64>)> {
        let me_hex = me.public_key().to_hex();
        let cid = self.id();
        let mut changes = vec![];
        let mut cuts = vec![];
        for ch in &mut self.private_channels {
            let mut sets: Vec<&Rotation> = rotations
                .iter()
                .filter(|s| {
                    s.scope_hex == ch.id
                        && s.new_epoch > ch.epoch
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
            let id = b32(&ch.id);
            let (mut chain_epoch, mut chain_key) = (ch.epoch, b32(&ch.key));
            let mut adopted: Option<(Bytes32, u64)> = None;
            let mut excluded_at: Option<u64> = None;
            let mut stepped: Vec<PriorKey> = vec![];
            let mut epochs: Vec<u64> = sets.iter().map(|s| s.new_epoch).collect();
            epochs.dedup();
            for epoch in epochs {
                let mut key_here: Option<(Bytes32, u64)> = None;
                let mut addressed = false;
                for set in sets.iter().filter(|s| s.new_epoch == epoch) {
                    let Some(blob) = rekey::my_locator(&set.rotator, &me_hex, &ch.id, epoch).and_then(|l| set.find_blob(&l)) else { continue };
                    addressed = true;
                    if set.continues_from(chain_epoch, &chain_key) != Continuity::Ok {
                        continue;
                    }
                    let Ok(rotator) = nostr::prelude::PublicKey::from_hex(&set.rotator) else { continue };
                    if let Ok(k) = rekey::open_blob(blob, me.secret_key(), &rotator).and_then(|p| rekey::decode_channel_blob(&p, &id, epoch)) {
                        let at = set.published_ms();
                        key_here = Some(match key_here {
                            Some((prev, prev_at)) => (prev.min(k), prev_at.min(at)),
                            None => (k, at),
                        });
                    }
                }
                if let Some((k, at)) = key_here {
                    stepped.insert(0, PriorKey { key: to_hex(&chain_key), epoch: chain_epoch, retired_at: Some(at / 1000) });
                    adopted = Some((k, epoch));
                    chain_epoch = epoch;
                    chain_key = k;
                    continue;
                }
                if addressed {
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
                    let mut priors = stepped;
                    priors.append(&mut ch.priors);
                    ch.priors = priors;
                    ch.key = to_hex(&k);
                    ch.epoch = epoch;
                    changes.push((ch.id.clone(), Some(epoch)));
                }
                (_, Some(x)) => {
                    cuts.push((ch.id.clone(), x));
                    changes.push((ch.id.clone(), None));
                }
                _ => {}
            }
        }
        for (id, epoch) in cuts {
            self.private_channels.retain(|c| c.id != id);
            self.channel_cuts.push((id, epoch));
        }
        changes
    }
}

fn private_streams(h: &PrivateChannelKey, id: &Bytes32) -> Vec<ChannelStream> {
    std::iter::once(ChannelStream { epoch: h.epoch, key: channel_group_key(&b32(&h.key), id, h.epoch), retired_at: None })
        .chain(h.priors.iter().filter_map(|p| {
            Some(ChannelStream { epoch: p.epoch, key: channel_group_key(&hex32(&p.key)?, id, p.epoch), retired_at: p.retired_at })
        }))
        .collect()
}
