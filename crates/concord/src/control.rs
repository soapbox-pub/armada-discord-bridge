//! The Control Plane fold — CORD-04. Replays opened editions into current state:
//! the owner-rooted Roster first (the legacy delegation fixpoint, or the ranked
//! vsk-13 fold once `@everyone` stands), then every gated entity (metadata,
//! Channels, Banlist, invite registries, pins, signals, and on the ranked Roster
//! Categories, overwrites, syncs and Writers ledgers) judged against it. A port
//! of Armada's `control.ts`; the comments there carry the reasoning.

use std::collections::{BTreeMap, HashMap, HashSet};

use nostr::prelude::{Event, Keys};
use serde_json::Value;

use crate::channel_seal::{SealedChannelMeta, sanitize_channel_fields};
use crate::derive::{banlist_locator, edition_binding, everyone_locator, grant_locator, invite_links_locator, signal_locator, sync_locator, writers_locator};
use crate::edition::{Citation, Edition, EditionMeta, Head, bootstrap_head, build_edition_rumor, fold_chain};
use crate::kinds::{self, SIGNAL_PAUSE};
use crate::rank::is_rank_key;
use crate::roles::{BENEATH_EVERY_ROLE, MAX_ROLES_PER_COMMUNITY, MemberGrant, NAME_MAX_BYTES, Overwrite, Role, Roster, cut_name, perm};
use crate::roster::{
    ALWAYS_MARKED_VSKS, AUTHORITY_VSKS, SealedBy, VSK_ACL, VSK_CATEGORY, VSK_RANKED_ROLE, VSK_SYNC, VSK_TENURE, VSK_WRITERS, fold_ranked_roster, is_listed, may_swap_overwrites,
    overwrite_authorized, overwrite_locator, parse_overwrite, parse_sync, roster_activated, seal_of,
};
use crate::strict;
use crate::writers::{LEDGER_ENTRY_SKEW_MS, LEDGER_HORIZON_MS, Ledger, Spell, ledger_extends, parse_ledger};
use crate::rumor::Rumor;
use crate::stream::{Opened, StreamError, StreamKey, WrapOptions, seal_and_wrap};
use crate::{Bytes32, hex32, is_hex64, to_hex};

pub const DESCRIPTION_MAX_BYTES: usize = 10_000;
pub const MAX_COMMUNITY_RELAYS: usize = 5;
const MAX_PAUSE_UNTIL_SECS: u64 = 30 * 24 * 60 * 60;
/// Implemented signal ids and the permission each needs; others stay invisible.
const SIGNAL_GATES: &[(&str, u64)] = &[(SIGNAL_PAUSE, perm::MANAGE_CHANNELS)];

/// An encrypted-blob pointer (icon / banner), CORD-02 §6.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImagePointer {
    pub url: String,
    pub key: String,
    pub nonce: String,
    pub hash: String,
}

impl ImagePointer {
    fn from_value(v: Option<&Value>) -> Option<Self> {
        serde_json::from_value(v?.clone()).ok()
    }
}

/// Community metadata (vsk 0). `raw` keeps every field for round-tripping.
#[derive(Clone, Debug)]
pub struct CommunityMetadata {
    pub name: String,
    pub description: Option<String>,
    pub relays: Vec<String>,
    pub icon: Option<ImagePointer>,
    pub banner: Option<ImagePointer>,
    /// The disappearing-messages timer in seconds (CORD-08); `None` = off.
    pub message_expiration: Option<u64>,
    pub raw: Value,
}

/// Channel metadata (vsk 2), folded.
#[derive(Clone, Debug, Default)]
pub struct FoldedChannel {
    pub channel_id_hex: String,
    /// Empty for a sealed Private Channel this reader holds no key to open.
    pub name: String,
    pub private: bool,
    pub deleted: bool,
    /// `"forum"` channels open thread-first (CORD-03 §2 `view`).
    pub forum: bool,
    /// The `view` as carried: `"chat"`, `"forum"`, `"voice"`, or unknown (read as chat).
    pub view: Option<String>,
    pub topic: Option<String>,
    /// The sidebar category's NAME: the Category entity's on the ranked Roster
    /// (resolved from `category_id`), Armada's `custom["armada.category"]` before.
    pub category: Option<String>,
    /// The Category entity this Channel files under (CORD-03 §4).
    pub category_id: Option<String>,
    /// Armada's legacy sidebar position (`custom["armada.order"]`).
    pub position: Option<f64>,
    /// The rank-key position (CORD-03 §2), ordering Channels on the ranked Roster.
    pub rank: Option<String>,
    /// A Private Channel's sealed details (CORD-03 §2), opened with its key.
    pub sealed: Option<SealedChannelMeta>,
    pub raw: Value,
}

/// A Category (vsk 15, CORD-03 §4).
#[derive(Clone, Debug)]
pub struct FoldedCategory {
    pub id_hex: String,
    pub name: String,
    /// Rank key ordering Categories; absent sorts after every keyed one.
    pub position: Option<String>,
    pub deleted: bool,
}

#[derive(Clone, Debug)]
pub struct FoldedSignal {
    pub content: Value,
    pub author: String,
    pub at: u64,
}

/// The Control Plane replayed into current state.
#[derive(Clone, Debug, Default)]
pub struct FoldedControl {
    pub roster: Roster,
    pub owner: String,
    pub metadata: Option<CommunityMetadata>,
    pub channels: BTreeMap<String, FoldedChannel>,
    pub banned: HashSet<String>,
    /// npub → `created_at` (seconds) of the newest authorized banlist edition naming them.
    pub banned_at: HashMap<String, u64>,
    pub live_invite_links: HashSet<String>,
    pub registries_by_creator: HashMap<String, Vec<String>>,
    /// Pin Lists by `pins_locator` eid: raw head content (decoding needs a channel key).
    pub pin_lists: HashMap<String, (String, String)>,
    pub signals: HashMap<String, FoldedSignal>,
    pub heads: HashMap<String, Head>,
    pub head_editions: HashMap<String, Edition>,
    /// Floored entities the served set couldn't account for (data availability only).
    pub incomplete: Vec<String>,
    /// On the vsk-13 Roster (CORD-04 §2): `roster.everyone` stands and the
    /// Channel permission entities fold.
    pub ranked: bool,
    /// Categories by id, deleted ones included and flagged.
    pub categories: BTreeMap<String, FoldedCategory>,
    /// Each member's sealed standings (CORD-04 §9), from the Tenures admitted.
    pub tenure: SealedBy,
    /// Restricted Channels' Writers ledgers (CORD-03 §1), by Channel id.
    pub writers: HashMap<String, Ledger>,
}

impl FoldedControl {
    /// Whether the CORD-04 §5 sync floor is met for an authority action outside
    /// the roster fold (deletes, kicks, rekeys). Completeness, not authorization.
    pub fn citation_satisfied(&self, community_id: &Bytes32, actor: &str, citation: Option<&Citation>) -> bool {
        citation_satisfied(&self.heads, &self.owner, community_id, actor, citation)
    }

    pub fn is_public(&self) -> bool {
        self.registries_by_creator.values().any(|s| !s.is_empty())
    }

    /// The active pause (CORD-04 §8) at `now` (unix seconds).
    pub fn active_pause(&self, now: u64) -> Option<(u64, Option<u64>)> {
        let head = self.signals.get(SIGNAL_PAUSE)?;
        if head.content.get("paused") != Some(&Value::Bool(true)) {
            return None;
        }
        let until = head.content.get("until").and_then(Value::as_u64);
        if until.is_some_and(|u| now >= u) {
            return None;
        }
        Some((head.at, until))
    }

    /// A member's permissions in one Channel (CORD-04 §8). See
    /// [`Roster::channel_permissions`]; the Channel's privacy is the fold's.
    pub fn channel_permissions(&self, member: &str, channel_id_hex: &str) -> u64 {
        let private = self.channels.get(channel_id_hex).is_some_and(|c| c.private);
        self.roster.channel_permissions(&self.owner, member, channel_id_hex, private)
    }

    /// Whether a member manages Channels: the owner, or an unbanned holder of
    /// MANAGE_CHANNELS. Their posts stand in a restricted Channel anywhere (CORD-03 §1).
    pub fn manages_channels(&self, member: &str) -> bool {
        member == self.owner || (!self.banned.contains(member) && self.roster.has(member, perm::MANAGE_CHANNELS))
    }

    /// May `actor` hide `author`'s message in this Channel (CORD-03 §3)?
    /// MANAGE_MESSAGES resolves through the Channel's overwrites on the ranked
    /// Roster, server-wide on the legacy one; the outrank is server-wide either way.
    pub fn may_hide_in(&self, actor: &str, author: &str, channel_id_hex: &str) -> bool {
        if !self.ranked {
            return self.roster.can_act_on_member(actor, &self.owner, author, perm::MANAGE_MESSAGES);
        }
        if author == self.owner || !self.roster.outranks_member(actor, &self.owner, author) {
            return false;
        }
        self.channel_permissions(actor, channel_id_hex) & perm::MANAGE_MESSAGES != 0
    }

    /// The live Writers ledger restricting a Channel, if one does now.
    pub fn restricting_ledger(&self, channel_id_hex: &str) -> Option<&Ledger> {
        self.writers.get(channel_id_hex).filter(|l| crate::writers::ledger_restricted(l))
    }
}

pub fn citation_satisfied(heads: &HashMap<String, Head>, owner: &str, community_id: &Bytes32, actor: &str, citation: Option<&Citation>) -> bool {
    if actor == owner {
        return true;
    }
    let Some(c) = citation else { return false };
    let Some(actor_bytes) = hex32(actor) else { return false };
    let eid = grant_locator(community_id, &actor_bytes);
    if c.entity_id != eid {
        return false;
    }
    let Some(head) = heads.get(&to_hex(&eid)) else { return false };
    if head.version > c.version {
        return true;
    }
    head.version == c.version && head.hash == c.edition_hash
}

fn utf8_len_ok(s: &str, max: usize) -> bool {
    s.len() <= max
}

/// Dedupe and truncate a relay set to the recommended cap.
pub fn cap_relays(relays: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for r in relays {
        if out.len() >= MAX_COMMUNITY_RELAYS {
            break;
        }
        if !r.is_empty() && !out.contains(&r) {
            out.push(r);
        }
    }
    out
}

/// The editions `admit` keeps, plus every edition a kept one builds on
/// (transitively): an author who has since lost the permission still wrote a
/// real link of the chain, and the authorized edition citing it vouches for it.
fn admitted_chain<'a>(editions: &[&'a Edition], admit: &dyn Fn(&Edition) -> bool) -> Vec<&'a Edition> {
    let mut kept: HashSet<Bytes32> = editions.iter().filter(|e| admit(e)).map(|e| e.rumor_id).collect();
    let mut frontier: Vec<&Edition> = editions.iter().copied().filter(|e| kept.contains(&e.rumor_id)).collect();
    while !frontier.is_empty() {
        let cited: HashSet<Bytes32> = frontier.iter().filter_map(|e| e.prev).collect();
        frontier = editions.iter().copied().filter(|e| !kept.contains(&e.rumor_id) && cited.contains(&e.self_hash)).collect();
        for e in &frontier {
            kept.insert(e.rumor_id);
        }
    }
    editions.iter().copied().filter(|e| kept.contains(&e.rumor_id)).collect()
}

/// Order one entity's editions into head candidates: the chain-verified head
/// first, then the rest version-descending (Armada's `headCandidates`). With
/// `admit`, editions it refuses never enter the walk unless an admitted one
/// builds on them: any keyholder can seal a skipped version, and counting junk
/// would freeze the entity.
fn head_candidates<'a>(editions: &[&'a Edition], floor: Option<&Head>, snapshot: bool, gapped_out: &mut bool, admit: Option<&dyn Fn(&Edition) -> bool>) -> Vec<&'a Edition> {
    let walked: Vec<&Edition> = match admit {
        Some(a) => admitted_chain(editions, a),
        None => editions.to_vec(),
    };
    let mut ordered: Vec<&Edition> = Vec::new();
    let mut seen: HashSet<Bytes32> = HashSet::new();
    let mut gapped = false;
    if snapshot {
        match bootstrap_head(&walked, floor.map_or(0, |f| f.version)) {
            Some(idx) => {
                ordered.push(walked[idx]);
                seen.insert(walked[idx].rumor_id);
            }
            None if floor.is_some() => gapped = true,
            None => {}
        }
    } else {
        let r = fold_chain(&walked, floor.map_or(0, |f| f.version), floor.map(|f| &f.hash));
        gapped = floor.is_some() && (r.gap || r.head.is_none());
        if let (Some(h), false) = (r.head, gapped) {
            ordered.push(walked[h]);
            seen.insert(walked[h].rumor_id);
        }
    }
    *gapped_out = gapped;
    let mut rest: Vec<&Edition> = walked
        .iter()
        .copied()
        .filter(|e| {
            if !seen.insert(e.rumor_id) {
                return false;
            }
            if let Some(f) = floor {
                if e.version < f.version {
                    return false;
                }
                if gapped && (e.version > f.version || e.self_hash != f.hash) {
                    return false;
                }
            }
            true
        })
        .collect();
    rest.sort_by(|a, b| b.version.cmp(&a.version).then(a.rumor_id.cmp(&b.rumor_id)));
    ordered.extend(rest);
    ordered
}

/// Record `e` as its coordinate's head. A Roster or Banlist head is never
/// replaced by another kind's edition at the same coordinate (Armada
/// `HeadSlots`): pins are read with no coordinate check, so without this a
/// PIN_MESSAGES holder could aim a Pin List at a moderator's Grant and
/// replace the head their citations are checked against, failing their
/// hides or passing stale ones.
fn settle(heads: &mut HashMap<String, Head>, head_editions: &mut HashMap<String, Edition>, e: &Edition) {
    let authority = |vsk: &str| AUTHORITY_VSKS.contains(&vsk);
    if head_editions.get(&e.eid_hex()).is_some_and(|prev| authority(&prev.vsk) && !authority(&e.vsk)) {
        return;
    }
    heads.insert(e.eid_hex(), Head { version: e.version, hash: e.self_hash });
    head_editions.insert(e.eid_hex(), e.clone());
}

/// Pick the first candidate passing `gate`; equal-version siblings are settled
/// by authority (`rank_of`) rather than the grindable rumor id.
fn pick_head<'a>(
    candidates: &[&'a Edition],
    heads: &mut HashMap<String, Head>,
    head_editions: &mut HashMap<String, Edition>,
    gate: &dyn Fn(&Edition) -> bool,
    rank_of: &dyn Fn(&str) -> i64,
) -> Option<&'a Edition> {
    let mut head: Option<&Edition> = None;
    for &p in candidates {
        if !gate(p) {
            continue;
        }
        match head {
            None => head = Some(p),
            Some(h) => {
                if p.version != h.version {
                    break;
                }
                if rank_of(&p.author) < rank_of(&h.author) {
                    head = Some(p);
                }
            }
        }
    }
    let head = head?;
    settle(heads, head_editions, head);
    Some(head)
}

/// Group candidates by version, ascending.
fn version_groups<T, F: Fn(&T) -> u64>(items: &[T], version: F) -> Vec<Vec<&T>> {
    let mut sorted: Vec<&T> = items.iter().collect();
    sorted.sort_by_key(|t| version(t));
    let mut groups: Vec<Vec<&T>> = Vec::new();
    for t in sorted {
        match groups.last_mut() {
            Some(g) if version(g[0]) == version(t) => g.push(t),
            _ => groups.push(vec![t]),
        }
    }
    groups
}

struct RoleCand<'a> {
    role: Role,
    e: &'a Edition,
}

struct GrantCand<'a> {
    grant: MemberGrant,
    e: &'a Edition,
}

fn rank(roster: &Roster, owner: &str, author: &str) -> i64 {
    if author == owner { -1 } else { i64::from(roster.highest_position(author).unwrap_or(BENEATH_EVERY_ROLE)) }
}

/// The legacy delegation fixpoint (CORD-04 §2): from the owner outward, admit
/// role and grant entities whose signer is authorized, until stable. Editing
/// acts on a target: a non-owner draws only on bits from Roles strictly above
/// both what an edition mints and what it replaces (downward support).
fn authorize_delegation(
    role_cands: &BTreeMap<String, Vec<RoleCand>>,
    grant_cands: &BTreeMap<String, Vec<GrantCand>>,
    community_id: &Bytes32,
    owner: &str,
    heads: &mut HashMap<String, Head>,
    head_editions: &mut HashMap<String, Edition>,
    excluded: &HashSet<String>,
) -> Roster {
    let mut roster = Roster::default();
    let mut settled_roles: HashSet<&str> = HashSet::new();
    let mut settled_grants: HashSet<&str> = HashSet::new();
    let mut grant_eid_of_member: HashMap<&str, &str> = HashMap::new();
    for (eid, cands) in grant_cands {
        if let Some(c) = cands.first() {
            grant_eid_of_member.insert(c.grant.member.as_str(), eid.as_str());
        }
    }

    let mut roles_frozen = false;
    let mut ranks_frozen = false;
    let mut changed = true;

    while changed {
        changed = false;

        let rank_pending = |author: &str, self_eid: Option<&str>, settled_grants: &HashSet<&str>| -> bool {
            if author == owner {
                return false;
            }
            match grant_eid_of_member.get(author) {
                Some(aeid) => Some(*aeid) != self_eid && !settled_grants.contains(aeid),
                None => false,
            }
        };
        // A citation is a sync floor, not the verdict: one that doesn't resolve
        // refuses, while an uncited edition declared no floor to wait for.
        let cited_ok = |heads: &HashMap<String, Head>, e: &Edition| {
            e.authority.is_none() || citation_satisfied(heads, owner, community_id, &e.author, e.authority.as_ref())
        };

        for (eid, cands) in role_cands {
            if settled_roles.contains(eid.as_str()) {
                continue;
            }
            if !ranks_frozen && cands.iter().any(|c| rank_pending(&c.e.author, None, &settled_grants)) {
                continue;
            }
            let mut admissible: HashSet<Bytes32> = HashSet::new();
            let mut standing: Option<u32> = None;
            for group in version_groups(cands, |c| c.e.version) {
                let mut group = group;
                group.sort_by(|a, b| rank(&roster, owner, &a.e.author).cmp(&rank(&roster, owner, &b.e.author)).then(a.e.rumor_id.cmp(&b.e.rumor_id)));
                for c in group {
                    let author = c.e.author.as_str();
                    let support = roster.permissions_above(author, c.role.position.min(standing.unwrap_or(u32::MAX)));
                    let ok = author == owner || (c.role.position != 0 && support & perm::MANAGE_ROLES != 0 && c.role.permissions & !support == 0);
                    if !ok || !cited_ok(heads, c.e) {
                        continue;
                    }
                    admissible.insert(c.e.rumor_id);
                    standing = Some(c.role.position);
                    break;
                }
            }
            let Some(pick) = cands.iter().find(|c| admissible.contains(&c.e.rumor_id)) else { continue };
            roster.roles.push(pick.role.clone());
            settled_roles.insert(eid.as_str());
            settle(heads, head_editions, pick.e);
            changed = true;
        }

        for (eid, cands) in grant_cands {
            if settled_grants.contains(eid.as_str()) {
                continue;
            }
            let role_pending = |rid: &str| role_cands.contains_key(rid) && !settled_roles.contains(rid);
            if !roles_frozen && cands.iter().any(|c| c.grant.role_ids.iter().any(|r| role_pending(r))) {
                continue;
            }
            if !ranks_frozen && cands.iter().any(|c| rank_pending(&c.e.author, Some(eid.as_str()), &settled_grants)) {
                continue;
            }
            let mut admissible: HashSet<Bytes32> = HashSet::new();
            let mut standing: Option<u32> = None;
            for group in version_groups(cands, |c| c.e.version) {
                let mut group = group;
                group.sort_by(|a, b| rank(&roster, owner, &a.e.author).cmp(&rank(&roster, owner, &b.e.author)).then(a.e.rumor_id.cmp(&b.e.rumor_id)));
                for c in group {
                    let author = c.e.author.as_str();
                    // Judged on the Roles it names that resolve, never on whether the rest do.
                    let positions: Vec<u32> = c.grant.role_ids.iter().filter_map(|rid| roster.role(rid).map(|r| r.position)).collect();
                    let reach = positions.iter().copied().chain(standing).min().unwrap_or(u32::MAX);
                    // An uncited Grant naming no published Role is a strip, and a strip must cite.
                    let strip = c.grant.role_ids.iter().all(|rid| !role_cands.contains_key(rid));
                    let ok = author == owner
                        || (c.grant.member != owner && roster.permissions_above(author, reach) & perm::MANAGE_ROLES != 0 && !(c.e.authority.is_none() && strip));
                    if !ok || !cited_ok(heads, c.e) {
                        continue;
                    }
                    admissible.insert(c.e.rumor_id);
                    standing = positions.iter().copied().min();
                    break;
                }
            }
            let Some(pick) = cands.iter().find(|c| admissible.contains(&c.e.rumor_id)) else { continue };
            // A Grant to a banned member links its chain but confers nothing (CORD-04 §4).
            if !excluded.contains(&pick.grant.member) {
                roster.grants.push(pick.grant.clone());
            }
            settled_grants.insert(eid.as_str());
            settle(heads, head_editions, pick.e);
            changed = true;
        }

        if !changed && !roles_frozen {
            roles_frozen = true;
            changed = true;
        } else if !changed && !ranks_frozen {
            ranks_frozen = true;
            changed = true;
        }
    }

    if roster.roles.len() > MAX_ROLES_PER_COMMUNITY {
        roster.roles.sort_by(|a, b| a.role_id.cmp(&b.role_id));
        roster.roles.truncate(MAX_ROLES_PER_COMMUNITY);
    }
    roster
}

fn parse_metadata(content: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(content).ok()?;
    let name = v.get("name")?.as_str()?;
    if !utf8_len_ok(name, NAME_MAX_BYTES) {
        return None;
    }
    match v.get("description") {
        None => {}
        Some(Value::String(d)) if utf8_len_ok(d, DESCRIPTION_MAX_BYTES) => {}
        _ => return None,
    }
    Some(v)
}

/// A Channel edition's content (CORD-03 §2), or `None` when it breaks its form.
/// A Private Channel may carry the SEALED form, whose details only its key opens.
pub fn read_channel_content(content: &str) -> Option<(serde_json::Map<String, Value>, Option<SealedChannelMeta>)> {
    let raw: Value = serde_json::from_str(content).ok()?;
    let c = raw.as_object()?;
    if c.get("deleted").is_some_and(|d| !d.is_boolean()) {
        return None;
    }
    if c.get("private") == Some(&Value::Bool(true))
        && let Some(sealed) = c.get("sealed").and_then(Value::as_str) {
            let epoch = c.get("epoch")?.as_str().and_then(crate::parse_tag_decimal)?;
            let mut meta = serde_json::Map::new();
            meta.insert("name".into(), Value::String(String::new()));
            meta.insert("private".into(), Value::Bool(true));
            if c.get("deleted") == Some(&Value::Bool(true)) {
                meta.insert("deleted".into(), Value::Bool(true));
            }
            return Some((meta, Some(SealedChannelMeta { epoch, sealed: sealed.to_owned(), prev_hex: None })));
        }
    if !c.get("private").is_some_and(Value::is_boolean) {
        return None;
    }
    Some((sanitize_channel_fields(c.clone())?, None))
}

/// A Category edition's content (CORD-03 §4), or `None` when it breaks its form.
fn read_category(content: &str) -> Option<FoldedCategory> {
    let raw: Value = serde_json::from_str(content).ok()?;
    let c = raw.as_object()?;
    if c.get("deleted") == Some(&Value::Bool(true)) {
        return Some(FoldedCategory { id_hex: String::new(), name: String::new(), position: None, deleted: true });
    }
    Some(FoldedCategory {
        id_hex: String::new(),
        name: c.get("name").and_then(Value::as_str).map(cut_name).unwrap_or_default(),
        position: c.get("position").and_then(Value::as_str).filter(|p| is_rank_key(p)).map(str::to_owned),
        deleted: false,
    })
}

fn folded_channel(eid: &str, raw: Value, ever_deleted: bool, sealed: Option<SealedChannelMeta>) -> FoldedChannel {
    let custom = raw.get("custom");
    let category = custom
        .and_then(|c| c.get("armada.category"))
        .and_then(|c| c.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|n| !n.is_empty() && n.len() <= NAME_MAX_BYTES)
        .map(str::to_owned);
    let position = custom.and_then(|c| c.get("armada.order")).and_then(|o| o.get("position")).and_then(Value::as_f64).filter(|p| p.is_finite());
    let view = raw.get("view").and_then(Value::as_str).map(str::to_owned);
    FoldedChannel {
        channel_id_hex: eid.to_owned(),
        name: raw.get("name").and_then(Value::as_str).unwrap_or_default().to_owned(),
        private: raw.get("private") == Some(&Value::Bool(true)),
        deleted: raw.get("deleted") == Some(&Value::Bool(true)) || ever_deleted,
        forum: view.as_deref() == Some("forum"),
        view,
        topic: raw.get("topic").and_then(Value::as_str).map(str::to_owned),
        category,
        category_id: raw.get("category").and_then(Value::as_str).map(str::to_lowercase),
        position,
        rank: raw.get("position").and_then(Value::as_str).map(str::to_owned),
        sealed,
        raw,
    }
}

fn validate_signal(signal_id: &str, content: &str, created_at: u64) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(content) else { return false };
    if !v.is_object() {
        return false;
    }
    if signal_id == SIGNAL_PAUSE {
        if !v.get("paused").is_some_and(Value::is_boolean) {
            return false;
        }
        if let Some(until) = v.get("until") {
            match until.as_u64() {
                Some(u) if u > 0 && u <= created_at + MAX_PAUSE_UNTIL_SECS => {}
                _ => return false,
            }
        }
        return true;
    }
    false
}

/// The most entries a Banlist stands for (CORD-04 §4).
pub const MAX_BANLIST: usize = 500;
/// The most Categories a reader folds (CORD-03 §4).
pub const MAX_CATEGORIES: usize = 100;

/// Replay opened control editions into current state. `prior_heads` floors a
/// tracking client's legacy fold; `snapshot_ids` (rumor ids that arrived under
/// the current post-Refounding epoch) switch those entities to bootstrap
/// folding. The ranked Roster is always folded fresh (see `roster.rs`).
pub fn fold_control(
    editions: &[Edition],
    community_id: &Bytes32,
    owner: &str,
    prior_heads: Option<&HashMap<String, Head>>,
    snapshot_ids: Option<&HashSet<Bytes32>>,
) -> FoldedControl {
    // CORD-04 §1: a marked edition bound to another Community is refused (a
    // replay from elsewhere), and so is an unmarked edition of a kind no older
    // client wrote.
    let binding = edition_binding(community_id);
    let refs: Vec<&Edition> = editions
        .iter()
        .filter(|e| match &e.binding {
            Some(b) => *b == binding,
            None => !ALWAYS_MARKED_VSKS.contains(&e.vsk.as_str()),
        })
        .collect();
    let first = fold_once(&refs, &refs, community_id, owner, prior_heads, snapshot_ids, &HashSet::new());
    // The owner is supreme: never bannable, or a BAN holder could silence them everywhere.
    let banned: HashSet<String> = first.banned.iter().filter(|pk| pk.as_str() != owner).cloned().collect();
    if banned.is_empty() {
        return FoldedControl { banned, ..first };
    }
    // A ban takes what its target wrote, except what a Tenure keeps (CORD-04 §4,
    // §9). The Roster still links what it refuses, so it folds every edition
    // with the banned excluded.
    let kept: Vec<&Edition> = refs.iter().copied().filter(|e| !banned.contains(&e.author) || is_listed(&first.tenure, &e.author, &to_hex(&e.self_hash))).collect();
    let mut second = fold_once(&kept, &refs, community_id, owner, prior_heads, snapshot_ids, &banned);
    // The Banlist's head is the one judged before the ban took anyone's support.
    let banlist_eid = to_hex(&banlist_locator(community_id));
    match (first.heads.get(&banlist_eid), first.head_editions.get(&banlist_eid)) {
        (Some(h), Some(e)) => {
            second.heads.insert(banlist_eid.clone(), *h);
            second.head_editions.insert(banlist_eid, e.clone());
        }
        _ => {
            second.heads.remove(&banlist_eid);
            second.head_editions.remove(&banlist_eid);
        }
    }
    second.banned = banned;
    second.banned_at = first.banned_at;
    second.incomplete = first.incomplete;
    second
}

/// Ordered head candidates per entity of one vsk, floored per prior head.
fn candidates<'e>(
    source: &HashMap<String, BTreeMap<String, Vec<&'e Edition>>>,
    vsk: &str,
    admit: Option<&dyn Fn(&Edition) -> bool>,
    gap_held: &mut HashSet<String>,
    prior_heads: Option<&HashMap<String, Head>>,
    snapshot_ids: Option<&HashSet<Bytes32>>,
) -> BTreeMap<String, Vec<&'e Edition>> {
    let mut out = BTreeMap::new();
    if let Some(m) = source.get(vsk) {
        for (eid, list) in m {
            let snapshot = snapshot_ids.is_some_and(|ids| list.iter().any(|e| ids.contains(&e.rumor_id)));
            let mut gapped = false;
            let cands = head_candidates(list, prior_heads.and_then(|h| h.get(eid)), snapshot, &mut gapped, admit);
            if gapped {
                gap_held.insert(eid.clone());
            }
            out.insert(eid.clone(), cands);
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn fold_once<'e>(
    editions: &[&'e Edition],
    roster_editions: &[&'e Edition],
    community_id: &Bytes32,
    owner: &str,
    prior_heads: Option<&HashMap<String, Head>>,
    snapshot_ids: Option<&HashSet<Bytes32>>,
    excluded: &HashSet<String>,
) -> FoldedControl {
    let cid_hex = to_hex(community_id);
    let group = |list: &[&'e Edition]| {
        let mut out: HashMap<String, BTreeMap<String, Vec<&'e Edition>>> = HashMap::new();
        for &e in list {
            out.entry(e.vsk.clone()).or_default().entry(e.eid_hex()).or_default().push(e);
        }
        out
    };
    let by_vsk = group(editions);
    // The Banlist, overwrites and syncs still link a banned member's editions, refused.
    let by_vsk_linked = group(roster_editions);
    let mut heads: HashMap<String, Head> = HashMap::new();
    let mut head_editions: HashMap<String, Edition> = HashMap::new();
    let mut gap_held: HashSet<String> = HashSet::new();

    let candidates_of = |source: &HashMap<String, BTreeMap<String, Vec<&'e Edition>>>, vsk: &str, admit: Option<&dyn Fn(&Edition) -> bool>, gap_held: &mut HashSet<String>| {
        candidates(source, vsk, admit, gap_held, prior_heads, snapshot_ids)
    };

    // 1. The Roster: the vsk-13 one once an owner-rooted `@everyone` stands, the
    // legacy fixpoint before.
    let ranked = roster_activated(roster_editions, community_id, owner);
    let mut sealed: SealedBy = HashMap::new();
    let mut roster = if ranked {
        let folded = fold_ranked_roster(roster_editions, community_id, owner, excluded);
        for (_, e) in folded.heads {
            settle(&mut heads, &mut head_editions, e);
        }
        sealed = folded.sealed;
        folded.roster
    } else {
        let mut role_cands: BTreeMap<String, Vec<RoleCand>> = BTreeMap::new();
        for (eid, cands) in candidates_of(&by_vsk, kinds::VSK_ROLE, None, &mut gap_held) {
            let parsed: Vec<RoleCand> = cands.into_iter().filter_map(|e| Role::from_json(&e.content).filter(|r| r.role_id == eid).map(|role| RoleCand { role, e })).collect();
            if !parsed.is_empty() {
                role_cands.insert(eid, parsed);
            }
        }
        let mut grant_cands: BTreeMap<String, Vec<GrantCand>> = BTreeMap::new();
        for (eid, cands) in candidates_of(&by_vsk, kinds::VSK_GRANT, None, &mut gap_held) {
            let parsed: Vec<GrantCand> = cands
                .into_iter()
                .filter_map(|e| {
                    let grant = MemberGrant::from_json(&e.content)?;
                    let member = hex32(&grant.member)?;
                    (to_hex(&grant_locator(community_id, &member)) == eid).then_some(GrantCand { grant, e })
                })
                .collect();
            if !parsed.is_empty() {
                grant_cands.insert(eid, parsed);
            }
        }
        authorize_delegation(&role_cands, &grant_cands, community_id, owner, &mut heads, &mut head_editions, excluded)
    };

    // Citations name Grant heads, which the Roster pass has now settled for good.
    let grant_heads = heads.clone();
    let roster_ref = roster.clone();
    let rank_of = |author: &str| rank(&roster_ref, owner, author);
    // A Tenure-listed edition stands without its citation (CORD-04 §9).
    let listed = |p: &Edition| ranked && is_listed(&sealed, &p.author, &to_hex(&p.self_hash));
    let citation_ok = |p: &Edition| listed(p) || citation_satisfied(&grant_heads, owner, community_id, &p.author, p.authority.as_ref());
    // Whether `p`'s signer may write it under `bits`, judged on the bit alone:
    // the Roster as it stands, `@everyone`'s bits counted, or a sealed standing.
    let may = |p: &Edition, bits: u64| {
        roster_ref.is_authorized(&p.author, owner, bits) || (ranked && seal_of(&sealed, &p.author, &to_hex(&p.self_hash), BENEATH_EVERY_ROLE) & bits == bits)
    };
    let holders = |bits: u64| move |p: &Edition| may(p, bits) && citation_ok(p);

    // 2. Metadata (vsk 0): the Community's own entity and an authorized actor.
    let mut metadata = None;
    {
        let admit = holders(perm::MANAGE_METADATA);
        let cands = candidates_of(&by_vsk, kinds::VSK_METADATA, Some(&admit), &mut gap_held).remove(&cid_hex).unwrap_or_default();
        let gate = |p: &Edition| may(p, perm::MANAGE_METADATA) && citation_ok(p) && parse_metadata(&p.content).is_some();
        if let Some(head) = pick_head(&cands, &mut heads, &mut head_editions, &gate, &rank_of) {
            let raw = parse_metadata(&head.content).expect("gated");
            let relays = raw
                .get("relays")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect::<Vec<_>>())
                .unwrap_or_default();
            metadata = Some(CommunityMetadata {
                name: raw["name"].as_str().unwrap_or_default().to_owned(),
                description: raw.get("description").and_then(Value::as_str).map(str::to_owned),
                relays: cap_relays(relays),
                icon: ImagePointer::from_value(raw.get("icon")),
                banner: ImagePointer::from_value(raw.get("banner")),
                message_expiration: raw.get("message_expiration").and_then(Value::as_u64).filter(|s| *s > 0),
                raw,
            });
        }
    }

    // An edition aimed at another entity's coordinate is no Channel or Category
    // (CORD-03 §2, §4): the Community's own, `@everyone`'s, the Banlist's, or one
    // an edition of another kind claims, signed by a holder of that kind's bit.
    let claim_bit = |vsk: &str| -> Option<u64> {
        Some(match vsk {
            kinds::VSK_METADATA => perm::MANAGE_METADATA,
            kinds::VSK_CHANNEL | VSK_CATEGORY | VSK_WRITERS => perm::MANAGE_CHANNELS,
            kinds::VSK_ROLE | kinds::VSK_GRANT | VSK_RANKED_ROLE | VSK_ACL | VSK_TENURE | VSK_SYNC => perm::MANAGE_ROLES,
            kinds::VSK_BANLIST => perm::BAN,
            kinds::VSK_INVITE_REGISTRY => perm::CREATE_INVITE,
            kinds::VSK_PINS => perm::PIN_MESSAGES,
            _ => return None,
        })
    };
    let taken_by = |kind: &str| -> HashSet<String> {
        let mut out: HashSet<String> = [cid_hex.clone(), to_hex(&everyone_locator(community_id)), to_hex(&banlist_locator(community_id))].into_iter().collect();
        for (vsk, by_eid) in &by_vsk {
            let Some(bit) = claim_bit(vsk) else { continue };
            if vsk == kind {
                continue;
            }
            for (eid, list) in by_eid {
                if list.iter().any(|e| roster_ref.is_authorized(&e.author, owner, bit)) {
                    out.insert(eid.clone());
                }
            }
        }
        out
    };

    // 3. Channels (vsk 2), each gated by MANAGE_CHANNELS. On the ranked Roster an
    // unmarked edition counts only for a Channel the switch listed, so an old
    // client can't add Channels the new rules never judged.
    let legacy_channels: Option<HashSet<String>> = if ranked { roster.legacy_channels.as_ref().map(|l| l.iter().cloned().collect()) } else { None };
    let not_channels = taken_by(kinds::VSK_CHANNEL);
    let mut channels = BTreeMap::new();
    {
        let admit = holders(perm::MANAGE_CHANNELS);
        for (eid, cands) in candidates_of(&by_vsk, kinds::VSK_CHANNEL, Some(&admit), &mut gap_held) {
            if not_channels.contains(&eid) {
                continue;
            }
            let gate = |p: &Edition| {
                may(p, perm::MANAGE_CHANNELS) && citation_ok(p) && !(legacy_channels.as_ref().is_some_and(|l| p.binding.is_none() && !l.contains(&eid)))
            };
            // A malformed edition still links and stands as the head, applying
            // nothing: the Channel reads as the newest standing edition with its form.
            let Some(head) = pick_head(&cands, &mut heads, &mut head_editions, &gate, &rank_of) else { continue };
            let applied = if read_channel_content(&head.content).is_some() {
                Some(head)
            } else {
                cands.iter().copied().find(|p| p.version <= head.version && gate(p) && read_channel_content(&p.content).is_some())
            };
            let Some(applied) = applied else { continue };
            let (meta, sealed_meta) = read_channel_content(&applied.content).expect("checked");
            // Deletion is terminal across every served edition the gate admits.
            let deletions: Vec<&Edition> = by_vsk
                .get(kinds::VSK_CHANNEL)
                .and_then(|m| m.get(&eid))
                .map(|l| l.iter().copied().filter(|p| gate(p) && read_channel_content(&p.content).is_some_and(|(m, _)| m.get("deleted") == Some(&Value::Bool(true)))).collect())
                .unwrap_or_default();
            if let Some(d) = deletions.iter().copied().min_by(|a, b| b.version.cmp(&a.version).then(a.rumor_id.cmp(&b.rumor_id))) {
                settle(&mut heads, &mut head_editions, d);
            }
            let sealed_meta = sealed_meta.map(|s| SealedChannelMeta { prev_hex: applied.prev.map(|p| to_hex(&p)), ..s });
            channels.insert(eid.clone(), folded_channel(&eid, Value::Object(meta), !deletions.is_empty(), sealed_meta));
        }
    }

    // 4. Banlist (vsk 4): the one anti-roster; an unauthorized head → empty.
    let mut banned = HashSet::new();
    let mut banned_at: HashMap<String, u64> = HashMap::new();
    {
        let eid = to_hex(&banlist_locator(community_id));
        let parse_list = |p: &Edition| strict::parse_string_array(&p.content).map(|l| l.into_iter().map(|s| s.to_lowercase()).collect::<Vec<_>>());
        let is_key = |pk: &str| pk.len() == 64 && pk.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
        let sealed_ban = |p: &Edition| ranked && seal_of(&sealed, &p.author, &to_hex(&p.self_hash), BENEATH_EVERY_ROLE) & perm::BAN != 0;
        // Banning acts on a member: BAN and a strict outrank, so a Moderator can't ban Admins.
        let entitled = |author: &str, pk: &str, p: &Edition| {
            roster_ref.can_act_on_member(author, owner, pk, perm::BAN)
                || (ranked && pk != owner && seal_of(&sealed, author, &to_hex(&p.self_hash), roster_ref.highest_position(pk).unwrap_or(BENEATH_EVERY_ROLE)) & perm::BAN != 0)
        };
        // On the ranked Roster the bit must come from the author's Roles:
        // `@everyone`'s bits author no Banlist (CORD-04 §2).
        let bans = |p: &Edition| {
            if ranked {
                p.author == owner || roster_ref.permissions_above(&p.author, BENEATH_EVERY_ROLE) & perm::BAN != 0 || sealed_ban(p)
            } else {
                roster_ref.is_authorized(&p.author, owner, perm::BAN)
            }
        };
        let admissible = |p: &Edition| bans(p) && (sealed_ban(p) || citation_ok(p)) && parse_list(p).is_some();
        let cands = candidates_of(&by_vsk_linked, kinds::VSK_BANLIST, Some(&admissible), &mut gap_held).remove(&eid).unwrap_or_default();
        // The head's list alone, each entry its author may name, the first 500.
        if let Some(head) = pick_head(&cands, &mut heads, &mut head_editions, &admissible, &rank_of) {
            for pk in parse_list(head).unwrap_or_default().into_iter().filter(|pk| entitled(&head.author, pk, head)).take(MAX_BANLIST) {
                if is_key(&pk) {
                    banned.insert(pk);
                }
            }
        }
        // Ban history: the newest admissible edition naming each npub its author may ban.
        for p in by_vsk_linked.get(kinds::VSK_BANLIST).and_then(|m| m.get(&eid)).into_iter().flatten() {
            if !admissible(p) {
                continue;
            }
            for pk in parse_list(p).unwrap_or_default() {
                if pk == owner || !is_key(&pk) || !entitled(&p.author, &pk, p) {
                    continue;
                }
                let e = banned_at.entry(pk).or_insert(p.created_at);
                *e = (*e).max(p.created_at);
            }
        }
    }

    // 5. Invite registries (vsk 8): each creator's own list, while they hold
    // CREATE_INVITE. The bit alone, no citation (Vector reads no floor here).
    let mut live_invite_links = HashSet::new();
    let mut registries_by_creator = HashMap::new();
    {
        let own = |p: &Edition| hex32(&p.author).is_some_and(|a| to_hex(&invite_links_locator(community_id, &a)) == p.eid_hex());
        let admit = |p: &Edition| may(p, perm::CREATE_INVITE) && own(p);
        for (_, cands) in candidates_of(&by_vsk, kinds::VSK_INVITE_REGISTRY, Some(&admit), &mut gap_held) {
            let gate = |p: &Edition| own(p) && may(p, perm::CREATE_INVITE) && serde_json::from_str::<Value>(&p.content).is_ok_and(|v| v.is_array());
            let Some(head) = pick_head(&cands, &mut heads, &mut head_editions, &gate, &rank_of) else { continue };
            let list: Vec<String> = serde_json::from_str::<Value>(&head.content)
                .ok()
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default()
                .iter()
                .filter_map(Value::as_str)
                .filter(|s| is_hex64(s))
                .map(str::to_owned)
                .collect();
            live_invite_links.extend(list.iter().map(|s| s.to_lowercase()));
            registries_by_creator.insert(head.author.clone(), list);
        }
    }

    // 6. Pin Lists (vsk 11), gated by PIN_MESSAGES; content carried verbatim.
    let mut pin_lists = HashMap::new();
    {
        let admit = holders(perm::PIN_MESSAGES);
        for (eid, cands) in candidates_of(&by_vsk, kinds::VSK_PINS, Some(&admit), &mut gap_held) {
            if let Some(head) = pick_head(&cands, &mut heads, &mut head_editions, &admit, &rank_of) {
                pin_lists.insert(eid, (head.content.clone(), head.author.clone()));
            }
        }
    }

    // 7. Community Signals (vsk 12): only implemented signal ids have a coordinate.
    let mut signals = HashMap::new();
    {
        let admit = |p: &Edition| SIGNAL_GATES.iter().any(|(_, bits)| may(p, *bits)) && citation_ok(p);
        let signal_cands = candidates_of(&by_vsk, kinds::VSK_SIGNALS, Some(&admit), &mut gap_held);
        for &(signal_id, gate_bits) in SIGNAL_GATES {
            let cands = signal_cands.get(&to_hex(&signal_locator(community_id, signal_id))).cloned().unwrap_or_default();
            let gate = |p: &Edition| may(p, gate_bits) && citation_ok(p) && validate_signal(signal_id, &p.content, p.created_at);
            if let Some(head) = pick_head(&cands, &mut heads, &mut head_editions, &gate, &rank_of) {
                signals.insert(
                    signal_id.to_owned(),
                    FoldedSignal { content: serde_json::from_str(&head.content).unwrap_or(Value::Null), author: head.author.clone(), at: head.created_at },
                );
            }
        }
    }

    // 8. On the ranked Roster: Writers ledgers (vsk 18), overwrites (vsk 14) and syncs (vsk 17).
    let mut writers: HashMap<String, Ledger> = HashMap::new();
    if ranked {
        let now_ms = crate::now_secs() * 1000;
        for (eid, list) in by_vsk.get(VSK_WRITERS).into_iter().flatten() {
            let ledger_of = |p: &Edition| parse_ledger(&p.content).filter(|l| hex32(&l.channel).is_some_and(|c| to_hex(&writers_locator(community_id, &c)) == *eid));
            let by_hash: HashMap<Bytes32, &Edition> = list.iter().rev().map(|e| (e.self_hash, *e)).collect();
            // Judged along the chain: an edition stands only on a predecessor
            // that stands, appending exactly one entry dated within ten minutes
            // of its own time and at most an hour past the clock, a writer entry
            // naming its signer as minter (CORD-03 §1).
            let memo: std::cell::RefCell<HashMap<Bytes32, bool>> = Default::default();
            fn judge(p: &Edition, memo: &std::cell::RefCell<HashMap<Bytes32, bool>>, by_hash: &HashMap<Bytes32, &Edition>, base: &dyn Fn(&Edition) -> Option<Ledger>) -> bool {
                if let Some(v) = memo.borrow().get(&p.rumor_id) {
                    return *v;
                }
                memo.borrow_mut().insert(p.rumor_id, false);
                let ok = (|| {
                    let l = base(p)?;
                    match p.prev {
                        None => (p.version == 1 && l.entries.len() == 1 && l.retired.is_empty()).then_some(()),
                        Some(prev) => match by_hash.get(&prev) {
                            // A predecessor not served: a fresh reader takes the link on trust.
                            None => Some(()),
                            Some(before) => {
                                let before_l = parse_ledger(&before.content)?;
                                (judge(before, memo, by_hash, base) && ledger_extends(&l, &before_l)).then_some(())
                            }
                        },
                    }
                })()
                .is_some();
                memo.borrow_mut().insert(p.rumor_id, ok);
                ok
            }
            let base = |p: &Edition| -> Option<Ledger> {
                let l = ledger_of(p)?;
                if !may(p, perm::MANAGE_CHANNELS) || !citation_ok(p) {
                    return None;
                }
                let last = l.entries.last()?;
                if last.at.abs_diff(p.created_at * 1000) > LEDGER_ENTRY_SKEW_MS || last.at > now_ms + LEDGER_HORIZON_MS {
                    return None;
                }
                if let Spell::Writer { by, .. } = &last.spell
                    && *by != p.author {
                        return None;
                    }
                Some(l)
            };
            let gate = |p: &Edition| judge(p, &memo, &by_hash, &base);
            let mut gapped = false;
            let ordered = head_candidates(list, None, false, &mut gapped, Some(&gate));
            if let Some(head) = pick_head(&ordered, &mut heads, &mut head_editions, &gate, &|_| 0)
                && let Some(l) = ledger_of(head) {
                    writers.insert(l.channel.clone(), l);
                }
        }

        // Overwrites, each judged on itself by downward support (CORD-04 §8).
        let mut overwrites: Vec<Overwrite> = Vec::new();
        for (eid, all) in by_vsk_linked.get(VSK_ACL).into_iter().flatten() {
            let overwrite_of = |p: &Edition| parse_overwrite(&p.content).filter(|o| overwrite_locator(community_id, &o.scope, &o.target).is_some_and(|l| to_hex(&l) == *eid));
            let list: Vec<&Edition> = all.iter().copied().filter(|p| overwrite_of(p).is_some()).collect();
            let ok = |p: &Edition| overwrite_of(p).is_some_and(|o| overwrite_authorized(&roster_ref, owner, &banned, &sealed, &o, &p.author, &to_hex(&p.self_hash)));
            let mut gapped = false;
            let ordered = head_candidates(&list, None, false, &mut gapped, Some(&ok));
            if let Some(o) = pick_head(&ordered, &mut heads, &mut head_editions, &ok, &rank_of).and_then(overwrite_of)
                && (o.allow != 0 || o.deny != 0) {
                    overwrites.push(o);
                }
        }
        roster.overwrites = overwrites;

        // Syncs: the signer must be able to write every overwrite the sync swaps,
        // the Category it leaves included (named by its served predecessor).
        let mut syncs: HashMap<String, String> = HashMap::new();
        for (eid, all) in by_vsk_linked.get(VSK_SYNC).into_iter().flatten() {
            let sync_of = |p: &Edition| parse_sync(&p.content).filter(|(c, _)| hex32(c).is_some_and(|c| to_hex(&sync_locator(community_id, &c)) == *eid));
            let list: Vec<&Edition> = all.iter().copied().filter(|p| sync_of(p).is_some()).collect();
            let ok = |p: &Edition| {
                let Some((channel, category)) = sync_of(p) else { return false };
                let hash = to_hex(&p.self_hash);
                if banned.contains(&p.author) && p.author != owner && !is_listed(&sealed, &p.author, &hash) {
                    return false;
                }
                let left = match p.prev {
                    None => None,
                    Some(prev) => match list.iter().find(|x| x.self_hash == prev) {
                        None => return false,
                        Some(x) => sync_of(x).and_then(|(_, c)| c),
                    },
                };
                let scopes: Vec<&str> = std::iter::once(channel.as_str()).chain(category.as_deref()).chain(left.as_deref()).collect();
                may_swap_overwrites(&roster, owner, &p.author, &scopes, &|r| seal_of(&sealed, &p.author, &hash, r))
            };
            let mut gapped = false;
            let ordered = head_candidates(&list, None, false, &mut gapped, Some(&ok));
            if let Some((channel, Some(category))) = pick_head(&ordered, &mut heads, &mut head_editions, &ok, &rank_of).and_then(sync_of) {
                syncs.insert(channel, category);
            }
        }
        roster.syncs = syncs;
    }

    // 9. Categories (vsk 15), edited under MANAGE_CHANNELS like any Channel, on either Roster.
    let not_categories = taken_by(VSK_CATEGORY);
    let mut categories: BTreeMap<String, FoldedCategory> = BTreeMap::new();
    {
        let admit = holders(perm::MANAGE_CHANNELS);
        for (eid, cands) in candidates_of(&by_vsk, VSK_CATEGORY, Some(&admit), &mut gap_held) {
            if not_categories.contains(&eid) {
                continue;
            }
            let Some(head) = pick_head(&cands, &mut heads, &mut head_editions, &admit, &rank_of) else { continue };
            let applied = if read_category(&head.content).is_some() {
                Some(head)
            } else {
                cands.iter().copied().find(|p| p.version <= head.version && admit(p) && read_category(&p.content).is_some())
            };
            let Some(applied) = applied else { continue };
            let mut read = read_category(&applied.content).expect("checked");
            let ever_deleted = by_vsk
                .get(VSK_CATEGORY)
                .and_then(|m| m.get(&eid))
                .is_some_and(|l| l.iter().any(|p| admit(p) && read_category(&p.content).is_some_and(|c| c.deleted)));
            read.id_hex = eid.clone();
            read.deleted |= ever_deleted;
            categories.insert(eid, read);
        }
        let live: Vec<String> = categories.values().filter(|c| !c.deleted).map(|c| c.id_hex.clone()).collect();
        for id in live.into_iter().skip(MAX_CATEGORIES) {
            categories.remove(&id);
        }
    }
    // On the ranked Roster a Channel's sidebar category is the Category entity's name.
    if ranked {
        for ch in channels.values_mut() {
            ch.category = ch.category_id.as_ref().and_then(|id| categories.get(id)).filter(|c| !c.deleted).map(|c| c.name.clone()).filter(|n| !n.is_empty());
        }
    }

    let served: HashSet<String> = by_vsk.values().flat_map(|m| m.keys().cloned()).collect();
    let mut incomplete: Vec<String> = gap_held.iter().cloned().collect();
    if let Some(prior) = prior_heads {
        for eid in prior.keys() {
            if !served.contains(eid) && !gap_held.contains(eid) {
                incomplete.push(eid.clone());
            }
        }
    }
    incomplete.sort();

    FoldedControl {
        roster,
        owner: owner.to_owned(),
        metadata,
        channels,
        banned,
        banned_at,
        live_invite_links,
        registries_by_creator,
        pin_lists,
        signals,
        heads,
        head_editions,
        incomplete,
        ranked,
        categories,
        tenure: sealed,
        writers,
    }
}

// ── Builders ────────────────────────────────────────────────────────────────

/// An edition its author must not publish: every verifier would drop it, so it
/// is refused here, at the one place that can still say why.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BuildError {
    #[error("{0} exceeds {NAME_MAX_BYTES} bytes")]
    NameTooLong(&'static str),
    #[error("description exceeds {DESCRIPTION_MAX_BYTES} bytes")]
    DescriptionTooLong,
    #[error("role position must be 1 or greater (position 0 is the owner's)")]
    RolePosition,
    #[error("not a 64-hex id: {0}")]
    BadId(&'static str),
}

/// Community metadata (vsk 0); eid = the community_id. Gated by MANAGE_METADATA.
pub fn build_metadata_edition(community_id: &Bytes32, metadata: &Value, meta: &EditionMeta) -> Result<Rumor, BuildError> {
    if !metadata.get("name").and_then(Value::as_str).is_some_and(|n| utf8_len_ok(n, NAME_MAX_BYTES)) {
        return Err(BuildError::NameTooLong("community name"));
    }
    if metadata.get("description").and_then(Value::as_str).is_some_and(|d| !utf8_len_ok(d, DESCRIPTION_MAX_BYTES)) {
        return Err(BuildError::DescriptionTooLong);
    }
    Ok(build_edition_rumor(kinds::VSK_METADATA, community_id, metadata.to_string(), meta))
}

/// Channel metadata (vsk 2); eid = the channel_id. Gated by MANAGE_CHANNELS.
pub fn build_channel_edition(channel_id: &Bytes32, metadata: &Value, meta: &EditionMeta) -> Result<Rumor, BuildError> {
    if !metadata.get("name").and_then(Value::as_str).is_some_and(|n| utf8_len_ok(n, NAME_MAX_BYTES)) {
        return Err(BuildError::NameTooLong("channel name"));
    }
    Ok(build_edition_rumor(kinds::VSK_CHANNEL, channel_id, metadata.to_string(), meta))
}

/// Role (vsk 1); eid = the role_id. Gated by MANAGE_ROLES. Position 0 is the
/// owner's alone (CORD-04 §3): a Role claiming it would be a peer nobody outranks.
pub fn build_role_edition(role: &Role, meta: &EditionMeta) -> Result<Rumor, BuildError> {
    if !utf8_len_ok(&role.name, NAME_MAX_BYTES) {
        return Err(BuildError::NameTooLong("role name"));
    }
    if role.position < 1 {
        return Err(BuildError::RolePosition);
    }
    let eid = hex32(&role.role_id).ok_or(BuildError::BadId("role_id"))?;
    Ok(build_edition_rumor(kinds::VSK_ROLE, &eid, role.to_json(), meta))
}

/// Grant (vsk 3); eid = grant_locator(cid, member). Empty role_ids = a revoke.
pub fn build_grant_edition(community_id: &Bytes32, grant: &MemberGrant, meta: &EditionMeta) -> Result<Rumor, BuildError> {
    let member = hex32(&grant.member).ok_or(BuildError::BadId("member"))?;
    Ok(build_edition_rumor(kinds::VSK_GRANT, &grant_locator(community_id, &member), grant.to_json(), meta))
}

/// Invite Registry (vsk 8); eid = invite_links_locator(cid, creator). Link-signer pubkeys only.
pub fn build_registry_edition(community_id: &Bytes32, creator_hex: &str, link_signers: &[String], meta: &EditionMeta) -> Result<Rumor, BuildError> {
    let creator = hex32(creator_hex).ok_or(BuildError::BadId("creator"))?;
    let content = serde_json::to_string(link_signers).expect("strings always serialize");
    Ok(build_edition_rumor(kinds::VSK_INVITE_REGISTRY, &invite_links_locator(community_id, &creator), content, meta))
}

/// The citation an actor attaches to act under the Grant edition `grant_hash`
/// at `version` (CORD-04 §5).
pub fn grant_citation(community_id: &Bytes32, member: &Bytes32, version: u64, grant_hash: Bytes32) -> Citation {
    Citation { entity_id: grant_locator(community_id, member), version, edition_hash: grant_hash }
}

// ── Armada channel extensions (CORD.md) ─────────────────────────────────────

pub const CHANNEL_CATEGORY_KEY: &str = "armada.category";
pub const CHANNEL_ORDER_KEY: &str = "armada.order";

/// Set (or clear) one `custom` member of channel metadata, other extensions
/// untouched; an emptied `custom` is removed rather than left as `{}`.
fn set_custom(metadata: &mut Value, key: &str, value: Option<Value>) {
    let Some(obj) = metadata.as_object_mut() else { return };
    let mut custom = match obj.remove("custom") {
        Some(Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    match value {
        Some(v) => {
            custom.insert(key.to_owned(), v);
        }
        None => {
            custom.remove(key);
        }
    }
    if !custom.is_empty() {
        obj.insert("custom".into(), Value::Object(custom));
    }
}

/// The sidebar category (`custom["armada.category"].name`); blank clears it.
pub fn with_channel_category(metadata: &mut Value, name: Option<&str>) {
    let trimmed = name.map(str::trim).filter(|n| !n.is_empty());
    set_custom(metadata, CHANNEL_CATEGORY_KEY, trimmed.map(|n| serde_json::json!({ "name": n })));
}

/// The sidebar position (`custom["armada.order"].position`).
pub fn with_channel_position(metadata: &mut Value, position: Option<u64>) {
    set_custom(metadata, CHANNEL_ORDER_KEY, position.map(|p| serde_json::json!({ "position": p })));
}

/// Sign (plaintext seal) and wrap one edition for the Control Plane. `control`
/// must be a write key: a split epoch's wrap is signed by the staff key.
pub fn seal_edition(rumor: &Rumor, control: &StreamKey, author: &Keys) -> Result<Event, StreamError> {
    seal_and_wrap(rumor, kinds::Plane::Control, control, author, WrapOptions::default())
}

// ── Dissolution (CORD-02 §9) ────────────────────────────────────────────────

/// Whether an opened dissolved-address event is the owner's tombstone FOR THIS
/// community. The `eid` binding is mandatory; an all-zero `eid` is refused.
pub fn is_dissolved_opened(opened: &Opened, owner: &str, community_id: &Bytes32) -> bool {
    opened.author() == owner
        && opened.seal_kind() == kinds::SEAL_PLAINTEXT
        && opened.rumor.kind == kinds::CONTROL
        && opened.rumor.tag_value("vsk") == Some(kinds::VSK_DISSOLVED)
        && opened.rumor.tag_value("eid") == Some(to_hex(community_id).as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::community::Membership;
    use crate::edition::{EditionMeta, parse_edition};
    use crate::roles::{Role, RoleScope};
    use crate::stream::open_plane_wrap;

    struct Plane {
        community: Membership,
        owner: Keys,
        editions: Vec<Edition>,
    }

    impl Plane {
        fn new() -> Plane {
            let owner = Keys::generate();
            let community = Membership::mint("t", &owner.public_key().to_hex(), vec![], 0);
            Plane { community, owner, editions: vec![] }
        }
        fn put(&mut self, rumor: &Rumor, by: &Keys) -> Edition {
            let control = self.community.control_write_stream().unwrap();
            let wrap = seal_edition(rumor, &control, by).unwrap();
            let e = parse_edition(open_plane_wrap(&wrap, &self.community.current_control_stream(), kinds::Plane::Control).unwrap()).unwrap();
            self.editions.push(e.clone());
            e
        }
        fn fold(&self) -> FoldedControl {
            fold_control(&self.editions, &self.community.id(), &self.community.owner, None, None)
        }
    }

    #[test]
    fn a_pin_list_aimed_at_a_grant_never_takes_its_head() {
        let mut p = Plane::new();
        let owner = p.owner.public_key().to_hex();
        let (alice, bob) = (Keys::generate(), Keys::generate());
        let cid = p.community.id();
        let pins_role = Role::new(&"aa".repeat(32), "Pinner", 2, perm::PIN_MESSAGES | perm::MANAGE_MESSAGES, RoleScope::Server);
        let owner_meta = EditionMeta { created_at: Some(1_700_000_000), ..EditionMeta::first(&owner, None) };
        p.put(&build_role_edition(&pins_role, &owner_meta).unwrap(), &p.owner.clone());
        let mut grant_hash = HashMap::new();
        for who in [&alice, &bob] {
            let g = MemberGrant { member: who.public_key().to_hex(), role_ids: vec![pins_role.role_id.clone()], control_wrap: None };
            let e = p.put(&build_grant_edition(&cid, &g, &owner_meta).unwrap(), &p.owner.clone());
            grant_hash.insert(who.public_key().to_hex(), e.self_hash);
        }
        let bob_eid = grant_locator(&cid, &bob.public_key().to_bytes());
        let alice_vac = Citation { entity_id: grant_locator(&cid, &alice.public_key().to_bytes()), version: 1, edition_hash: grant_hash[&alice.public_key().to_hex()] };
        // Alice, a pinner, aims a Pin List at Bob's Grant coordinate, at version 9.
        let alice_pk = alice.public_key().to_hex();
        let pins = build_edition_rumor(kinds::VSK_PINS, &bob_eid, "[]".into(), &EditionMeta { version: 9, ..EditionMeta::first(&alice_pk, Some(&alice_vac)) });
        p.put(&pins, &alice);
        let f = p.fold();
        let head = f.heads[&to_hex(&bob_eid)];
        assert_eq!((head.version, head.hash), (1, grant_hash[&bob.public_key().to_hex()]), "Bob's Grant keeps its head");
        let bob_vac = Citation { entity_id: bob_eid, version: 1, edition_hash: head.hash };
        assert!(f.citation_satisfied(&cid, &bob.public_key().to_hex(), Some(&bob_vac)));
    }
}
