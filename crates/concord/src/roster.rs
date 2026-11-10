//! The vsk-13 Roster (CORD-04 §2, §3, §9): Roles ordered by rank keys,
//! `@everyone`, Grants resolved against them, and Tenure, folded by DOWNWARD
//! SUPPORT — an edition counts only bits its signer holds through Roles ranked
//! strictly above everything it touches, so the fold resolves top-down from the
//! owner and has one answer whatever slice of the plane a reader holds.
//!
//! A port of Armada's `roster.ts` (itself a port of Vector's `fold_authority` /
//! `select_authorized` / `replay`), for a reader that folds the plane fresh:
//! the bridge holds no floors, so every floor arm of the original (held heads,
//! withheld editions, rebasing, voiding a banned floor author) is absent rather
//! than approximated. A reader that starts tracking floors must port those
//! arms, not bolt them on.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{Map, Value};

use crate::derive::{OverwriteTargetKind, acl_locator, everyone_locator, grant_locator, overwrite_target_bytes, tenure_locator};
use crate::edition::Edition;
use crate::rank::{dense_ranks, is_rank_key};
use crate::roles::{BENEATH_EVERY_ROLE, MAX_ROLES_PER_COMMUNITY, MAX_ROLES_PER_MEMBER, MemberGrant, Overwrite, OverwriteTarget, Role, RoleScope, Roster, cut_name, perm};
use crate::strict;
use crate::{Bytes32, hex32, is_hex64, to_hex};

pub const VSK_RANKED_ROLE: &str = "13";
pub const VSK_ACL: &str = "14";
pub const VSK_CATEGORY: &str = "15";
pub const VSK_TENURE: &str = "16";
pub const VSK_SYNC: &str = "17";
pub const VSK_WRITERS: &str = "18";

/// Kinds no older client wrote: marked in every Community, so an unmarked one
/// is refused (CORD-04 §1).
pub const ALWAYS_MARKED_VSKS: [&str; 6] = [VSK_RANKED_ROLE, VSK_ACL, VSK_CATEGORY, VSK_TENURE, VSK_SYNC, VSK_WRITERS];

/// The most Channels a switching `@everyone` lists (CORD-04 §2).
pub const MAX_LEGACY_CHANNELS: usize = 256;
pub const MAX_TENURE_ENTRIES: usize = 16;
pub const MAX_TENURE_HEADS: usize = 512;
const LINK_RUN_CAP: usize = 64;

// ── Wire content ─────────────────────────────────────────────────────────────

pub enum RankedRole {
    Live(Role),
    Deleted(String),
}

const RANKED_ROLE_FIELDS: [&str; 8] = ["role_id", "name", "rank", "permissions", "color", "display", "mentionable", "deleted"];

fn opt_is(v: Option<&Value>, check: fn(&Value) -> bool) -> bool {
    strict::none(v) || v.is_some_and(check)
}

/// A vsk-13 Role edition (CORD-04 §2). A field of the wrong type makes the
/// content unparseable, a deletion's included; `null` reads as absent. A live
/// Role needs a rank key; its position is assigned at fold time.
pub fn parse_ranked_role(content: &str) -> Option<RankedRole> {
    let c = strict::parse_object(content)?;
    let role_id = c.get("role_id")?.as_str().filter(|s| is_hex64(s))?.to_lowercase();
    if !opt_is(c.get("name"), Value::is_string) || !opt_is(c.get("rank"), Value::is_string) {
        return None;
    }
    for k in ["deleted", "display", "mentionable"] {
        if !opt_is(c.get(k), Value::is_boolean) {
            return None;
        }
    }
    // Absent reads as none, but a present null fails (Vector `perm_decimal_string_opt`).
    let permissions = match c.get("permissions") {
        None => 0,
        Some(v) => strict::permission_bits(v)?,
    };
    let color = if strict::none(c.get("color")) { 0 } else { strict::uint(c.get("color")?, u32::MAX as u64)? as u32 };
    if c.get("deleted") == Some(&Value::Bool(true)) {
        return Some(RankedRole::Deleted(role_id));
    }
    let rank = c.get("rank").and_then(Value::as_str).filter(|r| is_rank_key(r))?.to_owned();
    let extra: Map<String, Value> =
        strict::fields(&c).filter(|(k, _)| !RANKED_ROLE_FIELDS.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect();
    Some(RankedRole::Live(Role {
        role_id,
        name: cut_name(c.get("name").and_then(Value::as_str).unwrap_or("")),
        position: BENEATH_EVERY_ROLE,
        rank: Some(rank),
        permissions,
        scope: RoleScope::Server,
        color,
        display: c.get("display") == Some(&Value::Bool(true)),
        mentionable: c.get("mentionable") == Some(&Value::Bool(true)),
        extra,
    }))
}

/// A live vsk-13 Role's content: every field written, false flags included
/// (CORD-04 §2), unknown fields carried first as Armada writes them.
pub fn ranked_role_to_json(role: &Role) -> Option<String> {
    let rank = role.rank.as_deref().filter(|r| is_rank_key(r))?;
    let mut out = role.extra.clone();
    out.insert("role_id".into(), Value::String(role.role_id.clone()));
    out.insert("name".into(), Value::String(role.name.clone()));
    out.insert("rank".into(), Value::String(rank.to_owned()));
    out.insert("permissions".into(), Value::String(role.permissions.to_string()));
    out.insert("color".into(), Value::from(role.color));
    out.insert("display".into(), Value::Bool(role.display));
    out.insert("mentionable".into(), Value::Bool(role.mentionable));
    Some(Value::Object(out).to_string())
}

/// `@everyone`'s content: its bits, and the Channels that stood before the
/// switch. A Role's shape at its coordinate is a Role aimed there, not `@everyone`.
pub fn parse_everyone(content: &str) -> Option<(u64, Option<Vec<String>>)> {
    let c = strict::parse_object(content)?;
    if c.contains_key("role_id") {
        return None;
    }
    let permissions = strict::permission_bits(c.get("permissions")?)?;
    if strict::none(c.get("legacy")) {
        return Some((permissions, None));
    }
    let raw: Vec<&str> = c.get("legacy")?.as_array()?.iter().map(Value::as_str).collect::<Option<_>>()?;
    // In serde's BTreeSet order, cut before lowercasing (Vector `parse_everyone_content`).
    let ordered: std::collections::BTreeSet<&str> = raw.into_iter().collect();
    let kept: std::collections::BTreeSet<String> =
        ordered.into_iter().filter(|h| is_hex64(h)).take(MAX_LEGACY_CHANNELS).map(str::to_lowercase).collect();
    Some((permissions, Some(kept.into_iter().collect())))
}

pub fn everyone_to_json(permissions: u64, legacy: Option<&[String]>) -> String {
    let mut out = Map::new();
    out.insert("permissions".into(), Value::String(permissions.to_string()));
    if let Some(l) = legacy {
        let mut l = l.to_vec();
        l.sort();
        out.insert("legacy".into(), Value::from(l));
    }
    Value::Object(out).to_string()
}

/// One sealed standing in a Tenure (CORD-04 §9).
#[derive(Clone, Debug)]
pub struct TenureEntry {
    pub rank: String,
    pub permissions: u64,
    pub heads: Vec<String>,
}

/// A Tenure: entries with a malformed rank key, and malformed heads, dropped, then capped.
pub fn parse_tenure(content: &str) -> Option<(String, Vec<TenureEntry>)> {
    let c = strict::parse_object(content)?;
    let member = c.get("member")?.as_str()?.to_lowercase();
    let raw = match c.get("sealed") {
        None => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return None,
    };
    let mut sealed = Vec::new();
    for item in raw {
        if strict::repeated_keys(&item) {
            return None;
        }
        let e = item.as_object()?;
        let rank = e.get("rank")?.as_str()?;
        let permissions = strict::permission_bits(e.get("permissions")?)?;
        let heads: Vec<&str> = match e.get("heads") {
            None => Vec::new(),
            Some(Value::Array(a)) => a.iter().map(Value::as_str).collect::<Option<_>>()?,
            Some(_) => return None,
        };
        if !is_rank_key(rank) {
            continue;
        }
        sealed.push(TenureEntry {
            rank: rank.to_owned(),
            permissions,
            heads: heads.into_iter().filter(|h| is_hex64(h)).map(str::to_lowercase).take(MAX_TENURE_HEADS).collect(),
        });
    }
    sealed.truncate(MAX_TENURE_ENTRIES);
    Some((member, sealed))
}

/// An overwrite (CORD-04 §8), its bits masked to the overwritable set as it parses.
pub fn parse_overwrite(content: &str) -> Option<Overwrite> {
    let c = strict::parse_object(content)?;
    let scope = c.get("scope")?.as_str().filter(|s| is_hex64(s))?.to_lowercase();
    let t = c.get("target")?;
    if strict::repeated_keys(t) {
        return None;
    }
    let t = t.as_object()?;
    let id = t.get("id");
    let target = match t.get("kind").and_then(Value::as_str) {
        Some("everyone") if strict::none(id) => OverwriteTarget::Everyone,
        Some(kind @ ("role" | "member")) => {
            let id = id?.as_str().filter(|s| is_hex64(s))?.to_lowercase();
            if kind == "role" { OverwriteTarget::Role(id) } else { OverwriteTarget::Member(id) }
        }
        _ => return None,
    };
    let allow = strict::permission_bits(c.get("allow")?)?;
    let deny = strict::permission_bits(c.get("deny")?)?;
    Some(Overwrite { scope, target, allow: allow & perm::OVERWRITABLE, deny: deny & perm::OVERWRITABLE })
}

pub fn overwrite_to_json(o: &Overwrite) -> String {
    let target = match &o.target {
        OverwriteTarget::Everyone => serde_json::json!({ "kind": "everyone" }),
        OverwriteTarget::Role(id) => serde_json::json!({ "kind": "role", "id": id }),
        OverwriteTarget::Member(id) => serde_json::json!({ "kind": "member", "id": id }),
    };
    serde_json::json!({ "scope": o.scope, "target": target, "allow": o.allow.to_string(), "deny": o.deny.to_string() }).to_string()
}

/// The coordinate an overwrite lives at (CORD-04 §8).
pub fn overwrite_locator(community_id: &Bytes32, scope: &str, target: &OverwriteTarget) -> Option<Bytes32> {
    let tb = match target {
        OverwriteTarget::Everyone => overwrite_target_bytes(community_id, OverwriteTargetKind::Everyone, None),
        OverwriteTarget::Role(id) => overwrite_target_bytes(community_id, OverwriteTargetKind::Role, Some(&hex32(id)?)),
        OverwriteTarget::Member(id) => overwrite_target_bytes(community_id, OverwriteTargetKind::Member, Some(&hex32(id)?)),
    };
    Some(acl_locator(community_id, &hex32(scope)?, &tb))
}

/// A Channel's sync (CORD-04 §8): `(channel, category?)`. A `sync` that is no
/// string nor `null` leaves it unparseable; one that isn't a hex id reads as none.
pub fn parse_sync(content: &str) -> Option<(String, Option<String>)> {
    let c = strict::parse_object(content)?;
    let channel = c.get("channel")?.as_str().filter(|s| is_hex64(s))?.to_lowercase();
    let category = match c.get("sync") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s).filter(|s| is_hex64(s)).map(|s| s.to_lowercase()),
        Some(_) => return None,
    };
    Some((channel, category))
}

pub fn sync_to_json(channel: &str, category: Option<&str>) -> String {
    match category {
        Some(c) => serde_json::json!({ "channel": channel, "sync": c }).to_string(),
        None => serde_json::json!({ "channel": channel }).to_string(),
    }
}

// ── The fold ─────────────────────────────────────────────────────────────────

/// A sealed standing as the fold reads it: its rank mapped to a position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub position: u32,
    pub bits: u64,
    pub heads: HashSet<String>,
}

/// Each member's sealed standings, from the Tenures the fold admits.
pub type SealedBy = HashMap<String, Vec<Sealed>>;

/// The bits sealed for `author` over `hash` by every standing ranked above `reach`.
pub fn seal_of(sealed: &SealedBy, author: &str, hash: &str, reach: u32) -> u64 {
    sealed.get(author).map_or(0, |v| v.iter().filter(|e| e.position < reach && e.heads.contains(hash)).fold(0, |a, e| a | e.bits))
}

/// Some Tenure lists `hash` as `author`'s, at whatever standing.
pub fn is_listed(sealed: &SealedBy, author: &str, hash: &str) -> bool {
    sealed.get(author).is_some_and(|v| v.iter().any(|e| e.heads.contains(hash)))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CandKind {
    Live,
    Deleted,
    Everyone,
    History,
}

struct Cand<'a> {
    kind: CandKind,
    role: Option<Role>,
    legacy: Option<Vec<String>>,
    grant: Option<MemberGrant>,
    tenure: Option<(String, Vec<Sealed>)>,
    author: String,
    grant_hex: String,
    e: &'a Edition,
    hash_hex: String,
    id_hex: String,
    prev_hex: Option<String>,
}

/// `None` refuses; `Some(rank)` admits, conferring `rank`.
type Judged = Option<Option<u32>>;

fn stricter(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (None, b) => b,
        (a, None) => a,
        (Some(a), Some(b)) => Some(a.min(b)),
    }
}

/// A Roster's per-member questions answered from each member's Roles gathered once.
struct RoleIndex<'r> {
    by_id: HashMap<&'r str, &'r Role>,
    held: HashMap<&'r str, Vec<&'r Role>>,
}

impl<'r> RoleIndex<'r> {
    fn new(roster: &'r Roster) -> Self {
        let mut by_id: HashMap<&str, &Role> = HashMap::new();
        for r in &roster.roles {
            by_id.entry(r.role_id.as_str()).or_insert(r);
        }
        let mut held: HashMap<&str, Vec<&Role>> = HashMap::new();
        for g in &roster.grants {
            let list = held.entry(g.member.as_str()).or_default();
            for rid in &g.role_ids {
                if let Some(r) = by_id.get(rid.as_str()) {
                    list.push(r);
                }
            }
        }
        RoleIndex { by_id, held }
    }

    fn role(&self, id: &str) -> Option<&Role> {
        self.by_id.get(id).copied()
    }

    fn permissions_above(&self, member: &str, bound: u32) -> u64 {
        self.held.get(member).map_or(0, |rs| rs.iter().filter(|r| r.position < bound).fold(0, |a, r| a | r.permissions))
    }

    fn highest_position_above(&self, member: &str, bound: u32) -> Option<u32> {
        self.held.get(member).and_then(|rs| rs.iter().map(|r| r.position).filter(|p| *p < bound).min())
    }
}

fn fork_rank_above(index: &RoleIndex, owner: &str, author: &str, reach: u32) -> u32 {
    if author == owner { 0 } else { index.highest_position_above(author, reach).unwrap_or(BENEATH_EVERY_ROLE) }
}

/// CORD-04 §5 sync floor against the heads a fold round settled on.
fn citation_ok(heads: &HashMap<String, &Edition>, owner: &str, c: &Cand) -> bool {
    if c.author == owner {
        return true;
    }
    let Some(cite) = c.e.authority.as_ref() else { return false };
    if to_hex(&cite.entity_id) != c.grant_hex {
        return false;
    }
    let Some(head) = heads.get(&c.grant_hex) else { return false };
    if head.version > cite.version {
        return true;
    }
    head.version == cite.version && head.self_hash == cite.edition_hash
}

/// What naming `h` at version `ver` adds to the rank an edition acts on: through
/// refused editions (each perhaps a copy of one that stands, so the strictest
/// rank counts) to an admitted one. Without a floor, a run reaching the genesis
/// through refused editions proves nothing.
fn link_run(cands: &[Cand], start: &str, ver: u64, by_hash: &HashMap<&str, Vec<usize>>, conf: &[Judged], claims: &dyn Fn(&Cand) -> Option<u32>) -> Option<u32> {
    let mut acc: Option<u32> = None;
    let mut at = ver;
    let mut h = start.to_owned();
    for _ in 0..LINK_RUN_CAP {
        let js = by_hash.get(h.as_str())?;
        if cands[js[0]].e.version + 1 != at {
            return None;
        }
        if let Some(&k) = js.iter().find(|&&x| conf[x].is_some()) {
            return stricter(acc, conf[k].expect("checked"));
        }
        acc = stricter(acc, claims(&cands[js[0]]));
        at = cands[js[0]].e.version;
        h = cands[js[0]].prev_hex.clone()?;
    }
    None
}

/// One entity's chain, replayed ascending (CORD-04 §1, §3), and its head. Each
/// version acts on what the newest admitted version below it left, never on
/// what its own `prev` names alone (its author picks that). Fork siblings are
/// judged at the strictest rank any viable one claims. Candidates arrive
/// version-DESC; returns the head's index.
fn replay(
    cands: &[Cand],
    index: &RoleIndex,
    owner: &str,
    claims: &dyn Fn(&Cand) -> Option<u32>,
    judge: &dyn Fn(&Cand, u32) -> Judged,
    admitted_out: &mut HashSet<String>,
) -> Option<usize> {
    let n = cands.len();
    if n == 0 {
        return None;
    }
    let mut by_hash: HashMap<&str, Vec<usize>> = HashMap::new();
    for (j, c) in cands.iter().enumerate() {
        by_hash.entry(c.hash_hex.as_str()).or_default().push(j);
    }
    let mut admitted = vec![false; n];
    let mut conf: Vec<Judged> = vec![None; n];
    let mut standing: Vec<Option<u32>> = vec![None; n];
    let mut key: Vec<(u32, String)> = vec![(BENEATH_EVERY_ROLE, String::new()); n];
    let mut runs: HashMap<(String, u64), Option<u32>> = HashMap::new();
    let mut base: Option<u32> = None;

    let mut i = n;
    while i > 0 {
        let hi = i;
        let ver = cands[i - 1].e.version;
        while i > 0 && cands[i - 1].e.version == ver {
            i -= 1;
        }
        for j in i..hi {
            let constraint = match &cands[j].prev_hex {
                None => None,
                Some(prev) => *runs.entry((prev.clone(), ver)).or_insert_with(|| link_run(cands, prev, ver, &by_hash, &conf, claims)),
            };
            standing[j] = stricter(base, constraint);
        }
        let own = |j: usize| stricter(claims(&cands[j]), standing[j]).unwrap_or(BENEATH_EVERY_ROLE);
        let viable: Vec<bool> = (i..hi).map(|j| hi - i == 1 || judge(&cands[j], own(j)).is_some()).collect();
        let mut reach = BENEATH_EVERY_ROLE;
        for j in i..hi {
            if viable[j - i] {
                reach = reach.min(own(j));
            }
        }
        for j in i..hi {
            let c = &cands[j];
            key[j] = (fork_rank_above(index, owner, &c.author, reach), c.id_hex.clone());
            conf[j] = if viable[j - i] { judge(c, reach) } else { None };
            admitted[j] = conf[j].is_some();
            if admitted[j] {
                admitted_out.insert(c.id_hex.clone());
            }
        }
        let mut w: Option<usize> = None;
        for j in i..hi {
            if admitted[j] && w.is_none_or(|w| key[j] < key[w]) {
                w = Some(j);
            }
        }
        if let Some(w) = w {
            base = conf[w].expect("admitted");
        }
    }

    let top = (0..n).filter(|&j| admitted[j]).map(|j| cands[j].e.version).max()?;
    (0..n).filter(|&j| admitted[j] && cands[j].e.version == top).min_by(|&a, &b| key[a].cmp(&key[b]))
}

struct Cands<'a> {
    roles: BTreeMap<String, Vec<Cand<'a>>>,
    grants: BTreeMap<String, Vec<Cand<'a>>>,
    tenures: BTreeMap<String, Vec<Cand<'a>>>,
}

fn build_cands<'a>(editions: &[&'a Edition], community_id: &Bytes32) -> Cands<'a> {
    let everyone_hex = to_hex(&everyone_locator(community_id));
    let mut groups: BTreeMap<String, Vec<&Edition>> = BTreeMap::new();
    for &e in editions {
        if matches!(e.vsk.as_str(), "1" | VSK_RANKED_ROLE | "3" | VSK_TENURE) {
            groups.entry(e.eid_hex()).or_default().push(e);
        }
    }
    // Rank keys map to dense positions; a Tenure's ranks sit in the same order.
    let mut keys: Vec<String> = Vec::new();
    for &e in editions {
        if e.binding.is_none() {
            continue;
        }
        if e.vsk == VSK_RANKED_ROLE {
            if let Some(RankedRole::Live(r)) = parse_ranked_role(&e.content) {
                keys.extend(r.rank);
            }
        } else if e.vsk == VSK_TENURE {
            keys.extend(parse_tenure(&e.content).into_iter().flat_map(|(_, s)| s.into_iter().map(|x| x.rank)));
        }
    }
    let ranks = dense_ranks(keys.iter().map(String::as_str));
    let mut out = Cands { roles: BTreeMap::new(), grants: BTreeMap::new(), tenures: BTreeMap::new() };
    for (eid, group) in groups {
        for e in group {
            let mk = |kind: CandKind| Cand {
                kind,
                role: None,
                legacy: None,
                grant: None,
                tenure: None,
                author: e.author.clone(),
                grant_hex: hex32(&e.author).map(|a| to_hex(&grant_locator(community_id, &a))).unwrap_or_default(),
                e,
                hash_hex: to_hex(&e.self_hash),
                id_hex: to_hex(&e.rumor_id),
                prev_hex: e.prev.map(|p| to_hex(&p)),
            };
            match e.vsk.as_str() {
                "1" => {
                    if eid == everyone_hex {
                        continue;
                    }
                    if let Some(role) = Role::from_json(&e.content).filter(|r| r.role_id == eid) {
                        out.roles.entry(eid.clone()).or_default().push(Cand { role: Some(role), ..mk(CandKind::History) });
                    }
                }
                VSK_RANKED_ROLE => {
                    if e.binding.is_none() {
                        continue;
                    }
                    if eid == everyone_hex {
                        let Some((permissions, legacy)) = parse_everyone(&e.content) else { continue };
                        let role = Role {
                            role_id: everyone_hex.clone(),
                            name: "@everyone".into(),
                            position: BENEATH_EVERY_ROLE,
                            rank: None,
                            permissions,
                            scope: RoleScope::Server,
                            color: 0,
                            display: false,
                            mentionable: false,
                            extra: Map::new(),
                        };
                        out.roles.entry(eid.clone()).or_default().push(Cand { role: Some(role), legacy, ..mk(CandKind::Everyone) });
                        continue;
                    }
                    match parse_ranked_role(&e.content) {
                        Some(RankedRole::Live(mut r)) if r.role_id == eid => {
                            r.position = r.rank.as_ref().and_then(|k| ranks.get(k).copied()).unwrap_or(BENEATH_EVERY_ROLE);
                            out.roles.entry(eid.clone()).or_default().push(Cand { role: Some(r), ..mk(CandKind::Live) });
                        }
                        Some(RankedRole::Deleted(id)) if id == eid => {
                            let mut r = crate::roles::admin_role(&eid);
                            (r.name, r.position, r.permissions) = (String::new(), BENEATH_EVERY_ROLE, 0);
                            out.roles.entry(eid.clone()).or_default().push(Cand { role: Some(r), ..mk(CandKind::Deleted) });
                        }
                        _ => {}
                    }
                }
                VSK_TENURE => {
                    if e.binding.is_none() {
                        continue;
                    }
                    let Some((member, sealed)) = parse_tenure(&e.content) else { continue };
                    let (Some(m), Some(a)) = (hex32(&member), hex32(&e.author)) else { continue };
                    if to_hex(&tenure_locator(community_id, &m, &a)) != eid {
                        continue;
                    }
                    let entries = sealed
                        .into_iter()
                        .filter_map(|s| ranks.get(&s.rank).map(|&position| Sealed { position, bits: s.permissions, heads: s.heads.into_iter().collect() }))
                        .collect();
                    out.tenures.entry(eid.clone()).or_default().push(Cand { tenure: Some((member, entries)), ..mk(CandKind::Live) });
                }
                _ => {
                    let Some(mut grant) = MemberGrant::from_json(&e.content) else { continue };
                    let Some(m) = hex32(&grant.member) else { continue };
                    if to_hex(&grant_locator(community_id, &m)) != eid {
                        continue;
                    }
                    grant.role_ids = grant.role_ids.iter().map(|r| r.to_lowercase()).take(MAX_ROLES_PER_MEMBER).collect();
                    out.grants.entry(eid.clone()).or_default().push(Cand { grant: Some(grant), ..mk(CandKind::Live) });
                }
            }
        }
    }
    for m in [&mut out.roles, &mut out.grants, &mut out.tenures] {
        for list in m.values_mut() {
            list.sort_by(|a, b| b.e.version.cmp(&a.e.version).then_with(|| a.id_hex.cmp(&b.id_hex)));
        }
    }
    out
}

/// What the ranked Roster fold settles on.
pub struct RosterFold<'a> {
    pub roster: Roster,
    /// The head edition of each Roster entity, by eid hex.
    pub heads: HashMap<String, &'a Edition>,
    pub sealed: SealedBy,
}

fn same_roster(a: &Roster, b: &Roster) -> bool {
    a.everyone == b.everyone
        && a.legacy_channels == b.legacy_channels
        && a.roles.len() == b.roles.len()
        && a.grants.len() == b.grants.len()
        && a.roles.iter().zip(&b.roles).all(|(x, y)| x == y)
        && a.grants.iter().zip(&b.grants).all(|(x, y)| x.member == y.member && x.role_ids == y.role_ids)
}

/// The owner-seeded delegation fixpoint (CORD-04 §1-§3, §9): per entity the
/// highest edition its author is authorized to write under the Roster resolved
/// so far, round after round until nothing moves.
fn select_authorized<'a>(cands: &Cands<'a>, community_id: &Bytes32, owner: &str, excluded: &HashSet<String>) -> RosterFold<'a> {
    let everyone_hex = to_hex(&everyone_locator(community_id));
    let mut accepted = Roster::default();
    let mut heads: HashMap<String, &'a Edition> = HashMap::new();
    let mut sealed: SealedBy = HashMap::new();
    let bound = 2 * (cands.roles.len() + cands.grants.len() + cands.tenures.len()) + 8;

    for _ in 0..bound {
        let mut next = Roster::default();
        let mut next_heads: HashMap<String, &'a Edition> = HashMap::new();
        let mut next_admitted: HashSet<String> = HashSet::new();
        let mut next_sealed: SealedBy = HashMap::new();
        let standing = RoleIndex::new(&accepted);
        let cite_heads = &heads;
        let current_sealed = &sealed;
        let support_for = |author: &str, c: &Cand, reach: u32| standing.permissions_above(author, reach) | seal_of(current_sealed, author, &c.hash_hex, reach);

        for (eid, list) in &cands.tenures {
            let claims = |c: &Cand| c.tenure.as_ref().and_then(|(_, es)| es.iter().map(|e| e.position).min());
            let judge = |c: &Cand, _reach: u32| -> Judged {
                let (member, entries) = c.tenure.as_ref()?;
                let a = c.author.as_str();
                let listed = is_listed(current_sealed, a, &c.hash_hex);
                if excluded.contains(a) && !listed {
                    return None;
                }
                if member == a || member == owner {
                    return None;
                }
                if a != owner {
                    let can = entries.iter().all(|e| {
                        let support = support_for(a, c, e.position);
                        support & perm::MANAGE_ROLES != 0 && e.bits & !support == 0
                    });
                    if !can {
                        return None;
                    }
                }
                if !listed && c.e.authority.is_some() && !citation_ok(cite_heads, owner, c) {
                    return None;
                }
                Some(None)
            };
            let Some(j) = replay(list, &standing, owner, &claims, &judge, &mut next_admitted) else { continue };
            next_heads.insert(eid.clone(), list[j].e);
            let (member, entries) = list[j].tenure.clone().expect("tenure candidate");
            next_sealed.entry(member).or_default().extend(entries);
        }

        for (eid, list) in &cands.roles {
            // A deletion and a legacy edition claim no rank: they act at the one the Role stood at.
            let claims = |c: &Cand| if matches!(c.kind, CandKind::Deleted | CandKind::History) { None } else { c.role.as_ref().map(|r| r.position) };
            let judge = |c: &Cand, reach: u32| -> Judged {
                let role = c.role.as_ref()?;
                if c.kind == CandKind::History {
                    return None;
                }
                let a = c.author.as_str();
                let listed = is_listed(current_sealed, a, &c.hash_hex);
                if (excluded.contains(a) && !listed) || role.position == 0 {
                    return None;
                }
                if a != owner {
                    let support = support_for(a, c, reach);
                    if support & perm::MANAGE_ROLES == 0 || role.permissions & !support != 0 {
                        return None;
                    }
                }
                if !listed && c.e.authority.is_some() && !citation_ok(cite_heads, owner, c) {
                    return None;
                }
                Some(if c.kind == CandKind::Deleted { None } else { Some(role.position) })
            };
            let picked = replay(list, &standing, owner, &claims, &judge, &mut next_admitted);
            // Deletion is terminal over the authorized chain, and acts at every
            // rank the Role holds from the deletion on.
            let mut deletion: Option<usize> = None;
            for (j, d) in list.iter().enumerate() {
                if d.kind != CandKind::Deleted || !next_admitted.contains(&d.id_hex) {
                    continue;
                }
                let later = list
                    .iter()
                    .filter(|c| c.kind == CandKind::Live && c.e.version >= d.e.version && next_admitted.contains(&c.id_hex))
                    .filter_map(|c| c.role.as_ref().map(|r| r.position))
                    .min();
                if let Some(later) = later
                    && judge(d, later).is_none() {
                        continue;
                    }
                let better = match deletion {
                    None => true,
                    Some(k) => d.e.version > list[k].e.version || (d.e.version == list[k].e.version && d.id_hex < list[k].id_hex),
                };
                if better {
                    deletion = Some(j);
                }
            }
            if let Some(k) = deletion {
                next_heads.insert(eid.clone(), list[k].e);
                continue;
            }
            let Some(j) = picked else { continue };
            let c = &list[j];
            match c.kind {
                CandKind::Everyone => {
                    next.everyone = c.role.as_ref().map(|r| r.permissions);
                    next.legacy_channels = c.legacy.clone();
                }
                CandKind::Live => next.roles.push(c.role.clone().expect("live role")),
                _ => {}
            }
            next_heads.insert(eid.clone(), c.e);
        }

        for (eid, list) in &cands.grants {
            if list[0].grant.as_ref().is_some_and(|g| excluded.contains(&g.member)) {
                continue;
            }
            // Judged on what it names, never on whether those resolve.
            let claims = |c: &Cand| {
                c.grant.as_ref().and_then(|g| g.role_ids.iter().filter(|r| **r != everyone_hex).filter_map(|r| standing.role(r).map(|r| r.position)).min())
            };
            let judge = |c: &Cand, reach: u32| -> Judged {
                let g = c.grant.as_ref()?;
                let a = c.author.as_str();
                let listed = is_listed(current_sealed, a, &c.hash_hex);
                if (excluded.contains(a) && !listed) || excluded.contains(&g.member) {
                    return None;
                }
                // An uncited edition may add authority, but one naming no Role
                // anyone has published is a strip, and a strip must cite.
                if !listed && !citation_ok(cite_heads, owner, c) {
                    if c.e.authority.is_some() {
                        return None;
                    }
                    if g.role_ids.iter().all(|r| *r == everyone_hex || !cands.roles.contains_key(r)) {
                        return None;
                    }
                }
                let ok = a == owner || (g.member != owner && support_for(a, c, reach) & perm::MANAGE_ROLES != 0);
                ok.then(|| claims(c))
            };
            let Some(j) = replay(list, &standing, owner, &claims, &judge, &mut next_admitted) else { continue };
            next_heads.insert(eid.clone(), list[j].e);
            let g = list[j].grant.as_ref().expect("grant candidate");
            let ids: Vec<String> = g.role_ids.iter().filter(|r| **r != everyone_hex && standing.role(r).is_some()).cloned().collect();
            if !ids.is_empty() {
                next.grants.push(MemberGrant { member: g.member.clone(), role_ids: ids, control_wrap: g.control_wrap.clone() });
            }
        }

        let same_heads = next_heads.len() == heads.len() && next_heads.iter().all(|(k, e)| heads.get(k).is_some_and(|o| std::ptr::eq(*o, *e)));
        let settled = same_heads && same_roster(&next, &accepted) && next_sealed == sealed;
        accepted = next;
        sealed = next_sealed;
        heads = next_heads;
        if settled {
            break;
        }
    }
    RosterFold { roster: accepted, heads, sealed }
}

/// Whether a Community is on the vsk-13 Roster (CORD-04 §2): an owner-rooted
/// vsk-13 fold seats `@everyone`.
pub fn roster_activated(editions: &[&Edition], community_id: &Bytes32, owner: &str) -> bool {
    let everyone_hex = to_hex(&everyone_locator(community_id));
    let some = editions.iter().any(|e| e.vsk == VSK_RANKED_ROLE && e.binding.is_some() && e.eid_hex() == everyone_hex);
    if !some {
        return false;
    }
    select_authorized(&build_cands(editions, community_id), community_id, owner, &HashSet::new()).heads.contains_key(&everyone_hex)
}

/// Fold the vsk-13 Roster: Roles, `@everyone`, Grants and Tenures, banned
/// members' editions refused except what a Tenure keeps. Applies the 100-Role
/// cap after authority is resolved (CORD-04 §2).
pub fn fold_ranked_roster<'a>(editions: &[&'a Edition], community_id: &Bytes32, owner: &str, excluded: &HashSet<String>) -> RosterFold<'a> {
    let mut fold = select_authorized(&build_cands(editions, community_id), community_id, owner, excluded);
    let roster = &mut fold.roster;
    if roster.roles.len() > MAX_ROLES_PER_COMMUNITY {
        roster.roles.sort_by(|a, b| a.role_id.cmp(&b.role_id));
        roster.roles.truncate(MAX_ROLES_PER_COMMUNITY);
        let kept: HashSet<String> = roster.roles.iter().map(|r| r.role_id.clone()).collect();
        for g in &mut roster.grants {
            g.role_ids.retain(|r| kept.contains(r));
        }
        roster.grants.retain(|g| !g.role_ids.is_empty());
    }
    // The switch fixes the legacy list (CORD-04 §2): the owner's first
    // `@everyone` edition that reads as one, else the head's.
    let everyone_hex = to_hex(&everyone_locator(community_id));
    let switching = editions
        .iter()
        .filter(|e| e.vsk == VSK_RANKED_ROLE && e.binding.is_some() && e.author == owner && e.prev.is_none() && e.eid_hex() == everyone_hex)
        .filter(|e| parse_everyone(&e.content).is_some())
        .min_by(|a, b| a.version.cmp(&b.version).then_with(|| a.rumor_id.cmp(&b.rumor_id)));
    if let Some(legacy) = switching.and_then(|e| parse_everyone(&e.content)).and_then(|(_, l)| l) {
        roster.legacy_channels = Some(legacy);
    }
    fold
}

/// Whether an overwrite's signer could write it (CORD-04 §8): MANAGE_ROLES and
/// every bit it touches, above its target.
pub fn overwrite_authorized(roster: &Roster, owner: &str, banned: &HashSet<String>, sealed: &SealedBy, o: &Overwrite, author: &str, hash: &str) -> bool {
    let rank = match &o.target {
        OverwriteTarget::Everyone => BENEATH_EVERY_ROLE,
        OverwriteTarget::Role(id) => match roster.role(id) {
            Some(r) => r.position,
            None => return false,
        },
        OverwriteTarget::Member(m) => {
            if m == owner || banned.contains(m) {
                return false;
            }
            roster.highest_position(m).unwrap_or(BENEATH_EVERY_ROLE)
        }
    };
    if author == owner {
        return true;
    }
    if banned.contains(author) && !is_listed(sealed, author, hash) {
        return false;
    }
    let support = roster.permissions_above(author, rank) | seal_of(sealed, author, hash, rank);
    support & perm::MANAGE_ROLES != 0 && (o.allow | o.deny) & !support == 0
}

/// Whether `author` could write every overwrite in `scopes` as it stands: what
/// a sync swaps all at once (CORD-04 §8).
pub fn may_swap_overwrites(roster: &Roster, owner: &str, author: &str, scopes: &[&str], sealed_over: &dyn Fn(u32) -> u64) -> bool {
    if author == owner {
        return true;
    }
    let held = |rank: u32| roster.permissions_above(author, rank) | sealed_over(rank);
    if held(BENEATH_EVERY_ROLE) & perm::MANAGE_ROLES == 0 {
        return false;
    }
    roster.overwrites.iter().filter(|o| scopes.contains(&o.scope.as_str())).all(|o| {
        let rank = match &o.target {
            OverwriteTarget::Everyone => BENEATH_EVERY_ROLE,
            OverwriteTarget::Role(id) => roster.role(id).map_or(BENEATH_EVERY_ROLE, |r| r.position),
            OverwriteTarget::Member(m) => roster.highest_position(m).unwrap_or(BENEATH_EVERY_ROLE),
        };
        let support = held(rank);
        support & perm::MANAGE_ROLES != 0 && (o.allow | o.deny) & !support == 0
    })
}
