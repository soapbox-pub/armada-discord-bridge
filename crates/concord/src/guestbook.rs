//! The Guestbook Plane — CORD-02 §5: self-signed Joins and Leaves, authorized
//! Kicks, and refounder snapshots, coalesced flat to one state per npub.

use std::collections::{HashMap, HashSet};

use crate::edition::Citation;
use crate::kinds;
use crate::rumor::{Rumor, tag};
use crate::stream::Opened;

/// Entries dated further than this ahead of the local clock are dropped.
pub const MAX_FUTURE_MS: u64 = 60 * 60 * 1000;

pub fn join(author: &str, ms: u64, invite: Option<(&str, &str)>) -> Rumor {
    let tags = invite.map(|(creator, label)| vec![tag(["invite", creator, label])]).unwrap_or_default();
    Rumor::new(kinds::JOIN_LEAVE, "join", tags, author, Some(ms), None)
}

pub fn leave(author: &str, ms: u64) -> Rumor {
    Rumor::new(kinds::JOIN_LEAVE, "leave", vec![], author, Some(ms), None)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberState {
    Join,
    Leave,
    Kick,
}

#[derive(Clone, Debug)]
pub struct Coalesced {
    pub state: MemberState,
    pub ms: u64,
    pub rumor_id: String,
    pub from_snapshot: bool,
}

/// Coalesce opened guestbook events: latest ms per npub wins, ties to the lower
/// rumor id, firsthand beats a snapshot at the same instant. Kicks need
/// `can_kick(actor, target, citation)`; snapshots count only from `snapshot_authorities`.
pub fn coalesce(
    opened: &[Opened],
    now_ms: u64,
    banned: &HashSet<String>,
    snapshot_authorities: &HashSet<String>,
    can_kick: impl Fn(&str, &str, Option<&Citation>) -> bool,
) -> HashMap<String, Coalesced> {
    let mut by_member: HashMap<String, Coalesced> = HashMap::new();
    let mut apply = |pk: String, c: Coalesced| {
        let replace = match by_member.get(&pk) {
            None => true,
            Some(prev) if c.ms != prev.ms => c.ms > prev.ms,
            Some(prev) if prev.from_snapshot != c.from_snapshot => prev.from_snapshot,
            Some(prev) => c.rumor_id < prev.rumor_id,
        };
        if replace {
            by_member.insert(pk, c);
        }
    };
    for ev in opened {
        if ev.ms > now_ms + MAX_FUTURE_MS || ev.seal_kind() != kinds::SEAL_ENCRYPTED || banned.contains(ev.author()) {
            continue;
        }
        let r = &ev.rumor;
        match r.kind {
            kinds::JOIN_LEAVE => {
                let state = match r.content.as_str() {
                    "join" => MemberState::Join,
                    "leave" => MemberState::Leave,
                    _ => continue,
                };
                apply(r.pubkey.clone(), Coalesced { state, ms: ev.ms, rumor_id: r.id.clone(), from_snapshot: false });
            }
            kinds::KICK => {
                let Some(target) = r.tag_value("p") else { continue };
                if !can_kick(&r.pubkey, target, Citation::from_tags(&r.tags).as_ref()) {
                    continue;
                }
                apply(target.to_owned(), Coalesced { state: MemberState::Kick, ms: ev.ms, rumor_id: r.id.clone(), from_snapshot: false });
            }
            kinds::SNAPSHOT => {
                if !snapshot_authorities.contains(&r.pubkey) {
                    continue;
                }
                let Ok(members) = serde_json::from_str::<Vec<serde_json::Value>>(&r.content) else { continue };
                for pk in members.iter().filter_map(|v| v.as_str()).filter(|s| crate::is_hex64(s)) {
                    apply(pk.to_lowercase(), Coalesced { state: MemberState::Join, ms: ev.ms, rumor_id: r.id.clone(), from_snapshot: true });
                }
            }
            _ => {}
        }
    }
    by_member
}

/// A Timeout's `until` is capped this far past the rumor's own time (CORD-04 §8).
pub const TIMEOUT_MAX_SECS: u64 = 28 * 24 * 60 * 60;

/// One folded Timeout (CORD-04 §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldedTimeout {
    pub by: String,
    /// Its window: from its own time in whole seconds, inclusive, to `until`, exclusive.
    pub from_secs: u64,
    pub until: u64,
    pub ms: u64,
    pub rumor_id: String,
}

impl FoldedTimeout {
    /// Whether it runs at `now_ms`.
    pub fn running(&self, now_ms: u64) -> bool {
        self.until.saturating_mul(1000) > now_ms
    }

    /// Whether a post at `at_ms` falls inside its window while it runs: what
    /// readers collapse.
    pub fn silences(&self, at_ms: u64, now_ms: u64) -> bool {
        self.running(now_ms) && at_ms >= self.from_secs * 1000 && at_ms < self.until.saturating_mul(1000)
    }
}

fn sole_tag<'a>(r: &'a Rumor, name: &str) -> Option<&'a str> {
    let mut found = None;
    for t in r.tags.iter().filter(|t| t.len() >= 2 && t[0] == name) {
        if found.is_some() {
            return None;
        }
        found = Some(t[1].as_str());
    }
    found
}

/// Fold Timeouts (kind 3314, CORD-04 §8): per target, the newest by its time to
/// the millisecond among those `may_timeout(actor, target, citation)` lets time
/// the target out, the lower rumor id breaking a tie. `until` is capped at 28
/// days past the rumor's own time; a past `until` lifts. Exactly one `p` and one
/// `until`, and never the owner.
pub fn fold_timeouts(
    opened: &[Opened],
    now_ms: u64,
    owner: &str,
    banned: &HashSet<String>,
    may_timeout: impl Fn(&str, &str, Option<&Citation>) -> bool,
) -> HashMap<String, FoldedTimeout> {
    let mut out: HashMap<String, FoldedTimeout> = HashMap::new();
    for ev in opened {
        let r = &ev.rumor;
        if r.kind != kinds::TIMEOUT || ev.ms > now_ms + MAX_FUTURE_MS || ev.seal_kind() != kinds::SEAL_ENCRYPTED || banned.contains(ev.author()) {
            continue;
        }
        let Some(target) = sole_tag(r, "p").map(str::to_lowercase) else { continue };
        let Some(until_raw) = sole_tag(r, "until") else { continue };
        // Digits fitting a u64, leading zeros allowed, as Vector parses them.
        if until_raw.is_empty() || !until_raw.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(until) = until_raw.parse::<u64>() else { continue };
        if !crate::is_hex64(&target) || nostr::prelude::PublicKey::from_hex(&target).is_err() || target == owner {
            continue;
        }
        if !may_timeout(&r.pubkey, &target, Citation::from_tags(&r.tags).as_ref()) {
            continue;
        }
        let from_secs = ev.ms / 1000;
        let until = until.min(from_secs + TIMEOUT_MAX_SECS);
        if let Some(prev) = out.get(&target)
            && (ev.ms < prev.ms || (ev.ms == prev.ms && r.id >= prev.rumor_id)) {
                continue;
            }
        out.insert(target, FoldedTimeout { by: r.pubkey.clone(), from_secs, until, ms: ev.ms, rumor_id: r.id.clone() });
    }
    out
}
