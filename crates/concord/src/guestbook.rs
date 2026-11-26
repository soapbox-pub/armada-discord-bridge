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
    /// A Joined member the live epoch's complete snapshot omitted (CORD-02 §5).
    Refounded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coalesced {
    pub pubkey: String,
    pub state: MemberState,
    pub ms: u64,
    pub rumor_id: String,
    pub from_snapshot: bool,
}

/// Whether `actor`'s Kick of `target`, citing `citation`, at `ms`, is honored.
pub type CanKick<'a> = dyn Fn(&str, &str, Option<&Citation>, u64) -> bool + 'a;

/// How a Guestbook is read (Armada `coalesceGuestbook`'s options).
pub struct GuestbookOpts<'a> {
    pub now_ms: u64,
    pub banned: &'a HashSet<String>,
    /// KICK or BAN and a strict outrank, plus the sync floor via the Kick's citation.
    pub can_kick: &'a CanKick<'a>,
    /// Guestbook address → its epoch's minter: only that npub's snapshots count there.
    pub snapshot_authority_of: HashMap<String, String>,
    /// Addresses of epochs whose minter this member never verified, as a joiner
    /// holds them; resolved by [`GuestbookOpts::with_joiner_authorities`].
    pub unrecorded: HashSet<String>,
    /// Whether the fold lets an npub rotate the base: the owner, or a BAN holder.
    pub may_rotate: &'a dyn Fn(&str) -> bool,
    /// The live epoch's Guestbook address.
    pub live_pk: Option<String>,
}

impl GuestbookOpts<'_> {
    /// Names the minter of each unrecorded epoch (Armada `withJoinerAuthorities`):
    /// the earliest snapshot there from an npub that may rotate the base, the
    /// lower npub breaking a tie. The Refounder writes its snapshot as it mints.
    fn with_joiner_authorities(&self, opened: &[Opened]) -> HashMap<String, String> {
        let mut out = self.snapshot_authority_of.clone();
        let mut earliest: HashMap<&str, (&str, u64)> = HashMap::new();
        for ev in opened {
            if ev.rumor.kind != kinds::SNAPSHOT || !self.unrecorded.contains(&ev.stream_pk) || !self.admissible(ev) {
                continue;
            }
            if snap_tag(&ev.rumor.tags).is_none() || !(self.may_rotate)(ev.author()) {
                continue;
            }
            let best = earliest.get(ev.stream_pk.as_str());
            if best.is_none_or(|(a, ms)| ev.ms < *ms || (ev.ms == *ms && ev.author() < *a)) {
                earliest.insert(&ev.stream_pk, (ev.author(), ev.ms));
            }
        }
        for (pk, (author, _)) in earliest {
            out.insert(pk.to_owned(), author.to_owned());
        }
        out
    }

    fn admissible(&self, ev: &Opened) -> bool {
        ev.ms <= self.now_ms + MAX_FUTURE_MS && ev.seal_kind() == kinds::SEAL_ENCRYPTED && !self.banned.contains(ev.author())
    }
}

/// A Snapshot's `["snap", id, i, n]`: exactly one, 1 ≤ i ≤ n.
fn snap_tag(tags: &[Vec<String>]) -> Option<(String, u64, u64)> {
    let snaps: Vec<&Vec<String>> = tags.iter().filter(|t| t.len() >= 2 && t[0] == "snap").collect();
    let [t] = snaps.as_slice() else { return None };
    if t.len() < 4 || !crate::is_hex64(&t[1]) || !t[2].bytes().all(|b| b.is_ascii_digit()) || !t[3].bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (i, n) = (t[2].parse::<u64>().ok()?, t[3].parse::<u64>().ok()?);
    (i >= 1 && i <= n && n <= u32::MAX as u64).then(|| (t[1].to_lowercase(), i, n))
}

/// A Snapshot's members; malformed entries are dropped alone.
fn snapshot_members(content: &str) -> Vec<String> {
    let Ok(serde_json::Value::Array(list)) = serde_json::from_str::<serde_json::Value>(content) else { return vec![] };
    list.iter()
        .filter_map(|v| v.as_str())
        .map(str::to_lowercase)
        .filter(|pk| crate::is_hex64(pk) && nostr::prelude::PublicKey::from_hex(pk).is_ok())
        .collect()
}

/// Every Guestbook entry, judged (Armada `guestbookEntries`).
fn entries(opened: &[Opened], opts: &GuestbookOpts, mut apply: impl FnMut(Coalesced)) {
    let authority_of = opts.with_joiner_authorities(opened);
    for ev in opened {
        if !opts.admissible(ev) {
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
                apply(Coalesced { pubkey: r.pubkey.clone(), state, ms: ev.ms, rumor_id: r.id.clone(), from_snapshot: false });
            }
            kinds::KICK => {
                let Some(target) = sole_tag(r, "p").map(str::to_lowercase) else { continue };
                if !crate::is_hex64(&target) || !(opts.can_kick)(&r.pubkey, &target, Citation::from_tags(&r.tags).as_ref(), ev.ms) {
                    continue;
                }
                apply(Coalesced { pubkey: target, state: MemberState::Kick, ms: ev.ms, rumor_id: r.id.clone(), from_snapshot: false });
            }
            kinds::SNAPSHOT => {
                if authority_of.get(&ev.stream_pk) != Some(&r.pubkey) || snap_tag(&r.tags).is_none() {
                    continue;
                }
                for pk in snapshot_members(&r.content) {
                    apply(Coalesced { pubkey: pk, state: MemberState::Join, ms: ev.ms, rumor_id: r.id.clone(), from_snapshot: true });
                }
            }
            _ => {}
        }
    }
}

/// The live epoch's Refounding (CORD-02 §5, Armada `liveRefound`): the union of
/// every snapshot its minter put on the live epoch, cut at the earliest.
/// `None` unless every snapshot is whole — a missing chunk is no departure.
pub struct Refound {
    pub cut: u64,
    pub base: HashSet<String>,
    pub rumor_id: String,
}

pub fn live_refound(opened: &[Opened], opts: &GuestbookOpts) -> Option<Refound> {
    let live = opts.live_pk.as_ref()?;
    let authority = opts.with_joiner_authorities(opened).get(live)?.clone();
    let mut snapshots: HashMap<String, (HashSet<u64>, u64, Vec<&Opened>)> = HashMap::new();
    for ev in opened {
        if ev.rumor.kind != kinds::SNAPSHOT || &ev.stream_pk != live || ev.author() != authority || !opts.admissible(ev) {
            continue;
        }
        let Some((id, i, n)) = snap_tag(&ev.rumor.tags) else { continue };
        let s = snapshots.entry(id).or_default();
        s.0.insert(i);
        s.1 = s.1.max(n);
        s.2.push(ev);
    }
    if snapshots.is_empty() || snapshots.values().any(|(held, n, _)| (1..=*n).any(|i| !held.contains(&i))) {
        return None;
    }
    let mut out = Refound { cut: u64::MAX, base: HashSet::new(), rumor_id: String::new() };
    for ev in snapshots.values().flat_map(|s| s.2.iter()) {
        out.base.extend(snapshot_members(&ev.rumor.content));
        out.cut = out.cut.min(ev.ms);
        if out.rumor_id.is_empty() || ev.rumor.id < out.rumor_id {
            out.rumor_id = ev.rumor.id.clone();
        }
    }
    Some(out)
}

/// One final state per npub (CORD-02 §5): the latest Join, Leave or Kick wins,
/// ties to the lower rumor id, firsthand before a snapshot at one instant; a
/// Joined member the live Refounding omitted is `Refounded`.
pub fn coalesce(opened: &[Opened], opts: &GuestbookOpts) -> HashMap<String, Coalesced> {
    let mut by: HashMap<String, Coalesced> = HashMap::new();
    entries(opened, opts, |c| {
        let replace = match by.get(&c.pubkey) {
            None => true,
            Some(prev) if c.ms != prev.ms => c.ms > prev.ms,
            Some(prev) if prev.from_snapshot != c.from_snapshot => prev.from_snapshot,
            Some(prev) => c.rumor_id < prev.rumor_id,
        };
        if replace {
            by.insert(c.pubkey.clone(), c);
        }
    });
    if let (Some(refound), Some(live)) = (live_refound(opened, opts), opts.live_pk.as_ref()) {
        let plane_of: HashMap<&str, &str> = opened.iter().map(|e| (e.rumor.id.as_str(), e.stream_pk.as_str())).collect();
        for (pk, m) in by.iter_mut() {
            if m.state != MemberState::Join || refound.base.contains(pk) {
                continue;
            }
            let plane = plane_of.get(m.rumor_id.as_str());
            if m.ms < refound.cut || plane.is_some_and(|p| p != live) {
                *m = Coalesced { pubkey: pk.clone(), state: MemberState::Refounded, ms: refound.cut, rumor_id: refound.rumor_id.clone(), from_snapshot: true };
            }
        }
    }
    by
}

/// When to date `me`'s Join if the Guestbook, read whole, holds no state of
/// theirs (CORD-02 §5, Armada `joinToRestore`): at the live Refounding's cut,
/// else the live epoch's oldest entry, so two instances restoring it write one
/// rumor. `None` when a state of theirs stands, or nothing dates it.
pub fn join_to_restore(opened: &[Opened], opts: &GuestbookOpts, me: &str, owner: &str) -> Option<u64> {
    let live = opts.live_pk.as_ref()?;
    if me == owner || opts.banned.contains(me) {
        return None;
    }
    if coalesce(opened, opts).get(me).is_some_and(|c| c.state != MemberState::Refounded) {
        return None;
    }
    if let Some(r) = live_refound(opened, opts) {
        return Some(r.cut);
    }
    opened.iter().filter(|e| &e.stream_pk == live).map(|e| e.ms).min()
}

/// A Nickname's cap in Unicode scalar values (CORD-04 §10).
pub const NICKNAME_MAX_CHARS: usize = 32;

/// Whether `actor` may set `target`'s Nickname (Armada `mayName`): another's
/// with MANAGE_NICKNAMES over a member they outrank; one's own with
/// CHANGE_NICKNAME, which any member holds on the legacy Roster.
pub fn may_name(f: &crate::control::FoldedControl, actor: &str, target: &str) -> bool {
    if actor != target {
        return f.roster.can_act_on_member(actor, &f.owner, target, crate::roles::perm::MANAGE_NICKNAMES);
    }
    actor == f.owner || f.roster.everyone.is_none() || f.roster.has(actor, crate::roles::perm::CHANGE_NICKNAME)
}

/// The Nicknames members go by (CORD-04 §10, Armada `foldNicknames`): per
/// target the newest kind-3315 among those `may_name` lets name them, the
/// lower rumor id breaking a tie; `""` clears; while a member's Timeout runs
/// their own Nicknames name nobody. `opened` is the live epoch's Guestbook
/// only. Shown without direction controls and invisible spacers, which let a
/// Nickname pass for another, and trimmed.
pub fn fold_nicknames(
    opened: &[Opened],
    now_ms: u64,
    banned: &HashSet<String>,
    timeouts: &HashMap<String, FoldedTimeout>,
    may_name: impl Fn(&str, &str, Option<&Citation>) -> bool,
) -> HashMap<String, String> {
    let mut best: HashMap<String, (String, u64, String)> = HashMap::new();
    for ev in opened {
        let r = &ev.rumor;
        if r.kind != kinds::NICKNAME || ev.ms > now_ms + MAX_FUTURE_MS || ev.seal_kind() != kinds::SEAL_ENCRYPTED || banned.contains(ev.author()) {
            continue;
        }
        let Some(target) = sole_tag(r, "p").map(str::to_lowercase) else { continue };
        if !crate::is_hex64(&target) || r.content.chars().any(char::is_control) {
            continue;
        }
        if target == r.pubkey && timeouts.get(&target).is_some_and(|t| t.running(now_ms)) {
            continue;
        }
        if !may_name(&r.pubkey, &target, Citation::from_tags(&r.tags).as_ref()) {
            continue;
        }
        if let Some((_, ms, id)) = best.get(&target)
            && (ev.ms < *ms || (ev.ms == *ms && r.id >= *id))
        {
            continue;
        }
        let nick: String = r.content.chars().take(NICKNAME_MAX_CHARS).collect();
        best.insert(target, (nick, ev.ms, r.id.clone()));
    }
    const SPOOFING: &[char] = &['\u{061C}', '\u{200B}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2060}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{FEFF}'];
    best.into_iter()
        .filter_map(|(pk, (nick, _, _))| {
            let shown: String = nick.chars().filter(|c| !SPOOFING.contains(c)).collect();
            let shown = shown.trim();
            (!shown.is_empty()).then(|| (pk, shown.to_owned()))
        })
        .collect()
}

/// Every member's Guestbook entries in order of time: what a departure window reads.
pub type GuestbookHistory = HashMap<String, Vec<Coalesced>>;

pub fn guestbook_history(opened: &[Opened], opts: &GuestbookOpts) -> GuestbookHistory {
    let mut out: GuestbookHistory = HashMap::new();
    entries(opened, opts, |c| out.entry(c.pubkey.clone()).or_default().push(c));
    for list in out.values_mut() {
        // Winner last: time, a snapshot seed before a firsthand entry, then the higher id first.
        list.sort_by(|a, b| a.ms.cmp(&b.ms).then((!a.from_snapshot).cmp(&!b.from_snapshot)).then(b.rumor_id.cmp(&a.rumor_id)));
    }
    out
}

/// Whether `member` was away at `at_ms`: a Leave or Kick not yet followed by a Join (CORD-03 §1).
pub fn away_at(h: &GuestbookHistory, member: &str, at_ms: u64) -> bool {
    let mut away = false;
    for e in h.get(member).into_iter().flatten() {
        if e.ms > at_ms {
            break;
        }
        away = e.state != MemberState::Join;
    }
    away
}

/// Whether a span `member` spent away holding a Kick began by `at_ms` and
/// reaches a window that opened at `start_ms` (Armada `kickedAwayIn`).
pub fn kicked_away_in(h: &GuestbookHistory, member: &str, start_ms: u64, at_ms: u64) -> bool {
    let (mut from, mut kicked) = (None::<u64>, false);
    for e in h.get(member).into_iter().flatten() {
        match e.state {
            MemberState::Refounded => continue,
            MemberState::Join => {
                if from.is_some_and(|f| kicked && f <= at_ms && e.ms > start_ms) {
                    return true;
                }
                (from, kicked) = (None, false);
            }
            state => {
                from.get_or_insert(e.ms);
                kicked |= state == MemberState::Kick;
            }
        }
    }
    from.is_some_and(|f| kicked && f <= at_ms)
}

/// Whether a span `member` spent away holding a Kick reaches into a window that
/// opened at `start_ms` (Armada `kickedInto`): a span runs from the first Leave
/// or Kick after a Join to the next Join.
pub fn kicked_into(h: &GuestbookHistory, member: &str, start_ms: u64) -> bool {
    let (mut from, mut kicked) = (None::<u64>, false);
    for e in h.get(member).into_iter().flatten() {
        match e.state {
            MemberState::Refounded => continue,
            MemberState::Join => {
                if from.is_some() && kicked && e.ms > start_ms {
                    return true;
                }
                (from, kicked) = (None, false);
            }
            state => {
                from.get_or_insert(e.ms);
                kicked |= state == MemberState::Kick;
            }
        }
    }
    from.is_some() && kicked
}

/// Whether `member`'s latest entry is a Join.
pub fn is_member_in(h: &GuestbookHistory, member: &str) -> bool {
    h.get(member).and_then(|l| l.last()).is_some_and(|e| e.state == MemberState::Join)
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

/// The most Timeout rumors a [`TimeoutBook`] holds.
pub const MAX_TIMEOUTS_HELD: usize = 10_000;

/// The Guestbook's Timeout rumors a member holds for [`fold_timeouts`], kept
/// raw since whether one counts is judged against the Roster as it stands.
///
/// Any member holds the Guestbook key, so any member can publish Timeouts. A
/// plain bounded list filled with a flood stopped taking real ones, and every
/// Timeout after it went unseen. Only the newest per (author, target) is kept,
/// a rumor whose author couldn't time anyone out now is refused, and when the
/// book is full such authors' rumors are evicted first.
#[derive(Clone, Debug, Default)]
pub struct TimeoutBook {
    held: HashMap<(String, String), Opened>,
}

impl TimeoutBook {
    /// Hold `opened` if it is a Timeout. `moderates(author)` says whether the
    /// author could time anyone out by the Roster as read; pass `|_| true`
    /// before any fold, and [`TimeoutBook::prune`] once there is one.
    pub fn hold(&mut self, opened: Opened, moderates: impl Fn(&str) -> bool) {
        let r = &opened.rumor;
        if r.kind != kinds::TIMEOUT || !moderates(&r.pubkey) {
            return;
        }
        let Some(target) = sole_tag(r, "p").map(str::to_lowercase) else { return };
        let key = (r.pubkey.clone(), target);
        if let Some(prev) = self.held.get(&key)
            && (opened.ms < prev.ms || (opened.ms == prev.ms && r.id >= prev.rumor.id))
        {
            return;
        }
        if !self.held.contains_key(&key) && self.held.len() >= MAX_TIMEOUTS_HELD {
            self.prune(&moderates);
            if self.held.len() >= MAX_TIMEOUTS_HELD {
                return;
            }
        }
        self.held.insert(key, opened);
    }

    /// Drop the rumors of authors who couldn't time anyone out now.
    pub fn prune(&mut self, moderates: impl Fn(&str) -> bool) {
        self.held.retain(|(author, _), _| moderates(author));
    }

    pub fn len(&self) -> usize {
        self.held.len()
    }

    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    pub fn rumors(&self) -> Vec<Opened> {
        self.held.values().cloned().collect()
    }
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

#[cfg(test)]
mod timeout_book_tests {
    use super::*;
    use crate::kinds::Plane;
    use crate::stream::{StreamKey, WrapOptions, open_plane_wrap, seal_and_wrap};
    use nostr::prelude::Keys;

    fn timeout(by: &Keys, target: &str, ms: u64) -> Opened {
        let stream: StreamKey = (&crate::derive::guestbook_group_key(&[1; 32], &[2; 32], 0)).into();
        let r = Rumor::new(kinds::TIMEOUT, "", vec![tag(["p", target]), tag(["until", "9999999999"])], &by.public_key().to_hex(), Some(ms), None);
        open_plane_wrap(&seal_and_wrap(&r, Plane::Guestbook, &stream, by, WrapOptions::default()).unwrap(), &stream, Plane::Guestbook).unwrap()
    }

    #[test]
    fn a_flood_from_one_member_cant_crowd_out_a_moderators_timeout() {
        let (spammer, moderator) = (Keys::generate(), Keys::generate());
        let target = Keys::generate().public_key().to_hex();
        let mut book = TimeoutBook::default();
        for i in 0..20 {
            book.hold(timeout(&spammer, &target, 1_000 + i), |_| true);
        }
        assert_eq!(book.len(), 1, "one per author and target, the newest");
        assert_eq!(book.rumors()[0].ms, 1_019);
        let mod_hex = moderator.public_key().to_hex();
        book.prune(|a| a == mod_hex);
        assert!(book.is_empty());
        book.hold(timeout(&spammer, &target, 5_000), |a| a == mod_hex);
        book.hold(timeout(&moderator, &target, 5_000), |a| a == mod_hex);
        assert_eq!(book.len(), 1);
        assert_eq!(book.rumors()[0].author(), mod_hex);
    }
}

#[cfg(test)]
mod coalesce_tests {
    use super::*;
    use crate::kinds::Plane;
    use crate::stream::{StreamKey, WrapOptions, open_plane_wrap, seal_and_wrap};
    use nostr::prelude::Keys;

    fn stream(epoch: u64) -> StreamKey {
        (&crate::derive::guestbook_group_key(&[1; 32], &[2; 32], epoch)).into()
    }

    fn put(by: &Keys, r: Rumor, epoch: u64) -> Opened {
        let s = stream(epoch);
        open_plane_wrap(&seal_and_wrap(&r, Plane::Guestbook, &s, by, WrapOptions::default()).unwrap(), &s, Plane::Guestbook).unwrap()
    }

    fn kick(by: &Keys, target: &str, ms: u64) -> Rumor {
        Rumor::new(kinds::KICK, "", vec![tag(["p", target])], &by.public_key().to_hex(), Some(ms), None)
    }

    fn opts<'a>(banned: &'a HashSet<String>, kicker: &'a str, live: u64) -> GuestbookOpts<'a> {
        let can: &'a CanKick<'a> = Box::leak(Box::new(move |a: &str, _: &str, _: Option<&Citation>, _| a == kicker));
        let rot: &'a dyn Fn(&str) -> bool = Box::leak(Box::new(move |a: &str| a == kicker));
        GuestbookOpts {
            now_ms: 10_000_000,
            banned,
            can_kick: can,
            snapshot_authority_of: HashMap::new(),
            unrecorded: HashSet::new(),
            may_rotate: rot,
            live_pk: Some(stream(live).pk.to_hex()),
        }
    }

    #[test]
    fn a_kick_before_a_later_join_counts_for_nothing_and_a_stranger_kicks_nobody() {
        let (moderator, stranger, bot) = (Keys::generate(), Keys::generate(), Keys::generate());
        let me = bot.public_key().to_hex();
        let banned = HashSet::new();
        let mod_hex = moderator.public_key().to_hex();
        let o = opts(&banned, &mod_hex, 0);
        let mut opened = vec![put(&bot, join(&me, 1_000, None), 0), put(&moderator, kick(&moderator, &me, 2_000), 0)];
        assert_eq!(coalesce(&opened, &o)[&me].state, MemberState::Kick);
        opened.push(put(&bot, join(&me, 3_000, None), 0));
        assert_eq!(coalesce(&opened, &o)[&me].state, MemberState::Join, "re-invited after it");
        opened.push(put(&stranger, kick(&stranger, &me, 4_000), 0));
        assert_eq!(coalesce(&opened, &o)[&me].state, MemberState::Join);
        let h = guestbook_history(&opened, &o);
        assert!(away_at(&h, &me, 2_500) && !away_at(&h, &me, 3_500));
        assert!(kicked_away_in(&h, &me, 0, 2_500));
        assert!(is_member_in(&h, &me));
    }

    #[test]
    fn a_lost_join_is_restored_at_the_refounding_cut_and_never_over_one_that_stands() {
        let (refounder, bot) = (Keys::generate(), Keys::generate());
        let me = bot.public_key().to_hex();
        let banned = HashSet::new();
        let r_hex = refounder.public_key().to_hex();
        let mut o = opts(&banned, &r_hex, 1);
        o.unrecorded.insert(stream(1).pk.to_hex());
        let snap = |members: Vec<&str>, ms| {
            let snap_tag = vec!["snap".to_string(), "ab".repeat(32), "1".into(), "1".into()];
            Rumor::new(kinds::SNAPSHOT, serde_json::to_string(&members).unwrap(), vec![snap_tag], &r_hex, Some(ms), None)
        };
        let other = Keys::generate().public_key().to_hex();
        let mut opened = vec![put(&bot, join(&me, 1_000, None), 0), put(&refounder, snap(vec![&other], 5_000), 1)];
        assert_eq!(coalesce(&opened, &o)[&me].state, MemberState::Refounded, "the snapshot omitted us");
        assert_eq!(join_to_restore(&opened, &o, &me, "owner"), Some(5_000));
        opened.push(put(&refounder, snap(vec![&me], 5_000), 1));
        assert_eq!(join_to_restore(&opened, &o, &me, "owner"), None, "carried across by a snapshot");
    }
}

#[cfg(test)]
mod nickname_tests {
    use super::*;
    use crate::kinds::Plane;
    use crate::stream::{StreamKey, WrapOptions, open_plane_wrap, seal_and_wrap};
    use nostr::prelude::Keys;

    fn nick(by: &Keys, target: &str, name: &str, ms: u64) -> Opened {
        let s: StreamKey = (&crate::derive::guestbook_group_key(&[1; 32], &[2; 32], 0)).into();
        let r = Rumor::new(kinds::NICKNAME, name, vec![tag(["p", target])], &by.public_key().to_hex(), Some(ms), None);
        open_plane_wrap(&seal_and_wrap(&r, Plane::Guestbook, &s, by, WrapOptions::default()).unwrap(), &s, Plane::Guestbook).unwrap()
    }

    #[test]
    fn a_member_names_themselves_unless_timed_out_and_spoofing_marks_are_stripped() {
        let (alice, mallory) = (Keys::generate(), Keys::generate());
        let a = alice.public_key().to_hex();
        let may = |actor: &str, target: &str, _: Option<&Citation>| actor == target;
        let opened = vec![nick(&alice, &a, "Al\u{202E}ice", 1_000), nick(&mallory, &a, "Mal", 2_000)];
        let folded = fold_nicknames(&opened, 10_000, &HashSet::new(), &HashMap::new(), may);
        assert_eq!(folded.get(&a).map(String::as_str), Some("Alice"), "another's Nickname for her doesn't count");
        let t = HashMap::from([(a.clone(), FoldedTimeout { by: String::new(), from_secs: 0, until: 100, ms: 0, rumor_id: String::new() })]);
        assert!(fold_nicknames(&opened, 10_000, &HashSet::new(), &t, may).is_empty());
        let cleared = vec![opened[0].clone(), nick(&alice, &a, "", 3_000)];
        assert!(fold_nicknames(&cleared, 10_000, &HashSet::new(), &HashMap::new(), may).is_empty());
    }
}
