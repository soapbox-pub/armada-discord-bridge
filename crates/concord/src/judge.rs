//! How a reader judges one Channel post (CORD-03 §1, §3; CORD-04 §8): whether
//! it stands, is collapsed (shown folded, openable), or is held (kept out of the
//! timeline for every reader). A port of Armada's `channelJudges.ts` and the
//! pause and future-hold rules of its `chat.ts`.
//!
//! A bridge must relay only what stands. Relaying a collapsed or held post
//! hands Discord exactly what the community's own clients hide — the bridge
//! becomes the way around a Timeout, a read-only Channel or a pause.

use std::collections::HashMap;

use crate::Bytes32;
use crate::control::FoldedControl;
use crate::guestbook::{FoldedTimeout, GuestbookHistory, away_at, is_member_in, kicked_away_in};
use crate::kinds;
use crate::roles::perm;
use crate::writers::{Ledger, ledger_restricted, locked_at, post_stands, read_address_quiet, read_address_takes, rides_writer_address, writer_windows};

/// A message dated more than this ahead of the reader's clock waits for its time (CORD-03 §3).
pub const FUTURE_HOLD_MS: u64 = 5_000;
/// Past this horizon it isn't held but met again as its date nears.
pub const FUTURE_HORIZON_MS: u64 = 3_600_000;
/// How far past the ledger entry that moved an address a post crossing it still stands (CORD-03 §1).
pub const ENTRY_SKEW_MS: u64 = 10 * 60_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Stands,
    /// Folded by the community's readers: a running Timeout, a pause, or no
    /// Send Messages in an open Channel. Openable there, so never silently lost.
    Collapsed,
    /// Kept out of the timeline: a restricted Channel's ledger doesn't stand behind it.
    Held,
}

/// One post as the judge needs it.
#[derive(Clone, Copy, Debug)]
pub struct Post<'a> {
    pub author: &'a str,
    pub kind: u16,
    pub ms: u64,
    /// The newest edit's time, when edited: a Timeout collapses an edit made inside it.
    pub edited_ms: Option<u64>,
    pub tags: &'a [Vec<String>],
}

/// Whether a reader holds this back for its time: a message or thread reply
/// dated past the tolerance, within the hour's horizon (CORD-03 §3).
pub fn is_held_ahead(kind: u16, ms: u64, now_ms: u64) -> bool {
    matches!(kind, kinds::MESSAGE | kinds::COMMENT) && ms > now_ms + FUTURE_HOLD_MS && ms <= now_ms + FUTURE_HORIZON_MS
}

/// Whether a message is dated so far ahead that readers don't show it at all yet.
pub fn is_beyond_horizon(ms: u64, now_ms: u64) -> bool {
    ms > now_ms + FUTURE_HORIZON_MS
}

/// Judge one post in one Channel. `timeouts` is the Guestbook's folded
/// Timeouts (empty when unread). `history` is the Guestbook's entries
/// ([`crate::guestbook::guestbook_history`]); while it's unread, membership and
/// departures aren't judged, as Armada judges with its Guestbook unread.
///
/// `public_until_ms` is when a converted Channel went private (CORD-03 §2,
/// from its opened seal): a post dated before it was a public post, and isn't
/// collapsed for a Send Messages the private Channel no longer gives.
#[allow(clippy::too_many_arguments)]
pub fn judge_post(
    folded: &FoldedControl,
    community_id: &Bytes32,
    channel_id_hex: &str,
    post: Post,
    timeouts: &HashMap<String, FoldedTimeout>,
    history: Option<&GuestbookHistory>,
    now_ms: u64,
    public_until_ms: Option<u64>,
) -> Verdict {
    if let Some(ledger) = folded.writers.get(channel_id_hex)
        && !ledger_stands(folded, ledger, community_id, channel_id_hex, &post, history)
    {
        return Verdict::Held;
    }
    if collapses(folded, channel_id_hex, &post, timeouts, now_ms, public_until_ms) { Verdict::Collapsed } else { Verdict::Stands }
}

/// Whether readers ignore a reaction by `author` here (CORD-04 §8, Armada
/// `reactionIgnored`): on the ranked Roster, one whose author lacks
/// ADD_REACTIONS in the Channel as the Roster stands. Ignored, not deleted,
/// so a Roster that gives the bit back counts it again.
pub fn reaction_ignored(folded: &FoldedControl, channel_id_hex: &str, author: &str) -> bool {
    folded.ranked && folded.channel_permissions(author, channel_id_hex) & perm::ADD_REACTIONS == 0
}

/// A restricted Channel's judge (Armada `writerJudge`): a write stands by the
/// ledger, at an address that takes it from a writer who hadn't left, on a
/// certificate covering its kind, or on the Roster, from a member who manages
/// Channels or may make it there and crossed a move of the ledger. In a Locked
/// window every write is judged so, and the read address takes nothing once
/// its quiet span begins, a wrap backdated into it included.
fn ledger_stands(folded: &FoldedControl, ledger: &Ledger, community_id: &Bytes32, channel_id_hex: &str, m: &Post, history: Option<&GuestbookHistory>) -> bool {
    let owner = folded.owner.as_str();
    if folded.banned.contains(m.author) && m.author != owner {
        return false;
    }
    let wepoch = crate::rumor::tag_value(m.tags, "wepoch").map(|t| t.parse::<u64>().ok());
    let windows = writer_windows(ledger);
    let departed = |at: u64| history.is_some_and(|h| away_at(h, m.author, at));
    let by_ledger = {
        let quiet = read_address_quiet(ledger, m.ms);
        let open = read_address_takes(ledger, m.ms);
        match wepoch {
            None => !rides_writer_address(m.kind, locked_at(ledger, m.ms) || quiet) || (open && !quiet),
            Some(e) => {
                let start = e.and_then(|e| windows.iter().find(|w| w.epoch == e)).map_or(0, |w| w.from);
                // Dated before its window, the key it rides wasn't given yet.
                (open && m.ms >= start)
                    || (post_stands(ledger, community_id, m.author, m.kind, m.ms, m.tags)
                        && !history.is_some_and(|h| kicked_away_in(h, m.author, start, m.ms))
                        && !departed(m.ms))
            }
        }
    };
    if by_ledger || m.author == owner {
        return true;
    }
    let just_past = |edge: u64| edge <= m.ms && m.ms - edge < ENTRY_SKEW_MS;
    let crossed_a_move = windows.iter().any(|w| match wepoch {
        None => just_past(w.from),
        Some(e) => Some(w.epoch) == e && w.to.is_some_and(just_past),
    });
    let writes = ledger_restricted(ledger) && crossed_a_move && folded.may_send_kind(m.author, channel_id_hex, m.kind);
    let member = history.is_none_or(|h| is_member_in(h, m.author));
    (folded.manages_channels(m.author) || writes) && member && !departed(m.ms)
}

/// Posts inside their author's running Timeout, posts after a pause from
/// anyone but staff, and, in an open Channel on the ranked Roster, posts whose
/// author can't send there.
fn collapses(folded: &FoldedControl, channel_id_hex: &str, m: &Post, timeouts: &HashMap<String, FoldedTimeout>, now_ms: u64, public_until_ms: Option<u64>) -> bool {
    if let Some(t) = timeouts.get(m.author)
        && (t.silences(m.ms, now_ms) || m.edited_ms.is_some_and(|e| t.silences(e, now_ms))) {
            return true;
        }
    if let Some((since, _)) = folded.active_pause(now_ms / 1000)
        && m.ms >= since * 1000 && !folded.roster.is_staff(m.author, &folded.owner) {
            return true;
        }
    let public_era = public_until_ms.is_some_and(|until| m.ms < until);
    folded.ranked && folded.roster.everyone_sends(channel_id_hex) && !public_era && folded.channel_permissions(m.author, channel_id_hex) & perm::SEND_MESSAGES == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::FoldedChannel;
    use crate::roles::{Overwrite, OverwriteTarget};

    const OWNER: &str = "00000000000000000000000000000000000000000000000000000000000000aa";
    const ALICE: &str = "00000000000000000000000000000000000000000000000000000000000000a1";
    const CHAN: &str = "00000000000000000000000000000000000000000000000000000000000000c1";

    fn folded() -> FoldedControl {
        let mut f = FoldedControl { owner: OWNER.into(), ranked: true, ..Default::default() };
        f.roster.everyone = Some(perm::EVERYONE_DEFAULT);
        f.channels.insert(CHAN.into(), FoldedChannel { channel_id_hex: CHAN.into(), name: "c".into(), ..Default::default() });
        f
    }

    fn post(author: &str, ms: u64) -> Post<'_> {
        Post { author, kind: kinds::MESSAGE, ms, edited_ms: None, tags: &[] }
    }

    #[test]
    fn a_member_overwrite_denying_send_collapses_in_an_open_channel() {
        let mut f = folded();
        assert_eq!(judge_post(&f, &[0; 32], CHAN, post(ALICE, 1), &HashMap::new(), None, 2, None), Verdict::Stands);
        f.roster.overwrites.push(Overwrite { scope: CHAN.into(), target: OverwriteTarget::Member(ALICE.into()), allow: 0, deny: perm::SEND_MESSAGES });
        assert_eq!(judge_post(&f, &[0; 32], CHAN, post(ALICE, 1), &HashMap::new(), None, 2, None), Verdict::Collapsed);
    }

    #[test]
    fn a_timeout_collapses_inside_its_window_only() {
        let f = folded();
        let t = HashMap::from([(ALICE.to_owned(), FoldedTimeout { by: OWNER.into(), from_secs: 100, until: 200, ms: 100_000, rumor_id: String::new() })]);
        assert_eq!(judge_post(&f, &[0; 32], CHAN, post(ALICE, 150_000), &t, None, 160_000, None), Verdict::Collapsed);
        assert_eq!(judge_post(&f, &[0; 32], CHAN, post(ALICE, 50_000), &t, None, 160_000, None), Verdict::Stands);
        assert_eq!(judge_post(&f, &[0; 32], CHAN, post(ALICE, 150_000), &t, None, 250_000, None), Verdict::Stands, "a lapsed Timeout un-collapses");
    }

    #[test]
    fn a_locked_window_holds_a_reaction_at_the_read_address() {
        use crate::writers::{Spell, empty_ledger, ledger_appended, ledger_appended_locked};
        let mut f = folded();
        let writer = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_owned();
        let spell = || Spell::Writer { epoch: 1, pk: writer.clone(), root: 0, by: OWNER.into(), certifier: None };
        let reaction = Post { author: ALICE, kind: kinds::REACTION, ms: 100_000_000, edited_ms: None, tags: &[] };
        f.writers.insert(CHAN.into(), ledger_appended(&empty_ledger(CHAN), 1_000, spell()).unwrap());
        assert_eq!(judge_post(&f, &[0; 32], CHAN, reaction, &HashMap::new(), None, 100_000_000, None), Verdict::Stands, "reactions stay at the read address");
        f.writers.insert(CHAN.into(), ledger_appended_locked(&empty_ledger(CHAN), 1_000, spell()).unwrap());
        assert_eq!(judge_post(&f, &[0; 32], CHAN, reaction, &HashMap::new(), None, 100_000_000, None), Verdict::Held, "a Locked window takes them only from writers");
    }

    #[test]
    fn a_reaction_without_add_reactions_is_ignored_on_the_ranked_roster_only() {
        let mut f = folded();
        assert!(!reaction_ignored(&f, CHAN, ALICE));
        f.roster.overwrites.push(Overwrite { scope: CHAN.into(), target: OverwriteTarget::Member(ALICE.into()), allow: 0, deny: perm::ADD_REACTIONS });
        assert!(reaction_ignored(&f, CHAN, ALICE));
        assert!(!reaction_ignored(&f, CHAN, OWNER));
        f.ranked = false;
        assert!(!reaction_ignored(&f, CHAN, ALICE));
    }

    fn certified_ledger(f: &mut FoldedControl, certifier: &nostr::prelude::Keys, writer: &nostr::prelude::Keys) -> String {
        use crate::writers::{Spell, empty_ledger, ledger_appended_locked};
        let spell = Spell::Writer { epoch: 1, pk: writer.public_key().to_hex(), root: 0, by: OWNER.into(), certifier: Some(certifier.public_key().to_hex()) };
        f.writers.insert(CHAN.into(), ledger_appended_locked(&empty_ledger(CHAN), 1_000, spell).unwrap());
        writer.public_key().to_hex()
    }

    #[test]
    fn a_scoped_certificate_carries_a_reaction_but_never_a_post() {
        use crate::writers::{SCOPED_BITS, scoped_cert_digest, sign_writer_cert};
        let mut f = folded();
        let (certifier, address, bob) = (nostr::prelude::Keys::generate(), nostr::prelude::Keys::generate(), nostr::prelude::Keys::generate());
        certified_ledger(&mut f, &certifier, &address);
        let digest = scoped_cert_digest(&[0; 32], &crate::hex32(CHAN).unwrap(), 1, &bob.public_key().to_bytes(), SCOPED_BITS);
        let tags = vec![vec!["wepoch".to_string(), "1".into()], vec!["rcert".into(), sign_writer_cert(certifier.secret_key(), &digest), SCOPED_BITS.to_string()]];
        let bob_hex = bob.public_key().to_hex();
        let at = |kind| Post { author: &bob_hex, kind, ms: 5_000, edited_ms: None, tags: &tags };
        assert_eq!(judge_post(&f, &[0; 32], CHAN, at(kinds::REACTION), &HashMap::new(), None, 5_000, None), Verdict::Stands);
        assert_eq!(judge_post(&f, &[0; 32], CHAN, at(kinds::MESSAGE), &HashMap::new(), None, 5_000, None), Verdict::Held);
    }

    #[test]
    fn a_kicked_writer_with_a_kept_key_is_held() {
        use crate::guestbook::{Coalesced, MemberState};
        use crate::writers::{cert_digest, sign_writer_cert};
        let mut f = folded();
        let (certifier, address, bob) = (nostr::prelude::Keys::generate(), nostr::prelude::Keys::generate(), nostr::prelude::Keys::generate());
        certified_ledger(&mut f, &certifier, &address);
        let bob_hex = bob.public_key().to_hex();
        let cert = sign_writer_cert(certifier.secret_key(), &cert_digest(&[0; 32], &crate::hex32(CHAN).unwrap(), 1, &bob.public_key().to_bytes()));
        let tags = vec![vec!["wepoch".to_string(), "1".into()], vec!["wcert".into(), cert]];
        let post = Post { author: &bob_hex, kind: kinds::MESSAGE, ms: 9_000, edited_ms: None, tags: &tags };
        let entry = |state, ms| Coalesced { pubkey: bob_hex.clone(), state, ms, rumor_id: format!("{ms}"), from_snapshot: false };
        let mut h = HashMap::from([(bob_hex.clone(), vec![entry(MemberState::Join, 500)])]);
        assert_eq!(judge_post(&f, &[0; 32], CHAN, post, &HashMap::new(), Some(&h), 9_000, None), Verdict::Stands);
        h.get_mut(&bob_hex).unwrap().push(entry(MemberState::Kick, 7_000));
        assert_eq!(judge_post(&f, &[0; 32], CHAN, post, &HashMap::new(), Some(&h), 9_000, None), Verdict::Held, "kicked, the key kept");
        assert_eq!(judge_post(&f, &[0; 32], CHAN, post, &HashMap::new(), None, 9_000, None), Verdict::Stands, "with the Guestbook unread nothing is judged");
    }

    #[test]
    fn a_post_backdated_into_a_sealed_run_is_held() {
        use crate::writers::{Spell, empty_ledger, ledger_appended};
        let mut f = folded();
        let mut l = ledger_appended(&empty_ledger(CHAN), 1_000, Spell::Open).unwrap();
        let post = Post { author: ALICE, kind: kinds::MESSAGE, ms: 2_000_000, edited_ms: None, tags: &[] };
        f.writers.insert(CHAN.into(), l.clone());
        assert_eq!(judge_post(&f, &[0; 32], CHAN, post, &HashMap::new(), None, 3_000_000, None), Verdict::Stands);
        l.extra.insert("seal".into(), serde_json::json!({ "page": null, "read": 0, "until": 1_000_000, "run": 1_000_000, "count": 0 }));
        f.writers.insert(CHAN.into(), l);
        assert_eq!(judge_post(&f, &[0; 32], CHAN, post, &HashMap::new(), None, 3_000_000, None), Verdict::Held);
    }

    #[test]
    fn future_posts_wait() {
        assert!(!is_held_ahead(kinds::MESSAGE, 1_004_000, 1_000_000));
        assert!(is_held_ahead(kinds::MESSAGE, 1_006_000, 1_000_000));
        assert!(!is_held_ahead(kinds::REACTION, 1_006_000, 1_000_000));
        assert!(is_beyond_horizon(1_000_000 + FUTURE_HORIZON_MS + 1, 1_000_000));
    }
}
