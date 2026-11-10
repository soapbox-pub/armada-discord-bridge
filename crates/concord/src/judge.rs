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
use crate::guestbook::FoldedTimeout;
use crate::kinds;
use crate::roles::perm;
use crate::writers::{Ledger, ledger_restricted, post_stands, read_address_takes, rides_writer_address, writer_windows};

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
/// Timeouts (empty when unread). Membership and departures are not judged:
/// like Armada with its Guestbook unread, the ledger and the Roster decide.
pub fn judge_post(folded: &FoldedControl, community_id: &Bytes32, channel_id_hex: &str, post: Post, timeouts: &HashMap<String, FoldedTimeout>, now_ms: u64) -> Verdict {
    if let Some(ledger) = folded.writers.get(channel_id_hex)
        && !ledger_stands(folded, ledger, community_id, channel_id_hex, &post) {
            return Verdict::Held;
        }
    if collapses(folded, channel_id_hex, &post, timeouts, now_ms) { Verdict::Collapsed } else { Verdict::Stands }
}

/// A restricted Channel's judge (Armada `writerJudge`): a post stands by the
/// ledger, at an address that takes it, or on the Roster, from a member who
/// manages Channels or may post there and crossed a move of the ledger.
fn ledger_stands(folded: &FoldedControl, ledger: &Ledger, community_id: &Bytes32, channel_id_hex: &str, m: &Post) -> bool {
    let owner = folded.owner.as_str();
    if folded.banned.contains(m.author) && m.author != owner {
        return false;
    }
    let wepoch = crate::rumor::tag_value(m.tags, "wepoch").map(|t| t.parse::<u64>().ok());
    let windows = writer_windows(ledger);
    let open = read_address_takes(ledger, m.ms);
    let by_ledger = match wepoch {
        None => open || !rides_writer_address(m.kind),
        Some(_) if open => true,
        Some(_) => post_stands(ledger, community_id, m.author, m.ms, m.tags),
    };
    if by_ledger {
        return true;
    }
    if m.author == owner {
        return true;
    }
    let just_past = |edge: u64| edge <= m.ms && m.ms - edge < ENTRY_SKEW_MS;
    let crossed_a_move = windows.iter().any(|w| match wepoch {
        None => just_past(w.from),
        Some(e) => Some(w.epoch) == e && w.to.is_some_and(just_past),
    });
    let may_post = folded.channel_permissions(m.author, channel_id_hex) & perm::SEND_MESSAGES != 0;
    let writes = ledger_restricted(ledger) && crossed_a_move && may_post;
    folded.manages_channels(m.author) || writes
}

/// Posts inside their author's running Timeout, posts after a pause from
/// anyone but staff, and, in an open Channel on the ranked Roster, posts whose
/// author can't send there.
fn collapses(folded: &FoldedControl, channel_id_hex: &str, m: &Post, timeouts: &HashMap<String, FoldedTimeout>, now_ms: u64) -> bool {
    if let Some(t) = timeouts.get(m.author)
        && (t.silences(m.ms, now_ms) || m.edited_ms.is_some_and(|e| t.silences(e, now_ms))) {
            return true;
        }
    if let Some((since, _)) = folded.active_pause(now_ms / 1000)
        && m.ms >= since * 1000 && !folded.roster.is_staff(m.author, &folded.owner) {
            return true;
        }
    folded.ranked && folded.roster.everyone_sends(channel_id_hex) && folded.channel_permissions(m.author, channel_id_hex) & perm::SEND_MESSAGES == 0
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
        assert_eq!(judge_post(&f, &[0; 32], CHAN, post(ALICE, 1), &HashMap::new(), 2), Verdict::Stands);
        f.roster.overwrites.push(Overwrite { scope: CHAN.into(), target: OverwriteTarget::Member(ALICE.into()), allow: 0, deny: perm::SEND_MESSAGES });
        assert_eq!(judge_post(&f, &[0; 32], CHAN, post(ALICE, 1), &HashMap::new(), 2), Verdict::Collapsed);
    }

    #[test]
    fn a_timeout_collapses_inside_its_window_only() {
        let f = folded();
        let t = HashMap::from([(ALICE.to_owned(), FoldedTimeout { by: OWNER.into(), from_secs: 100, until: 200, ms: 100_000, rumor_id: String::new() })]);
        assert_eq!(judge_post(&f, &[0; 32], CHAN, post(ALICE, 150_000), &t, 160_000), Verdict::Collapsed);
        assert_eq!(judge_post(&f, &[0; 32], CHAN, post(ALICE, 50_000), &t, 160_000), Verdict::Stands);
        assert_eq!(judge_post(&f, &[0; 32], CHAN, post(ALICE, 150_000), &t, 250_000), Verdict::Stands, "a lapsed Timeout un-collapses");
    }

    #[test]
    fn future_posts_wait() {
        assert!(!is_held_ahead(kinds::MESSAGE, 1_004_000, 1_000_000));
        assert!(is_held_ahead(kinds::MESSAGE, 1_006_000, 1_000_000));
        assert!(!is_held_ahead(kinds::REACTION, 1_006_000, 1_000_000));
        assert!(is_beyond_horizon(1_000_000 + FUTURE_HORIZON_MS + 1, 1_000_000));
    }
}
