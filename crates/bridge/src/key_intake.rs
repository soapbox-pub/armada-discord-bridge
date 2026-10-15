//! Private-channel key intake: how the bridge is let into a gated room.
//!
//! A Public Channel derives its key from the community root, so the invite the
//! bridge joined with already reads every one of them. A Private Channel does
//! not: its key is an independent random secret, delivered per member (CORD-03
//! §1) as a Direct Invite (CORD-05 §6), giftwrapped to the recipient and
//! carrying exactly the channels that member's Roles entitle them to.
//!
//! So "add the bridge to #mods-only" in Armada lands here, and without this the
//! bridge's channel list is frozen at whatever its join bundle carried: a
//! Private Channel whose key it lacks is absent from `channels()`, and the bridge
//! reports "concord channel not found" for a room it can see named in the fold.
//!
//! Nothing is persisted. A Direct Invite is a durable relay event sealed TO US,
//! so re-scanning at boot recovers the same keys from the same relays — the
//! bridge needs no key custody of its own. The bound: a relay that has dropped
//! the wrap takes the key with it, and re-granting from Armada re-delivers.
//!
//! Rotation is NOT handled here. A rekey (CORD-06) delivers a new channel epoch
//! at the rekey addresses, which nothing subscribes to yet: after a
//! revoke-driven rotation the bridge keeps a superseded key and goes quiet on
//! that channel until it is re-invited.

use std::collections::HashMap;

use concord::community::Membership;
use concord::kinds;
use nostr::prelude::*;

use crate::relays::RelayLike;

/// How many giftwraps to pull per relay set. Bounded: this runs at boot.
const SCAN_LIMIT: usize = 200;

pub struct KeyIntake {
    /// The community with every newly-learned channel key merged in.
    pub community: Membership,
    /// Channel ids (hex) whose keys this scan added or advanced.
    pub learned: Vec<String>,
}

/// Scan the identity's giftwrap inbox for Direct Invites to THIS community and
/// merge the private-channel keys they carry.
///
/// `is_authorized_sender` decides whether a sender may vend channel keys here:
/// the owner, or a roster member holding MANAGE_CHANNELS. It is REQUIRED. Our
/// npub is public (kind 0, guestbook join, kind 10050), and the community's id,
/// owner and salt ride in every invite, so anyone at all can seal a well-formed
/// bundle to us naming this community. Without the gate, a stranger's bundle
/// claiming a higher epoch for a real channel id would replace that channel's
/// key — silently redirecting everything the bridge mirrors into a stream only
/// the attacker can read, persisting across restarts because the forged wrap
/// stays on the relays.
///
/// The scan is indexed by the wrap's outer `k` tag, which is why a recipient can
/// ask for exactly their invites. The tag is unsigned relay-visible bytes and
/// never authority: every wrap is still unwrapped, seal-verified and validated.
pub async fn intake_direct_invite_keys(
    relay_sets: &[&dyn RelayLike],
    identity: &Keys,
    community: &Membership,
    is_authorized_sender: impl Fn(&str) -> bool,
) -> KeyIntake {
    let filter = Filter::new()
        .kind(Kind::Custom(kinds::WRAP))
        .pubkey(identity.public_key())
        .custom_tag(SingleLetterTag::from_char('k').expect("k is a single-letter tag"), kinds::DIRECT_INVITE.to_string())
        .limit(SCAN_LIMIT);

    let mut wraps: HashMap<EventId, Event> = HashMap::new();
    for relays in relay_sets {
        for event in relays.query(vec![filter.clone()]).await.unwrap_or_default() {
            wraps.insert(event.id, event);
        }
    }
    // Oldest first, so a later vend at the same epoch never undoes an earlier one.
    let mut wraps: Vec<Event> = wraps.into_values().collect();
    wraps.sort_by_key(|w| w.created_at);

    let mut next = community.clone();
    let mut learned: Vec<String> = Vec::new();
    for wrap in &wraps {
        let Some(invite) = concord::direct_invite::unwrap(wrap, identity) else { continue };
        // WHO sealed this, before WHAT it says. Unwrapping proves the sender
        // (the seal opens only under the pairwise key, and the rumor's claimed
        // author must equal the seal's), but proven-who is not authorized-to.
        if !is_authorized_sender(&invite.inviter) {
            tracing::warn!(sender = %&invite.inviter[..8], "ignoring direct invite from unauthorized sender");
            continue;
        }
        // A bundle for another community is not ours to merge: channel ids are
        // random values that say nothing about which community minted them.
        if !invite.bundle.community_id.eq_ignore_ascii_case(&community.community_id) {
            continue;
        }
        // Union, never replace: a partial vend (one channel, which is what a
        // single role grant produces) must not displace keys already held, and
        // an id we hold can still ADVANCE — a re-vend at a higher epoch is a
        // rotation we were kept through.
        for id in next.adopt_catch_up(&invite.bundle) {
            if !learned.contains(&id) {
                learned.push(id);
            }
        }
    }
    next.relays = community.relays.clone();
    KeyIntake { community: next, learned }
}
