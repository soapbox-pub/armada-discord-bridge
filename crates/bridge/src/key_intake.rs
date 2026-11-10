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
//! On a Community on the ranked Roster (CORD-04 §2) keys travel differently: a
//! member an overwrite lets into a Private Channel is handed its key on the
//! Channel's access plane (CORD-03 §5), and a Private Channel is born, and
//! re-keyed after a ban, by a Channel rotation at its rekey address (CORD-06).
//! [`intake_access_keys`] reads both. Like a Direct Invite, each is a durable
//! relay event addressed to us, so a scan at every start recovers them and
//! nothing is persisted.

use std::collections::HashMap;

use concord::community::Membership;
use concord::control::FoldedControl;
use concord::delivery::{access_delivery_admits, access_key_refuted, open_access_key, parse_delivery};
use concord::direct_invite::{VendVerdict, judge_vend};
use concord::kinds::{self, Plane};
use concord::rekey::{group_rotations, parse_rekey};
use concord::stream::{StreamKey, open_plane_wrap};
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
/// Each vended key is judged against `folded` exactly as Armada judges a
/// catch-up ([`judge_vend`]). Our npub is public (kind 0, guestbook join, kind
/// 10050), and the community's id, owner and salt ride in every invite, so
/// anyone at all can seal a well-formed bundle to us naming this community; a
/// stranger's, or a banned or merely-entitled member's, claiming a higher
/// epoch for a real channel would otherwise replace that channel's key —
/// silently redirecting everything the bridge mirrors into a stream only the
/// sender can read, persisting across restarts because the wrap stays on the
/// relays.
///
/// The scan is indexed by the wrap's outer `k` tag, which is why a recipient can
/// ask for exactly their invites. The tag is unsigned relay-visible bytes and
/// never authority: every wrap is still unwrapped, seal-verified and validated.
pub async fn intake_direct_invite_keys(
    relay_sets: &[&dyn RelayLike],
    identity: &Keys,
    community: &Membership,
    folded: &FoldedControl,
) -> KeyIntake {
    let filter = Filter::new()
        .kind(Kind::Custom(kinds::WRAP))
        .pubkey(identity.public_key())
        .custom_tag(SingleLetterTag::from_char('k').expect("k is a single-letter tag"), kinds::DIRECT_INVITE.to_string())
        .limit(SCAN_LIMIT);

    // All sets at once, each settled: a start waited on this scan, set after
    // set, for the slowest relay of each. A key a late relay holds is missed
    // for this start only; it fails "channel not found" and retries.
    let scans = relay_sets.iter().map(|relays| relays.query_settled(vec![filter.clone()]));
    let mut wraps: HashMap<EventId, Event> = HashMap::new();
    for event in futures_util::future::join_all(scans).await.into_iter().flat_map(Result::unwrap_or_default) {
        wraps.insert(event.id, event);
    }
    // Oldest first, so a later vend at the same epoch never undoes an earlier one.
    let mut wraps: Vec<Event> = wraps.into_values().collect();
    wraps.sort_by_key(|w| w.created_at);

    let me = identity.public_key().to_hex();
    let mut next = community.clone();
    let mut learned: Vec<String> = Vec::new();
    for wrap in &wraps {
        let Some(invite) = concord::direct_invite::unwrap(wrap, identity) else { continue };
        // A bundle for another community is not ours to merge: channel ids are
        // random values that say nothing about which community minted them.
        if !invite.bundle.community_id.eq_ignore_ascii_case(&community.community_id) {
            continue;
        }
        // WHO sealed this, and whether the fold stands behind each key, before
        // WHAT it says. Unwrapping proves the sender (the seal opens only under
        // the pairwise key, and the rumor's claimed author must equal the
        // seal's), but proven-who is not authorized-to.
        let mut bundle = invite.bundle.clone();
        bundle.channels.retain(|c| {
            let held = next.private_channels.iter().find(|h| h.id.eq_ignore_ascii_case(&c.id)).map(|h| h.epoch);
            match judge_vend(folded, &me, &invite.inviter, c, held) {
                VendVerdict::Adopt => true,
                verdict => {
                    tracing::warn!(sender = %&invite.inviter[..8], channel = %c.id.get(..8).unwrap_or(&c.id), ?verdict, "ignoring a vended channel key");
                    false
                }
            }
        });
        // Union, never replace: a partial vend (one channel, which is what a
        // single role grant produces) must not displace keys already held, and
        // an id we hold can still ADVANCE — a re-vend at a higher epoch is a
        // rotation we were kept through.
        for id in next.adopt_catch_up(&bundle) {
            if !learned.contains(&id) {
                learned.push(id);
            }
        }
    }
    next.relays = community.relays.clone();
    KeyIntake { community: next, learned }
}

/// Take the Private Channel keys the ranked Roster hands this identity: access
/// deliveries on each Private Channel's access plane, then the Channel
/// rotations that carry the keys it holds forward (CORD-03 §5, CORD-06).
///
/// A delivered key is taken only as Armada takes one: this identity's fold
/// lets it view the Channel, the deliverer holds the Channel and isn't banned,
/// the epoch is the sealed head's or the next (the next only from the owner or
/// a manager), and at the sealed head's epoch the key must open the seal. The
/// seal is what authenticates a key; without these checks anyone who can
/// reach the plane could hand the bridge a key of their own and read
/// everything it mirrors.
pub async fn intake_access_keys(relays: &dyn RelayLike, identity: &Keys, community: &Membership, folded: &FoldedControl) -> KeyIntake {
    let me = identity.public_key().to_hex();
    let mut next = community.clone();
    let mut learned: Vec<String> = Vec::new();
    if folded.ranked {
        let wanted: Vec<(String, StreamKey)> = folded
            .channels
            .values()
            .filter(|c| c.private && !c.deleted)
            .filter(|c| folded.roster.channel_permissions(&folded.owner, &me, &c.channel_id_hex, true) & concord::roles::perm::VIEW_CHANNEL != 0)
            .filter_map(|c| Some((c.channel_id_hex.clone(), (&community.access_plane(&concord::hex32(&c.channel_id_hex)?)).into())))
            .collect();
        if !wanted.is_empty() {
            let filter = Filter::new().kind(Kind::Custom(kinds::WRAP)).authors(wanted.iter().map(|(_, s)| s.pk).collect::<Vec<_>>()).limit(SCAN_LIMIT);
            let mut wraps = relays.query_settled(vec![filter]).await.unwrap_or_default();
            wraps.sort_by_key(|w| w.created_at);
            for wrap in &wraps {
                let Some((channel_hex, plane)) = wanted.iter().find(|(_, s)| s.pk == wrap.pubkey) else { continue };
                let Some(d) = open_plane_wrap(wrap, plane, Plane::Rekey).ok().and_then(|o| parse_delivery(&o)) else { continue };
                if d.form != "access" || d.scope_hex != *channel_hex {
                    continue;
                }
                let sealed = folded.channels.get(channel_hex).and_then(|c| c.sealed.as_ref());
                if !access_delivery_admits(folded, sealed, channel_hex, &me, &d.deliverer, d.new_epoch) {
                    continue;
                }
                let Some(id) = concord::hex32(channel_hex) else { continue };
                let Some((epoch, key)) = open_access_key(&d, identity, &id) else { continue };
                if access_key_refuted(sealed, &id, epoch, &key) {
                    tracing::warn!(channel = %&channel_hex[..8], deliverer = %&d.deliverer[..8], "refusing a delivered key that doesn't open the channel's seal");
                    continue;
                }
                if next.adopt_channel_key(channel_hex, epoch, &key) && !learned.contains(channel_hex) {
                    learned.push(channel_hex.clone());
                }
            }
        }
    }
    // Rotations carry every held key forward: a birth at epoch 1, or the
    // re-key a ban or revoke triggers, which would otherwise leave the bridge
    // on a superseded key, silent.
    let addresses = next.channel_rekey_addresses();
    if !addresses.is_empty() {
        let streams: Vec<StreamKey> = addresses.iter().map(|(g, _, _)| g.into()).collect();
        let filter = Filter::new().kind(Kind::Custom(kinds::WRAP)).authors(streams.iter().map(|s| s.pk).collect::<Vec<_>>()).limit(SCAN_LIMIT);
        let wraps = relays.query_settled(vec![filter]).await.unwrap_or_default();
        let parsed = wraps
            .iter()
            .filter_map(|w| {
                let stream = streams.iter().find(|s| s.pk == w.pubkey)?;
                parse_rekey(&open_plane_wrap(w, stream, Plane::Rekey).ok()?).ok()
            })
            .collect();
        for (id, epoch) in next.apply_channel_rotations(&group_rotations(parsed), folded, identity) {
            match epoch {
                Some(_) if !learned.contains(&id) => learned.push(id),
                Some(_) => {}
                None => tracing::warn!(channel = %&id[..8], "a channel rotation cut this bridge out"),
            }
        }
    }
    KeyIntake { community: next, learned }
}
