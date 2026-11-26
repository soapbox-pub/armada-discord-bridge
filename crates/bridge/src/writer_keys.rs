//! Posting in a restricted Channel as one of its writers (CORD-03 §1): reading
//! a Channel's writer deliveries off its access plane. What a member takes
//! from them, and writes with, is the kernel's (`concord::writer_keys`),
//! shared with armada-matrix-bridge.
//!
//! Every identity the bridge posts as is a member like any other here: a
//! puppet an Armada moderator approved is owed the key by the same writer duty
//! that serves Armada's members, and takes it the same way.

use concord::community::Membership;
use concord::control::FoldedControl;
use concord::delivery::ParsedDelivery;
use concord::kinds;
use concord::stream::StreamKey;
pub use concord::writer_keys::{HeldWriter, HeldWriters, UsableWriter, WriterNeed, held_id, is_writer_delivery, open_writer_delivery, take_writer_deliveries, usable_writer, writer_needs};
use concord::hex32;
use nostr::prelude::*;

use crate::relays::{RelayLike, query_all_settled};

/// Read a restricted Channel's writer deliveries off its access plane, from
/// `since_secs` on. Paged: an access plane carries a delivery per approval,
/// and a Community approving members by the hundred is exactly the one that
/// needs this.
pub async fn fetch_writer_deliveries(relays: &dyn RelayLike, community: &Membership, f: &FoldedControl, channel_id_hex: &str, since_secs: u64) -> anyhow::Result<Vec<ParsedDelivery>> {
    let Some(channel) = hex32(channel_id_hex) else { return Ok(vec![]) };
    let plane: StreamKey = (&community.access_plane(&channel)).into();
    relays.register_auth_keys(plane.sk.clone().map(Keys::new).into_iter().collect());
    let filter = Filter::new().kind(Kind::Custom(kinds::WRAP)).author(plane.pk).since(Timestamp::from_secs(since_secs));
    let wraps = query_all_settled(relays, filter).await?;
    Ok(wraps.iter().filter_map(|w| open_writer_delivery(w, community, f, channel_id_hex)).collect())
}

/// Read and take what the writer deliveries on each owed Channel's access
/// plane hand `identity`, returning the epochs that changed.
pub async fn intake_writer_keys(relays: &dyn RelayLike, identity: &Keys, community: &Membership, f: &FoldedControl, held: &HeldWriters) -> HeldWriters {
    let me = identity.public_key().to_hex();
    let cid = community.id();
    let mut changed = HeldWriters::new();
    for ch in f.writers.keys() {
        if writer_needs(f, &cid, ch, &me, held).is_none() {
            continue;
        }
        match fetch_writer_deliveries(relays, community, f, ch, 0).await {
            Ok(deliveries) => changed.extend(take_writer_deliveries(&deliveries, identity, &cid, f, ch, held)),
            Err(error) => tracing::warn!(error = %format!("{error:#}"), "reading writer deliveries failed"),
        }
    }
    changed
}
