//! The Concord client and Direct Invite key intake over an in-memory relay:
//! everything a real Armada client would publish, read back the way Armada
//! reads it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge::client::{ConcordClient, OpenedChat, SendChat, now_ms, resolve_invite};
use bridge::key_intake::intake_direct_invite_keys;
use bridge::relays::{MemoryRelay, RelayLike};
use concord::community::Membership;
use concord::control::{build_channel_edition, seal_edition};
use concord::edition::EditionMeta;
use concord::invite::{InviteBundle, build_bundle_event, build_invite_url, mint_token};
use concord::kinds::{self, Plane};
use concord::nostr::prelude::*;
use concord::stream::{StreamKey, open_plane_wrap, seal_and_wrap};
use serde_json::json;

struct World {
    relay: MemoryRelay,
    owner: Keys,
    community: Membership,
}

fn world() -> World {
    let owner = Keys::generate();
    let community = Membership::mint("Test", &owner.public_key().to_hex(), vec!["wss://relay.example".into()], 0);
    World { relay: MemoryRelay::new(), owner, community }
}

fn bundle(m: &Membership, channels: serde_json::Value) -> InviteBundle {
    serde_json::from_value(json!({
        "community_id": m.community_id, "owner": m.owner, "owner_salt": m.owner_salt,
        "community_root": m.root, "root_epoch": m.root_epoch, "control_pk": m.control_pk,
        "channels": channels, "relays": m.relays, "name": m.name,
    }))
    .unwrap()
}

impl World {
    fn client(&self, primary: Keys) -> Arc<ConcordClient> {
        ConcordClient::new(self.community.clone(), Arc::new(self.relay.clone()), primary)
    }

    /// The owner publishes a channel edition.
    fn channel(&self, id: [u8; 32], name: &str, private: bool) {
        let owner = self.owner.public_key().to_hex();
        let rumor = build_channel_edition(&id, &json!({ "name": name, "private": private }), &EditionMeta::first(&owner, None)).unwrap();
        let control = self.community.control_write_stream().unwrap();
        self.relay.inject(seal_edition(&rumor, &control, &self.owner).unwrap());
    }

    /// The owner vends a private channel key to `to` as a Direct Invite.
    fn vend(&self, from: &Keys, to: &Keys, community: &Membership, id: [u8; 32], key: [u8; 32], epoch: u64) {
        let b = bundle(community, json!([{ "id": hex::encode(id), "key": hex::encode(key), "epoch": epoch, "name": "mods" }]));
        self.relay.inject(concord::direct_invite::send(&b, from, &to.public_key(), None).unwrap());
    }
}

#[tokio::test]
async fn resolves_an_invite_and_refuses_a_forged_bundle() {
    let w = world();
    let link = Keys::generate();
    let token = mint_token();
    let url = build_invite_url("https://armada.buzz", &link.public_key(), &token, &w.community.relays).unwrap();
    w.relay.inject(build_bundle_event(&bundle(&w.community, json!([])), &token, &link).unwrap());
    let joined = resolve_invite(&url, &w.relay).await.unwrap();
    assert_eq!(joined.membership.community_id, w.community.community_id);
    assert_eq!(joined.membership.root, w.community.root);

    // A bundle signed by anyone else is not at the link's coordinate.
    let impostor = MemoryRelay::new();
    impostor.inject(build_bundle_event(&bundle(&w.community, json!([])), &token, &Keys::generate()).unwrap());
    assert!(resolve_invite(&url, &impostor).await.is_err());
}

#[tokio::test]
async fn sends_chat_that_opens_with_binding_tags_and_refuses_banned_authors() {
    let w = world();
    let chan = [1u8; 32];
    w.channel(chan, "general", false);
    let client = w.client(Keys::generate());
    client.sync_control().await.unwrap();
    let channel = client.channel(&hex::encode(chan)).expect("folded channel");
    let alice = Keys::generate();
    let (rumor, wrap) = client.send_chat(&channel, SendChat::message(&alice, "hi")).await.unwrap();
    let opened = open_plane_wrap(&wrap, &(&channel.current().key).into(), Plane::Chat).unwrap();
    assert_eq!(opened.rumor, rumor);
    concord::stream::check_channel_binding(&opened.rumor, &channel.id_hex, 0).unwrap();

    let mut folded = (*client.folded().unwrap()).clone();
    folded.banned.insert(alice.public_key().to_hex());
    client.set_folded(folded);
    assert!(client.send_chat(&channel, SendChat::message(&alice, "again")).await.is_err());
}

#[tokio::test]
async fn publishes_joins_typing_and_a_valid_manifest() {
    let w = world();
    let chan = [1u8; 32];
    w.channel(chan, "general", false);
    let client = w.client(Keys::generate());
    client.sync_control().await.unwrap();
    let puppet = Keys::generate();
    let join = client.publish_join(now_ms(), Some(&puppet)).await.unwrap();
    let opened = open_plane_wrap(&join, &w.community.current_guestbook_stream(), Plane::Guestbook).unwrap();
    assert_eq!((opened.author(), opened.rumor.content.as_str()), (puppet.public_key().to_hex().as_str(), "join"));

    let channel = client.channel(&hex::encode(chan)).unwrap();
    client.send_typing(&channel, &puppet, now_ms()).await.unwrap();
    let typing = w.relay.published().into_iter().find(|e| e.kind == Kind::Custom(kinds::WRAP_EPHEMERAL)).unwrap();
    assert_eq!(open_plane_wrap(&typing, &(&channel.current().key).into(), Plane::Chat).unwrap().rumor.kind, kinds::TYPING);

    client.publish_manifest(&[bridge::client::BotCommand { name: "help", description: "d", args: vec![] }]).await.unwrap();
    let manifest = w.relay.published().into_iter().find(|e| e.kind == Kind::Custom(kinds::BOT_MANIFEST)).unwrap();
    let body: serde_json::Value = serde_json::from_str(&manifest.content).unwrap();
    assert_eq!(body, json!({ "v": 1, "commands": [{ "name": "help", "description": "d", "args": [] }] }));
}

#[tokio::test]
async fn streams_each_rumor_once_and_cursors_durable_wraps_only() {
    let w = world();
    let chan = [1u8; 32];
    w.channel(chan, "general", false);
    let client = w.client(Keys::generate());
    client.sync_control().await.unwrap();
    let channel = client.channel(&hex::encode(chan)).unwrap();
    let (chats, cursors) = (Arc::new(Mutex::new(Vec::<OpenedChat>::new())), Arc::new(Mutex::new(0)));
    let (c1, c2) = (chats.clone(), cursors.clone());
    let _sub = client.subscribe_channel(&channel, Arc::new(move |c| c1.lock().unwrap().push(c)), Some(Arc::new(move |_, _| *c2.lock().unwrap() += 1)));

    let alice = Keys::generate();
    let (_, wrap) = client.send_chat(&channel, SendChat::message(&alice, "once")).await.unwrap();
    // A second wrap of the same rumor (a relay re-delivery) is not a second message.
    let seal = concord::stream::seal_rumor(&open_plane_wrap(&wrap, &(&channel.current().key).into(), Plane::Chat).unwrap().rumor, kinds::SEAL_ENCRYPTED, &channel.current().key.conv_key, &alice).unwrap();
    w.relay.inject(concord::stream::wrap_seal(&seal, &(&channel.current().key).into(), Default::default()).unwrap());
    client.send_typing(&channel, &alice, now_ms()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let kinds_seen: Vec<u16> = chats.lock().unwrap().iter().map(|c| c.kind()).collect();
    assert_eq!(kinds_seen, [kinds::MESSAGE, kinds::TYPING]);
    assert_eq!(*cursors.lock().unwrap(), 2, "both durable wraps advance the cursor; typing does not");
}

#[tokio::test]
async fn live_folds_a_new_channel_edition() {
    let w = world();
    let client = w.client(Keys::generate());
    client.sync_control().await.unwrap();
    assert!(client.channels().is_empty());
    let folds = Arc::new(Mutex::new(0));
    let f = folds.clone();
    let _sub = client.subscribe_control(Some(Arc::new(move |_| *f.lock().unwrap() += 1)));
    w.channel([2u8; 32], "random", false);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(client.channels().iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["random"]);
    assert_eq!(*folds.lock().unwrap(), 1, "one re-fold for the batch");
}

#[tokio::test]
async fn backfill_returns_chats_oldest_first_with_the_newest_wrap_time() {
    let w = world();
    let chan = [1u8; 32];
    w.channel(chan, "general", false);
    let client = w.client(Keys::generate());
    client.sync_control().await.unwrap();
    let channel = client.channel(&hex::encode(chan)).unwrap();
    let alice = Keys::generate();
    for (i, text) in ["second", "first"].iter().enumerate() {
        let ms = 1_700_000_000_000 - i as u64 * 1000;
        client.send_chat(&channel, SendChat { ms: Some(ms), ..SendChat::message(&alice, *text) }).await.unwrap();
    }
    let (chats, newest) = client.backfill_channel(&channel, 0, 500).await.unwrap();
    assert_eq!(chats.iter().map(|c| c.content()).collect::<Vec<_>>(), ["first", "second"]);
    assert!(newest.is_some());
}

// ── Direct Invite key intake ────────────────────────────────────────────────

const PRIVATE: [u8; 32] = [5u8; 32];

#[tokio::test]
async fn merges_a_key_vended_by_an_entitled_sender() {
    let w = world();
    w.channel(PRIVATE, "mods", true);
    let bridge = Keys::generate();
    w.vend(&w.owner, &bridge, &w.community, PRIVATE, [6u8; 32], 0);
    let owner = w.community.owner.clone();
    let intake = intake_direct_invite_keys(&[&w.relay as &dyn RelayLike], &bridge, &w.community, |pk| pk == owner).await;
    assert_eq!(intake.learned, [hex::encode(PRIVATE)]);
    let client = ConcordClient::new(intake.community, Arc::new(w.relay.clone()), bridge);
    client.sync_control().await.unwrap();
    assert!(client.channel(&hex::encode(PRIVATE)).is_some(), "the gated channel is readable now");
}

#[tokio::test]
async fn refuses_strangers_other_communities_and_other_recipients() {
    let w = world();
    let bridge = Keys::generate();
    let stranger = Keys::generate();
    // An unauthorized sender — including one claiming a higher epoch for a
    // channel we hold, the redirect attack the gate exists for.
    w.vend(&stranger, &bridge, &w.community, PRIVATE, [7u8; 32], 9999);
    // A bundle for a different community, from the owner.
    let other = Membership::mint("Other", &w.owner.public_key().to_hex(), vec![], 0);
    w.vend(&w.owner, &bridge, &other, PRIVATE, [8u8; 32], 0);
    // An invite sealed to somebody else.
    w.vend(&w.owner, &Keys::generate(), &w.community, PRIVATE, [9u8; 32], 0);
    let owner = w.community.owner.clone();
    let intake = intake_direct_invite_keys(&[&w.relay as &dyn RelayLike], &bridge, &w.community, |pk| pk == owner).await;
    assert!(intake.learned.is_empty());
    assert!(intake.community.private_channels.is_empty());
}

#[tokio::test]
async fn adopts_a_re_vend_that_advances_the_epoch_and_keeps_the_old_key_for_history() {
    let w = world();
    let bridge = Keys::generate();
    let owner = w.community.owner.clone();
    w.vend(&w.owner, &bridge, &w.community, PRIVATE, [6u8; 32], 0);
    let first = intake_direct_invite_keys(&[&w.relay as &dyn RelayLike], &bridge, &w.community, |pk| pk == owner).await;
    w.vend(&w.owner, &bridge, &w.community, PRIVATE, [7u8; 32], 1);
    let second = intake_direct_invite_keys(&[&w.relay as &dyn RelayLike], &bridge, &first.community, |pk| pk == owner).await;
    assert_eq!(second.learned, [hex::encode(PRIVATE)]);
    let held = &second.community.private_channels[0];
    assert_eq!((held.epoch, held.key.as_str()), (1, hex::encode([7u8; 32]).as_str()));
    assert_eq!(held.priors[0].key, hex::encode([6u8; 32]));
}

#[test]
fn guestbook_wraps_open_under_the_guestbook_stream_only() {
    let w = world();
    let alice = Keys::generate();
    let rumor = concord::guestbook::join(&alice.public_key().to_hex(), now_ms(), None);
    let gb: StreamKey = w.community.current_guestbook_stream();
    let wrap = seal_and_wrap(&rumor, Plane::Guestbook, &gb, &alice, Default::default()).unwrap();
    assert!(open_plane_wrap(&wrap, &gb, Plane::Guestbook).is_ok());
    assert!(open_plane_wrap(&wrap, &w.community.current_control_stream(), Plane::Control).is_err());
}
