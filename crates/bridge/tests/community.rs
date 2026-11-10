//! The shared community runtime over an in-memory relay that, like the real
//! ones, caps standing subscriptions per connection.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge::client::{OpenedChat, SendChat};
use bridge::community::{CommunityRuntime, RESUBSCRIBE_SETTLE};
use bridge::relays::MemoryRelay;
use concord::community::{Membership, PrivateChannelKey};
use concord::control::{build_channel_edition, seal_edition};
use concord::edition::EditionMeta;
use concord::nostr::prelude::*;
use serde_json::json;

const CAP: usize = 3;

struct World {
    relay: MemoryRelay,
    owner: Keys,
    community: Membership,
}

fn world() -> World {
    let owner = Keys::generate();
    let community = Membership::mint("Test", &owner.public_key().to_hex(), vec!["wss://relay.example".into()], 0);
    let relay = MemoryRelay::new();
    relay.cap_subscriptions(CAP);
    World { relay, owner, community }
}

impl World {
    fn channel(&self, id: [u8; 32], name: &str, private: bool) {
        let owner = self.owner.public_key().to_hex();
        let rumor = build_channel_edition(&id, &json!({ "name": name, "private": private }), &EditionMeta::first(&owner, None)).unwrap();
        self.relay.inject(seal_edition(&rumor, &self.community.control_write_stream().unwrap(), &self.owner).unwrap());
    }

    async fn open(&self, cursors: Arc<Mutex<usize>>) -> Arc<CommunityRuntime> {
        let on_cursor = Arc::new(move |_: String, _: u64| *cursors.lock().unwrap() += 1);
        CommunityRuntime::open(self.community.clone(), Arc::new(self.relay.clone()), Some(on_cursor)).await.unwrap()
    }
}

type Inbox = Arc<Mutex<Vec<OpenedChat>>>;

fn inbox() -> (Inbox, bridge::client::ChatHandler) {
    let got: Inbox = Arc::default();
    let g = got.clone();
    (got, Arc::new(move |c| g.lock().unwrap().push(c)))
}

/// Wait for the debounced resubscribe to have happened; `channel()` lookups
/// are slow enough in a debug build that a fixed sleep is not.
async fn eventually(what: &str, done: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn heard(inbox: &Inbox, n: usize) {
    eventually("delivery", || inbox.lock().unwrap().len() >= n).await;
}

#[tokio::test]
async fn thirty_bridges_share_two_subscriptions_and_each_hears_only_its_channel() {
    let w = world();
    let ids: Vec<[u8; 32]> = (0..30).map(|_| concord::random32()).collect();
    for (i, id) in ids.iter().enumerate() {
        w.channel(*id, &format!("c{i}"), false);
    }
    let cursors = Arc::new(Mutex::new(0));
    let rt = w.open(cursors.clone()).await;

    let mut bridges = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        let client = rt.client_for(w.community.clone(), Keys::generate());
        let channel = client.channel(&hex::encode(id)).expect("folded");
        let (got, on_chat) = inbox();
        let attachment = rt.attach(&format!("b{i}"), client.clone(), channel.clone(), on_chat);
        bridges.push((client, channel, got, attachment));
    }
    // Control plus one merged chat REQ, however many bridges: the cap of 3
    // would have refused a REQ per bridge from the second bridge on.
    eventually("the chat REQ", || w.relay.open_subscriptions() == 2).await;
    assert_eq!(w.relay.refused_subscriptions(), 0);

    let alice = Keys::generate();
    for (i, (client, channel, _, _)) in bridges.iter().enumerate() {
        client.send_chat(channel, SendChat::message(&alice, format!("hello {i}"))).await.unwrap();
    }
    for (_, _, got, _) in &bridges {
        heard(got, 1).await;
    }
    for (i, (_, channel, got, _)) in bridges.iter().enumerate() {
        let got = got.lock().unwrap();
        assert_eq!(got.len(), 1, "bridge {i}");
        assert_eq!(got[0].content(), format!("hello {i}"));
        assert_eq!(got[0].channel_id_hex, channel.id_hex);
    }
    assert_eq!(*cursors.lock().unwrap(), 30);

    // And the cap is real: a REQ per bridge, as before, is refused past it.
    let _per_bridge: Vec<_> = bridges.iter().map(|(c, ch, _, _)| c.subscribe_channel(ch, Arc::new(|_| {}), None)).collect();
    assert_eq!(w.relay.refused_subscriptions(), 30 - (CAP - 2));
}

#[tokio::test]
async fn detaching_narrows_the_subscription_and_the_last_one_closes_it() {
    let w = world();
    let (a, b) = (concord::random32(), concord::random32());
    w.channel(a, "a", false);
    w.channel(b, "b", false);
    let rt = w.open(Arc::default()).await;
    let ca = rt.client_for(w.community.clone(), Keys::generate());
    let cb = rt.client_for(w.community.clone(), Keys::generate());
    let (va, vb) = (ca.channel(&hex::encode(a)).unwrap(), cb.channel(&hex::encode(b)).unwrap());
    let (got_a, on_a) = inbox();
    let (got_b, on_b) = inbox();
    let att_a = rt.attach("a", ca.clone(), va.clone(), on_a);
    let att_b = rt.attach("b", cb.clone(), vb.clone(), on_b);
    eventually("the chat REQ", || w.relay.open_subscriptions() == 2).await;

    drop(att_b);
    assert_eq!(rt.bridges(), 1);
    // The REQ is replaced in place, so wait for one naming only a's streams.
    tokio::time::sleep(RESUBSCRIBE_SETTLE * 3).await;
    let alice = Keys::generate();
    ca.send_chat(&va, SendChat::message(&alice, "to a")).await.unwrap();
    cb.send_chat(&vb, SendChat::message(&alice, "to b")).await.unwrap();
    heard(&got_a, 1).await;
    assert!(got_b.lock().unwrap().is_empty(), "a detached bridge hears nothing");

    drop(att_a);
    eventually("the chat REQ to close", || w.relay.open_subscriptions() == 1).await;
    drop(rt);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(w.relay.open_subscriptions(), 0);
}

#[tokio::test]
async fn a_private_key_vended_to_one_bridge_stays_with_that_bridge() {
    let w = world();
    let (public, private) = (concord::random32(), concord::random32());
    w.channel(public, "general", false);
    w.channel(private, "mods", true);
    let rt = w.open(Arc::default()).await;

    // Bridge A was let into #mods; bridge B, same community, was not.
    let mut with_key = w.community.clone();
    with_key.private_channels.push(PrivateChannelKey {
        id: hex::encode(private),
        key: hex::encode(concord::random32()),
        epoch: 0,
        name: "mods".into(),
        priors: vec![],
    });
    let ca = rt.client_for(with_key, Keys::generate());
    let cb = rt.client_for(w.community.clone(), Keys::generate());
    let mods = ca.channel(&hex::encode(private)).expect("A holds the key");
    assert!(cb.channel(&hex::encode(private)).is_none(), "B must not see a room it was not let into");

    let (got_a, on_a) = inbox();
    let (got_b, on_b) = inbox();
    let _a = rt.attach("a", ca.clone(), mods.clone(), on_a);
    let _b = rt.attach("b", cb.clone(), cb.channel(&hex::encode(public)).unwrap(), on_b);
    eventually("the chat REQ", || w.relay.open_subscriptions() == 2).await;
    ca.send_chat(&mods, SendChat::message(&Keys::generate(), "secret")).await.unwrap();
    heard(&got_a, 1).await;
    assert!(got_b.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_key_taken_while_running_moves_the_shared_chat_req() {
    let w = world();
    let private = concord::random32();
    w.channel(private, "mods", true);
    let rt = w.open(Arc::default()).await;
    let key = |k: [u8; 32], epoch: u64| PrivateChannelKey { id: hex::encode(private), key: hex::encode(k), epoch, name: "mods".into(), priors: vec![] };
    let mut held = w.community.clone();
    held.private_channels.push(key(concord::random32(), 0));
    let client = rt.client_for(held.clone(), Keys::generate());
    let (got, on_chat) = inbox();
    let attachment = rt.attach("a", client.clone(), client.channel(&hex::encode(private)).unwrap(), on_chat);
    eventually("the chat REQ", || w.relay.open_subscriptions() == 2).await;

    // The client takes epoch 1 (as follow_channel_keys would) and the runtime
    // is told: the attachment's view, and the REQ under it, move to the new stream.
    held.private_channels[0] = key(concord::random32(), 1);
    client.set_community(held);
    rt.refresh();
    let at_new_epoch = || attachment.channel().is_some_and(|c| c.streams.iter().any(|s| s.epoch == 1));
    eventually("the attachment's view to move", at_new_epoch).await;
    tokio::time::sleep(RESUBSCRIBE_SETTLE * 2).await;
    let mods = client.channel(&hex::encode(private)).unwrap();
    client.send_chat(&mods, SendChat::message(&Keys::generate(), "after the rotation")).await.unwrap();
    heard(&got, 1).await;
    assert_eq!(got.lock().unwrap()[0].epoch, 1);
}

// ── Refoundings ─────────────────────────────────────────────────────────────

/// What a Refounding leaves a member holding at the new epoch, and the
/// rotation that carries it (CORD-06 §1: a 104-byte member blob per recipient).
struct Refounding {
    after: Membership,
}

/// The owner refounds `from` to its next epoch, with blobs for `recipients`.
fn refound(w: &World, from: &Membership, recipients: &[&Keys]) -> Refounding {
    use base64::Engine;
    use concord::derive::{base_rekey_group_key, control_signer_group_key, conversation_key, epoch_key_commitment};
    let (cid, next) = (from.id(), from.root_epoch + 1);
    let (new_root, new_control_root) = (concord::random32(), concord::random32());
    let control_pk = control_signer_group_key(&new_control_root, &cid, next).keys.public_key();
    let mut plain = vec![0u8; 32];
    plain.extend_from_slice(&next.to_be_bytes());
    plain.extend_from_slice(&new_root);
    plain.extend_from_slice(&control_pk.to_bytes());
    let plain = base64::engine::general_purpose::STANDARD.encode(plain);
    let owner = w.owner.public_key().to_hex();
    let scope = concord::rekey::ROOT_SCOPE_HEX;
    let blobs: Vec<serde_json::Value> = recipients
        .iter()
        .map(|r| {
            let conv = conversation_key(w.owner.secret_key(), &r.public_key());
            let locator = concord::rekey::my_locator(&owner, &r.public_key().to_hex(), scope, next).unwrap();
            json!({ "locator": locator, "wrapped": concord::nip44::encrypt_str(&conv, &plain).unwrap() })
        })
        .collect();
    let tags = vec![
        vec!["scope".to_string(), scope.to_string()],
        vec!["newepoch".into(), next.to_string()],
        vec!["prevepoch".into(), from.root_epoch.to_string()],
        vec!["prevcommit".into(), hex::encode(epoch_key_commitment(from.root_epoch, &from.root_key()))],
        vec!["chunk".into(), "1".into(), "1".into()],
    ];
    let ms = bridge::client::now_ms();
    let rumor = concord::rumor::Rumor::new(concord::kinds::REKEY, serde_json::Value::Array(blobs).to_string(), tags, &owner, Some(ms), None);
    let address: concord::stream::StreamKey = (&base_rekey_group_key(&from.root_key(), &cid, next)).into();
    w.relay.inject(concord::stream::seal_and_wrap(&rumor, concord::kinds::Plane::Rekey, &address, &w.owner, Default::default()).unwrap());

    // The owner's own view afterwards: the new root, and the staff key to it.
    let mut after = from.clone();
    for r in &mut after.held_roots {
        r.retired_at.get_or_insert(ms / 1000);
    }
    after.held_roots.insert(
        0,
        concord::community::HeldRoot { epoch: next, key: hex::encode(new_root), control_pk: Some(control_pk.to_hex()), retired_at: None, refounder: Some(owner) },
    );
    after.root = hex::encode(new_root);
    after.root_epoch = next;
    after.control_pk = Some(control_pk.to_hex());
    after.control_root = Some(hex::encode(new_control_root));
    Refounding { after }
}

#[tokio::test]
async fn a_refounding_while_running_moves_each_kept_bridge_and_the_shared_fold_and_pauses_the_one_left_out() {
    let w = world();
    let general = concord::random32();
    w.channel(general, "general", false);
    let rt = w.open(Arc::default()).await;
    let excluded: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen = excluded.clone();
    rt.set_on_excluded(Arc::new(move |id| seen.lock().unwrap().push(id)));

    let (kept, dropped) = (Keys::generate(), Keys::generate());
    let ca = rt.client_for(w.community.clone(), kept.clone());
    let cb = rt.client_for(w.community.clone(), dropped.clone());
    let (got, on_a) = inbox();
    let (_, on_b) = inbox();
    let a = rt.attach("a", ca.clone(), ca.channel(&hex::encode(general)).unwrap(), on_a);
    let _b = rt.attach("b", cb.clone(), cb.channel(&hex::encode(general)).unwrap(), on_b);
    eventually("the chat REQ", || w.relay.open_subscriptions() == 2).await;

    // The owner refounds, keeping A and leaving B out.
    let r = refound(&w, &w.community, &[&kept]);
    eventually("A to take the new root", || ca.community().root_epoch == 1).await;
    eventually("B to be reported", || excluded.lock().unwrap().as_slice() == ["b"]).await;
    assert_eq!(cb.community().root_epoch, 0, "B holds no key to the new root");
    eventually("A's view to move to the new root's stream", || a.channel().is_some_and(|c| c.current().epoch == 1)).await;

    // The shared fold follows the new epoch's Control Plane live: a channel
    // made there after the Refounding appears.
    let after = concord::random32();
    let rumor = build_channel_edition(&after, &json!({ "name": "after", "private": false }), &EditionMeta::first(&w.owner.public_key().to_hex(), None)).unwrap();
    w.relay.inject(seal_edition(&rumor, &r.after.control_write_stream().unwrap(), &w.owner).unwrap());
    eventually("the new epoch's edition to fold", || ca.channel(&hex::encode(after)).is_some()).await;

    // And A hears what's posted at the new root.
    tokio::time::sleep(RESUBSCRIBE_SETTLE * 2).await;
    let general_now = ca.channel(&hex::encode(general)).unwrap();
    ca.send_chat(&general_now, SendChat::message(&Keys::generate(), "after the refounding")).await.unwrap();
    heard(&got, 1).await;
    assert_eq!(got.lock().unwrap()[0].epoch, 1);
}

#[tokio::test]
async fn a_start_walks_every_refounding_since_the_invite_and_hands_the_fold_the_newest_root() {
    let w = world();
    let general = concord::random32();
    w.channel(general, "general", false);
    let rt = w.open(Arc::default()).await;
    let bridge = Keys::generate();
    let first = refound(&w, &w.community, &[&bridge]);
    let second = refound(&w, &first.after, &[&bridge]);

    let folded = rt.folded().unwrap();
    let intake = bridge::key_intake::intake_base_rotations(rt.relays().as_ref(), &bridge, &w.community, &folded).await;
    assert_eq!((intake.adopted, intake.excluded), (Some(2), None));
    assert_eq!(intake.community.root, second.after.root);
    assert!(rt.adopt_base(&intake.community).await.unwrap());
    assert!(!rt.adopt_base(&w.community).await.unwrap(), "never back to an older root");

    // An identity with no blob there takes nothing from them.
    let stranger = Keys::generate();
    let other = bridge::key_intake::intake_base_rotations(rt.relays().as_ref(), &stranger, &w.community, &folded).await;
    assert_eq!(other.adopted, None);
}
