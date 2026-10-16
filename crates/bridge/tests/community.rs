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
