//! Live check against a real relay: mint a throwaway community, publish a
//! channel, subscribe to it, send one message, and report what came back.
//!
//!   cargo run -p bridge --example live_probe -- wss://relay.ditto.pub

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bridge::client::{ConcordClient, SendChat};
use bridge::relays::{Hub, RelayLike};
use concord::community::Membership;
use concord::control::{build_channel_edition, seal_edition};
use concord::edition::EditionMeta;
use nostr::prelude::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info,relay_pool=debug".into())).init();
    bridge::tls::install();
    let relay = std::env::args().nth(1).unwrap_or_else(|| "wss://relay.ditto.pub".into());
    let owner = Keys::generate();
    let m = Membership::mint("probe", &owner.public_key().to_hex(), vec![relay.clone()], 0);
    let hub = Hub::new(Keys::generate());
    let relays = hub.relays(vec![relay]);
    let client = ConcordClient::new(m.clone(), Arc::new(relays.clone()), Keys::generate());

    let id = concord::random32();
    let rumor = build_channel_edition(&id, &serde_json::json!({ "name": "probe", "private": false }), &EditionMeta::first(&m.owner, None))?;
    relays.publish(&seal_edition(&rumor, &m.control_write_stream().unwrap(), &owner)?).await?;
    let folded = client.sync_control().await?;
    println!("fold: {} channel(s)", folded.channels.len());
    let channel = client.channel(&hex::encode(id)).expect("channel folded");

    let (got, cursors) = (Arc::new(Mutex::new(0)), Arc::new(Mutex::new(0)));
    let (g, c) = (got.clone(), cursors.clone());
    let _sub = client.subscribe_channel(&channel, Arc::new(move |_| *g.lock().unwrap() += 1), Some(Arc::new(move |_, _| *c.lock().unwrap() += 1)));
    tokio::time::sleep(Duration::from_secs(3)).await;
    let alice = Keys::generate();
    client.send_chat(&channel, SendChat::message(&alice, "probe")).await?;
    println!("published");
    tokio::time::sleep(Duration::from_secs(5)).await;
    println!("subscription delivered {} chat(s), {} cursor(s)", got.lock().unwrap(), cursors.lock().unwrap());
    let (back, _) = client.backfill_channel(&channel, 0, 10).await?;
    println!("query returned {} chat(s)", back.len());
    Ok(())
}
