//! Bridge service entry point: the env-provisioned single-link daemon.
//!
//! Required env beyond config: BRIDGE_INVITE_URL, DISCORD_TOKEN,
//! DISCORD_GUILD_ID, DISCORD_CHANNEL_ID; optional CONCORD_CHANNEL_ID (defaults
//! to the first channel in the control fold). The portal hosts bridges
//! in-process and does not need this.
//!
//! Keys are re-resolved from the invite on every boot (the bundle lives on
//! relays).

use std::sync::{Arc, OnceLock};

use anyhow::Context;
use async_trait::async_trait;
use bridge::client::{ConcordClient, OpenedChat, now_ms, resolve_invite};
use bridge::config::BridgeConfig;
use bridge::discord::{DiscordAdapter, DiscordEvents, TypingEvent};
use bridge::key_intake::intake_direct_invite_keys;
use bridge::relays::{Hub, RelayLike};
use bridge::router::{BridgeRouter, RouterOptions, SelfIds};
use bridge::store::{MappingStore, PgMappingStore};
use bridge::types::{ChannelLink, DiscordInboundMessage, DiscordMessageDelete, DiscordReaction};
use concord::invite::{invite_delivery_relays, parse_invite_link, stock_relays};
use concord::roles::perm;
use nostr::prelude::*;
use serde_json::json;

fn primary_keys(value: &str) -> anyhow::Result<Keys> {
    let sk = if value.starts_with("nsec1") { SecretKey::from_bech32(value)? } else { SecretKey::from_hex(value)? };
    Ok(Keys::new(sk))
}

/// Routes the one linked channel's Discord events to the router.
struct Single {
    link: ChannelLink,
    router: OnceLock<Arc<BridgeRouter>>,
}

impl Single {
    fn router(&self, channel_id: &str) -> Option<&Arc<BridgeRouter>> {
        (channel_id == self.link.discord_channel_id).then(|| self.router.get()).flatten()
    }
}

fn logged<T>(what: &str, result: anyhow::Result<T>) {
    if let Err(error) = result {
        tracing::error!(%error, "{what} failed");
    }
}

#[async_trait]
impl DiscordEvents for Single {
    async fn on_message(&self, msg: DiscordInboundMessage) {
        if let Some(r) = self.router(&msg.channel_id) {
            logged("discord -> concord", r.on_discord_message(msg, &self.link).await);
        }
    }
    async fn on_message_update(&self, msg: DiscordInboundMessage) {
        if let Some(r) = self.router(&msg.channel_id) {
            logged("discord edit", r.on_discord_edit(&msg, &self.link).await);
        }
    }
    async fn on_message_delete(&self, del: DiscordMessageDelete) {
        if let Some(r) = self.router(&del.channel_id) {
            logged("discord delete", r.on_discord_delete(&del, &self.link).await);
        }
    }
    async fn on_reaction_add(&self, reaction: DiscordReaction) {
        if let Some(r) = self.router(&reaction.channel_id) {
            logged("discord reaction", r.on_discord_reaction(&reaction, &self.link).await);
        }
    }
    async fn on_reaction_remove(&self, reaction: DiscordReaction) {
        if let Some(r) = self.router(&reaction.channel_id) {
            logged("discord reaction remove", r.on_discord_reaction_remove(&reaction, &self.link).await);
        }
    }
    async fn on_typing(&self, typing: TypingEvent) {
        if typing.bot {
            return;
        }
        if let Some(r) = self.router(&typing.channel_id) {
            logged("discord typing", r.on_discord_typing(&typing.user_id, &self.link).await);
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout())).with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tokio_postgres=warn".into())).init();
    let config = BridgeConfig::from_process_env()?;
    let pool = bridge::db::connect(&config.database_url, 8)?;
    let applied = bridge::db::migrate(&pool).await?;
    if !applied.is_empty() {
        tracing::info!("migrations applied: {}", applied.join(", "));
    }

    let env = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
    let (Some(invite_url), Some(guild_id), Some(channel_id)) = (env("BRIDGE_INVITE_URL"), env("DISCORD_GUILD_ID"), env("DISCORD_CHANNEL_ID")) else {
        tracing::info!("config OK; set BRIDGE_INVITE_URL, DISCORD_TOKEN, DISCORD_GUILD_ID, DISCORD_CHANNEL_ID to go live");
        return Ok(());
    };
    if config.discord_token.is_empty() {
        tracing::info!("config OK; set DISCORD_TOKEN to go live");
        return Ok(());
    }

    // ── Concord side ─────────────────────────────────────────────────────────
    let link = parse_invite_link(&invite_url).context("BRIDGE_INVITE_URL is not a valid Armada invite")?;
    let bootstrap = Hub::new(Keys::generate()).relays(if link.bootstrap_relays.is_empty() { stock_relays() } else { link.bootstrap_relays });
    let community = resolve_invite(&invite_url, &bootstrap).await?.membership;
    drop(bootstrap);
    tracing::info!(community = %&community.community_id[..8], name = %community.name, "joined material");

    let primary = primary_keys(&config.primary_secret_key)?;
    let relays = Hub::new(primary.clone()).relays(community.relays.clone());

    // Fold the Control Plane FIRST: it reads from the root the invite carried,
    // so the roster — and therefore who may vend a channel key — is knowable
    // before we accept any. The intake refuses bundles from anyone else.
    let preflight = ConcordClient::new(community.clone(), Arc::new(relays.clone()), primary.clone());
    let folded = preflight.sync_control().await?;
    // Private-channel keys addressed to us since the last boot. The stock
    // floor is scanned too: it is where a sender delivers to an npub with no
    // published inbox (which we were, until the 10050 below).
    let floor = relays.with_urls(invite_delivery_relays(&[]));
    let owner = community.owner.clone();
    let intake = intake_direct_invite_keys(&[&relays, &floor], &primary, &community, |pk| {
        folded.roster.is_authorized(pk, &owner, perm::MANAGE_CHANNELS)
    })
    .await;
    if !intake.learned.is_empty() {
        tracing::info!(count = intake.learned.len(), "learned private-channel keys from direct invites");
    }
    let client = if intake.learned.is_empty() {
        preflight
    } else {
        let client = ConcordClient::new(intake.community, Arc::new(relays.clone()), primary.clone());
        client.sync_control().await?;
        client
    };

    let concord_channel_id = env("CONCORD_CHANNEL_ID").or_else(|| client.channels().first().map(|c| c.id_hex.clone()));
    let channel = concord_channel_id.as_deref().and_then(|id| client.channel(id)).with_context(|| {
        let have: Vec<String> = client.channels().iter().map(|c| c.id_hex[..8].to_owned()).collect();
        format!("concord channel not found (have: {})", have.join(", "))
    })?;
    tracing::info!(channel = %channel.name, "target channel");

    if let Err(error) = client.publish_join(now_ms(), None).await {
        tracing::warn!(%error, "guestbook join failed");
    }
    let profile = json!({
        "name": "Discord <-> Armada Bridge Bot",
        "about": "Automated bridge account: mirrors this channel with a Discord server.",
        "bot": true,
    });
    if let Err(error) = client.publish_profile(&primary, &profile).await {
        tracing::warn!(%error, "profile publish failed");
    }
    // Point our giftwrap inbox at the community relays (NIP-17 kind 10050),
    // the list Armada resolves before sending a Direct Invite.
    if let Err(error) = client.publish_dm_relays(&primary, &community.relays).await {
        tracing::warn!(%error, "DM relay list publish failed");
    }

    // ── Storage, Discord, router ────────────────────────────────────────────
    let store = Arc::new(PgMappingStore::new(pool));
    let link = ChannelLink {
        discord_guild_id: guild_id,
        discord_channel_id: channel_id,
        community_id: community.community_id.clone(),
        concord_channel_id_hex: channel.id_hex.clone(),
        enabled: true,
    };
    store.ensure_link(&link, &community.relays, Some(&community.name)).await?;

    let single = Arc::new(Single { link: link.clone(), router: OnceLock::new() });
    let adapter = DiscordAdapter::connect(&config.discord_token, single.clone()).await?;
    let mut options = RouterOptions { bridge_edits: config.bridge_edits, ..Default::default() };
    if !config.blossom_server.is_empty() {
        options.blobs = Some(Arc::new(bridge::blossom::BlossomStore::new(bridge::blossom::blossom_servers(&config.blossom_server))?));
    }
    if !config.klipy_api_key.is_empty() {
        options.klipy = Some(Arc::new(bridge::klipy::KlipyClient::new(config.klipy_api_key.clone(), reqwest::Client::new())));
    }
    let router = Arc::new(BridgeRouter::new(
        client.clone(),
        bridge::puppets::PuppetCache::new(config.master_secret_hex.clone()),
        store.clone() as Arc<dyn MappingStore>,
        adapter.clone(),
        Arc::new(bridge::profiles::Kind0ProfileResolver::new(Arc::new(relays.clone()) as Arc<dyn RelayLike>)),
        SelfIds { application_id: adapter.application_id(), webhook_ids: adapter.own_webhook_ids() },
        options,
    ));
    let _ = single.router.set(router.clone());
    tracing::info!("discord gateway up");

    let on_chat = {
        let (router, link) = (router.clone(), link.clone());
        Arc::new(move |chat: OpenedChat| {
            let (router, link) = (router.clone(), link.clone());
            tokio::spawn(async move { logged("concord -> discord", router.on_concord_chat(&chat, &link).await) });
        })
    };
    let on_cursor = {
        let (store, cid) = (store.clone(), community.community_id.clone());
        Arc::new(move |pk: String, at: u64| {
            let (store, cid) = (store.clone(), cid.clone());
            tokio::spawn(async move { let _ = store.cursor_set(&cid, &pk, at).await; });
        }) as bridge::client::CursorHandler
    };

    // Bounded catch-up for messages missed while down (no cursor = fresh link,
    // live-only on purpose). The mapping table dedupes anything mirrored.
    let stream_pks: Vec<String> = channel.streams.iter().map(|s| s.key.pk_hex()).collect();
    if let Some(cursor) = store.cursor_get(&community.community_id, &stream_pks).await? {
        let (chats, newest) = client.backfill_channel(&channel, cursor.saturating_sub(60), 500).await?;
        for chat in &chats {
            if let Err(error) = router.on_concord_chat(chat, &link).await {
                tracing::warn!(rumor = %chat.rumor_id(), %error, "backfill mirror failed");
            }
        }
        if let Some(newest) = newest {
            for pk in &stream_pks {
                let _ = store.cursor_set(&community.community_id, pk, newest).await;
            }
        }
        if !chats.is_empty() {
            tracing::info!(count = chats.len(), "backfilled wraps missed while down");
        }
    }

    let current = Arc::new(std::sync::Mutex::new((channel.clone(), client.subscribe_channel(&channel, on_chat.clone(), Some(on_cursor.clone())))));
    // A rekey mints new stream keys; a REQ pinned to the old ones goes silent
    // while publishes (fresh channel lookup) keep working.
    let _control = {
        let (client2, current, link) = (client.clone(), current.clone(), link.clone());
        client.subscribe_control(Some(Arc::new(move |_| {
            let Some(fresh) = client2.channel(&link.concord_channel_id_hex) else { return };
            let mut cur = current.lock().unwrap_or_else(|e| e.into_inner());
            let keys = |c: &concord::community::ChannelView| c.streams.iter().map(|s| s.key.pk_hex()).collect::<Vec<_>>();
            if keys(&fresh) == keys(&cur.0) {
                return;
            }
            *cur = (fresh.clone(), client2.subscribe_channel(&fresh, on_chat.clone(), Some(on_cursor.clone())));
            tracing::info!("stream keys rotated; chat subscription refreshed");
        })))
    };
    tracing::info!("live in both directions");

    shutdown_signal().await;
    tracing::info!("shutting down");
    adapter.stop();
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = ctrl_c.await;
}
