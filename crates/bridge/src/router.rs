//! The bidirectional message router: the only place where Discord events and
//! Concord rumors meet. Its ports (webhook sender, mapping store, profile
//! resolver, blob host) are traits so the router tests offline; the Discord
//! adapter and Postgres store plug in at wiring time.
//!
//! Loop prevention, both layers, lives here:
//!  1. proxy tag: never bridge a Concord rumor that carries one; never bridge a
//!     Discord message authored by our own webhooks or application.
//!  2. identity: never bridge a Concord rumor authored by one of our puppets,
//!     and never bridge a rumor we already have a mapping row for.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use concord::community::ChannelView;
use concord::kinds;
use nostr::prelude::Keys;
use regex::Regex;
use serde_json::json;

use crate::blossom::BlobPort;
use crate::client::{ConcordClient, OpenedChat, SendChat, has_proxy_tag, now_ms, proxy_tag};
use crate::gif::{ffmpeg_available, mp4_to_gif};
use crate::imeta::{
    attachment_filename, decrypt_blob, imeta_fields, is_supported_encryption, mime_from_url, parse_imeta_encryption, with_extension,
};
use crate::klipy::{GifResolver, klipy_item};
use crate::markup::{
    apply_custom_emoji, concord_custom_emoji_to_discord, custom_emoji_tags, discord_emoji_url, escape_markdown, reaction_emoji,
    strip_attached_urls, upgrade_gif_embed,
};
use crate::net::{Prober, SafeProber};
use crate::profiles::{ProfileResolver, fallback_profile};
use crate::puppets::PuppetCache;
use crate::store::MappingStore;
use crate::transform::{DISCORD_MAX_CHARS, concord_to_discord, discord_to_concord, split_for_discord, substituted_embed_media};
use crate::types::{
    ChannelLink, DiscordAttachmentIn, DiscordInboundMessage, DiscordMessageDelete, DiscordReaction, DiscordUserRef, EmbedIn,
    MessageMappingRow, Origin, ReactionMappingRow,
};

/// Attachment ceiling both ways (webhook upload limit for standard guilds).
pub const MAX_BLOB_BYTES: usize = 10 * 1024 * 1024;

/// Download ATTEMPTS per inbound rumor. Discord accepts 10 attachments per
/// message, so anything past this could never be sent anyway — but the tag
/// count is attacker-chosen and the downloads used to run before the send was
/// attempted, which made one rumor with a few hundred `imeta` tags into a few
/// gigabytes of buffering and a few hundred outbound requests.
///
/// Counting attempts rather than successes is the whole point: a cap on
/// successes is no cap at all against URLs chosen to fail.
const MAX_IMETA_DOWNLOADS: usize = 10;

/// Total attachment bytes held in memory while assembling ONE inbound rumor.
///
/// The per-file cap and the attempt cap multiply: ten files at MAX_BLOB_BYTES
/// is 100 MB retained at once. The process this happens in also holds
/// PORTAL_SEAL_KEY, so "it eventually OOMs" is not a survivable outcome. Set
/// above Discord's own per-message ceiling: a rumor that exceeds this could not
/// have been delivered whole in any case.
const MAX_IMETA_TOTAL_BYTES: usize = 25 * 1024 * 1024;

/// Discord messages one inbound rumor may fan out into.
///
/// Each part is a webhook send AND a mapping row, so the split is the cheapest
/// amplifier in the bridge. Ten parts is 20,000 characters — far past any real
/// chat message, and a tenth of the worst case.
const MAX_DISCORD_PARTS: usize = 10;

/// Inbound rumors allowed to queue for one bridged channel before new ones are
/// dropped. Deep enough that a legitimate burst or a catch-up backfill never
/// touches it; shallow enough that a flood cannot grow the heap without bound.
const MAX_QUEUED_CHATS: usize = 200;

/// Minimum gap between forwarded typing signals, per direction key.
const TYPING_THROTTLE: Duration = Duration::from_secs(4);

/// Discord's "Missing Permissions" (50013): the bot lacks a permission the
/// operation needed — for the bridge, almost always Manage Webhooks on the
/// mirrored channel. A distinct error so the manager can tell the owner
/// instead of silently retrying a send that will never land.
#[derive(Debug, thiserror::Error)]
#[error("the bot is missing a Discord permission: {0}")]
pub struct MissingPermissions(pub String);

pub fn is_missing_permissions(error: &anyhow::Error) -> bool {
    error.chain().any(|e| e.is::<MissingPermissions>())
}

#[derive(Clone, Debug)]
pub struct FileUpload {
    pub name: String,
    pub data: Vec<u8>,
}

/// One persona post through the channel's webhook.
#[derive(Clone, Debug, Default)]
pub struct WebhookMessage {
    pub username: String,
    pub avatar_url: Option<String>,
    pub content: String,
    /// Embed descriptions.
    pub embeds: Vec<String>,
    pub files: Vec<FileUpload>,
}

#[async_trait]
pub trait WebhookSender: Send + Sync {
    /// Post as the given persona; returns the created Discord message id.
    async fn send(&self, link: &ChannelLink, message: WebhookMessage) -> anyhow::Result<String>;
    /// Remove a bridged message (webhook delete; bot delete for user posts).
    async fn delete(&self, link: &ChannelLink, discord_message_id: &str) -> anyhow::Result<()>;
    /// Edit a webhook-authored mirror in place.
    async fn edit(&self, link: &ChannelLink, discord_message_id: &str, content: &str) -> anyhow::Result<()>;
    /// React as the bot account (webhooks cannot react).
    async fn react(&self, link: &ChannelLink, discord_message_id: &str, emoji: &str) -> anyhow::Result<()>;
    /// Remove the bot's own reaction.
    async fn unreact(&self, link: &ChannelLink, discord_message_id: &str, emoji: &str) -> anyhow::Result<()>;
    /// Show the bot's typing indicator in the channel (lasts ~10 s on Discord).
    async fn send_typing(&self, link: &ChannelLink) -> anyhow::Result<()>;
}

/// What identifies our own posts on Discord, for echo suppression. The webhook
/// set grows as the adapter creates webhooks, so it is shared, not copied.
#[derive(Clone, Default)]
pub struct SelfIds {
    pub application_id: String,
    pub webhook_ids: Arc<RwLock<HashSet<String>>>,
}

#[derive(Clone)]
pub struct RouterOptions {
    /// Kind 3302 is not frozen in the CORDs yet; off by default.
    pub bridge_edits: bool,
    /// When set, attachments rehost through Blossom instead of rotting CDN links.
    pub blobs: Option<Arc<dyn BlobPort>>,
    /// Resolves Klipy GIF-picker sends to their real GIF (KLIPY_API_KEY).
    pub klipy: Option<Arc<dyn GifResolver>>,
    /// Probes GIF variants; always the guarded prober outside tests.
    pub prober: Arc<dyn Prober>,
}

impl Default for RouterOptions {
    fn default() -> Self {
        RouterOptions { bridge_edits: false, blobs: None, klipy: None, prober: Arc::new(SafeProber) }
    }
}

pub struct BridgeRouter {
    client: Arc<ConcordClient>,
    puppets: PuppetCache,
    store: Arc<dyn MappingStore>,
    webhooks: Arc<dyn WebhookSender>,
    profiles: Arc<dyn ProfileResolver>,
    self_ids: SelfIds,
    options: RouterOptions,
    /// discord user id -> last published "name|avatar" (skip republishing).
    published_profiles: Mutex<HashMap<String, String>>,
    /// discord user ids whose puppet published a Guestbook join this run.
    joined_puppets: Mutex<HashSet<String>>,
    /// direction key -> last forwarded typing signal.
    last_typing: Mutex<HashMap<String, Instant>>,
    /// Serialises inbound rumors; see [`BridgeRouter::on_concord_chat`].
    chat_queue: tokio::sync::Mutex<()>,
    queued: AtomicUsize,
}

fn first_tag_value<'a>(tags: &'a [Vec<String>], name: &str) -> Option<&'a str> {
    tags.iter().find(|t| t.first().is_some_and(|n| n == name) && t.get(1).is_some_and(|v| !v.is_empty())).map(|t| t[1].as_str())
}

impl BridgeRouter {
    pub fn new(
        client: Arc<ConcordClient>,
        puppets: PuppetCache,
        store: Arc<dyn MappingStore>,
        webhooks: Arc<dyn WebhookSender>,
        profiles: Arc<dyn ProfileResolver>,
        self_ids: SelfIds,
        options: RouterOptions,
    ) -> Self {
        BridgeRouter {
            client,
            puppets,
            store,
            webhooks,
            profiles,
            self_ids,
            options,
            published_profiles: Mutex::default(),
            joined_puppets: Mutex::default(),
            last_typing: Mutex::default(),
            chat_queue: tokio::sync::Mutex::new(()),
            queued: AtomicUsize::new(0),
        }
    }

    pub fn client(&self) -> &Arc<ConcordClient> {
        &self.client
    }

    /// Whether `key` may forward a typing signal now; records it if so.
    fn typing_allowed(&self, key: String) -> bool {
        let mut last = self.last_typing.lock().unwrap_or_else(|e| e.into_inner());
        if last.get(&key).is_some_and(|at| at.elapsed() < TYPING_THROTTLE) {
            return false;
        }
        last.insert(key, Instant::now());
        true
    }

    /// Keep the puppet's kind 0 in step with the Discord identity so Armada
    /// shows the person's name and avatar instead of an anonymous key. Failure
    /// is tolerable (the message still bridges); it retries on the next change.
    async fn sync_puppet_profile(&self, author: &DiscordUserRef, keys: &Keys) -> anyhow::Result<()> {
        let fingerprint = format!("{}|{}", author.display, author.avatar_url.as_deref().unwrap_or(""));
        if self.published_profiles.lock().unwrap_or_else(|e| e.into_inner()).get(&author.id) == Some(&fingerprint) {
            return Ok(());
        }
        let mut meta = json!({ "name": author.display });
        if let Some(picture) = &author.avatar_url {
            meta["picture"] = json!(picture);
        }
        meta["about"] = json!("Bridged from Discord by armada-bridge.");
        self.client.publish_profile(keys, &meta).await?;
        self.published_profiles.lock().unwrap_or_else(|e| e.into_inner()).insert(author.id.clone(), fingerprint);
        Ok(())
    }

    /// Guestbook join (kind 3306) the first time a puppet speaks, so bridged
    /// users show in the Armada member list. Backdated to the message for
    /// history imports. Failure tolerated: retried on the puppet's next message.
    async fn publish_puppet_join(&self, discord_user_id: &str, keys: &Keys, ms: Option<u64>) {
        if self.joined_puppets.lock().unwrap_or_else(|e| e.into_inner()).contains(discord_user_id) {
            return;
        }
        match self.client.publish_join(ms.unwrap_or_else(now_ms), Some(keys)).await {
            Ok(_) => {
                self.joined_puppets.lock().unwrap_or_else(|e| e.into_inner()).insert(discord_user_id.to_owned());
            }
            Err(error) => tracing::warn!(user = discord_user_id, %error, "guestbook join failed"),
        }
    }

    fn channel(&self, link: &ChannelLink) -> Option<ChannelView> {
        self.client.channel(&link.concord_channel_id_hex)
    }

    /// Discord TYPING_START -> ephemeral kind 23311 from the user's puppet,
    /// throttled per user and channel to Armada's own publisher cadence.
    pub async fn on_discord_typing(&self, user_id: &str, link: &ChannelLink) -> anyhow::Result<()> {
        if !link.enabled {
            return Ok(());
        }
        let Some(channel) = self.channel(link) else { return Ok(()) };
        if !self.typing_allowed(format!("d:{}:{user_id}", link.discord_channel_id)) {
            return Ok(());
        }
        let puppet = self.puppets.get(user_id)?;
        if self.client.is_banned(&puppet.pk) {
            return Ok(());
        }
        self.client.send_typing(&channel, &puppet.keys, now_ms()).await
    }

    /// Discord -> Concord. Returns the rumor id, or `None` when skipped.
    pub async fn on_discord_message(&self, msg: DiscordInboundMessage, link: &ChannelLink) -> anyhow::Result<Option<String>> {
        if !link.enabled {
            return Ok(None);
        }
        // Layer 1: our own webhook posts and application messages never bounce back.
        if msg.webhook_id.as_ref().is_some_and(|id| self.self_ids.webhook_ids.read().unwrap_or_else(|e| e.into_inner()).contains(id)) {
            return Ok(None);
        }
        if msg.application_id.as_ref().is_some_and(|id| !id.is_empty() && *id == self.self_ids.application_id) {
            return Ok(None);
        }
        // Other bots are skipped by default to avoid bot loops.
        if msg.author.bot {
            return Ok(None);
        }
        // Deleted, or key not held: nothing to do.
        let Some(channel) = self.channel(link) else { return Ok(None) };

        let puppet = self.puppets.get(&msg.author.id)?;
        let mut tags = vec![proxy_tag(&msg.guild_id, &msg.channel_id, &msg.id)];
        tags.extend(custom_emoji_tags(&msg.content));
        let source = match self.klipy_gif(&msg, &puppet.keys, &mut tags).await {
            Some(source) => source,
            None => {
                let upgraded = upgrade_gif_embed(msg.clone(), self.options.prober.as_ref()).await;
                self.transcoded_gif_fallback(upgraded, &puppet.keys, &mut tags).await
            }
        };
        self.tag_embed_media(&source, &mut tags);
        let attachments = self.rehost_attachments(&source, &puppet.keys, &mut tags).await;
        let content = discord_to_concord(&DiscordInboundMessage { attachments, ..source });
        if content.is_empty() {
            return Ok(None);
        }

        if let Err(error) = self.sync_puppet_profile(&msg.author, &puppet.keys).await {
            tracing::warn!(user = %msg.author.id, %error, "puppet profile publish failed");
        }
        self.publish_puppet_join(&msg.author.id, &puppet.keys, msg.timestamp_ms).await;
        if let Some(reference) = &msg.referenced_message_id {
            // NIP-C7 inline quote-reply naming the mapped rumor and its author.
            // An unmapped reference (pre-bridge history) degrades to a bare message.
            if let Some(target) = self.store.by_discord_id(reference).await?.into_iter().next() {
                let author_pk = match target.origin {
                    Origin::Discord => self.puppets.get(&target.author_ref)?.pk,
                    Origin::Concord => target.author_ref.clone(),
                };
                tags.push(vec!["q".into(), target.concord_rumor_id.clone(), String::new(), author_pk]);
            }
        }

        let send = SendChat { content, author: &puppet.keys, kind: kinds::MESSAGE, tags, ms: msg.timestamp_ms };
        let (rumor, _) = self.client.send_chat(&channel, send).await?;
        self.store
            .insert(&MessageMappingRow {
                discord_message_id: msg.id.clone(),
                discord_channel_id: msg.channel_id.clone(),
                concord_rumor_id: rumor.id.clone(),
                concord_channel_id: link.concord_channel_id_hex.clone(),
                community_id: link.community_id.clone(),
                origin: Origin::Discord,
                author_ref: msg.author.id.clone(),
                part_index: 0,
            })
            .await?;
        Ok(Some(rumor.id))
    }

    /// Discord MESSAGE_DELETE -> kind 5 from the original author's puppet.
    /// Deleting a mirror of an Armada member's message stops at Discord: the
    /// puppet cannot (and must not) tombstone someone else's rumor.
    pub async fn on_discord_delete(&self, del: &DiscordMessageDelete, link: &ChannelLink) -> anyhow::Result<Option<String>> {
        if !link.enabled {
            return Ok(None);
        }
        let Some(row) = self.store.by_discord_id(&del.id).await?.into_iter().next() else { return Ok(None) };
        if row.origin != Origin::Discord {
            return Ok(None);
        }
        let Some(channel) = self.channel(link) else { return Ok(None) };
        let puppet = self.puppets.get(&row.author_ref)?;
        let tags = vec![vec!["e".into(), row.concord_rumor_id.clone()], proxy_tag(&del.guild_id, &del.channel_id, &del.id)];
        let send = SendChat { content: String::new(), author: &puppet.keys, kind: kinds::DELETE, tags, ms: None };
        let (rumor, _) = self.client.send_chat(&channel, send).await?;
        Ok(Some(rumor.id))
    }

    /// Discord MESSAGE_UPDATE -> kind 3302 from the original author's puppet.
    /// Off unless `bridge_edits`: the 3302 payload is not frozen in the CORDs.
    pub async fn on_discord_edit(&self, msg: &DiscordInboundMessage, link: &ChannelLink) -> anyhow::Result<Option<String>> {
        if !self.options.bridge_edits || !link.enabled {
            return Ok(None);
        }
        let Some(row) = self.store.by_discord_id(&msg.id).await?.into_iter().next() else { return Ok(None) };
        if row.origin != Origin::Discord {
            return Ok(None);
        }
        let Some(channel) = self.channel(link) else { return Ok(None) };
        let content = discord_to_concord(msg);
        if content.is_empty() {
            return Ok(None);
        }
        let puppet = self.puppets.get(&row.author_ref)?;
        let tags = vec![vec!["e".into(), row.concord_rumor_id.clone()], proxy_tag(&msg.guild_id, &msg.channel_id, &msg.id)];
        let send = SendChat { content, author: &puppet.keys, kind: kinds::EDIT, tags, ms: None };
        let (rumor, _) = self.client.send_chat(&channel, send).await?;
        Ok(Some(rumor.id))
    }

    /// Discord MESSAGE_REACTION_ADD -> kind 7 from the reactor's puppet. Custom
    /// guild emoji carry NIP-30: content `:name:` plus an `emoji` tag with the
    /// stable CDN image, self-contained for any Armada reader.
    pub async fn on_discord_reaction(&self, reaction: &DiscordReaction, link: &ChannelLink) -> anyhow::Result<Option<String>> {
        if !link.enabled || reaction.user.bot {
            return Ok(None);
        }
        let Some(name) = reaction.emoji.name.as_deref().filter(|n| !n.is_empty()) else { return Ok(None) };
        let custom = reaction.emoji.id.as_deref();
        let content = match custom {
            Some(_) => format!(":{name}:"),
            None => name.to_owned(),
        };
        // Mapping key: unicode as-is; custom as name:id (what the bot reacts with).
        let emoji_key = match custom {
            Some(id) => format!("{name}:{id}"),
            None => name.to_owned(),
        };
        let Some(row) = self.store.by_discord_id(&reaction.message_id).await?.into_iter().next() else { return Ok(None) };
        let Some(channel) = self.channel(link) else { return Ok(None) };

        let puppet = self.puppets.get(&reaction.user.id)?;
        if let Err(error) = self.sync_puppet_profile(&reaction.user, &puppet.keys).await {
            tracing::warn!(user = %reaction.user.id, %error, "puppet profile publish failed");
        }
        let mut tags = vec![
            vec!["e".into(), row.concord_rumor_id.clone()],
            vec!["k".into(), kinds::MESSAGE.to_string()],
            proxy_tag(&reaction.guild_id, &reaction.channel_id, &reaction.message_id),
        ];
        if let Some(id) = custom {
            tags.push(vec!["emoji".into(), name.to_owned(), discord_emoji_url(id, reaction.emoji.animated)]);
        }
        let send = SendChat { content, author: &puppet.keys, kind: kinds::REACTION, tags, ms: None };
        let (rumor, _) = self.client.send_chat(&channel, send).await?;
        self.store
            .insert_reaction(&ReactionMappingRow {
                rumor_id: rumor.id.clone(),
                discord_message_id: reaction.message_id.clone(),
                emoji: emoji_key,
                origin: Origin::Discord,
                author_ref: reaction.user.id.clone(),
            })
            .await?;
        Ok(Some(rumor.id))
    }

    /// Discord MESSAGE_REACTION_REMOVE -> puppet kind 5 tombstoning the kind 7.
    /// The `k` tag marks it a reaction delete for Armada's fold.
    pub async fn on_discord_reaction_remove(&self, reaction: &DiscordReaction, link: &ChannelLink) -> anyhow::Result<Option<String>> {
        if !link.enabled || reaction.user.bot {
            return Ok(None);
        }
        let Some(name) = reaction.emoji.name.as_deref().filter(|n| !n.is_empty()) else { return Ok(None) };
        let emoji_key = match reaction.emoji.id.as_deref() {
            Some(id) => format!("{name}:{id}"),
            None => name.to_owned(),
        };
        let Some(row) = self.store.reaction_by_discord(&reaction.message_id, &reaction.user.id, &emoji_key).await? else {
            return Ok(None);
        };
        if row.origin != Origin::Discord {
            return Ok(None);
        }
        let Some(channel) = self.channel(link) else { return Ok(None) };
        let puppet = self.puppets.get(&reaction.user.id)?;
        let tags = vec![
            vec!["e".into(), row.rumor_id.clone()],
            vec!["k".into(), kinds::REACTION.to_string()],
            proxy_tag(&reaction.guild_id, &reaction.channel_id, &reaction.message_id),
        ];
        let send = SendChat { content: String::new(), author: &puppet.keys, kind: kinds::DELETE, tags, ms: None };
        let (rumor, _) = self.client.send_chat(&channel, send).await?;
        self.store.delete_reaction(&row.rumor_id).await?;
        Ok(Some(rumor.id))
    }
}

impl BridgeRouter {
    /// Concord -> Discord, one rumor at a time per bridged channel. Returns the
    /// created Discord message ids (a long rumor may split).
    ///
    /// Both entry points dispatch these fire-and-forget, so without the queue
    /// they ran fully concurrently and a burst held every rumor's attachments
    /// at once — the per-rumor byte budget bounds one rumor, not N of them.
    /// Serialising also gives the mirror the ordering a channel is expected to
    /// have. Past [`MAX_QUEUED_CHATS`] new rumors are dropped: shedding load
    /// beats unbounded growth, and the relay copy is still the record.
    pub async fn on_concord_chat(&self, chat: &OpenedChat, link: &ChannelLink) -> anyhow::Result<Vec<String>> {
        if self.queued.fetch_add(1, Ordering::SeqCst) >= MAX_QUEUED_CHATS {
            self.queued.fetch_sub(1, Ordering::SeqCst);
            tracing::warn!(
                rumor = %&chat.rumor_id()[..8],
                channel = %link.discord_channel_id,
                "dropping inbound rumor: the channel's queue is full",
            );
            return Ok(vec![]);
        }
        let result = {
            let _turn = self.chat_queue.lock().await;
            self.dispatch_concord_chat(chat, link).await
        };
        self.queued.fetch_sub(1, Ordering::SeqCst);
        result
    }

    async fn dispatch_concord_chat(&self, chat: &OpenedChat, link: &ChannelLink) -> anyhow::Result<Vec<String>> {
        if !link.enabled {
            return Ok(vec![]);
        }
        // Layers 1 and 2: bridge-originated or already-bridged rumors never
        // bounce. The primary's own posts (confirm requests, announcements)
        // stay Armada-side; mirroring them trips Discord's webhook username
        // filter ("Discord <-> Armada Bridge Bot") and is noise regardless.
        let author = chat.author();
        if author == self.client.primary_pk()
            || has_proxy_tag(chat.tags())
            || self.puppets.is_puppet_pubkey(author)
            || self.client.is_banned(author)
        {
            return Ok(vec![]);
        }
        match chat.kind() {
            kinds::TYPING => {
                // Forwarded as the bot's typing indicator, throttled per channel
                // (Discord's indicator lasts ~10 s; Armada publishes every 4 s).
                if self.typing_allowed(format!("c:{}", link.discord_channel_id)) {
                    let _ = self.webhooks.send_typing(link).await;
                }
                return Ok(vec![]);
            }
            kinds::DELETE => return self.on_concord_delete(chat, link).await.map(|_| vec![]),
            kinds::REACTION => return self.on_concord_reaction(chat, link).await.map(|_| vec![]),
            kinds::EDIT => return self.on_concord_edit(chat, link).await.map(|_| vec![]),
            // Kind 9 messages and kind 1111 thread replies both bridge; Discord
            // has no thread on our side, so comments flatten with a jump link.
            kinds::MESSAGE | kinds::COMMENT => {}
            _ => return Ok(vec![]),
        }
        if !self.store.by_rumor_id(chat.rumor_id()).await?.is_empty() {
            return Ok(vec![]);
        }

        let profile = self.profiles.resolve(author).await.unwrap_or_else(|_| fallback_profile(author));
        let (files, urls) = self.files_from_imeta(chat).await;
        let text = apply_custom_emoji(&concord_to_discord(&strip_attached_urls(chat.content(), &urls)), chat.tags());
        let mut parts = split_for_discord(&text, DISCORD_MAX_CHARS);
        // Cap the fan-out. Inbound length is bounded only by what NIP-44 can
        // carry (~64 KB), so without this one publish by one member becomes ~33
        // webhook sends and 33 mapping rows — a flood amplifier available to
        // anyone who can post in the Concord channel.
        let dropped = parts.len().saturating_sub(MAX_DISCORD_PARTS);
        if dropped > 0 {
            parts.truncate(MAX_DISCORD_PARTS);
            // Say so in-channel rather than silently losing the tail; replace
            // the end of the last part instead of appending past 2000.
            let notice = format!("\n… {dropped} more part{} not mirrored", if dropped == 1 { "" } else { "s" });
            let last = parts.last_mut().expect("capped at ten, so non-empty");
            let keep = DISCORD_MAX_CHARS.saturating_sub(notice.encode_utf16().count());
            let mut units = 0;
            let cut = last.char_indices().find(|(_, c)| {
                units += c.len_utf16();
                units > keep
            });
            if let Some((i, _)) = cut {
                last.truncate(i);
            }
            last.push_str(&notice);
        }
        let reply = self.reply_embed(chat, link).await?;
        let mut files = Some(files);
        let mut ids = Vec::new();
        for (index, part) in parts.into_iter().enumerate() {
            let message = WebhookMessage {
                username: profile.name.clone(),
                avatar_url: profile.avatar_url.clone(),
                content: part,
                embeds: if index == 0 { reply.clone().into_iter().collect() } else { vec![] },
                files: files.take().unwrap_or_default(),
            };
            let discord_message_id = self.webhooks.send(link, message).await?;
            self.store
                .insert(&MessageMappingRow {
                    discord_message_id: discord_message_id.clone(),
                    discord_channel_id: link.discord_channel_id.clone(),
                    concord_rumor_id: chat.rumor_id().to_owned(),
                    concord_channel_id: link.concord_channel_id_hex.clone(),
                    community_id: link.community_id.clone(),
                    origin: Origin::Concord,
                    author_ref: author.to_owned(),
                    part_index: index as i32,
                })
                .await?;
            ids.push(discord_message_id);
        }
        Ok(ids)
    }

    /// Kind 5 -> remove every mapped Discord part. Honored for the rumor's own
    /// author and for MANAGE_MESSAGES holders (moderator deletes propagate).
    async fn on_concord_delete(&self, chat: &OpenedChat, link: &ChannelLink) -> anyhow::Result<()> {
        let targets: Vec<&str> =
            chat.tags().iter().filter(|t| t.first().is_some_and(|n| n == "e") && t.get(1).is_some_and(|v| !v.is_empty())).map(|t| t[1].as_str()).collect();
        for target in targets {
            // A kind 7 tombstone: un-react on Discord once the last mirrored
            // reaction with that emoji is gone (many reactors collapse into one
            // bot reaction).
            if let Some(reaction) = self.store.reaction_by_rumor_id(target).await? {
                let own = reaction.origin == Origin::Concord && reaction.author_ref == chat.author();
                if !own && !self.client.is_moderator(chat.author()) {
                    continue;
                }
                self.store.delete_reaction(target).await?;
                if reaction.origin == Origin::Concord
                    && self.store.count_concord_reactions(&reaction.discord_message_id, &reaction.emoji).await? == 0
                    && let Err(error) = self.webhooks.unreact(link, &reaction.discord_message_id, &reaction.emoji).await
                {
                    tracing::warn!(message = %reaction.discord_message_id, %error, "discord unreact failed");
                }
                continue;
            }
            let rows = self.store.by_rumor_id(target).await?;
            let Some(first) = rows.first() else { continue };
            let own = first.origin == Origin::Concord && first.author_ref == chat.author();
            if !own && !self.client.is_moderator(chat.author()) {
                continue;
            }
            for row in &rows {
                if let Err(error) = self.webhooks.delete(link, &row.discord_message_id).await {
                    tracing::warn!(message = %row.discord_message_id, %error, "discord delete failed");
                }
            }
        }
        Ok(())
    }

    /// Kind 7 -> bot reaction on the mapped Discord message.
    async fn on_concord_reaction(&self, chat: &OpenedChat, link: &ChannelLink) -> anyhow::Result<()> {
        if self.store.reaction_by_rumor_id(chat.rumor_id()).await?.is_some() {
            return Ok(()); // relay echo
        }
        let Some(target) = first_tag_value(chat.tags(), "e") else { return Ok(()) };
        // Unicode maps directly; an Armada custom emoji maps back only when its
        // image is a Discord CDN emoji (i.e. originally bridged from Discord).
        let Some(emoji) = reaction_emoji(chat.content()).or_else(|| concord_custom_emoji_to_discord(chat.tags())) else {
            return Ok(());
        };
        let rows = self.store.by_rumor_id(target).await?;
        let Some(row) = rows.iter().find(|r| r.part_index == 0).or(rows.first()) else { return Ok(()) };
        self.webhooks.react(link, &row.discord_message_id, &emoji).await?;
        self.store
            .insert_reaction(&ReactionMappingRow {
                rumor_id: chat.rumor_id().to_owned(),
                discord_message_id: row.discord_message_id.clone(),
                emoji,
                origin: Origin::Concord,
                author_ref: chat.author().to_owned(),
            })
            .await
    }

    /// Kind 3302 -> edit the webhook mirrors in place. Author-only, matching
    /// Armada's apply-phase author check. Grown messages append fresh parts;
    /// shrunk ones blank the leftovers.
    async fn on_concord_edit(&self, chat: &OpenedChat, link: &ChannelLink) -> anyhow::Result<()> {
        if !self.options.bridge_edits {
            return Ok(());
        }
        let Some(target) = first_tag_value(chat.tags(), "e") else { return Ok(()) };
        let mut rows = self.store.by_rumor_id(target).await?;
        rows.sort_by_key(|r| r.part_index);
        let Some(first) = rows.first() else { return Ok(()) };
        if first.origin != Origin::Concord || first.author_ref != chat.author() {
            return Ok(());
        }
        let parts = split_for_discord(&concord_to_discord(chat.content()), DISCORD_MAX_CHARS);
        for (i, row) in rows.iter().enumerate() {
            let content = parts.get(i).map(String::as_str).unwrap_or("*(removed by edit)*");
            if let Err(error) = self.webhooks.edit(link, &row.discord_message_id, content).await {
                tracing::warn!(message = %row.discord_message_id, %error, "discord edit failed");
            }
        }
        if parts.len() > rows.len() {
            let profile = self.profiles.resolve(chat.author()).await.unwrap_or_else(|_| fallback_profile(chat.author()));
            for (i, part) in parts.iter().enumerate().skip(rows.len()) {
                let message = WebhookMessage {
                    username: profile.name.clone(),
                    avatar_url: profile.avatar_url.clone(),
                    content: part.clone(),
                    ..Default::default()
                };
                let discord_message_id = self.webhooks.send(link, message).await?;
                self.store
                    .insert(&MessageMappingRow {
                        discord_message_id,
                        discord_channel_id: link.discord_channel_id.clone(),
                        concord_rumor_id: target.to_owned(),
                        concord_channel_id: link.concord_channel_id_hex.clone(),
                        community_id: link.community_id.clone(),
                        origin: Origin::Concord,
                        author_ref: chat.author().to_owned(),
                        part_index: i as i32,
                    })
                    .await?;
            }
        }
        Ok(())
    }

    /// The replied-to rumor -> an embed linking the mapped Discord message.
    /// Kind 9 inline replies carry `q`; kind 1111 comments point at their
    /// immediate parent with lowercase `e` (thread root `E` as fallback).
    async fn reply_embed(&self, chat: &OpenedChat, link: &ChannelLink) -> anyhow::Result<Option<String>> {
        let mut target = first_tag_value(chat.tags(), "q");
        if target.is_none() && chat.kind() == kinds::COMMENT {
            target = first_tag_value(chat.tags(), "e").or_else(|| first_tag_value(chat.tags(), "E"));
        }
        let Some(target) = target else { return Ok(None) };
        let rows = self.store.by_rumor_id(target).await?;
        let Some(row) = rows.iter().find(|r| r.part_index == 0).or(rows.first()) else { return Ok(None) };
        let url = format!("https://discord.com/channels/{}/{}/{}", link.discord_guild_id, row.discord_channel_id, row.discord_message_id);
        if row.origin == Origin::Concord {
            let profile = self.profiles.resolve(&row.author_ref).await.unwrap_or_else(|_| fallback_profile(&row.author_ref));
            // The name is a kind 0 field, so its author chooses it, and Discord
            // renders markdown in an embed description. Unescaped, a display
            // name of `[#general](https://phishing.example)` produced an
            // arbitrary link inside an embed the BRIDGE authored, borrowing its
            // apparent authority.
            return Ok(Some(format!("Replying to {} ([view message]({url}))", escape_markdown(&profile.name))));
        }
        Ok(Some(format!("Replying to [this message]({url})")))
    }
}

static MP4_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\.mp4(\?|$)").unwrap());

impl BridgeRouter {
    /// A Klipy GIF-picker send, resolved to its real GIF through the Items API
    /// and rehosted on Blossom; `None` leaves the message to the generic embed
    /// path.
    ///
    /// Keyed on the content alone, not on Discord's embed: the embed can arrive
    /// in a later MESSAGE_UPDATE, and the slug in the page URL is all the lookup
    /// needs. If Blossom is absent or refuses the upload, the Klipy URL itself
    /// is still the real GIF, so it crosses tagged rather than falling back to
    /// the mp4.
    async fn klipy_gif(&self, msg: &DiscordInboundMessage, author: &Keys, tags: &mut Vec<Vec<String>>) -> Option<DiscordInboundMessage> {
        let klipy = self.options.klipy.as_ref()?;
        let page = msg.content.trim();
        klipy_item(page)?;
        let gif = klipy.resolve_gif(page, MAX_BLOB_BYTES as u64).await?;
        let dim = match (gif.width, gif.height) {
            (Some(w), Some(h)) if w > 0 && h > 0 => vec![format!("dim {w}x{h}")],
            _ => vec![],
        };
        let substituted = |media: &str| DiscordInboundMessage {
            embeds: vec![EmbedIn { url: Some(page.to_owned()), media_url: Some(media.to_owned()) }],
            ..msg.clone()
        };
        if let Some(blobs) = &self.options.blobs {
            let rehosted = async {
                let (data, _) = blobs.download(&gif.url, MAX_BLOB_BYTES).await?;
                // "GIF8": the Items API named this file, but the CDN is the one
                // that serves a placeholder for anything it cannot find.
                anyhow::ensure!(data.starts_with(b"GIF8"), "klipy served something that is not a GIF");
                let uploaded = blobs.upload(&data, "image/gif", author).await?;
                anyhow::Ok((with_extension(&uploaded.url, "image/gif"), uploaded.sha256, data.len()))
            };
            match rehosted.await {
                Ok((url, sha256, size)) => {
                    let mut imeta = vec!["imeta".into(), format!("url {url}"), "m image/gif".into(), format!("x {sha256}"), format!("size {size}")];
                    imeta.extend(dim);
                    tags.push(imeta);
                    return Some(substituted(&url));
                }
                Err(error) => tracing::warn!(%error, "klipy rehost failed"),
            }
        }
        let mut imeta = vec!["imeta".into(), format!("url {}", gif.url), "m image/gif".into()];
        imeta.extend(dim);
        tags.push(imeta);
        Some(substituted(&gif.url))
    }

    /// Last resort for gifv embeds with no real .gif anywhere: download the
    /// short mp4, transcode with ffmpeg, rehost on Blossom. Skipped without
    /// ffmpeg or a Blossom server; any failure keeps the mp4 URL.
    ///
    /// The transcode used to succeed and still arrive as a link, because a
    /// Blossom URL is content-addressed (`/<sha256>`) and the bytes never got an
    /// `imeta` tag. Both halves are fixed: the extension goes back on the URL,
    /// and the tag pushed here names exactly what lands in the content.
    async fn transcoded_gif_fallback(&self, msg: DiscordInboundMessage, author: &Keys, tags: &mut Vec<Vec<String>>) -> DiscordInboundMessage {
        let Some(blobs) = &self.options.blobs else { return msg };
        let Some(embed) = msg.embeds.first() else { return msg };
        let Some(media) = embed.media_url.clone().filter(|m| MP4_URL.is_match(m)) else { return msg };
        if embed.url.as_deref() != Some(msg.content.trim()) || !ffmpeg_available() {
            return msg;
        }
        let page = embed.url.clone();
        let transcoded = async {
            let (data, _) = blobs.download(&media, MAX_BLOB_BYTES).await?;
            let gif = mp4_to_gif(&data).await?;
            anyhow::ensure!(gif.len() <= MAX_BLOB_BYTES, "transcoded GIF exceeds the upload cap");
            let uploaded = blobs.upload(&gif, "image/gif", author).await?;
            anyhow::Ok((with_extension(&uploaded.url, "image/gif"), uploaded.sha256, gif.len()))
        };
        match transcoded.await {
            Ok((url, sha256, size)) => {
                tags.push(vec!["imeta".into(), format!("url {url}"), "m image/gif".into(), format!("x {sha256}"), format!("size {size}")]);
                DiscordInboundMessage { embeds: vec![EmbedIn { url: page, media_url: Some(url) }], ..msg }
            }
            Err(error) => {
                tracing::warn!(%error, "gif transcode fallback failed");
                msg
            }
        }
    }

    /// Tag the media URL that replaces a GIF-picker page link in the content.
    ///
    /// Without this a picker send crosses as a bare URL: no `m`, no `x`, no
    /// `size`. A URL with an imeta entry is also the only one Armada exempts
    /// from tracking-param stripping, which is what breaks a signed provider
    /// URL. Only the fields we actually know: these bytes belong to a
    /// third-party provider and are not downloaded, so there is no honest `x`
    /// or `size` to publish — the same shape Armada's own GIF picker emits.
    fn tag_embed_media(&self, msg: &DiscordInboundMessage, tags: &mut Vec<Vec<String>>) {
        let Some(url) = substituted_embed_media(msg) else { return };
        let field = format!("url {url}");
        // The transcode path already published a fuller tag for this exact URL.
        if tags.iter().any(|t| t.first().is_some_and(|n| n == "imeta") && t.contains(&field)) {
            return;
        }
        let Some(mime) = mime_from_url(url) else { return };
        tags.push(vec!["imeta".into(), field, format!("m {mime}")]);
    }

    /// Rehost Discord CDN attachments (signed URLs expire in ~24 h) on Blossom,
    /// signed by the puppet, and record NIP-92 imeta tags. Any failure falls
    /// back to the CDN link so the message still bridges.
    async fn rehost_attachments(&self, msg: &DiscordInboundMessage, author: &Keys, tags: &mut Vec<Vec<String>>) -> Vec<DiscordAttachmentIn> {
        let Some(blobs) = &self.options.blobs else { return msg.attachments.clone() };
        let mut out = Vec::with_capacity(msg.attachments.len());
        for attachment in &msg.attachments {
            let rehosted = async {
                let (data, mime) = blobs.download(&attachment.url, MAX_BLOB_BYTES).await?;
                // A served `application/octet-stream` tells us nothing, and it
                // decides whether the far side renders the image or a download
                // card. The CDN filename is the better witness in that case.
                let kind = if mime == "application/octet-stream" { mime_from_url(&attachment.url).map(str::to_owned).unwrap_or(mime) } else { mime };
                let uploaded = blobs.upload(&data, &kind, author).await?;
                // Content-addressed URLs arrive extension-less unless the server
                // chose one; BUD-01 serves the same blob either way, and the
                // extension is what Discord's unfurl and Armada's sniffing read.
                anyhow::Ok((with_extension(&uploaded.url, &kind), kind, uploaded.sha256, data.len()))
            };
            match rehosted.await {
                Ok((url, kind, sha256, size)) => {
                    let mut imeta = vec!["imeta".into(), format!("url {url}"), format!("m {kind}"), format!("x {sha256}"), format!("size {size}")];
                    // The original filename, so the far side can name a download.
                    if let Some(name) = &attachment.filename {
                        imeta.push(format!("name {name}"));
                    }
                    tags.push(imeta);
                    out.push(DiscordAttachmentIn { url, filename: attachment.filename.clone() });
                }
                Err(error) => {
                    tracing::warn!(url = %attachment.url, %error, "blossom rehost failed");
                    out.push(attachment.clone());
                }
            }
        }
        out
    }

    /// NIP-92 imeta tags -> downloaded webhook file uploads, plus the URLs that
    /// became files (so they can leave the text).
    ///
    /// Every attachment sent from a Concord community is client-encrypted, and
    /// this read once looked only at `url` and `size` — so the bytes handed to
    /// Discord were AES-GCM ciphertext, named after a content-addressed URL with
    /// no extension. `imeta` supplies the key material the tag carries, and the
    /// name comes from `m`, the only thing that knows the plaintext type.
    async fn files_from_imeta(&self, chat: &OpenedChat) -> (Vec<FileUpload>, Vec<String>) {
        let mut files = Vec::new();
        let mut urls = Vec::new();
        let Some(blobs) = &self.options.blobs else { return (files, urls) };
        // ATTEMPTS, not successes: a download that 404s or never answers leaves
        // a success count untouched, so a rumor of a few thousand dead imeta
        // tags would still make a few thousand sequential outbound requests.
        let mut attempted = 0;
        // Bytes actually held. MAX_BLOB_BYTES bounds ONE file; every download
        // is retained until the whole rumor is sent, so this is the bound that
        // keeps the process alive.
        let mut held = 0usize;
        for tag in chat.tags() {
            if tag.first().map(String::as_str) != Some("imeta") {
                continue;
            }
            if attempted >= MAX_IMETA_DOWNLOADS {
                break;
            }
            let remaining = MAX_IMETA_TOTAL_BYTES.saturating_sub(held);
            if remaining == 0 {
                break;
            }
            let fields = imeta_fields(tag);
            let Some(url) = fields.get("url").filter(|u| !u.is_empty()) else { continue };
            let encryption = parse_imeta_encryption(&fields);
            // Encrypted with something we cannot apply: fail closed the way
            // Armada does and leave the URL in the text. Uploading the blob
            // anyway is exactly the bug — Discord would attach ciphertext under
            // the sender's name, and nothing downstream would say why.
            if encryption.is_some() && !is_supported_encryption(encryption.as_ref()) {
                tracing::warn!(%url, "imeta uses encryption we cannot apply");
                continue;
            }
            // Advisory only: `size` is whatever the sender wrote, and absent on
            // a tag built to evade this. The byte counter in safe_fetch is the
            // real bound; this just avoids a download that admits it is too big.
            let cap = MAX_BLOB_BYTES.min(remaining);
            if fields.get("size").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0) > cap {
                continue;
            }
            attempted += 1;
            let fetched = async {
                let (data, mime) = blobs.download(url, cap).await?;
                let plaintext = match &encryption {
                    Some(enc) => decrypt_blob(&data, enc)?,
                    None => data,
                };
                anyhow::Ok((plaintext, mime))
            };
            match fetched.await {
                Ok((data, served)) => {
                    // `m` wins over the served type: on an encrypted attachment
                    // the response describes the CIPHERTEXT.
                    let kind = fields
                        .get("m")
                        .filter(|m| !m.is_empty())
                        .cloned()
                        .or_else(|| mime_from_url(url).map(str::to_owned))
                        .unwrap_or(served);
                    held += data.len();
                    files.push(FileUpload { name: attachment_filename(url, &kind, fields.get("name").map(String::as_str)), data });
                    urls.push(url.clone());
                }
                Err(error) => tracing::warn!(%url, %error, "imeta download failed"),
            }
        }
        (files, urls)
    }
}

#[cfg(test)]
#[path = "router_tests.rs"]
mod tests;
