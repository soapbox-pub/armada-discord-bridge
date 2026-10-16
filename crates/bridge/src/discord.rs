//! Discord adapter: gateway ingestion and webhook impersonation.
//!
//! Gateway: GUILDS + GUILD_MESSAGES + GUILD_MESSAGE_REACTIONS +
//! GUILD_MESSAGE_TYPING + MESSAGE_CONTENT (privileged; toggle in the developer
//! portal). Events map to the router's transport-agnostic shapes in
//! [`crate::types`]; twilight types never cross the router boundary.
//!
//! Webhooks: one `armada-bridge` webhook per bridged channel, created on
//! demand and cached; per-message username/avatar overrides render Concord
//! members. Mentions are never forwarded as pings (allowed_mentions: none).
//!
//! There is deliberately no gateway cache. The TS adapter ran on discord.js,
//! whose defaults keep 200 messages per channel and every user and member ever
//! seen, forever. The GuildMessages intent delivers every message in every
//! channel of every guild the bot is in — bridged or not, a hundred guilds of
//! them — so those caches only ever grew, and with the rest of the process
//! they ran the container out of memory (2026-09-23). Nothing here needs
//! history from a cache: display names come from the event payload itself
//! (`member.nick`, `author.global_name`, `author.name`), and the one event
//! that lacks them (reaction remove) fetches the user over REST. Do not add
//! twilight-cache-inmemory back without bounding it. The one thing kept is
//! [`Directory`]: server and text-channel names and each channel's newest
//! message id, one entry per server and channel, removed when they go.

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use async_trait::async_trait;
use regex::Regex;
use tokio::sync::{mpsc, watch};
use twilight_gateway::error::ReceiveMessageErrorType;
use twilight_gateway::{CloseFrame, Config, Event, EventTypeFlags, Intents, MessageSender, Shard, ShardState, StreamExt as _};
use twilight_http::Client;
use twilight_http::api_error::ApiError;
use twilight_http::error::ErrorType;
use twilight_http::request::AuditLogReason as _;
use twilight_http::request::channel::reaction::RequestReactionType;
use twilight_model::channel::message::{AllowedMentions, Embed, EmojiReactionType, Mention};
use twilight_model::channel::{Channel, ChannelType, Message};
use twilight_model::gateway::payload::incoming::GuildCreate;
use twilight_model::gateway::GatewayReaction;
use twilight_model::http::attachment::Attachment;
use twilight_model::id::Id;
use twilight_model::id::marker::{ChannelMarker, MessageMarker, UserMarker, WebhookMarker};
use twilight_model::user::User;
use twilight_model::util::ImageHash;

use crate::discord_directory::Directory;
use crate::router::{MissingPermissions, WebhookMessage, WebhookSender};
use crate::transform::sanitize_username;
use crate::types::{
    ChannelLink, DiscordAttachmentIn, DiscordEmoji, DiscordInboundMessage, DiscordMentionIn, DiscordMessageDelete,
    DiscordReaction, DiscordUserRef, EmbedIn,
};

pub const BRIDGE_WEBHOOK_NAME: &str = "armada-bridge";

/// The persona a send falls back to when Discord refuses the real name.
const FALLBACK_USERNAME: &str = "bridged member";

/// Discord's "Missing Permissions" API error code.
const MISSING_PERMISSIONS: u64 = 50013;

/// Discord's "Invalid Form Body" API error code.
const INVALID_FORM_BODY: u64 = 50035;

/// Discord's "Unknown Webhook" API error code.
const UNKNOWN_WEBHOOK: u64 = 10015;

/// How long `stop` lets a shard flush its close frame (so the bot shows
/// offline at once rather than when its presence times out).
const CLOSE_FLUSH: Duration = Duration::from_secs(5);

/// What a `/command` message carries to the host's command handler.
#[derive(Clone, Debug)]
pub struct CommandMessage {
    pub id: String,
    pub channel_id: String,
    pub guild_id: String,
    pub content: String,
    pub author_bot: bool,
    pub webhook_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct TypingEvent {
    pub channel_id: String,
    pub guild_id: String,
    pub user_id: String,
    pub bot: bool,
}

#[async_trait]
pub trait DiscordEvents: Send + Sync + 'static {
    async fn on_message(&self, msg: DiscordInboundMessage);
    /// Return true when the host consumed the message as a command (called
    /// BEFORE on_message; synchronous decision, like the TS onBotCommand).
    fn on_bot_command(&self, _msg: &CommandMessage) -> bool {
        false
    }
    async fn on_message_update(&self, _msg: DiscordInboundMessage) {}
    async fn on_message_delete(&self, _del: DiscordMessageDelete) {}
    async fn on_reaction_add(&self, _r: DiscordReaction) {}
    async fn on_reaction_remove(&self, _r: DiscordReaction) {}
    async fn on_typing(&self, _t: TypingEvent) {}
    /// A server's GUILD_CREATE arrived: on connect for every server the bot
    /// is in, and when it is added to one.
    async fn on_guild_available(&self, _guild_id: String) {}
    /// The bot left a server or was removed from it (not an outage).
    async fn on_guild_removed(&self, _guild_id: String) {}
}

fn intents() -> Intents {
    Intents::GUILDS
        | Intents::GUILD_MESSAGES
        | Intents::GUILD_MESSAGE_REACTIONS
        | Intents::GUILD_MESSAGE_TYPING
        | Intents::MESSAGE_CONTENT
}

/// Only these are deserialized; everything else the intents deliver is skipped
/// as raw text. Guild creates are the large ones (full channel, role and
/// emoji lists) and are wanted for the [`Directory`]: one per server on
/// connect, kept only as names and newest message ids, then dropped. With
/// them the portal's resident memory stayed at ~385MB (2026-10-16).
fn wanted_events() -> EventTypeFlags {
    EventTypeFlags::READY
        | EventTypeFlags::MESSAGE_CREATE
        | EventTypeFlags::MESSAGE_UPDATE
        | EventTypeFlags::MESSAGE_DELETE
        | EventTypeFlags::REACTION_ADD
        | EventTypeFlags::REACTION_REMOVE
        | EventTypeFlags::TYPING_START
        | EventTypeFlags::GUILD_CREATE
        | EventTypeFlags::GUILD_UPDATE
        | EventTypeFlags::GUILD_DELETE
        | EventTypeFlags::CHANNEL_CREATE
        | EventTypeFlags::CHANNEL_UPDATE
        | EventTypeFlags::CHANNEL_DELETE
}

/// No pings, ever: bridged text quotes `@everyone` and user mentions verbatim.
fn no_mentions() -> AllowedMentions {
    AllowedMentions::default()
}

#[derive(Clone)]
struct BotUser {
    id: Id<UserMarker>,
    avatar: Option<ImageHash>,
    discriminator: u16,
}

#[derive(Clone)]
struct CachedWebhook {
    id: Id<WebhookMarker>,
    token: String,
}

pub struct DiscordAdapter {
    http: Client,
    events: Arc<dyn DiscordEvents>,
    senders: Vec<MessageSender>,
    stop_tx: watch::Sender<bool>,
    stopped: AtomicBool,
    application_id: RwLock<String>,
    bot: RwLock<Option<BotUser>>,
    /// Webhook ids we created or adopted; the router uses this set for echo
    /// suppression.
    own_webhook_ids: Arc<RwLock<HashSet<String>>>,
    /// channel id -> its bridge webhook. Bounded by the number of bridged
    /// channels: only links ever reach `webhook_for`.
    webhooks: Mutex<HashMap<String, CachedWebhook>>,
    /// Serialises webhook lookup-or-create so two first sends into one
    /// channel cannot each create a webhook.
    webhook_create: tokio::sync::Mutex<()>,
    directory: Mutex<Directory>,
}

impl DiscordAdapter {
    /// Log in, start the gateway shard(s) Discord recommends, and resolve
    /// once every shard is READY. A fatal close (bad token, disallowed
    /// intents) or a failed connection before READY is an error, so the
    /// caller can retry with backoff; after READY, twilight reconnects by
    /// itself and errors are only logged.
    pub async fn connect(token: &str, events: Arc<dyn DiscordEvents>) -> anyhow::Result<Arc<DiscordAdapter>> {
        let http = Client::new(token.to_owned());
        let config = Config::new(token.to_owned(), intents());
        // What twilight_gateway::create_recommended does, which sits behind a
        // feature this crate does not enable. A bad token fails here (401).
        let info = http
            .gateway()
            .authed()
            .await
            .context("discord gateway: could not get the recommended shard count")?
            .model()
            .await?;
        let shards: Vec<Shard> =
            twilight_gateway::create_iterator(0..info.shards, info.shards, config, |_, builder| builder.build()).collect();
        let (stop_tx, stop_rx) = watch::channel(false);
        let adapter = Arc::new(DiscordAdapter {
            http,
            events,
            senders: shards.iter().map(Shard::sender).collect(),
            stop_tx,
            stopped: AtomicBool::new(false),
            application_id: RwLock::default(),
            bot: RwLock::default(),
            own_webhook_ids: Arc::default(),
            webhooks: Mutex::default(),
            webhook_create: tokio::sync::Mutex::new(()),
            directory: Mutex::default(),
        });

        let pending = shards.len();
        let (ready_tx, mut ready_rx) = mpsc::channel(pending.max(1));
        for shard in shards {
            tokio::spawn(run_shard(shard, adapter.clone(), ready_tx.clone(), stop_rx.clone()));
        }
        drop(ready_tx);
        for _ in 0..pending {
            let outcome = match ready_rx.recv().await {
                Some(outcome) => outcome,
                None => Err(anyhow!("discord gateway: shard ended before READY")),
            };
            if let Err(error) = outcome {
                adapter.stop();
                return Err(error);
            }
        }
        tracing::info!(shards = pending, application = %adapter.application_id(), "discord gateway ready");
        Ok(adapter)
    }

    /// Shut every shard down; idempotent.
    pub fn stop(&self) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        for sender in &self.senders {
            _ = sender.close(CloseFrame::NORMAL);
        }
        _ = self.stop_tx.send(true);
    }

    fn directory(&self) -> std::sync::MutexGuard<'_, Directory> {
        self.directory.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Wait (up to `limit`) for a GUILD_CREATE from every server READY listed,
    /// so the boot that follows reads names and newest message ids from the
    /// gateway instead of REST. Returns how many never arrived.
    pub async fn wait_for_directory(&self, limit: Duration) -> usize {
        let deadline = tokio::time::Instant::now() + limit;
        while !self.directory().is_loaded() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let d = self.directory();
        let (guilds, channels) = d.len();
        tracing::info!(guilds, channels, missing = d.pending(), "discord directory loaded");
        d.pending()
    }

    /// A text channel's name as the gateway last described it.
    pub fn known_channel_name(&self, channel_id: &str) -> Option<String> {
        self.directory().channel_name(channel_id.parse().ok()?).map(str::to_owned)
    }

    /// `Some(false)` when the gateway has described every server the bot is in
    /// and this is not one of them: the bot was removed, and REST about it
    /// can only fail. `None` while that is not yet known.
    pub fn in_guild(&self, guild_id: &str) -> Option<bool> {
        self.directory().has_guild(guild_id.parse().ok()?)
    }

    pub fn known_guild_name(&self, guild_id: &str) -> Option<String> {
        self.directory().guild_name(guild_id.parse().ok()?).map(str::to_owned)
    }

    /// The channel's newest message id as far as the gateway has said; `None`
    /// when it has not described the channel (or it never had a message).
    pub fn last_message_id(&self, channel_id: &str) -> Option<u64> {
        self.directory().last_message_id(channel_id.parse().ok()?)
    }

    pub fn application_id(&self) -> String {
        self.application_id.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The set the router reads for echo suppression; shared, and grows as
    /// webhooks are created.
    pub fn own_webhook_ids(&self) -> Arc<RwLock<HashSet<String>>> {
        self.own_webhook_ids.clone()
    }

    /// The bot account's own avatar, for the bridge's Concord kind 0.
    pub fn bot_avatar_url(&self) -> Option<String> {
        let bot = self.bot.read().unwrap_or_else(|e| e.into_inner()).clone()?;
        Some(format!("{}?size=256", avatar_url(bot.id, bot.avatar.as_ref(), bot.discriminator)))
    }

    fn bot_id(&self) -> Option<Id<UserMarker>> {
        self.bot.read().unwrap_or_else(|e| e.into_inner()).as_ref().map(|b| b.id)
    }

    /// Post a plain bot message (not a webhook) into a channel. Used for the
    /// missing-permission notice: it needs only Send Messages, so it can still
    /// land in the very channel where Manage Webhooks — and thus persona
    /// mirroring — is what's missing.
    pub async fn notice(&self, channel_id: &str, content: &str) -> anyhow::Result<()> {
        let mentions = no_mentions();
        self.http
            .create_message(channel_id.parse()?)
            .content(content)
            .allowed_mentions(Some(&mentions))
            .await
            .map_err(|e| api_error(e, "discord notice"))?;
        Ok(())
    }

    /// Bot reply to a message (command answers). Never pings the author.
    pub async fn reply(&self, channel_id: &str, message_id: &str, content: &str) -> anyhow::Result<()> {
        let mentions = no_mentions();
        self.http
            .create_message(channel_id.parse()?)
            .content(content)
            .reply(message_id.parse()?)
            .allowed_mentions(Some(&mentions))
            .await
            .map_err(|e| api_error(e, "discord reply"))?;
        Ok(())
    }

    /// Display name of a guild text channel (dashboard labels).
    pub async fn channel_name(&self, channel_id: &str) -> anyhow::Result<String> {
        let channel = self
            .http
            .channel(channel_id.parse()?)
            .await
            .map_err(|e| api_error(e, "discord channel fetch"))?
            .model()
            .await?;
        if channel.kind != ChannelType::GuildText {
            bail!("channel {channel_id} is not a guild text channel");
        }
        Ok(channel.name.unwrap_or_default())
    }

    /// Display name of a guild (dashboard labels).
    pub async fn guild_name(&self, guild_id: &str) -> anyhow::Result<String> {
        let guild =
            self.http.guild(guild_id.parse()?).await.map_err(|e| api_error(e, "discord guild fetch"))?.model().await?;
        Ok(guild.name)
    }

    async fn webhook_for(&self, channel_id: &str) -> anyhow::Result<CachedWebhook> {
        if let Some(cached) = self.cached_webhook(channel_id) {
            return Ok(cached);
        }
        let _creating = self.webhook_create.lock().await;
        if let Some(cached) = self.cached_webhook(channel_id) {
            return Ok(cached);
        }
        let id: Id<ChannelMarker> = channel_id.parse()?;
        let channel = self.http.channel(id).await.map_err(|e| api_error(e, "discord channel fetch"))?.model().await?;
        if channel.kind != ChannelType::GuildText {
            bail!("channel {channel_id} is not a guild text channel");
        }
        let existing = self
            .http
            .channel_webhooks(id)
            .await
            .map_err(|e| api_error(e, "discord webhook list"))?
            .models()
            .await?
            .into_iter()
            .find(|wh| wh.name.as_deref() == Some(BRIDGE_WEBHOOK_NAME) && wh.token.is_some());
        let webhook = match existing {
            Some(webhook) => webhook,
            None => self
                .http
                .create_webhook(id, BRIDGE_WEBHOOK_NAME)
                .reason("Armada bridge persona posts")
                .await
                .map_err(|e| api_error(e, "discord webhook create"))?
                .model()
                .await?,
        };
        let token = webhook.token.ok_or_else(|| anyhow!("discord returned webhook {} without a token", webhook.id))?;
        let cached = CachedWebhook { id: webhook.id, token };
        self.webhooks.lock().unwrap_or_else(|e| e.into_inner()).insert(channel_id.to_owned(), cached.clone());
        self.own_webhook_ids.write().unwrap_or_else(|e| e.into_inner()).insert(webhook.id.to_string());
        Ok(cached)
    }

    fn cached_webhook(&self, channel_id: &str) -> Option<CachedWebhook> {
        self.webhooks.lock().unwrap_or_else(|e| e.into_inner()).get(channel_id).cloned()
    }

    /// A webhook deleted from Discord's side stays "Unknown" forever; drop it
    /// so the next send finds or creates a live one instead of failing until
    /// restart. Its id stays in `own_webhook_ids`: old mirrors still carry it.
    fn forget_dead_webhook(&self, channel_id: &str, error: &twilight_http::Error) {
        if api_code(error) == Some(UNKNOWN_WEBHOOK) {
            self.webhooks.lock().unwrap_or_else(|e| e.into_inner()).remove(channel_id);
        }
    }

    async fn execute(
        &self,
        webhook: &CachedWebhook,
        username: &str,
        message: &WebhookMessage,
        embeds: &[Embed],
        files: &[Attachment],
    ) -> Result<twilight_http::Response<Message>, twilight_http::Error> {
        let mentions = no_mentions();
        let mut request = self
            .http
            .execute_webhook(webhook.id, &webhook.token)
            .username(username)
            .embeds(embeds)
            .attachments(files)
            .allowed_mentions(Some(&mentions));
        if !message.content.is_empty() {
            request = request.content(&message.content);
        }
        if let Some(avatar) = &message.avatar_url {
            request = request.avatar_url(avatar);
        }
        request.wait().await
    }
}

#[async_trait]
impl WebhookSender for DiscordAdapter {
    /// Post as a Concord member persona; returns the created message id.
    async fn send(&self, link: &ChannelLink, message: WebhookMessage) -> anyhow::Result<String> {
        let channel_id = &link.discord_channel_id;
        let webhook = self.webhook_for(channel_id).await?;
        let embeds: Vec<Embed> = message.embeds.iter().map(|d| description_embed(d)).collect();
        let files: Vec<Attachment> = message
            .files
            .iter()
            .enumerate()
            .map(|(i, f)| Attachment::from_bytes(f.name.clone(), f.data.clone(), i as u64))
            .collect();
        let username = webhook_username(&message.username);
        let response = match self.execute(&webhook, &username, &message, &embeds, &files).await {
            Ok(response) => response,
            // Discord's username filter normalizes lookalike characters, so it
            // can reject names our sanitizer passed. Never drop the message
            // over a display name: retry once under a neutral one.
            Err(error) if is_username_rejection(&error) => {
                tracing::warn!(username = %message.username, "discord rejected webhook username; retrying as {FALLBACK_USERNAME:?}");
                self.execute(&webhook, FALLBACK_USERNAME, &message, &embeds, &files).await.map_err(|e| {
                    self.forget_dead_webhook(channel_id, &e);
                    api_error(e, "discord webhook send")
                })?
            }
            Err(error) => {
                self.forget_dead_webhook(channel_id, &error);
                return Err(api_error(error, "discord webhook send"));
            }
        };
        Ok(response.model().await?.id.to_string())
    }

    /// Remove a bridged message. Webhook delete covers our own mirrors;
    /// user-authored posts (moderator delete from the Armada side) need the
    /// bot's Manage Messages permission.
    async fn delete(&self, link: &ChannelLink, discord_message_id: &str) -> anyhow::Result<()> {
        let channel_id: Id<ChannelMarker> = link.discord_channel_id.parse()?;
        let message_id: Id<MessageMarker> = discord_message_id.parse()?;
        let webhook = self.webhook_for(&link.discord_channel_id).await?;
        if self.http.delete_webhook_message(webhook.id, &webhook.token, message_id).await.is_ok() {
            return Ok(());
        }
        self.http.delete_message(channel_id, message_id).await.map_err(|e| api_error(e, "discord delete"))?;
        Ok(())
    }

    /// Edit a webhook-authored mirror in place.
    async fn edit(&self, link: &ChannelLink, discord_message_id: &str, content: &str) -> anyhow::Result<()> {
        let webhook = self.webhook_for(&link.discord_channel_id).await?;
        let mentions = no_mentions();
        self.http
            .update_webhook_message(webhook.id, &webhook.token, discord_message_id.parse()?)
            .content(Some(content))
            .allowed_mentions(Some(&mentions))
            .await
            .map_err(|e| {
                self.forget_dead_webhook(&link.discord_channel_id, &e);
                api_error(e, "discord edit")
            })?;
        Ok(())
    }

    /// React as the bot account (webhooks cannot react). Unicode emoji go
    /// as-is; a custom one arrives as `name:id`.
    async fn react(&self, link: &ChannelLink, discord_message_id: &str, emoji: &str) -> anyhow::Result<()> {
        let custom = custom_emoji(emoji);
        let reaction = match &custom {
            Some((name, id)) => RequestReactionType::Custom { id: id.parse()?, name: Some(name) },
            None => RequestReactionType::Unicode { name: emoji },
        };
        self.http
            .create_reaction(link.discord_channel_id.parse()?, discord_message_id.parse()?, &reaction)
            .await
            .map_err(|e| api_error(e, "discord react"))?;
        Ok(())
    }

    /// Remove the bot's own reaction (custom emoji resolve by id).
    async fn unreact(&self, link: &ChannelLink, discord_message_id: &str, emoji: &str) -> anyhow::Result<()> {
        let custom = custom_emoji(emoji);
        let reaction = match &custom {
            Some((name, id)) => RequestReactionType::Custom { id: id.parse()?, name: Some(name) },
            None => RequestReactionType::Unicode { name: emoji },
        };
        self.http
            .delete_current_user_reaction(link.discord_channel_id.parse()?, discord_message_id.parse()?, &reaction)
            .await
            .map_err(|e| api_error(e, "discord unreact"))?;
        Ok(())
    }

    /// Show the bot's typing indicator (lasts ~10 s or until a send).
    async fn send_typing(&self, link: &ChannelLink) -> anyhow::Result<()> {
        self.http
            .create_typing_trigger(link.discord_channel_id.parse()?)
            .await
            .map_err(|e| api_error(e, "discord typing"))?;
        Ok(())
    }
}

/// `name:id` for a custom emoji, split; `None` means unicode.
///
/// The name half is bounded even though only the id resolves the emoji: this
/// value is read back out of the mapping row, and rows written before the
/// sender validated emoji names can hold anything. `.+` against a 60KB string
/// was a quadratic backtrack in the TS bridge for a capture it did not use;
/// Rust's regex does not backtrack, but the bound still keeps such a name out
/// of the API path the reaction is addressed by.
fn custom_emoji(emoji: &str) -> Option<(&str, &str)> {
    static CUSTOM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([A-Za-z0-9_]{2,32}):(\d{1,25})$").unwrap());
    let caps = CUSTOM.captures(emoji)?;
    Some((caps.get(1)?.as_str(), caps.get(2)?.as_str()))
}

/// A bridged reply/quote: description only.
fn description_embed(description: &str) -> Embed {
    Embed {
        author: None,
        color: None,
        description: Some(description.to_owned()),
        fields: Vec::new(),
        footer: None,
        image: None,
        kind: "rich".to_owned(),
        provider: None,
        thumbnail: None,
        timestamp: None,
        title: None,
        url: None,
        video: None,
    }
}

/// [`sanitize_username`], then made acceptable to twilight's own pre-flight
/// check, which counts CHARACTERS where the sanitizer counts UTF-16 units: a
/// lone astral character (one emoji) passes the sanitizer as two units and
/// fails twilight locally as one char — before Discord is asked, so the
/// fallback retry would never see a Discord rejection to react to.
fn webhook_username(name: &str) -> String {
    let mut name = sanitize_username(name);
    while name.chars().count() < 2 {
        name.push('_');
    }
    name
}

/// The Discord API error code a failed request carried, if it got that far.
fn api_code(error: &twilight_http::Error) -> Option<u64> {
    match error.kind() {
        ErrorType::Response { error: ApiError::General(general), .. } => Some(general.code),
        _ => None,
    }
}

/// Error code 50035 with a USERNAME_INVALID flavored field error.
fn is_username_rejection(error: &twilight_http::Error) -> bool {
    match error.kind() {
        ErrorType::Response { error: ApiError::General(general), body, .. } => username_rejected(general.code, body),
        _ => false,
    }
}

fn username_rejected(code: u64, body: &[u8]) -> bool {
    code == INVALID_FORM_BODY && String::from_utf8_lossy(body).contains("USERNAME_INVALID")
}

/// Discord's "Missing Permissions" (50013) as the router's
/// [`MissingPermissions`], so the manager can tell the owner instead of
/// silently retrying a send that will never land.
fn permission_error(code: Option<u64>, what: &str, detail: &dyn Display) -> Option<anyhow::Error> {
    (code == Some(MISSING_PERMISSIONS)).then(|| anyhow::Error::new(MissingPermissions(format!("{what}: {detail}"))))
}

fn api_error(error: twilight_http::Error, what: &str) -> anyhow::Error {
    match permission_error(api_code(&error), what, &error) {
        Some(missing) => missing,
        None => anyhow::Error::new(error).context(what.to_owned()),
    }
}

/// One shard's event loop. Reports READY (or the failure that precluded it)
/// once on `ready`, then keeps dispatching until stopped or fatally closed.
async fn run_shard(
    mut shard: Shard,
    adapter: Arc<DiscordAdapter>,
    ready: mpsc::Sender<anyhow::Result<()>>,
    mut stop: watch::Receiver<bool>,
) {
    let shard_id = shard.id();
    let mut ready = Some(ready);
    let report = |ready: &mut Option<mpsc::Sender<anyhow::Result<()>>>, outcome: anyhow::Result<()>| {
        if let Some(tx) = ready.take() {
            _ = tx.try_send(outcome);
            true
        } else {
            false
        }
    };
    loop {
        let item = tokio::select! {
            _ = stop.changed() => {
                // Let the queued close frame reach Discord so the bot goes
                // offline now, not when its presence times out.
                _ = tokio::time::timeout(CLOSE_FLUSH, async {
                    while let Some(item) = shard.next_event(wanted_events()).await {
                        if matches!(item, Ok(Event::GatewayClose(_))) {
                            break;
                        }
                    }
                })
                .await;
                break;
            }
            item = shard.next_event(wanted_events()) => item,
        };
        let Some(item) = item else {
            report(&mut ready, Err(anyhow!("discord gateway: shard {shard_id} ended before READY")));
            break;
        };
        let event = match item {
            Ok(event) => event,
            // Failing to reach the gateway at all before READY is the caller's
            // to retry with backoff; afterwards twilight keeps reconnecting.
            Err(error) if matches!(error.kind(), ReceiveMessageErrorType::Reconnect) => {
                let message = format!("discord gateway: shard {shard_id} could not connect: {error}");
                if !report(&mut ready, Err(anyhow!(message))) {
                    tracing::warn!(shard = %shard_id, error = %format!("{error:#}"), "discord gateway reconnect failed; retrying");
                }
                continue;
            }
            Err(error) => {
                tracing::warn!(shard = %shard_id, error = %format!("{error:#}"), "discord gateway event dropped");
                continue;
            }
        };
        match event {
            Event::Ready(r) => {
                adapter.directory().expect(r.guilds.iter().map(|g| g.id.get()));
                *adapter.application_id.write().unwrap_or_else(|e| e.into_inner()) = r.application.id.to_string();
                *adapter.bot.write().unwrap_or_else(|e| e.into_inner()) =
                    Some(BotUser { id: r.user.id, avatar: r.user.avatar, discriminator: r.user.discriminator });
                report(&mut ready, Ok(()));
            }
            Event::GatewayClose(frame) if shard.state() == ShardState::FatallyClosed => {
                // Invalid token, disallowed intents, invalid shard: twilight
                // will not reconnect, and nothing short of a fix will help.
                let (code, reason) = frame.map(|f| (f.code, f.reason.into_owned())).unwrap_or_default();
                let error = anyhow!("discord gateway: shard {shard_id} closed fatally ({code} {reason})");
                if !report(&mut ready, Err(error)) {
                    tracing::error!(shard = %shard_id, code, %reason, "discord gateway closed fatally; no longer receiving events");
                }
                break;
            }
            Event::GatewayClose(frame) => {
                if adapter.stopped.load(Ordering::SeqCst) {
                    break;
                }
                tracing::info!(shard = %shard_id, ?frame, "discord gateway closed; reconnecting");
            }
            event => dispatch(&adapter, event),
        }
    }
}

/// Hand an event to the host. Every handler runs as its own task so one slow
/// handler cannot stall the shard's heartbeat and event loop.
/// A text channel as the directory keeps it, or `None` for anything else.
fn text_channel(channel: &Channel) -> Option<(u64, String, Option<u64>)> {
    (channel.kind == ChannelType::GuildText)
        .then(|| (channel.id.get(), channel.name.clone().unwrap_or_default(), channel.last_message_id.map(|m| m.get())))
}

fn channel_changed(d: &mut Directory, c: &Channel) {
    match (text_channel(c), c.guild_id) {
        (Some((id, name, last)), Some(guild)) => d.channel_upserted(guild.get(), id, name, last),
        _ => d.channel_removed(c.id.get()),
    }
}

fn update_directory(adapter: &DiscordAdapter, event: &Event) {
    let mut d = adapter.directory();
    match event {
        Event::GuildCreate(created) => match created.as_ref() {
            GuildCreate::Available(guild) => d.guild_created(guild.id.get(), guild.name.clone(), guild.channels.iter().filter_map(text_channel)),
            GuildCreate::Unavailable(guild) => d.guild_unavailable(guild.id.get()),
        },
        Event::GuildUpdate(updated) => d.guild_renamed(updated.id.get(), updated.name.clone()),
        // An outage (unavailable) keeps what we knew; leaving or deletion does not.
        Event::GuildDelete(deleted) if deleted.unavailable != Some(true) => d.guild_removed(deleted.id.get()),
        Event::ChannelCreate(c) => channel_changed(&mut d, &c.0),
        Event::ChannelUpdate(c) => channel_changed(&mut d, &c.0),
        Event::ChannelDelete(c) => d.channel_removed(c.id.get()),
        // Every message raises its channel's newest id, bridged yet or not:
        // that is what makes skipping a catch-up on it safe.
        Event::MessageCreate(created) => d.message_created(created.channel_id.get(), created.id.get()),
        _ => {}
    }
}

fn dispatch(adapter: &Arc<DiscordAdapter>, event: Event) {
    update_directory(adapter, &event);
    let events = adapter.events.clone();
    match event {
        Event::GuildCreate(created) => {
            if let GuildCreate::Available(guild) = *created {
                let guild_id = guild.id.to_string();
                tokio::spawn(async move { events.on_guild_available(guild_id).await });
            }
        }
        Event::GuildDelete(deleted) if deleted.unavailable != Some(true) => {
            let guild_id = deleted.id.to_string();
            tokio::spawn(async move { events.on_guild_removed(guild_id).await });
        }
        Event::MessageCreate(created) => {
            let message = created.0;
            // Guild-scoped bot commands the host intercepts BEFORE any router
            // (/help, /bridge); returning true consumes the message.
            if events.on_bot_command(&command_message(&message)) {
                return;
            }
            let inbound = to_inbound(&message);
            tokio::spawn(async move { events.on_message(inbound).await });
        }
        Event::MessageUpdate(updated) => {
            // A full message since API v10; twilight 0.17 models it as one.
            let inbound = to_inbound(&updated.0);
            tokio::spawn(async move { events.on_message_update(inbound).await });
        }
        Event::MessageDelete(deleted) => {
            let del = DiscordMessageDelete {
                id: deleted.id.to_string(),
                channel_id: deleted.channel_id.to_string(),
                guild_id: deleted.guild_id.map(|g| g.to_string()).unwrap_or_default(),
            };
            tokio::spawn(async move { events.on_message_delete(del).await });
        }
        Event::ReactionAdd(added) => {
            let adapter = adapter.clone();
            tokio::spawn(async move {
                match adapter.reaction(&added.0).await {
                    Ok(Some(reaction)) => events.on_reaction_add(reaction).await,
                    Ok(None) => {}
                    Err(error) => tracing::error!(error = %format!("{error:#}"), "discord reaction add failed"),
                }
            });
        }
        Event::ReactionRemove(removed) => {
            let adapter = adapter.clone();
            tokio::spawn(async move {
                match adapter.reaction(&removed.0).await {
                    Ok(Some(reaction)) => events.on_reaction_remove(reaction).await,
                    Ok(None) => {}
                    Err(error) => tracing::error!(error = %format!("{error:#}"), "discord reaction remove failed"),
                }
            });
        }
        Event::TypingStart(typing) => {
            let typing = TypingEvent {
                channel_id: typing.channel_id.to_string(),
                guild_id: typing.guild_id.map(|g| g.to_string()).unwrap_or_default(),
                user_id: typing.user_id.to_string(),
                bot: typing.member.as_ref().is_some_and(|m| m.user.bot),
            };
            tokio::spawn(async move { events.on_typing(typing).await });
        }
        _ => {}
    }
}

impl DiscordAdapter {
    /// A gateway reaction as the router sees it, or `None` for our own bot's.
    /// Reaction add carries the member; reaction remove carries only the user
    /// id, so the user is fetched.
    async fn reaction(&self, r: &GatewayReaction) -> anyhow::Result<Option<DiscordReaction>> {
        if self.bot_id() == Some(r.user_id) {
            return Ok(None);
        }
        let user = match &r.member {
            Some(member) => user_ref(&member.user, member.nick.as_deref()),
            None => {
                let user = self
                    .http
                    .user(r.user_id)
                    .await
                    .map_err(|e| api_error(e, "discord user fetch"))?
                    .model()
                    .await?;
                user_ref(&user, None)
            }
        };
        Ok(Some(to_reaction(r, user)))
    }
}

fn command_message(m: &Message) -> CommandMessage {
    CommandMessage {
        id: m.id.to_string(),
        channel_id: m.channel_id.to_string(),
        guild_id: m.guild_id.map(|g| g.to_string()).unwrap_or_default(),
        content: m.content.clone(),
        author_bot: m.author.bot,
        webhook_id: m.webhook_id.map(|w| w.to_string()),
    }
}

/// Server nickname, else global display name, else username.
///
/// Reactions use the nickname too (the TS adapter used only the global name
/// there): the router republishes the puppet's kind 0 whenever the display
/// changes, so two different names for one person on messages and reactions
/// would flip the profile back and forth.
fn user_ref(user: &User, nick: Option<&str>) -> DiscordUserRef {
    DiscordUserRef {
        id: user.id.to_string(),
        display: nick.or(user.global_name.as_deref()).unwrap_or(&user.name).to_owned(),
        avatar_url: Some(avatar_url(user.id, user.avatar.as_ref(), user.discriminator)),
        bot: user.bot,
    }
}

/// The user's avatar, or Discord's default embed avatar when they have none
/// (what discord.js `displayAvatarURL` returned, so a puppet always has one).
fn avatar_url(id: Id<UserMarker>, avatar: Option<&ImageHash>, discriminator: u16) -> String {
    match avatar {
        Some(hash) => format!("https://cdn.discordapp.com/avatars/{id}/{hash}.png"),
        None => {
            // Migrated usernames (discriminator 0) index by id; legacy
            // `name#1234` accounts by discriminator.
            let index = if discriminator == 0 { (id.get() >> 22) % 6 } else { u64::from(discriminator) % 5 };
            format!("https://cdn.discordapp.com/embed/avatars/{index}.png")
        }
    }
}

fn mention_ref(mention: &Mention) -> DiscordMentionIn {
    let nick = mention.member.as_ref().and_then(|m| m.nick.as_deref());
    // twilight's Mention drops the payload's global_name, so the fallback is
    // the username where discord.js would have shown the display name.
    DiscordMentionIn { id: mention.id.to_string(), display: nick.unwrap_or(&mention.name).to_owned() }
}

fn embed_in(embed: &Embed) -> EmbedIn {
    static GIF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\.gif(\?|$)").unwrap());
    let urls: Vec<&str> = [
        embed.video.as_ref().and_then(|v| v.url.as_deref()),
        embed.image.as_ref().map(|i| i.url.as_str()),
        embed.thumbnail.as_ref().map(|t| t.url.as_str()),
    ]
    .into_iter()
    .flatten()
    .filter(|u| !u.is_empty())
    .collect();
    // Prefer an actual .gif so Armada inlines motion; mp4 renders as video
    // or falls back to a direct-media link either way.
    let media_url = urls.iter().find(|u| GIF.is_match(u)).or(urls.first()).map(|u| (*u).to_owned());
    EmbedIn { url: embed.url.clone(), media_url }
}

pub fn to_inbound(m: &Message) -> DiscordInboundMessage {
    let nick = m.member.as_ref().and_then(|p| p.nick.as_deref());
    DiscordInboundMessage {
        id: m.id.to_string(),
        channel_id: m.channel_id.to_string(),
        guild_id: m.guild_id.map(|g| g.to_string()).unwrap_or_default(),
        author: user_ref(&m.author, nick),
        content: m.content.clone(),
        attachments: m
            .attachments
            .iter()
            .map(|a| DiscordAttachmentIn { url: a.url.clone(), filename: Some(a.filename.clone()) })
            .collect(),
        mentions: m.mentions.iter().map(mention_ref).collect(),
        channel_names: HashMap::new(),
        embeds: m.embeds.iter().map(embed_in).collect(),
        webhook_id: m.webhook_id.map(|w| w.to_string()),
        application_id: m.application_id.map(|a| a.to_string()),
        referenced_message_id: m.reference.as_ref().and_then(|r| r.message_id).map(|id| id.to_string()),
        timestamp_ms: None,
    }
}

fn to_reaction(r: &GatewayReaction, user: DiscordUserRef) -> DiscordReaction {
    let emoji = match &r.emoji {
        EmojiReactionType::Custom { animated, id, name } => {
            DiscordEmoji { name: name.clone(), id: Some(id.to_string()), animated: *animated }
        }
        EmojiReactionType::Unicode { name } => DiscordEmoji { name: Some(name.clone()), id: None, animated: false },
    };
    DiscordReaction {
        message_id: r.message_id.to_string(),
        channel_id: r.channel_id.to_string(),
        guild_id: r.guild_id.map(|g| g.to_string()).unwrap_or_default(),
        emoji,
        user,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn user(id: &str, name: &str, global: Option<&str>, avatar: Option<&str>) -> Value {
        json!({ "id": id, "username": name, "global_name": global, "avatar": avatar, "discriminator": "0" })
    }

    fn message(extra: Value) -> Message {
        let mut base = json!({
            "id": "1100000000000000001",
            "channel_id": "1200000000000000002",
            "guild_id": "1300000000000000003",
            "author": user("80351110224678912", "nelly", Some("Nelly"), Some("8342729096ea3675442027381ff50dfe")),
            "content": "hello",
            "timestamp": "2026-10-15T12:00:00.000000+00:00",
            "edited_timestamp": null,
            "tts": false,
            "mention_everyone": false,
            "mention_roles": [],
            "mentions": [],
            "attachments": [],
            "embeds": [],
            "pinned": false,
            "type": 0,
        });
        for (k, v) in extra.as_object().unwrap() {
            base[k] = v.clone();
        }
        serde_json::from_value(base).unwrap()
    }

    fn member(nick: Option<&str>) -> Value {
        json!({ "nick": nick, "roles": [], "joined_at": "2026-01-01T00:00:00.000000+00:00", "deaf": false, "mute": false, "flags": 0 })
    }

    #[test]
    fn display_prefers_nick_then_global_then_username() {
        let m = message(json!({ "member": member(Some("Nell (mod)")) }));
        assert_eq!(to_inbound(&m).author.display, "Nell (mod)");
        let m = message(json!({ "member": member(None) }));
        assert_eq!(to_inbound(&m).author.display, "Nelly");
        let m = message(json!({ "author": user("80351110224678912", "nelly", None, None) }));
        assert_eq!(to_inbound(&m).author.display, "nelly");
    }

    #[test]
    fn inbound_carries_ids_avatar_and_reference() {
        let m = message(json!({
            "webhook_id": "1400000000000000004",
            "application_id": "1500000000000000005",
            "message_reference": { "message_id": "1000000000000000009", "channel_id": "1200000000000000002" },
            "attachments": [{ "id": "1", "filename": "cat.png", "size": 3, "url": "https://cdn/cat.png", "proxy_url": "https://media/cat.png" }],
        }));
        let inbound = to_inbound(&m);
        assert_eq!(inbound.id, "1100000000000000001");
        assert_eq!(inbound.guild_id, "1300000000000000003");
        assert_eq!(inbound.webhook_id.as_deref(), Some("1400000000000000004"));
        assert_eq!(inbound.application_id.as_deref(), Some("1500000000000000005"));
        assert_eq!(inbound.referenced_message_id.as_deref(), Some("1000000000000000009"));
        assert_eq!(inbound.attachments, vec![DiscordAttachmentIn { url: "https://cdn/cat.png".into(), filename: Some("cat.png".into()) }]);
        assert_eq!(
            inbound.author.avatar_url.as_deref(),
            Some("https://cdn.discordapp.com/avatars/80351110224678912/8342729096ea3675442027381ff50dfe.png")
        );
        assert_eq!(inbound.timestamp_ms, None);
        let cmd = command_message(&m);
        assert_eq!(cmd.webhook_id.as_deref(), Some("1400000000000000004"));
        assert!(!cmd.author_bot);
    }

    #[test]
    fn default_avatar_indexes_by_id_or_discriminator() {
        let id = Id::new(80351110224678912);
        let expected = (80351110224678912u64 >> 22) % 6;
        assert_eq!(avatar_url(id, None, 0), format!("https://cdn.discordapp.com/embed/avatars/{expected}.png"));
        assert_eq!(avatar_url(id, None, 1337), "https://cdn.discordapp.com/embed/avatars/2.png");
        let m = message(json!({ "author": user("80351110224678912", "nelly", None, None) }));
        assert_eq!(to_inbound(&m).author.avatar_url, Some(avatar_url(id, None, 0)));
    }

    #[test]
    fn embed_media_prefers_gif_then_first_present() {
        let m = message(json!({ "embeds": [
            {
                "type": "gifv",
                "url": "https://tenor.com/view/cat-123",
                "video": { "url": "https://media.tenor.com/x.mp4" },
                "thumbnail": { "url": "https://media.tenor.com/x.GIF?ex=1" },
            },
            { "type": "image", "image": { "url": "https://i.example/a.png" }, "thumbnail": { "url": "https://i.example/b.png" } },
            { "type": "link", "url": "https://example.com" },
        ] }));
        let embeds = to_inbound(&m).embeds;
        assert_eq!(embeds[0].media_url.as_deref(), Some("https://media.tenor.com/x.GIF?ex=1"));
        assert_eq!(embeds[0].url.as_deref(), Some("https://tenor.com/view/cat-123"));
        assert_eq!(embeds[1].media_url.as_deref(), Some("https://i.example/a.png"));
        assert_eq!(embeds[2], EmbedIn { url: Some("https://example.com".into()), media_url: None });
    }

    #[test]
    fn mentions_use_member_nick_when_present() {
        let m = message(json!({ "mentions": [
            { "id": "1", "username": "alice", "discriminator": "0", "avatar": null, "public_flags": 0, "member": member(Some("Ally")) },
            { "id": "2", "username": "bob", "discriminator": "0", "avatar": null, "public_flags": 0 },
        ] }));
        let mentions = to_inbound(&m).mentions;
        assert_eq!(mentions[0], DiscordMentionIn { id: "1".into(), display: "Ally".into() });
        assert_eq!(mentions[1], DiscordMentionIn { id: "2".into(), display: "bob".into() });
    }

    #[test]
    fn reaction_converts_custom_and_unicode_emoji() {
        let mut member_json = member(Some("Nell"));
        member_json["user"] = user("7", "nelly", Some("Nelly"), None);
        let r: GatewayReaction = serde_json::from_value(json!({
            "burst": false,
            "channel_id": "2",
            "guild_id": "3",
            "message_id": "4",
            "user_id": "7",
            "member": member_json,
            "emoji": { "id": "99", "name": "party", "animated": true },
        }))
        .unwrap();
        let member = r.member.as_ref().unwrap();
        let reaction = to_reaction(&r, user_ref(&member.user, member.nick.as_deref()));
        assert_eq!(reaction.message_id, "4");
        assert_eq!(reaction.guild_id, "3");
        assert_eq!(reaction.emoji, DiscordEmoji { name: Some("party".into()), id: Some("99".into()), animated: true });
        assert_eq!(reaction.user.display, "Nell");

        let r: GatewayReaction = serde_json::from_value(json!({
            "burst": false, "channel_id": "2", "message_id": "4", "user_id": "7", "emoji": { "id": null, "name": "👍" },
        }))
        .unwrap();
        let reaction = to_reaction(&r, DiscordUserRef::default());
        assert_eq!(reaction.emoji, DiscordEmoji { name: Some("👍".into()), id: None, animated: false });
        assert_eq!(reaction.guild_id, "");
    }

    #[test]
    fn custom_emoji_parse_is_bounded_and_ascii() {
        assert_eq!(custom_emoji("party_parrot:123456789012345678"), Some(("party_parrot", "123456789012345678")));
        assert_eq!(custom_emoji("👍"), None);
        assert_eq!(custom_emoji("a:1"), None, "one-char name");
        assert_eq!(custom_emoji("ñame:1"), None, "non-ASCII \\w");
        assert_eq!(custom_emoji(&format!("{}:1", "x".repeat(33))), None);
        assert_eq!(custom_emoji(&format!("ok:{}", "1".repeat(26))), None);
    }

    #[test]
    fn username_rejection_needs_both_code_and_field_error() {
        let body = br#"{"code":50035,"errors":{"username":{"_errors":[{"code":"USERNAME_INVALID","message":"bad"}]}},"message":"Invalid Form Body"}"#;
        assert!(username_rejected(50035, body));
        assert!(!username_rejected(50035, br#"{"code":50035,"errors":{"content":{}}}"#));
        assert!(!username_rejected(50013, body));
    }

    #[test]
    fn webhook_username_survives_twilight_char_count() {
        assert_eq!(webhook_username("😀").chars().count(), 2);
        assert_eq!(webhook_username("Discord fan"), "disc-rd fan");
    }

    #[test]
    fn missing_permissions_surfaces_as_router_error() {
        let error = permission_error(Some(50013), "discord webhook send", &"Missing Permissions").unwrap();
        assert!(crate::router::is_missing_permissions(&error));
        assert!(permission_error(Some(50001), "x", &"Missing Access").is_none());
        assert!(permission_error(None, "x", &"timeout").is_none());
    }
}
