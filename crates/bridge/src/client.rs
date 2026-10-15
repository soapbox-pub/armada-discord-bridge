//! Headless Concord client: everything the bridge needs to be a community
//! member. Join from an invite, fold the Control Plane, and publish chat rumors
//! signed by any local identity (primary or puppet).
//!
//! Loop prevention layer 1 lives here: every rumor the bridge publishes carries
//! a `proxy` tag naming its Discord origin, and the router refuses to bridge any
//! incoming rumor that has one.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, bail};
use concord::chat::Binding;
use concord::community::{ChannelView, Membership};
use concord::control::{FoldedControl, fold_control};
use concord::edition::{Edition, parse_edition};
use concord::invite::{InviteBundle, parse_bundle_event, parse_invite_link};
use concord::kinds::{self, Plane};
use concord::roles::perm;
use concord::rumor::Rumor;
use concord::stream::{StreamKey, WrapOptions, check_channel_binding, open_plane_wrap, seal_and_wrap};
use nostr::prelude::*;
use serde_json::{Value, json};
use tokio::task::JoinHandle;

use crate::relays::RelayLike;

/// NIP-48 tag stamped on every bridge-published rumor:
/// `["proxy", <discord permalink>, "web"]`. The full URL keeps the origin
/// clickable in any client that surfaces proxy tags.
pub const TAG_PROXY: &str = "proxy";

/// How long `subscribe_control` gathers arriving control wraps before re-folding.
pub const CONTROL_REFOLD: Duration = Duration::from_millis(250);

/// Rumor ids remembered per channel subscription for deduplication.
const SEEN_RUMORS_MAX: usize = 65_536;

pub fn proxy_tag(guild_id: &str, channel_id: &str, message_id: &str) -> Vec<String> {
    vec![TAG_PROXY.into(), format!("https://discord.com/channels/{guild_id}/{channel_id}/{message_id}"), "web".into()]
}

/// True when a rumor was published by any bridge (ours or a peer's).
pub fn has_proxy_tag(tags: &[Vec<String>]) -> bool {
    tags.iter().any(|t| t.first().is_some_and(|n| n == TAG_PROXY))
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// A chat rumor opened and binding-checked against the channel that read it.
#[derive(Clone, Debug)]
pub struct OpenedChat {
    pub rumor: Rumor,
    /// The ordering time in ms.
    pub ms: u64,
    pub channel_id_hex: String,
    pub epoch: u64,
}

impl OpenedChat {
    pub fn rumor_id(&self) -> &str {
        &self.rumor.id
    }
    pub fn author(&self) -> &str {
        &self.rumor.pubkey
    }
    pub fn kind(&self) -> u16 {
        self.rumor.kind
    }
    pub fn content(&self) -> &str {
        &self.rumor.content
    }
    pub fn tags(&self) -> &[Vec<String>] {
        &self.rumor.tags
    }
}

/// Open one chat wrap for `channel`, or `None` if it is not readable there.
///
/// A retired epoch is sealed history, not a live channel: anything sealed under
/// its key but dated after the superseding rotation is refused, so key
/// possession alone cannot keep an ejected member writing into an epoch the
/// community rotated away from.
pub fn open_chat(wrap: &Event, channel: &ChannelView) -> Option<OpenedChat> {
    let stream = channel.streams.iter().find(|s| s.key.pubkey() == wrap.pubkey)?;
    let key: StreamKey = (&stream.key).into();
    // Plane::Chat also refuses a plaintext seal: that would make the message a
    // standalone signed artifact any relay could display (CORD-02 §5).
    let opened = open_plane_wrap(wrap, &key, Plane::Chat).ok()?;
    check_channel_binding(&opened.rumor, &channel.id_hex, stream.epoch).ok()?;
    if stream.retired_at.is_some_and(|cutoff| opened.rumor.created_at > cutoff) {
        return None;
    }
    Some(OpenedChat { ms: opened.ms, rumor: opened.rumor, channel_id_hex: channel.id_hex.clone(), epoch: stream.epoch })
}

/// What resolving an invite yields.
pub struct JoinResult {
    pub membership: Membership,
    pub bundle: InviteBundle,
}

/// Resolve an Armada invite URL into join material: fetch the kind-33301 bundle,
/// decrypt it with the fragment token, and validate the self-certifying id.
///
/// Raced across relays rather than merged: one bundle is all this needs, every
/// relay serving it serves the same self-certifying bytes, and validation
/// refuses a forgery — so the first relay to answer is as good as all of them.
/// Merging made every boot wait out the slowest relay for each of ~200 bridges,
/// and made one unresponsive relay look exactly like a deleted bundle.
pub async fn resolve_invite(invite_url: &str, relays: &dyn RelayLike) -> anyhow::Result<JoinResult> {
    let link = parse_invite_link(invite_url).context("not a valid Armada invite URL")?;
    let signer = PublicKey::from_hex(&link.link_signer)?;
    let filter = Filter::new().kind(Kind::Custom(kinds::INVITE_BUNDLE)).author(signer).limit(8);
    let events = relays.query_race(vec![filter]).await;
    let newest = events.iter().max_by_key(|e| e.created_at).context("invite bundle not found on bootstrap relays")?;
    let bundle = parse_bundle_event(newest, &link, now_ms())?;
    let membership = Membership::from_bundle(&bundle, now_ms());
    Ok(JoinResult { membership, bundle })
}

/// Aborts its task when dropped, taking the task's subscription with it.
pub struct TaskGuard(JoinHandle<()>);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub type ChatHandler = Arc<dyn Fn(OpenedChat) + Send + Sync>;
pub type CursorHandler = Arc<dyn Fn(String, u64) + Send + Sync>;
pub type FoldHandler = Arc<dyn Fn(Arc<FoldedControl>) + Send + Sync>;

/// One entry of the kind-10304 command manifest (Armada's draft bot NIP).
pub struct BotCommand {
    pub name: &'static str,
    pub description: &'static str,
    pub args: Vec<BotCommandArg>,
}

pub struct BotCommandArg {
    pub name: &'static str,
    pub kind: &'static str,
    pub description: &'static str,
    pub required: bool,
    pub choices: Option<Vec<&'static str>>,
}

pub struct ConcordClient {
    community: Membership,
    relays: Arc<dyn RelayLike>,
    primary: Keys,
    folded: RwLock<Option<Arc<FoldedControl>>>,
}

impl ConcordClient {
    pub fn new(community: Membership, relays: Arc<dyn RelayLike>, primary: Keys) -> Arc<ConcordClient> {
        // NIP-42-gated relays require AUTH as every queried stream author.
        let mut keys = stream_keys(&community.control_streams());
        keys.extend(stream_keys(&community.guestbook_streams()));
        relays.register_auth_keys(keys);
        Arc::new(ConcordClient { community, relays, primary, folded: RwLock::new(None) })
    }

    pub fn community(&self) -> &Membership {
        &self.community
    }

    pub fn relays(&self) -> &Arc<dyn RelayLike> {
        &self.relays
    }

    /// The bridge's own posting identity; the router skips its messages.
    pub fn primary(&self) -> &Keys {
        &self.primary
    }

    pub fn primary_pk(&self) -> String {
        self.primary.public_key().to_hex()
    }

    pub fn folded(&self) -> Option<Arc<FoldedControl>> {
        self.folded.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Install a fold directly (tests, and folds computed elsewhere).
    pub fn set_folded(&self, folded: FoldedControl) {
        *self.folded.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(folded));
    }

    fn fold(&self, editions: &[Edition]) -> Arc<FoldedControl> {
        let folded = Arc::new(fold_control(editions, &self.community.id(), &self.community.owner, None, None));
        *self.folded.write().unwrap_or_else(|e| e.into_inner()) = Some(folded.clone());
        folded
    }

    fn control_filter(&self) -> Filter {
        let pks = self.community.control_streams().iter().map(|s| s.pk).collect::<Vec<_>>();
        Filter::new().kind(Kind::Custom(kinds::WRAP)).authors(pks)
    }

    /// Open control wraps into editions, skipping anything that is not one.
    fn open_editions(&self, wraps: &[Event]) -> Vec<Edition> {
        let streams = self.community.control_streams();
        wraps
            .iter()
            .filter_map(|w| {
                let stream = streams.iter().find(|s| s.pk == w.pubkey)?;
                parse_edition(open_plane_wrap(w, stream, Plane::Control).ok()?).ok()
            })
            .collect()
    }

    /// Fetch and fold the Control Plane (channels, roles, banlist).
    pub async fn sync_control(&self) -> anyhow::Result<Arc<FoldedControl>> {
        let wraps = self.relays.query(vec![self.control_filter()]).await?;
        Ok(self.fold(&self.open_editions(&wraps)))
    }

    /// Channels readable with held keys, per the current fold.
    pub fn channels(&self) -> Vec<ChannelView> {
        let channels = self.community.channels(self.folded().as_deref());
        let keys = channels.iter().flat_map(|c| c.streams.iter().map(|s| s.key.keys.clone())).collect();
        self.relays.register_auth_keys(keys);
        channels
    }

    pub fn channel(&self, id_hex: &str) -> Option<ChannelView> {
        self.channels().into_iter().find(|c| c.id_hex == id_hex)
    }

    /// Honest clients drop banned authors; the bridge must never publish for them.
    pub fn is_banned(&self, pubkey_hex: &str) -> bool {
        self.folded().is_some_and(|f| f.banned.contains(pubkey_hex))
    }

    pub fn is_authorized(&self, pubkey_hex: &str, bits: u64) -> bool {
        self.folded().is_some_and(|f| f.roster.is_authorized(pubkey_hex, &self.community.owner, bits))
    }

    /// MANAGE_MESSAGES holder (or owner) per the current fold.
    pub fn is_moderator(&self, pubkey_hex: &str) -> bool {
        self.is_authorized(pubkey_hex, perm::MANAGE_MESSAGES)
    }

    async fn publish_signed(&self, author: &Keys, kind: u16, content: String, tags: Vec<Vec<String>>) -> anyhow::Result<Event> {
        let tags = tags.into_iter().map(Tag::parse).collect::<Result<Vec<_>, _>>()?;
        let event = EventBuilder::new(Kind::Custom(kind), content).tags(tags).finalize(author)?;
        self.relays.publish(&event).await?;
        Ok(event)
    }

    /// A kind-0 profile for an identity (puppets: Discord name and avatar). A
    /// plain event: Armada resolves member profiles from the community relays.
    pub async fn publish_profile(&self, author: &Keys, meta: &Value) -> anyhow::Result<()> {
        self.publish_signed(author, 0, meta.to_string(), vec![]).await.map(drop)
    }

    /// The NIP-17 DM relay list (kind 10050): where our giftwrap inbox lives,
    /// and so where a Direct Invite carrying a private-channel key is delivered.
    /// The community relays are the honest answer for a bridge: it is reachable
    /// about one community only, and already holds connections to exactly those.
    pub async fn publish_dm_relays(&self, author: &Keys, relays: &[String]) -> anyhow::Result<()> {
        let tags = relays.iter().map(|url| vec!["relay".to_string(), url.clone()]).collect();
        self.publish_signed(author, kinds::DM_RELAYS, String::new(), tags).await.map(drop)
    }

    /// A Guestbook join (kind 3306) for an identity: the primary by default, or a
    /// puppet so bridged Discord users appear in the member list.
    pub async fn publish_join(&self, ms: u64, author: Option<&Keys>) -> anyhow::Result<Event> {
        let author = author.unwrap_or(&self.primary);
        let rumor = concord::guestbook::join(&author.public_key().to_hex(), ms, None);
        let wrap = seal_and_wrap(&rumor, Plane::Guestbook, &self.community.current_guestbook_stream(), author, WrapOptions::default())?;
        self.relays.publish(&wrap).await?;
        Ok(wrap)
    }

    /// The primary's kind-10304 command manifest. Replaceable, so boot
    /// republish is the update mechanism.
    pub async fn publish_manifest(&self, commands: &[BotCommand]) -> anyhow::Result<()> {
        let commands: Vec<Value> = commands
            .iter()
            .map(|c| {
                let args: Vec<Value> = c
                    .args
                    .iter()
                    .map(|a| {
                        let mut arg = json!({ "name": a.name, "type": a.kind, "description": a.description, "required": a.required });
                        if let Some(choices) = &a.choices {
                            arg["choices"] = json!(choices);
                        }
                        arg
                    })
                    .collect();
                json!({ "name": c.name, "description": c.description, "args": args })
            })
            .collect();
        let content = json!({ "v": 1, "commands": commands }).to_string();
        let primary = self.primary.clone();
        self.publish_signed(&primary, kinds::BOT_MANIFEST, content, vec![]).await.map(drop)
    }

    /// An ephemeral typing signal (kind 23311 in a 21059 wrap). Relays never
    /// store it, so failure is not worth surfacing.
    pub async fn send_typing(&self, channel: &ChannelView, author: &Keys, ms: u64) -> anyhow::Result<()> {
        let b = Binding { channel_id_hex: &channel.id_hex, epoch: channel.current().epoch };
        let rumor = concord::chat::typing(&b, &author.public_key().to_hex(), ms);
        let stream: StreamKey = (&channel.current().key).into();
        let wrap = seal_and_wrap(&rumor, Plane::Chat, &stream, author, WrapOptions { ephemeral: true, expiration: None })?;
        self.relays.publish(&wrap).await
    }

    /// Publish a chat rumor into a channel: binding tags, author-signed seal,
    /// stream-signed wrap, any-accept broadcast. Returns both layers so the
    /// caller can persist the rumor id mapping.
    pub async fn send_chat(&self, channel: &ChannelView, msg: SendChat<'_>) -> anyhow::Result<(Rumor, Event)> {
        let pk = msg.author.public_key().to_hex();
        if self.is_banned(&pk) {
            bail!("author {pk} is banned in this community");
        }
        let mut tags = concord::stream::channel_binding_tags(&channel.id_hex, channel.current().epoch);
        tags.extend(msg.tags);
        let rumor = Rumor::new(msg.kind, msg.content, tags, &pk, Some(msg.ms.unwrap_or_else(now_ms)), None);
        let stream: StreamKey = (&channel.current().key).into();
        let wrap = seal_and_wrap(&rumor, Plane::Chat, &stream, msg.author, WrapOptions::default())?;
        self.relays.publish(&wrap).await?;
        Ok((rumor, wrap))
    }

    /// Live-stream a channel's chat: a standing REQ across every held epoch's
    /// stream address, opened and binding-checked, deduped by rumor id.
    /// `on_cursor` is called per durable wrap that opened; it feeds catch-up.
    pub fn subscribe_channel(&self, channel: &ChannelView, on_chat: ChatHandler, on_cursor: Option<CursorHandler>) -> TaskGuard {
        // Live tail only: without a floor, relays replay stored history into
        // the router on every subscribe. Catch-up after downtime is cursor
        // work. A small overlap absorbs clock skew.
        let since = Timestamp::from_secs((now_ms() / 1000).saturating_sub(60));
        let pks = channel.streams.iter().map(|s| s.key.pubkey()).collect::<Vec<_>>();
        let filter = Filter::new().kinds([Kind::Custom(kinds::WRAP), Kind::Custom(kinds::WRAP_EPHEMERAL)]).authors(pks).since(since);
        let mut sub = self.relays.subscribe(vec![filter]);
        let channel = channel.clone();
        TaskGuard(tokio::spawn(async move {
            let mut seen: HashSet<String> = HashSet::new();
            while let Some(wrap) = sub.recv().await {
                let Some(chat) = open_chat(&wrap, &channel) else { continue };
                if wrap.kind == Kind::Custom(kinds::WRAP)
                    && let Some(cursor) = &on_cursor
                {
                    cursor(wrap.pubkey.to_hex(), wrap.created_at.as_secs());
                }
                if seen.len() >= SEEN_RUMORS_MAX {
                    seen.clear();
                }
                if !seen.insert(chat.rumor.id.clone()) {
                    continue;
                }
                on_chat(chat);
            }
        }))
    }

    /// Bounded catch-up: every durable wrap on the channel's streams newer than
    /// `since_secs`, opened and sorted oldest first so the caller can replay
    /// them in order (the mapping table dedupes already-mirrored rumors).
    /// Returns the chats and the newest wrap timestamp seen, the next cursor.
    pub async fn backfill_channel(&self, channel: &ChannelView, since_secs: u64, limit: usize) -> anyhow::Result<(Vec<OpenedChat>, Option<u64>)> {
        let pks = channel.streams.iter().map(|s| s.key.pubkey()).collect::<Vec<_>>();
        let filter = Filter::new().kind(Kind::Custom(kinds::WRAP)).authors(pks).since(Timestamp::from_secs(since_secs)).limit(limit);
        let wraps = self.relays.query(vec![filter]).await?;
        let mut chats: Vec<OpenedChat> = wraps.iter().filter_map(|w| open_chat(w, channel)).collect();
        chats.sort_by_key(|c| c.ms);
        let newest = wraps.iter().map(|w| w.created_at.as_secs()).max();
        Ok((chats, newest))
    }

    /// Live-fold the Control Plane, so bans and channel changes apply to (nearly)
    /// the very next send.
    ///
    /// Re-folds are batched over [`CONTROL_REFOLD`]: the REQ has no `since`, so
    /// every relay replays the whole plane on subscribe, and folding once per
    /// arriving wrap made that replay quadratic. Each wrap is opened once, on
    /// arrival; a re-fold only replays the editions already opened.
    pub fn subscribe_control(self: &Arc<Self>, on_fold: Option<FoldHandler>) -> TaskGuard {
        let mut sub = self.relays.subscribe(vec![self.control_filter()]);
        let me = Arc::downgrade(self);
        TaskGuard(tokio::spawn(async move {
            let mut editions: HashMap<EventId, Edition> = HashMap::new();
            let mut pending = false;
            loop {
                let next = if pending {
                    match tokio::time::timeout(CONTROL_REFOLD, sub.recv()).await {
                        Ok(next) => next,
                        Err(_) => {
                            pending = false;
                            let Some(me) = me.upgrade() else { return };
                            let all: Vec<Edition> = editions.values().cloned().collect();
                            let folded = me.fold(&all);
                            if let Some(f) = &on_fold {
                                f(folded);
                            }
                            continue;
                        }
                    }
                } else {
                    sub.recv().await
                };
                let Some(wrap) = next else { return };
                if editions.contains_key(&wrap.id) {
                    continue;
                }
                let Some(me) = me.upgrade() else { return };
                if let Some(edition) = me.open_editions(std::slice::from_ref(&wrap)).pop() {
                    editions.insert(wrap.id, edition);
                    pending = true;
                }
            }
        }))
    }
}

/// What `send_chat` publishes.
pub struct SendChat<'a> {
    pub content: String,
    /// The signing identity; a puppet for bridged Discord users.
    pub author: &'a Keys,
    pub kind: u16,
    /// Extra tags (proxy, q/reply, imeta, ...).
    pub tags: Vec<Vec<String>>,
    /// Send time in epoch ms; defaults to now.
    pub ms: Option<u64>,
}

impl<'a> SendChat<'a> {
    pub fn message(author: &'a Keys, content: impl Into<String>) -> Self {
        SendChat { content: content.into(), author, kind: kinds::MESSAGE, tags: vec![], ms: None }
    }
}

fn stream_keys(streams: &[StreamKey]) -> Vec<Keys> {
    streams.iter().filter_map(|s| s.sk.clone().map(Keys::new)).collect()
}
