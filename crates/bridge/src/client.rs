//! Headless Concord client: everything the bridge needs to be a community
//! member. Join from an invite, fold the Control Plane, and publish chat rumors
//! signed by any local identity (primary or puppet).
//!
//! Loop prevention layer 1 lives here: every rumor the bridge publishes carries
//! a `proxy` tag naming its Discord origin, and the router refuses to bridge any
//! incoming rumor that has one.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, bail};
use concord::chat::Binding;
use concord::community::{ChannelView, Membership};
use concord::control::{FoldedControl, fold_control};
use concord::edition::{Edition, parse_edition};
use concord::guestbook::{FoldedTimeout, fold_timeouts};
use concord::invite::{InviteBundle, parse_bundle_event, parse_invite_link};
use concord::judge::{Post, Verdict, judge_post};
use concord::kinds::{self, Plane};
use concord::roles::perm;
use concord::rumor::Rumor;
use concord::stream::{
    MAX_EVENT_BYTES, Opened, StreamKey, WrapOptions, check_channel_binding, check_writer_binding, open_plane_wrap, seal_and_wrap, seal_rumor, wrap_seal,
};
use concord::writers::rides_writer_address;
use nostr::prelude::*;
use serde_json::{Value, json};
use tokio::task::JoinHandle;

use crate::recent::RecentIds;
use crate::relays::RelayLike;

/// NIP-48 tag stamped on every bridge-published rumor:
/// `["proxy", <discord permalink>, "web"]`. The full URL keeps the origin
/// clickable in any client that surfaces proxy tags.
pub const TAG_PROXY: &str = "proxy";

/// How long `subscribe_control` gathers arriving control wraps before re-folding.
pub const CONTROL_REFOLD: Duration = Duration::from_millis(250);

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
    /// The writer epoch whose address served it, in a restricted Channel.
    pub writer_epoch: Option<u64>,
}

/// Why the bridge declined to post for someone: Armada's readers would hold or
/// collapse the post, so publishing it would only put a message on the relays
/// that nobody sees, while Discord shows it as delivered.
#[derive(Debug, thiserror::Error)]
#[error("{reason}")]
pub struct PostRefused {
    pub reason: &'static str,
    /// Every Discord member's post would be refused here, not one member's.
    pub channel_wide: bool,
}

impl PostRefused {
    fn channel(reason: &'static str) -> PostRefused {
        PostRefused { reason, channel_wide: true }
    }
}

/// Every address a Channel's posts arrive at: its read streams and, in a
/// restricted Channel, its writer addresses.
pub fn channel_addresses(channel: &ChannelView) -> Vec<PublicKey> {
    channel.streams.iter().map(|s| s.key.pubkey()).chain(channel.writers.iter().map(|w| w.pk)).collect()
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
    if let Some(stream) = channel.streams.iter().find(|s| s.key.pubkey() == wrap.pubkey) {
        let key: StreamKey = (&stream.key).into();
        return finish_chat(wrap, &key, channel, stream.epoch, stream.retired_at, None);
    }
    // A writer address signs its wraps with the writer key but encrypts under
    // the Channel's READ key (CORD-03 §1), so it is tried under every one.
    let writer = channel.writers.iter().find(|w| w.pk == wrap.pubkey)?;
    channel.streams.iter().find_map(|stream| {
        let key = StreamKey { pk: writer.pk, conv_key: stream.key.conv_key, sk: None, restricted: false };
        finish_chat(wrap, &key, channel, stream.epoch, stream.retired_at, Some(writer.epoch))
    })
}

fn finish_chat(wrap: &Event, key: &StreamKey, channel: &ChannelView, epoch: u64, retired_at: Option<u64>, writer_epoch: Option<u64>) -> Option<OpenedChat> {
    // Plane::Chat also refuses a plaintext seal: that would make the message a
    // standalone signed artifact any relay could display (CORD-02 §5).
    let opened = open_plane_wrap(wrap, key, Plane::Chat).ok()?;
    check_channel_binding(&opened.rumor, &channel.id_hex, epoch).ok()?;
    check_writer_binding(&opened.rumor, writer_epoch).ok()?;
    if retired_at.is_some_and(|cutoff| opened.rumor.created_at > cutoff) {
        return None;
    }
    Some(OpenedChat { ms: opened.ms, rumor: opened.rumor, channel_id_hex: channel.id_hex.clone(), epoch, writer_epoch })
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

impl TaskGuard {
    pub fn spawn(task: impl std::future::Future<Output = ()> + Send + 'static) -> TaskGuard {
        TaskGuard(tokio::spawn(task))
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub type ChatHandler = Arc<dyn Fn(OpenedChat) + Send + Sync>;
pub type CursorHandler = Arc<dyn Fn(String, u64) + Send + Sync>;
pub type FoldHandler = Arc<dyn Fn(Arc<FoldedControl>) + Send + Sync>;

/// The latest Control Plane fold, shareable between clients of one community.
type FoldCell = Arc<RwLock<Option<Arc<FoldedControl>>>>;

/// The Guestbook's Timeout rumors seen so far, shared like the fold. Kept raw:
/// whether one counts is judged against the Roster as it stands (CORD-04 §8).
type TimeoutCell = Arc<RwLock<HashMap<String, Opened>>>;

/// How long a key watcher lets a rotation's chunks land before reading it.
const KEY_SETTLE: Duration = Duration::from_millis(750);

/// A shared fold and this client's keyed reading of it (see `folded`).
type KeyedCache = std::sync::Mutex<Option<(Arc<FoldedControl>, Arc<FoldedControl>)>>;

/// Timeouts run at most 28 days, so older Guestbook entries can't hold one.
const TIMEOUT_LOOKBACK_SECS: u64 = 28 * 24 * 60 * 60;
/// Bound on Timeout rumors held per community: a flood can't grow it without end.
const MAX_TIMEOUTS_HELD: usize = 10_000;

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
    /// Swapped when a rotation or delivery hands this client a channel key
    /// while it runs (see `follow_channel_keys`).
    community: RwLock<Arc<Membership>>,
    relays: Arc<dyn RelayLike>,
    primary: Keys,
    folded: FoldCell,
    keyed: KeyedCache,
    timeouts: TimeoutCell,
}

impl ConcordClient {
    pub fn new(community: Membership, relays: Arc<dyn RelayLike>, primary: Keys) -> Arc<ConcordClient> {
        // NIP-42-gated relays require AUTH as every queried stream author.
        let mut keys = stream_keys(&community.control_streams());
        keys.extend(stream_keys(&community.guestbook_streams()));
        relays.register_auth_keys(keys);
        Arc::new(ConcordClient {
            community: RwLock::new(Arc::new(community)),
            relays,
            primary,
            folded: FoldCell::default(),
            keyed: KeyedCache::default(),
            timeouts: TimeoutCell::default(),
        })
    }

    /// A client for another member of `with`'s community: its own membership
    /// (so its own private-channel keys) and posting identity, over `with`'s
    /// relays and reading `with`'s fold. The fold depends only on the base the
    /// two must share: a Direct Invite can add channel keys but never move it.
    pub fn sharing_fold(community: Membership, primary: Keys, with: &ConcordClient) -> Arc<ConcordClient> {
        debug_assert_eq!(community.community_id, with.community().community_id);
        Arc::new(ConcordClient {
            community: RwLock::new(Arc::new(community)),
            relays: with.relays.clone(),
            primary,
            folded: with.folded.clone(),
            keyed: KeyedCache::default(),
            timeouts: with.timeouts.clone(),
        })
    }

    pub fn community(&self) -> Arc<Membership> {
        self.community.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Take a membership holding newer channel keys. The base may not move:
    /// the fold this client shares was read from it.
    pub fn set_community(&self, community: Membership) {
        debug_assert_eq!(community.community_id, self.community().community_id);
        *self.community.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(community);
        // The creators a keyed fold opened depend on the keys held.
        *self.keyed.lock().unwrap_or_else(|e| e.into_inner()) = None;
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

    /// The community's fold as THIS client reads it. The shared fold is keyless
    /// (bridges of one community never pool keys), but a sealed Private
    /// Channel's creator is readable only with its key and changes who may view
    /// it (CORD-04 §8), so each client adds the creators its own keys open, as
    /// Armada's fold does. Cached per shared fold: opening seals on every
    /// judged post would be the hot path.
    pub fn folded(&self) -> Option<Arc<FoldedControl>> {
        let base = self.folded.read().unwrap_or_else(|e| e.into_inner()).clone()?;
        if !base.ranked {
            return Some(base);
        }
        let mut cache = self.keyed.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((from, keyed)) = cache.as_ref()
            && Arc::ptr_eq(from, &base)
        {
            return Some(keyed.clone());
        }
        let creators = self.community().open_creators(&base);
        let keyed = if creators.is_empty() {
            base.clone()
        } else {
            let mut f = (*base).clone();
            f.roster.creators = creators;
            Arc::new(f)
        };
        *cache = Some((base, keyed.clone()));
        Some(keyed)
    }

    /// Install a fold directly (tests, and folds computed elsewhere).
    pub fn set_folded(&self, folded: FoldedControl) {
        *self.folded.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(folded));
    }

    fn fold(&self, editions: &[Edition]) -> Arc<FoldedControl> {
        let folded = Arc::new(fold_control(editions, &self.community().id(), &self.community().owner, None, None));
        *self.folded.write().unwrap_or_else(|e| e.into_inner()) = Some(folded.clone());
        folded
    }

    fn control_filter(&self) -> Filter {
        let pks = self.community().control_streams().iter().map(|s| s.pk).collect::<Vec<_>>();
        Filter::new().kind(Kind::Custom(kinds::WRAP)).authors(pks)
    }

    /// Open control wraps into editions, skipping anything that is not one.
    fn open_editions(&self, wraps: &[Event]) -> Vec<Edition> {
        let streams = self.community().control_streams();
        wraps
            .iter()
            .filter_map(|w| {
                let stream = streams.iter().find(|s| s.pk == w.pubkey)?;
                parse_edition(open_plane_wrap(w, stream, Plane::Control).ok()?).ok()
            })
            .collect()
    }

    /// Fetch and fold the Control Plane (channels, roles, banlist).
    ///
    /// Settled, not merged across every relay: a start waited out the slowest
    /// relay of its community on this fold, and a boot took ~40 minutes while
    /// one sat at 7.7s (2026-10-16). What a late relay holds — a channel, a
    /// role, a ban — reaches the fold through the live control subscription,
    /// which replays the whole plane from every relay and re-folds within
    /// CONTROL_REFOLD of it arriving. A start that misses a channel this way
    /// re-folds once, then retries on backoff.
    ///
    /// The Guestbook's Timeouts ride the same query. Catch-up backfill runs
    /// on this first fold, before the live subscription has delivered
    /// anything, so without them a timed-out member's posts from while the
    /// bridge was down were mirrored.
    pub async fn sync_control(&self) -> anyhow::Result<Arc<FoldedControl>> {
        let (guestbook, guestbook_filter) = self.guestbook_filter();
        let wraps = self.relays.query_settled(vec![self.control_filter(), guestbook_filter]).await?;
        let (timeouts, control): (Vec<Event>, Vec<Event>) = wraps.into_iter().partition(|w| guestbook.iter().any(|s| s.pk == w.pubkey));
        for wrap in &timeouts {
            self.take_timeout(wrap, &guestbook);
        }
        Ok(self.fold(&self.open_editions(&control)))
    }

    /// Channels readable with held keys, per the current fold.
    pub fn channels(&self) -> Vec<ChannelView> {
        let channels = self.community().channels(self.folded().as_deref());
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
        self.folded().is_some_and(|f| f.roster.is_authorized(pubkey_hex, &self.community().owner, bits))
    }

    /// MANAGE_MESSAGES holder (or owner) per the current fold.
    pub fn is_moderator(&self, pubkey_hex: &str) -> bool {
        self.is_authorized(pubkey_hex, perm::MANAGE_MESSAGES)
    }

    /// May `deleter`'s kind 5 hide `author`'s message in this Channel (CORD-03 §3)?
    /// Against the CURRENT Roster: Manage Messages in the Channel (its
    /// overwrites on the ranked Roster) and a strict outrank of the author; the
    /// citation is a sync floor, so an uncited moderator hide waits rather than
    /// counting on a Grant this fold hasn't read.
    pub fn may_hide(&self, deleter: &str, author: &str, channel_id_hex: &str, delete: &Rumor) -> bool {
        let Some(f) = self.folded() else { return false };
        f.may_hide_in(deleter, author, channel_id_hex) && f.citation_satisfied(&self.community().id(), deleter, concord::edition::Citation::from_tags(&delete.tags).as_ref())
    }

    /// The Timeouts running now, judged against the current Roster.
    pub fn timeouts(&self) -> HashMap<String, FoldedTimeout> {
        let Some(f) = self.folded() else { return HashMap::new() };
        let opened: Vec<Opened> = self.timeouts.read().unwrap_or_else(|e| e.into_inner()).values().cloned().collect();
        let cid = self.community().id();
        fold_timeouts(&opened, now_ms(), &f.owner, &f.banned, |actor, target, citation| {
            f.roster.can_act_on_member(actor, &f.owner, target, perm::MODERATE_MEMBERS) && f.citation_satisfied(&cid, actor, citation)
        })
    }

    /// How Armada's readers judge this post (CORD-03 §1, CORD-04 §8). Without a
    /// fold nothing can be judged, and the bridge never runs without one.
    pub fn judge(&self, chat: &OpenedChat) -> Verdict {
        let Some(f) = self.folded() else { return Verdict::Stands };
        let post = Post { author: chat.author(), kind: chat.kind(), ms: chat.ms, edited_ms: None, tags: chat.tags() };
        let public_until = self.community().public_until(&f, &chat.channel_id_hex);
        judge_post(&f, &self.community().id(), &chat.channel_id_hex, post, &self.timeouts(), now_ms(), public_until)
    }

    /// Why a post of `kind` by `author_pk` would not stand in this Channel, if it
    /// wouldn't. A puppet holds `@everyone`'s bits and manages nothing, so in a
    /// restricted (read-only) Channel its post would be held from every reader,
    /// and with Send Messages denied it would be collapsed. Reactions and
    /// deletions stay at the read address and are judged by no ledger.
    pub fn post_refusal(&self, channel: &ChannelView, author_pk: &str, kind: u16) -> Option<PostRefused> {
        let f = self.folded()?;
        if !rides_writer_address(kind) {
            return None;
        }
        if f.restricting_ledger(&channel.id_hex).is_some() && !f.manages_channels(author_pk) {
            return Some(PostRefused::channel("the Armada channel is read-only: only its writers can post there"));
        }
        // A Timeout is a moderator's word on Armada: posts inside it collapse
        // there (CORD-04 §8), so a timed-out puppet isn't posted for.
        if self.timeouts().get(author_pk).is_some_and(|t| t.running(now_ms())) {
            return Some(PostRefused { reason: "this member is timed out in the Armada community", channel_wide: false });
        }
        if f.ranked {
            let p = f.channel_permissions(author_pk, &channel.id_hex);
            // A private channel lets in only those its overwrites name, and a
            // puppet is named by none: every post would be collapsed.
            if p & perm::VIEW_CHANNEL == 0 {
                return Some(PostRefused::channel("the Armada channel is private, and Discord members aren't let into it"));
            }
            if p & perm::SEND_MESSAGES == 0 {
                return Some(PostRefused::channel("Send Messages is denied to this member in the Armada channel"));
            }
        }
        None
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
        let wrap = seal_and_wrap(&rumor, Plane::Guestbook, &self.community().current_guestbook_stream(), author, WrapOptions::default())?;
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
        // Typing moves to the writer address in a restricted Channel; a signal
        // of the moment that wouldn't stand is simply not sent.
        if self.post_refusal(channel, &author.public_key().to_hex(), kinds::TYPING).is_some() {
            return Ok(());
        }
        let b = Binding { channel_id_hex: &channel.id_hex, epoch: channel.current().epoch };
        let rumor = concord::chat::typing(&b, &author.public_key().to_hex(), ms);
        let stream: StreamKey = (&channel.current().key).into();
        let wrap = seal_and_wrap(&rumor, Plane::Chat, &stream, author, WrapOptions { ephemeral: true, ..Default::default() })?;
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
        if let Some(refused) = self.post_refusal(channel, &pk, msg.kind) {
            return Err(refused.into());
        }
        let mut tags = concord::stream::channel_binding_tags(&channel.id_hex, channel.current().epoch);
        tags.extend(msg.tags);
        let rumor = Rumor::new(msg.kind, msg.content, tags, &pk, Some(msg.ms.unwrap_or_else(now_ms)), None);
        let stream: StreamKey = (&channel.current().key).into();
        // The wrap's `p` is the author's derived wrap-owner key, not a random
        // one, so the puppet (any instance of this bridge holding its key) can
        // find and delete its own wraps later (CORD-01 §Deletions).
        let rumor_id = concord::hex32(&rumor.id).context("rumor id is 32 bytes")?;
        let owner = concord::derive::wrap_owner_key(msg.author.secret_key(), &stream.pk.to_bytes(), &rumor_id);
        let seal = seal_rumor(&rumor, Plane::Chat.seal_kind(), &stream.conv_key, msg.author)?;
        let wrap = wrap_seal(&seal, &stream, WrapOptions { p: Some(owner.public_key()), ..Default::default() })?;
        // Relays drop an event past 64 KB (CORD-02 Appendix B): refuse here,
        // where the caller can still say so, instead of losing it on the wire.
        if wrap.as_json().len() > MAX_EVENT_BYTES {
            bail!("the message is too large for a relay event once encrypted");
        }
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
        let filter = Filter::new().kinds([Kind::Custom(kinds::WRAP), Kind::Custom(kinds::WRAP_EPHEMERAL)]).authors(channel_addresses(channel)).since(since);
        let mut sub = self.relays.subscribe(vec![filter]);
        let channel = channel.clone();
        TaskGuard(tokio::spawn(async move {
            let mut seen = RecentIds::default();
            while let Some(wrap) = sub.recv().await {
                let Some(chat) = open_chat(&wrap, &channel) else { continue };
                if wrap.kind == Kind::Custom(kinds::WRAP)
                    && let Some(cursor) = &on_cursor
                {
                    cursor(wrap.pubkey.to_hex(), wrap.created_at.as_secs());
                }
                if !seen.insert(&chat.rumor.id) {
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
        let filter = Filter::new().kind(Kind::Custom(kinds::WRAP)).authors(channel_addresses(channel)).since(Timestamp::from_secs(since_secs)).limit(limit);
        let wraps = self.relays.query(vec![filter]).await?;
        let mut chats: Vec<OpenedChat> = wraps.iter().filter_map(|w| open_chat(w, channel)).collect();
        chats.sort_by_key(|c| c.ms);
        let newest = wraps.iter().map(|w| w.created_at.as_secs()).max();
        Ok((chats, newest))
    }

    /// The Guestbook's address set and the filter reading its Timeouts (kind
    /// 3314) for the per-post judge. A Timeout runs at most 28 days, so the
    /// filter reaches back only that far.
    fn guestbook_filter(&self) -> (Vec<StreamKey>, Filter) {
        let streams = self.community().guestbook_streams();
        let since = Timestamp::from_secs((now_ms() / 1000).saturating_sub(TIMEOUT_LOOKBACK_SECS));
        let filter = Filter::new().kind(Kind::Custom(kinds::WRAP)).authors(streams.iter().map(|s| s.pk).collect::<Vec<_>>()).since(since);
        (streams, filter)
    }

    /// Hold a Guestbook wrap if it is a Timeout.
    fn take_timeout(&self, wrap: &Event, streams: &[StreamKey]) {
        let Some(stream) = streams.iter().find(|s| s.pk == wrap.pubkey) else { return };
        let Ok(opened) = open_plane_wrap(wrap, stream, Plane::Guestbook) else { return };
        if opened.rumor.kind != kinds::TIMEOUT {
            return;
        }
        let mut held = self.timeouts.write().unwrap_or_else(|e| e.into_inner());
        if held.len() < MAX_TIMEOUTS_HELD || held.contains_key(&opened.rumor.id) {
            held.insert(opened.rumor.id.clone(), opened);
        }
    }

    /// Live-fold the Control Plane, so bans and channel changes apply to (nearly)
    /// the very next send.
    ///
    /// Re-folds are batched over [`CONTROL_REFOLD`]: the REQ has no `since`, so
    /// every relay replays the whole plane on subscribe, and folding once per
    /// arriving wrap made that replay quadratic. Each wrap is opened once, on
    /// arrival; a re-fold only replays the editions already opened.
    ///
    /// The same REQ follows the Guestbook's Timeouts: relays cap standing
    /// subscriptions, and a community's Control Plane and Guestbook are read
    /// together anyway.
    /// Follow the community's Refoundings with this client's own identity
    /// (see [`crate::key_intake::intake_base_rotations`]), taking the new root
    /// into its membership. Its channels then derive from the new root.
    pub async fn adopt_base_rotations(&self) -> crate::key_intake::BaseIntake {
        let Some(folded) = self.folded() else {
            return crate::key_intake::BaseIntake { community: (*self.community()).clone(), adopted: None, excluded: None };
        };
        let intake = crate::key_intake::intake_base_rotations(self.relays.as_ref(), &self.primary, &self.community(), &folded).await;
        if let Some(epoch) = intake.adopted {
            tracing::info!(community = %&intake.community.community_id[..8], epoch, "took the community's new root");
            self.set_community(intake.community.clone());
        }
        intake
    }

    /// Move this client's base (roots, Control Plane address) up to `other`'s,
    /// keeping its own channel keys. For the community's shared fold reader,
    /// which holds no identity that could open a rotation's blob: it takes the
    /// root a bridge verified. False when `other` is no newer.
    pub fn take_base_from(&self, other: &Membership) -> bool {
        let mine = self.community();
        if other.community_id != mine.community_id || other.root_epoch <= mine.root_epoch {
            return false;
        }
        let mut next = (*mine).clone();
        next.held_roots = other.held_roots.clone();
        next.root = other.root.clone();
        next.root_epoch = other.root_epoch;
        next.control_pk = other.control_pk.clone();
        next.control_root = other.control_root.clone();
        self.set_community(next);
        // Read the new epoch's Control Plane and Guestbook as every member
        // does, and stop AUTHing as nothing.
        let mut keys = stream_keys(&self.community().control_streams());
        keys.extend(stream_keys(&self.community().guestbook_streams()));
        self.relays.register_auth_keys(keys);
        true
    }

    /// Follow a private channel's key while the bridge runs: its next
    /// rotations and its access deliveries. Each wrap arriving at one of those
    /// addresses re-runs the same vetted intake a start runs, and a key it
    /// takes for this channel swaps in this client's membership and calls
    /// `on_change`, so the caller can move its chat REQ.
    ///
    /// Without it a rotation (a ban, a revoke, an owner re-keying) left the
    /// bridge reading and writing the superseded epoch until its next restart:
    /// Armada's members moved to the new stream, and the channel went quiet in
    /// both directions while every bridge looked healthy.
    pub fn follow_channel_keys(self: &Arc<Self>, channel_id_hex: &str, on_change: Arc<dyn Fn() + Send + Sync>) -> TaskGuard {
        let me = Arc::downgrade(self);
        let channel = channel_id_hex.to_owned();
        TaskGuard::spawn(async move {
            let mut seen = RecentIds::default();
            'resubscribe: loop {
                let Some(client) = me.upgrade() else { return };
                let Some(id) = concord::hex32(&channel) else { return };
                let streams = key_watch_streams(&client.community(), &channel, &id);
                client.relays.register_auth_keys(crate::key_intake::auth_keys(&streams));
                let since = Timestamp::from_secs((now_ms() / 1000).saturating_sub(60));
                let filter = Filter::new().kind(Kind::Custom(kinds::WRAP)).authors(streams.iter().map(|s| s.pk).collect::<Vec<_>>()).since(since);
                let mut sub = client.relays.subscribe(vec![filter]);
                let addresses: Vec<PublicKey> = streams.iter().map(|s| s.pk).collect();
                drop(client);
                loop {
                    let Some(wrap) = sub.recv().await else { return };
                    // A resubscription replays the last minute; what was
                    // already read is no news.
                    if !seen.insert(&wrap.id.to_hex()) {
                        continue;
                    }
                    // A rotation arrives as several chunks; let them land.
                    tokio::time::sleep(KEY_SETTLE).await;
                    let Some(client) = me.upgrade() else { return };
                    let Some(folded) = client.folded() else { continue };
                    let held = client.community();
                    let intake = crate::key_intake::intake_access_keys(client.relays.as_ref(), &client.primary, &held, &folded).await;
                    if !intake.learned.is_empty() {
                        let ours = intake.learned.contains(&channel);
                        client.set_community(intake.community);
                        if ours {
                            tracing::info!(channel = %&channel[..8], "took a new key for the bridged channel while running");
                            on_change();
                        }
                    }
                    // A new epoch moves the next rotation's address.
                    if key_watch_streams(&client.community(), &channel, &id).iter().map(|s| s.pk).ne(addresses.iter().copied()) {
                        continue 'resubscribe;
                    }
                }
            }
        })
    }

    ///
    /// `on_base` is called when a wrap lands at the next base rotation's
    /// address, in the same REQ: a Refounding is under way, and the caller
    /// follows it with each bridge's own identity (only they can open their
    /// blobs). The subscription names the addresses of the root held when it
    /// started, so the caller replaces it once a new root is taken.
    pub fn subscribe_control(self: &Arc<Self>, on_fold: Option<FoldHandler>, on_base: Option<Arc<dyn Fn() + Send + Sync>>) -> TaskGuard {
        let (guestbook, guestbook_filter) = self.guestbook_filter();
        let base: StreamKey = (&self.community().next_base_rekey_address()).into();
        self.relays.register_auth_keys(crate::key_intake::auth_keys([&base]));
        let since = Timestamp::from_secs((now_ms() / 1000).saturating_sub(60));
        let base_filter = Filter::new().kind(Kind::Custom(kinds::WRAP)).author(base.pk).since(since);
        let mut sub = self.relays.subscribe(vec![self.control_filter(), guestbook_filter, base_filter]);
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
                if wrap.pubkey == base.pk {
                    if let Some(f) = &on_base {
                        f();
                    }
                    continue;
                }
                let Some(me) = me.upgrade() else { return };
                if guestbook.iter().any(|s| s.pk == wrap.pubkey) {
                    me.take_timeout(&wrap, &guestbook);
                    continue;
                }
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

/// Where a held private channel's next keys arrive: its upcoming rotations
/// and its access plane.
fn key_watch_streams(community: &Membership, channel_id_hex: &str, id: &concord::Bytes32) -> Vec<StreamKey> {
    let mut streams: Vec<StreamKey> =
        community.channel_rekey_addresses().into_iter().filter(|(_, c, _)| c == channel_id_hex).map(|(g, _, _)| (&g).into()).collect();
    streams.push((&community.access_plane(id)).into());
    streams
}

fn stream_keys(streams: &[StreamKey]) -> Vec<Keys> {
    streams.iter().filter_map(|s| s.sk.clone().map(Keys::new)).collect()
}
