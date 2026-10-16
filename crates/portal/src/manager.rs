//! BridgeManager: the portal's data plane. Owns one Discord gateway (one bot
//! application serves every bridge) and, per bridge, a headless Concord client.
//! Drives the lifecycle: draft -> pending_confirm (in-channel code) -> active
//! (routing attached) -> paused/severed/unlinked.
//!
//! The in-channel confirm is the Armada side's consent gate: only a member
//! holding MANAGE_CHANNELS (or the owner) can flip a bridge live, and the
//! portal cannot bypass it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use async_trait::async_trait;
use bridge::client::{BotCommand, BotCommandArg, ConcordClient, OpenedChat, SendChat, now_ms, resolve_invite};
use bridge::community::{Attachment, CommunityRuntime};
use bridge::discord::{CommandMessage, DiscordAdapter, DiscordEvents, TypingEvent};
use bridge::key_intake::intake_direct_invite_keys;
use bridge::profiles::Kind0ProfileResolver;
use bridge::puppets::PuppetCache;
use bridge::relays::{Hub, RelayLike, Relays};
use bridge::router::{BridgeRouter, RouterOptions, SelfIds, WebhookMessage, is_missing_permissions};
use bridge::store::{MappingStore, PgMappingStore};
use bridge::transform::parse_bot_command;
use bridge::types::{ChannelLink, DiscordInboundMessage, DiscordMessageDelete, DiscordReaction};
use concord::community::{ChannelView, Membership};
use concord::invite::{invite_delivery_relays, parse_invite_link, stock_relays};
use concord::roles::perm;
use deadpool_postgres::Pool;
use nostr::prelude::{Keys, SecretKey};
use rand::RngCore;
use regex::Regex;
use serde_json::{Value, json};
use tokio::task::JoinHandle;

use crate::catchup::{CatchUpIo, catch_up_needed, replay_discord_since};
use crate::discord_rest::{DiscordRest, RestMessage, rest_to_inbound};
use crate::env::PortalEnv;
use crate::relay_guard::filter_public_relays;
use crate::seal::{seal, unseal};

mod history_jobs;

/// Every column a bridge row is read with. `bridge_id` is read as text and
/// compared as `($1::text)::uuid`, so no uuid type crosses the driver.
pub const BRIDGE_COLUMNS: &str = "bridge_id::text AS bridge_id, owner_discord_id, status, status_detail, invite_url_sealed, \
     master_secret_sealed, primary_sk_sealed, primary_pk, community_id, community_name, discord_guild_id, \
     discord_channel_id, concord_channel_id, confirm_code, options, link_group::text AS link_group, history";

#[derive(Clone, Debug, Default)]
pub struct BridgeRow {
    pub bridge_id: String,
    pub owner_discord_id: String,
    pub status: String,
    pub status_detail: Option<String>,
    pub invite_url_sealed: Option<Vec<u8>>,
    pub master_secret_sealed: Option<Vec<u8>>,
    pub primary_sk_sealed: Option<Vec<u8>>,
    pub primary_pk: Option<String>,
    pub community_id: Option<String>,
    pub community_name: Option<String>,
    pub discord_guild_id: Option<String>,
    pub discord_channel_id: Option<String>,
    pub concord_channel_id: Option<String>,
    pub confirm_code: Option<String>,
    pub options: Value,
    /// Bridges linked in one request share a group and its confirm code.
    pub link_group: Option<String>,
    /// History requested for this bridge, and its progress (migration 019).
    pub history: Value,
}

impl BridgeRow {
    pub fn from_row(r: &tokio_postgres::Row) -> BridgeRow {
        BridgeRow {
            bridge_id: r.get("bridge_id"),
            owner_discord_id: r.get("owner_discord_id"),
            status: r.get("status"),
            status_detail: r.get("status_detail"),
            invite_url_sealed: r.get("invite_url_sealed"),
            master_secret_sealed: r.get("master_secret_sealed"),
            primary_sk_sealed: r.get("primary_sk_sealed"),
            primary_pk: r.get("primary_pk"),
            community_id: r.get("community_id"),
            community_name: r.get("community_name"),
            discord_guild_id: r.get("discord_guild_id"),
            discord_channel_id: r.get("discord_channel_id"),
            concord_channel_id: r.get("concord_channel_id"),
            confirm_code: r.get("confirm_code"),
            options: r.get("options"),
            link_group: r.get("link_group"),
            history: r.get("history"),
        }
    }
}

pub async fn bridge_by_id(pool: &Pool, bridge_id: &str) -> anyhow::Result<Option<BridgeRow>> {
    let sql = format!("SELECT {BRIDGE_COLUMNS} FROM bridges WHERE bridge_id = ($1::text)::uuid");
    Ok(pool.get().await?.query_opt(&sql, &[&bridge_id]).await?.as_ref().map(BridgeRow::from_row))
}

pub static CONFIRM_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^/bridge confirm ([0-9a-f]{8})$").unwrap());

/// How long a bridge may keep failing to start before the failure is committed
/// as a sever. Relays give no tombstones: an empty query for the invite bundle
/// can mean the community was dissolved, or that no relay happened to answer
/// inside one boot's window — the two are indistinguishable from a single
/// attempt. Only failure sustained across retries this long is treated as the
/// community actually being gone.
pub const START_FAILURE_SEVER_AFTER: &str = "7 days";
const START_RETRY_BASE: Duration = Duration::from_secs(5 * 60);
const START_RETRY_MAX: Duration = Duration::from_secs(6 * 60 * 60);

/// Backoff for reconnecting the shared gateway after its login fails. Short,
/// because the gateway being down blocks every active bridge at once.
const GATEWAY_RETRY_BASE: Duration = Duration::from_secs(10);
const GATEWAY_RETRY_MAX: Duration = Duration::from_secs(10 * 60);

/// How many bridges may be starting at once during boot; see `start_all`.
const START_CONCURRENCY: usize = 12;

/// Most Discord messages one start-time catch-up reads per channel. Bounds an
/// old anchor — a bridge down for weeks — to a burst the channel can absorb.
const DISCORD_CATCHUP_MAX: usize = 500;

/// Deadlines for each stage of a bridge start. Every relay call carries its own
/// timeout, but not everything a start awaits does, and one start that never
/// returns holds a boot worker for good: with START_CONCURRENCY of them stuck,
/// every bridge still queued stays dark (2026-10-16, 20 bridges). A stage that
/// overruns is a start failure like any other — retried with backoff, never a
/// sever on its own — and its error names the stage.
const STAGE_RELAY: Duration = Duration::from_secs(90);
const STAGE_DNS: Duration = Duration::from_secs(30);
const STAGE_DB: Duration = Duration::from_secs(30);
const STAGE_NAMES: Duration = Duration::from_secs(15);
/// Backstop over a whole start, past the sum of its stages.
const START_DEADLINE: Duration = Duration::from_secs(10 * 60);

/// How long a boot waits for the gateway to describe every server before
/// starting bridges anyway; what is missing falls back to REST.
const DIRECTORY_WAIT: Duration = Duration::from_secs(30);

/// Where a boot's Discord facts came from: the gateway's directory, or REST.
/// Reported and reset with each `start_all`, so a boot's REST cost is visible.
#[derive(Default)]
struct DiscordCalls {
    /// Bridges paused because the bot is no longer in their server.
    removed: AtomicUsize,
    names_known: AtomicUsize,
    names_fetched: AtomicUsize,
    catch_ups_skipped: AtomicUsize,
    catch_ups_fetched: AtomicUsize,
}

impl DiscordCalls {
    fn take(&self) -> String {
        let n = |a: &AtomicUsize| a.swap(0, Ordering::Relaxed);
        format!(
            "{} paused (bot removed from their server); names: {} from the gateway, {} via REST; Discord catch-up: {} skipped, {} fetched",
            n(&self.removed),
            n(&self.names_known),
            n(&self.names_fetched),
            n(&self.catch_ups_skipped),
            n(&self.catch_ups_fetched)
        )
    }
}

/// How long a community that failed to open fails its bridges' starts without
/// trying again. Its bridges are queued together at boot, and each one
/// re-running a fold that just timed out would hold a boot worker for the
/// whole relay deadline, one bridge after another.
const COMMUNITY_REOPEN_AFTER: Duration = Duration::from_secs(60);

async fn stage<T>(name: &str, limit: Duration, fut: impl std::future::Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
    match tokio::time::timeout(limit, fut).await {
        Ok(result) => result,
        Err(_) => bail!("{name} timed out after {}s", limit.as_secs()),
    }
}

/// Raised when an active bridge is asked to start while the shared Discord
/// gateway is down. Deliberately its OWN error, not a start failure: the
/// gateway being unreachable is process-wide and transient and says NOTHING
/// about the community, so it must never advance the seven-day sever streak.
/// Treating it as a start failure once severed every active bridge on a boot
/// that raced a Discord API blip (2026-08-27, ~378 bridges).
#[derive(Debug, thiserror::Error)]
#[error("Discord gateway not connected; deferring bridge start")]
pub struct GatewayUnavailable;

/// Raised when a bridge's Discord server is one the bot is no longer in. Not a
/// start failure: nothing about the community is wrong, and retrying cannot
/// help until someone re-adds the bot. The bridge is paused instead, marked so
/// that re-adding the bot resumes it (see `pause_bot_removed`).
#[derive(Debug, thiserror::Error)]
#[error("the bot was removed from this Discord server")]
pub struct BotRemoved;

/// `options` keys marking a pause the portal made, not a person. Only such a
/// pause is ever lifted automatically; any other stop clears them.
const PAUSED_FOR: &str = "pausedFor";
const RESUME_TO: &str = "resumeTo";
const BOT_REMOVED: &str = "bot-removed";
const BOT_REMOVED_DETAIL: &str = "The bot was removed from this Discord server. Add it back and the bridge resumes on its own.";

/// The kind-10304 command manifest every bridge primary advertises.
pub fn bridge_commands() -> Vec<BotCommand> {
    vec![
        BotCommand {
            name: "bridge",
            description: "Manage this channel's Discord bridge. /bridge confirm <code> approves a pending link.",
            args: vec![
                BotCommandArg { name: "action", kind: "choice", description: "What to do", required: true, choices: Some(vec!["confirm"]) },
                BotCommandArg { name: "code", kind: "string", description: "The 8-character confirm code", required: true, choices: None },
            ],
        },
        BotCommand { name: "help", description: "What this bridge bot does and which commands it answers.", args: vec![] },
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveStatus {
    PendingConfirm,
    Active,
}

/// A community's shared runtime, and the connections it runs on.
struct Community {
    runtime: Arc<CommunityRuntime>,
    relays: Relays,
}

/// Where a community is, or was, opened. Bridges of one community start
/// concurrently at boot; the lock makes the first open it and the rest wait.
#[derive(Default)]
struct CommunitySlot {
    live: Weak<Community>,
    failed: Option<(Instant, String)>,
}

/// Which bridges can share a runtime: those whose memberships agree on
/// everything the control fold and the connections depend on. Holds the root,
/// so it lives only in memory and is never logged.
fn community_key(m: &Membership) -> String {
    let mut relays = m.relays.clone();
    relays.sort();
    format!("{}|{}|{}|{}|{}", m.community_id, m.root_epoch, m.root, m.control_pk.as_deref().unwrap_or(""), relays.join(" "))
}

struct Running {
    id: String,
    client: Arc<ConcordClient>,
    community: Arc<Community>,
    link: ChannelLink,
    confirm_code: String,
    /// The channel as first started; the attachment tracks rekeys after that.
    channel: Mutex<ChannelView>,
    status: Mutex<LiveStatus>,
    router: RwLock<Option<Arc<BridgeRouter>>>,
    attachment: Mutex<Option<Attachment>>,
}

impl Running {
    fn router(&self) -> Option<Arc<BridgeRouter>> {
        self.router.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn status(&self) -> LiveStatus {
        *self.status.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn channel(&self) -> ChannelView {
        let current = self.attachment.lock().unwrap_or_else(|e| e.into_inner()).as_ref().and_then(Attachment::channel);
        current.unwrap_or_else(|| self.channel.lock().unwrap_or_else(|e| e.into_inner()).clone())
    }
    fn primary(&self) -> &Keys {
        self.client.primary()
    }
    /// Stop receiving chat. The community's runtime, connections and
    /// subscriptions go with its last bridge.
    fn halt(&self) {
        self.attachment.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
}

/// Full-jitter backoff: bridges share relays, so one relay outage puts many of
/// them in the retry path at once, and identical delays would line them up on
/// the same tick against a host that is already struggling.
fn jittered(base: Duration, max: Duration, attempt: u32) -> Duration {
    let cap = (base * 2u32.pow(attempt.min(6))).min(max);
    let half = cap / 2;
    half + half.mul_f64(rand::random::<f64>())
}

pub struct BridgeManager {
    me: Weak<BridgeManager>,
    pool: Pool,
    env: PortalEnv,
    rest: DiscordRest,
    /// One shared store: mapping rows for every router, plus catch-up cursors.
    store: Arc<PgMappingStore>,
    communities: Mutex<HashMap<String, Arc<tokio::sync::Mutex<CommunitySlot>>>>,
    /// Resolves the invites of starting bridges. One hub, not one per start:
    /// that was a burst of fresh connections per bridge at every boot, and
    /// relays that limit connection rate answer a burst with 429s. Connections
    /// close on their own once idle.
    bootstrap: Arc<Hub>,
    /// Every community's connections: one per relay for the process, whose
    /// subscriptions relay-pool merges into a few REQs (see bridge::relays
    /// for the three layouts that failed first).
    communities_hub: Arc<Hub>,
    adapter: RwLock<Option<Arc<DiscordAdapter>>>,
    running: Mutex<HashMap<String, Arc<Running>>>,
    by_discord_channel: Mutex<HashMap<String, String>>,
    /// Pending start-retry timers by bridge id; cancelled by `stop`.
    start_retries: Mutex<HashMap<String, JoinHandle<()>>>,
    /// Set once boot's `start_all` has run, so a LATE gateway connect knows to
    /// bring deferred bridges up rather than double-start them.
    booted: AtomicBool,
    discord_calls: DiscordCalls,
    /// Bridges with a history copy running in this process.
    history_running: Mutex<std::collections::HashSet<String>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl BridgeManager {
    pub fn new(pool: Pool, env: PortalEnv) -> Arc<BridgeManager> {
        Arc::new_cyclic(|me| BridgeManager {
            me: me.clone(),
            store: Arc::new(PgMappingStore::new(pool.clone())),
            pool,
            env,
            rest: DiscordRest::new(),
            communities: Mutex::default(),
            bootstrap: Hub::new(Keys::generate()),
            communities_hub: Hub::with_query_limit(Keys::generate(), bridge::relays::SHARED_HUB_QUERY_CONCURRENCY),
            adapter: RwLock::new(None),
            running: Mutex::default(),
            by_discord_channel: Mutex::default(),
            start_retries: Mutex::default(),
            booted: AtomicBool::new(false),
            discord_calls: DiscordCalls::default(),
            history_running: Mutex::default(),
        })
    }

    fn arc(&self) -> Arc<BridgeManager> {
        self.me.upgrade().expect("the manager outlives its own calls")
    }

    fn adapter(&self) -> Option<Arc<DiscordAdapter>> {
        self.adapter.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn store(&self) -> &Arc<PgMappingStore> {
        &self.store
    }

    /// Communities with a live runtime (operational visibility).
    pub fn communities(&self) -> usize {
        lock(&self.communities).values().filter(|s| s.try_lock().is_ok_and(|s| s.live.strong_count() > 0)).count()
    }

    /// Relay counters summed over every connection set in use, with how many
    /// sockets are open to each relay.
    pub fn relay_stats(&self) -> std::collections::BTreeMap<String, (usize, relay_pool::RelayStats)> {
        let mut hubs: Vec<Arc<Hub>> = vec![self.bootstrap.clone()];
        for slot in lock(&self.communities).values() {
            if let Ok(slot) = slot.try_lock()
                && let Some(community) = slot.live.upgrade()
                && !hubs.iter().any(|h| Arc::ptr_eq(h, community.relays.hub()))
            {
                hubs.push(community.relays.hub().clone());
            }
        }
        let mut out: std::collections::BTreeMap<String, (usize, relay_pool::RelayStats)> = Default::default();
        for (url, s) in hubs.iter().flat_map(|h| h.stats()) {
            let (sockets, t) = out.entry(url).or_default();
            *sockets += usize::from(s.connected);
            t.connected |= s.connected;
            t.connects += s.connects;
            t.connect_failures += s.connect_failures;
            t.refused += s.refused;
            t.closed += s.closed;
            t.auth_rejected += s.auth_rejected;
            t.reqs += s.reqs;
        }
        out
    }

    pub async fn init(&self) -> anyhow::Result<()> {
        if self.env.discord_bot_token.is_empty() {
            tracing::warn!("DISCORD_TOKEN not set; bridges cannot go live");
        } else {
            self.connect_adapter(0).await;
        }
        if let Some(adapter) = self.adapter() {
            // The bot may have been re-added while the portal was down.
            for guild in self.bot_removed_guilds().await? {
                if adapter.in_guild(&guild) == Some(true) {
                    self.resume_bot_removed(&guild).await?;
                }
            }
        }
        self.start_all(self.bridges_to_start().await?).await;
        self.booted.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Every bridge that should be running, most recently active first.
    ///
    /// Boot is a queue, and whatever sits at the back stays dark until the front
    /// has started; in heap order that was arbitrary, so a busy channel could
    /// wait out the whole boot behind hundreds that never speak. Ordering by the
    /// newest mirrored message puts the conversations people are having first.
    async fn bridges_to_start(&self) -> anyhow::Result<Vec<BridgeRow>> {
        let sql = format!(
            "SELECT {BRIDGE_COLUMNS} FROM bridges b
             LEFT JOIN LATERAL (
               SELECT m.created_at FROM messages m
               WHERE m.tenant_id = 'default' AND m.discord_channel_id = b.discord_channel_id
               ORDER BY m.created_at DESC LIMIT 1
             ) last ON true
             WHERE b.status IN ('pending_confirm', 'active')
             ORDER BY last.created_at DESC NULLS LAST"
        );
        Ok(self.pool.get().await?.query(&sql, &[]).await?.iter().map(BridgeRow::from_row).collect())
    }

    /// Bring up the shared Discord gateway, retrying with capped backoff.
    ///
    /// A failed login (the REST preflight refused during a network blip,
    /// 2026-08-27) used to leave the gateway down for the whole process
    /// lifetime, which turned that blip into a mass sever. Now the gateway heals
    /// on its own and deferred bridges come up when it does. A persistent error
    /// (bad token, MESSAGE_CONTENT not enabled) just keeps logging.
    fn connect_adapter(&self, attempt: u32) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let events = Arc::new(ManagerEvents(self.me.clone()));
            match DiscordAdapter::connect(&self.env.discord_bot_token, events).await {
                Ok(adapter) => {
                    tracing::info!("discord gateway up");
                    // Before any bridge starts, so their names and catch-up
                    // checks read the directory rather than REST.
                    adapter.wait_for_directory(DIRECTORY_WAIT).await;
                    *self.adapter.write().unwrap_or_else(|e| e.into_inner()) = Some(adapter);
                    if self.booted.load(Ordering::SeqCst) {
                        let me = self.arc();
                        tokio::spawn(async move { me.on_adapter_connected().await });
                    }
                }
                Err(error) => {
                    let delay = jittered(GATEWAY_RETRY_BASE, GATEWAY_RETRY_MAX, attempt);
                    tracing::error!(attempt = attempt + 1, retry_in_s = delay.as_secs(), error = %format!("{error:#}"), "discord gateway failed to start");
                    let me = self.arc();
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        me.connect_adapter(attempt + 1).await;
                    });
                }
            }
        })
    }

    /// The gateway came up AFTER boot. Bridges that deferred while it was down
    /// are sitting on a backoff timer; start them now.
    async fn on_adapter_connected(&self) {
        let Ok(rows) = self.bridges_to_start().await else { return };
        let deferred: Vec<BridgeRow> = rows.into_iter().filter(|r| !self.is_live(&r.bridge_id)).collect();
        for row in &deferred {
            self.cancel_start_retry(&row.bridge_id);
        }
        if !deferred.is_empty() {
            tracing::info!(count = deferred.len(), "gateway back; starting deferred bridges");
            self.start_all(deferred).await;
        }
    }

    /// Bring every stored bridge up, several at a time.
    ///
    /// One at a time took half an hour for a few hundred bridges, and a single
    /// unresponsive relay made the wait unbounded for everything after it.
    /// Bounded rather than unbounded: bridges share relays and one bot token, so
    /// starting all at once would aim hundreds of simultaneous REQs at the same
    /// few hosts and spend the token's REST budget on name lookups.
    async fn start_all(&self, rows: Vec<BridgeRow>) {
        let began = Instant::now();
        let total = rows.len();
        let ids: Vec<String> = rows.iter().map(|r| r.bridge_id.clone()).collect();
        let queue = Arc::new(Mutex::new(std::collections::VecDeque::from(rows)));
        let workers = (0..START_CONCURRENCY.min(total)).map(|_| {
            let queue = queue.clone();
            async move {
                loop {
                    let next = lock(&queue).pop_front();
                    let Some(row) = next else { break };
                    self.start_tracked(row, 0).await;
                }
            }
        });
        futures_util::future::join_all(workers).await;
        let live = ids.iter().filter(|id| self.is_live(id)).count();
        tracing::info!("{live}/{total} bridges live in {}s; {}", began.elapsed().as_secs(), self.discord_calls.take());
    }

    fn active_router_for(&self, discord_channel_id: &str) -> Option<(Arc<Running>, Arc<BridgeRouter>)> {
        let id = lock(&self.by_discord_channel).get(discord_channel_id).cloned()?;
        let rb = lock(&self.running).get(&id).cloned()?;
        if rb.status() != LiveStatus::Active {
            return None;
        }
        let router = rb.router()?;
        Some((rb, router))
    }

    pub fn live_count(&self) -> usize {
        lock(&self.running).len()
    }

    pub fn is_live(&self, bridge_id: &str) -> bool {
        lock(&self.running).contains_key(bridge_id)
    }

    /// The live router and link for a Discord channel (history backfill hook).
    pub fn router_for(&self, discord_channel_id: &str) -> Option<(Arc<BridgeRouter>, ChannelLink)> {
        self.active_router_for(discord_channel_id).map(|(rb, router)| (router, rb.link.clone()))
    }

    /// Re-fold the control plane for the live bridge on a Discord channel, so a
    /// just-imported channel is known before the backfill publishes into it.
    pub async fn resync_for(&self, discord_channel_id: &str) -> anyhow::Result<()> {
        if let Some((rb, _)) = self.active_router_for(discord_channel_id) {
            rb.client.sync_control().await?;
        }
        Ok(())
    }

    /// Whether the live bridge's fold knows this Concord channel.
    pub fn channel_known(&self, discord_channel_id: &str, concord_channel_id_hex: &str) -> bool {
        self.active_router_for(discord_channel_id).is_some_and(|(rb, _)| rb.client.channel(concord_channel_id_hex).is_some())
    }
}

/// What the wizard's pairing step shows for a pasted invite.
pub struct InspectedInvite {
    pub community_id: String,
    pub name: String,
    pub relays: Vec<String>,
    pub channels: Vec<ChannelView>,
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

impl BridgeManager {
    /// A relay handle for a list that arrived in an invite: both the bootstrap
    /// relays encoded in the pasted link and the community relays on the event
    /// it resolves to are attacker-reachable, and neither may name a host
    /// inside our network.
    async fn guarded(&self, hub: &Arc<Hub>, relays: &[String]) -> bridge::relays::Relays {
        hub.relays(filter_public_relays(relays, &stock_relays()).await)
    }

    async fn bootstrap_relays(&self, hub: &Arc<Hub>, invite_url: &str) -> anyhow::Result<Relays> {
        let link = parse_invite_link(invite_url).context("not a valid Armada invite URL")?;
        let relays = if link.bootstrap_relays.is_empty() { stock_relays() } else { link.bootstrap_relays };
        Ok(self.guarded(hub, &relays).await)
    }

    /// Resolve and fold a community for the wizard's pairing step (transient,
    /// and on its own connections: the link is whatever was pasted).
    pub async fn inspect_invite(&self, invite_url: &str) -> anyhow::Result<InspectedInvite> {
        let bootstrap = self.bootstrap_relays(&Hub::new(Keys::generate()), invite_url).await?;
        let joined = resolve_invite(invite_url, &bootstrap).await?;
        let m = joined.membership;
        let relays = self.guarded(&Hub::new(Keys::generate()), &m.relays).await;
        let client = ConcordClient::new(m.clone(), Arc::new(relays), Keys::generate());
        client.sync_control().await?;
        Ok(InspectedInvite {
            community_id: m.community_id.clone(),
            name: m.name.clone(),
            relays: m.relays.clone(),
            channels: client.channels(),
        })
    }

    /// One sealed master secret per (community, guild): the first channel
    /// mints, the rest reuse, so a Discord user keeps one npub across every
    /// channel bridged between the same server and community. The primary key
    /// makes concurrent activations race-proof: both insert, one wins, both
    /// read back the same row.
    pub async fn shared_master_secret(&self, community_id: &str, guild_id: &str) -> anyhow::Result<Vec<u8>> {
        let candidate = seal(&self.env.seal_key_hex, &random_hex(32))?;
        let db = self.pool.get().await?;
        db.execute(
            "INSERT INTO guild_community_secrets (community_id, discord_guild_id, master_secret_sealed)
             VALUES ($1, $2, $3) ON CONFLICT (community_id, discord_guild_id) DO NOTHING",
            &[&community_id, &guild_id, &candidate],
        )
        .await?;
        let row = db
            .query_one(
                "SELECT master_secret_sealed FROM guild_community_secrets WHERE community_id = $1 AND discord_guild_id = $2",
                &[&community_id, &guild_id],
            )
            .await?;
        Ok(row.get(0))
    }

    /// Mint a bridge's identity and move it to `status`, WITHOUT starting it.
    async fn provision(&self, row: &BridgeRow, status: &str, confirm_code: Option<String>) -> anyhow::Result<BridgeRow> {
        let (Some(community_id), Some(guild_id)) = (&row.community_id, &row.discord_guild_id) else {
            bail!("bridge must be linked (community + guild) before activation");
        };
        let primary = Keys::generate();
        let master = self.shared_master_secret(community_id, guild_id).await?;
        let primary_sealed = seal(&self.env.seal_key_hex, &primary.secret_key().to_secret_hex())?;
        self.pool
            .get()
            .await?
            .execute(
                "UPDATE bridges SET master_secret_sealed = $2, primary_sk_sealed = $3, primary_pk = $4,
                   confirm_code = coalesce($5, confirm_code), status = $6, status_detail = NULL, updated_at = now()
                 WHERE bridge_id = ($1::text)::uuid",
                &[&row.bridge_id, &master, &primary_sealed, &primary.public_key().to_hex(), &confirm_code, &status],
            )
            .await?;
        bridge_by_id(&self.pool, &row.bridge_id).await?.context("bridge vanished during activation")
    }

    /// Mint per-bridge secrets and move draft -> pending_confirm.
    pub async fn activate(&self, row: &BridgeRow) -> anyhow::Result<()> {
        let fresh = self.provision(row, "pending_confirm", Some(random_hex(4))).await?;
        self.start(&fresh).await
    }

    /// Provision every bridge of a group linked together, then start them
    /// in the background, retried like any start.
    ///
    /// `code: Some` leaves them pending under that one code, so confirming
    /// any of them confirms all. `None` starts them live with no in-channel
    /// confirm, which is only for a link whose consent was already proven: a
    /// request signed by a key that holds Manage Channels in the community,
    /// checked against the same fold the confirm would be (see `authorizes`).
    ///
    /// Every row is provisioned before any starts, so the first request
    /// posted already names the whole group.
    pub async fn activate_group(&self, rows: &[BridgeRow], code: Option<&str>) -> anyhow::Result<()> {
        let mut provisioned = Vec::with_capacity(rows.len());
        for row in rows {
            provisioned.push(match code {
                Some(code) => self.provision(row, "pending_confirm", Some(code.to_owned())).await?,
                None => self.provision(row, "active", None).await?,
            });
        }
        let me = self.arc();
        tokio::spawn(async move {
            for row in provisioned {
                me.start_tracked(row, 0).await;
            }
        });
        Ok(())
    }

    /// Whether `pubkey` holds `bits` (or owns the community) in the community
    /// an invite resolves to, per a fresh fold of its Control Plane.
    pub async fn authorizes(&self, invite_url: &str, pubkey: &str, bits: u64) -> anyhow::Result<bool> {
        let bootstrap = self.bootstrap_relays(&Hub::new(Keys::generate()), invite_url).await?;
        let joined = resolve_invite(invite_url, &bootstrap).await?;
        let relays = self.guarded(&Hub::new(Keys::generate()), &joined.membership.relays).await;
        let client = ConcordClient::new(joined.membership, Arc::new(relays), Keys::generate());
        client.sync_control().await?;
        Ok(client.is_authorized(pubkey, bits))
    }

    /// Mint the identity of a bridge the server importer created and mark it
    /// active — no in-channel confirm, because the portal custodially owns the
    /// imported community, so the consent that gate exists for is implicit.
    ///
    /// Split from starting because a private channel's key has to reach this
    /// npub before the bridge boots: `start` takes key delivery once, at boot.
    pub async fn provision_imported(&self, row: &BridgeRow) -> anyhow::Result<BridgeRow> {
        self.provision(row, "active", None).await
    }

    /// Start an already-provisioned bridge. Safe to retry: `start` is idempotent.
    pub async fn start_imported(&self, row: &BridgeRow) -> anyhow::Result<()> {
        self.start(row).await
    }

    fn start<'a>(&'a self, row: &'a BridgeRow) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>> {
        Box::pin(stage("starting the bridge", START_DEADLINE, self.start_inner(row)))
    }

    async fn start_inner(&self, row: &BridgeRow) -> anyhow::Result<()> {
        if self.is_live(&row.bridge_id) {
            return Ok(());
        }
        // An active bridge mirrors through the shared gateway, so without it
        // there is nothing to attach: defer before folding a whole community.
        if row.status == "active" && self.adapter().is_none() {
            return Err(GatewayUnavailable.into());
        }
        // Before any relay work: nothing it brings up could reach Discord.
        if let (Some(adapter), Some(guild)) = (self.adapter(), row.discord_guild_id.as_deref())
            && adapter.in_guild(guild) == Some(false)
        {
            return Err(BotRemoved.into());
        }
        let (Some(invite_sealed), Some(master_sealed), Some(primary_sealed)) =
            (&row.invite_url_sealed, &row.master_secret_sealed, &row.primary_sk_sealed)
        else {
            bail!("bridge is missing sealed key material");
        };
        let invite_url = unseal(&self.env.seal_key_hex, invite_sealed)?;
        let bootstrap = stage("vetting bootstrap relays", STAGE_DNS, self.bootstrap_relays(&self.bootstrap, &invite_url)).await?;
        let joined = stage("resolving the invite", STAGE_RELAY, resolve_invite(&invite_url, &bootstrap)).await?;
        let membership = joined.membership;

        let primary = Keys::new(SecretKey::from_hex(&unseal(&self.env.seal_key_hex, primary_sealed)?)?);
        // The Control Plane is folded once per community, before any key is
        // accepted: it reads from the root the invite carried, so the roster —
        // and with it, who may vend a channel key — is knowable first.
        let community = self.community(&membership).await?;
        let relays = &community.relays;
        // NIP-42 as the bridge's own npub too: relays that gate kind 1059 serve
        // a giftwrap only to the pubkey it is addressed to, and the Direct
        // Invites carrying private-channel keys are addressed to this npub.
        // Under a random identity the bridge could never read its own key
        // deliveries — every private channel an import admitted it to failed
        // "concord channel not found" on every start (2026-09-24).
        relays.register_auth_keys(vec![primary.clone()]);
        let folded = community.runtime.folded().context("community has no fold")?;
        let floor = relays.with_urls(invite_delivery_relays(&[]));
        floor.register_auth_keys(vec![primary.clone()]);
        let owner = membership.owner.clone();
        let intake = stage("scanning for direct invites", STAGE_RELAY, async {
            Ok(intake_direct_invite_keys(&[relays, &floor], &primary, &membership, |pk| {
                folded.roster.is_authorized(pk, &owner, perm::MANAGE_CHANNELS)
            })
            .await)
        })
        .await?;
        // This bridge's keys only: see bridge::community on why they are never pooled.
        let client = community.runtime.client_for(intake.community, primary.clone());

        let channel_id = row.concord_channel_id.as_deref().context("bridge has no concord channel")?;
        // The shared fold is live, but only as live as the last edition to
        // arrive: an import publishes a channel and starts its bridge moments
        // later. A miss earns one fresh fold (shared with the community) first.
        let channel = match client.channel(channel_id) {
            Some(channel) => Some(channel),
            None => {
                stage("re-folding the control plane", STAGE_RELAY, client.sync_control()).await?;
                client.channel(channel_id)
            }
        }
        .context("concord channel not found (deleted, or key not held)")?;

        // Refresh display names each start, so renames heal. A failed lookup is
        // None, and writing None over a correct name blanked the dashboard on
        // one rate-limited boot; keep what we knew unless Discord answered.
        let adapter = self.adapter();
        let (discord_name, guild_name) = match &adapter {
            Some(a) => {
                let calls = &self.discord_calls;
                let known = |name: Option<String>| {
                    let counter = if name.is_some() { &calls.names_known } else { &calls.names_fetched };
                    counter.fetch_add(1, Ordering::Relaxed);
                    name
                };
                // The gateway's directory first. REST is the fallback, and
                // cosmetic, so bounded and best-effort: a lookup queued behind
                // Discord's ratelimiter has no deadline of its own, and once
                // held a boot worker, and every bridge queued behind it, forever.
                let channel_name = async {
                    let id = row.discord_channel_id.as_deref()?;
                    match known(a.known_channel_name(id)) {
                        Some(name) => Some(name),
                        None => tokio::time::timeout(STAGE_NAMES, a.channel_name(id)).await.ok()?.ok(),
                    }
                };
                let guild_name = async {
                    let id = row.discord_guild_id.as_deref()?;
                    match known(a.known_guild_name(id)) {
                        Some(name) => Some(name),
                        None => tokio::time::timeout(STAGE_NAMES, a.guild_name(id)).await.ok()?.ok(),
                    }
                };
                tokio::join!(channel_name, guild_name)
            }
            None => (None, None),
        };
        stage("waiting for a database connection", STAGE_DB, async { Ok(self.pool.get().await?) })
            .await?
            .execute(
                "UPDATE bridges SET concord_channel_name = $2,
                   discord_channel_name = coalesce($3, discord_channel_name),
                   discord_guild_name = coalesce($4, discord_guild_name)
                 WHERE bridge_id = ($1::text)::uuid",
                &[&row.bridge_id, &channel.name, &discord_name, &guild_name],
            )
            .await?;

        // Four announcements nothing below reads: the join, our giftwrap inbox
        // (so the next key handoff reaches relays we watch), the bot profile,
        // and the command manifest. Awaited in sequence they cost up to four
        // publish timeouts with routing unattached, so they run on their own.
        {
            let client = client.clone();
            let relays_list = membership.relays.clone();
            let picture = adapter.as_ref().and_then(|a| a.bot_avatar_url());
            tokio::spawn(async move {
                let primary = client.primary().clone();
                let mut profile = json!({
                    "name": "Discord <-> Armada Bridge Bot",
                    "about": "Automated bridge account: posts link confirmations and mirrors this channel with a Discord server.",
                    "bot": true,
                });
                if let Some(p) = picture {
                    profile["picture"] = json!(p);
                }
                let commands = bridge_commands();
                let _ = tokio::join!(
                    client.publish_join(now_ms(), None),
                    client.publish_dm_relays(&primary, &relays_list),
                    client.publish_profile(&primary, &profile),
                    client.publish_manifest(&commands),
                );
            });
        }

        let link = ChannelLink {
            discord_guild_id: row.discord_guild_id.clone().unwrap_or_default(),
            discord_channel_id: row.discord_channel_id.clone().unwrap_or_default(),
            community_id: membership.community_id.clone(),
            concord_channel_id_hex: channel.id_hex.clone(),
            enabled: true,
        };
        let status = if row.status == "active" { LiveStatus::Active } else { LiveStatus::PendingConfirm };
        let rb = Arc::new(Running {
            id: row.bridge_id.clone(),
            client: client.clone(),
            community,
            link,
            confirm_code: row.confirm_code.clone().unwrap_or_default(),
            channel: Mutex::new(channel.clone()),
            status: Mutex::new(status),
            router: RwLock::new(None),
            attachment: Mutex::new(None),
        });
        self.attach_chat(&rb, &channel);

        if status == LiveStatus::Active {
            let live_from_ms = now_ms();
            self.attach_routing(&rb, &unseal(&self.env.seal_key_hex, master_sealed)?, &row.options)?;
            let me = self.arc();
            let rb2 = rb.clone();
            tokio::spawn(async move {
                if let Err(error) = me.backfill_missed(&rb2).await {
                    tracing::warn!(bridge = %rb2.id, error = %format!("{error:#}"), "catch-up backfill failed");
                }
                if let Err(error) = me.catch_up_discord(&rb2, live_from_ms).await {
                    tracing::warn!(bridge = %rb2.id, error = %format!("{error:#}"), "Discord catch-up failed");
                }
            });
        } else {
            let content = self.confirm_request(row, &client, &rb.confirm_code).await?;
            stage("posting the confirm request", STAGE_RELAY, client.send_chat(&channel, SendChat::message(rb.primary(), content))).await?;
        }
        lock(&self.running).insert(rb.id.clone(), rb);
        Ok(())
    }

    /// The request a pending bridge posts in its Armada channel. A bridge
    /// linked with others names every channel of the group, because one
    /// confirm approves them all: a moderator must see what they enable.
    async fn confirm_request(&self, row: &BridgeRow, client: &ConcordClient, code: &str) -> anyhow::Result<String> {
        let disclosure = "Bridged messages LEAVE end-to-end encryption and are mirrored to Discord in plaintext.";
        let mut names = Vec::new();
        if let Some(group) = &row.link_group {
            let siblings = self
                .pool
                .get()
                .await?
                .query(
                    "SELECT concord_channel_id FROM bridges WHERE link_group = ($1::text)::uuid AND community_id = $2
                       AND confirm_code = $3 AND status = 'pending_confirm' ORDER BY created_at",
                    &[group, &row.community_id, &code],
                )
                .await?;
            for sibling in siblings {
                let id: Option<String> = sibling.get(0);
                let name = id.as_deref().and_then(|id| client.channel(id)).map_or_else(|| "an unknown channel".to_owned(), |c| format!("#{}", c.name));
                names.push(name);
            }
        }
        Ok(if names.len() > 1 {
            format!(
                "A Discord bridge requests to link {} channels of this community: {}. {disclosure} A member with Manage Channels \
                 can enable all of them by replying here or in any of them:\n/bridge confirm {code}",
                names.len(),
                names.join(", ")
            )
        } else {
            format!(
                "A Discord bridge requests to link this channel. {disclosure} A member with Manage Channels can enable it by replying:\n/bridge confirm {code}"
            )
        })
    }

    /// The runtime for `membership`'s community, opened if no bridge holds it.
    async fn community(&self, membership: &Membership) -> anyhow::Result<Arc<Community>> {
        let slot = {
            let mut slots = lock(&self.communities);
            slots.retain(|_, slot| Arc::strong_count(slot) > 1 || slot.try_lock().map_or(true, |s| s.live.strong_count() > 0));
            slots.entry(community_key(membership)).or_default().clone()
        };
        let mut slot = slot.lock().await;
        if let Some(live) = slot.live.upgrade() {
            return Ok(live);
        }
        if let Some((at, error)) = &slot.failed
            && at.elapsed() < COMMUNITY_REOPEN_AFTER
        {
            bail!("opening the community failed {}s ago: {error}", at.elapsed().as_secs());
        }
        let opened = async {
            let hub = self.communities_hub.clone();
            let relays = stage("vetting community relays", STAGE_DNS, async { Ok(self.guarded(&hub, &membership.relays).await) }).await?;
            let store = self.store.clone();
            let community_id = membership.community_id.clone();
            let on_cursor: bridge::client::CursorHandler = Arc::new(move |stream_pk: String, at: u64| {
                let (store, community_id) = (store.clone(), community_id.clone());
                tokio::spawn(async move {
                    let _ = store.cursor_set(&community_id, &stream_pk, at).await;
                });
            });
            let runtime =
                stage("folding the control plane", STAGE_RELAY, CommunityRuntime::open(membership.clone(), Arc::new(relays.clone()), Some(on_cursor))).await?;
            // A fold with no channels is no relay having answered, not a
            // community without channels: one has a bridge into it. Kept, it
            // would fail every bridge of the community "channel not found"
            // until the live fold caught up.
            if runtime.folded().is_none_or(|f| f.channels.is_empty()) {
                bail!("the control plane came back empty");
            }
            Ok(Arc::new(Community { runtime, relays }))
        };
        match opened.await {
            Ok(community) => {
                *slot = CommunitySlot { live: Arc::downgrade(&community), failed: None };
                Ok(community)
            }
            Err(error) => {
                slot.failed = Some((Instant::now(), format!("{error:#}")));
                Err(error)
            }
        }
    }

    /// Deliver the bridge's channel chat to its handler, over its community's
    /// shared subscription (which also follows rekeys).
    fn attach_chat(&self, rb: &Arc<Running>, channel: &ChannelView) {
        let (me, weak_rb) = (self.me.clone(), Arc::downgrade(rb));
        let on_chat = Arc::new(move |chat: OpenedChat| {
            let (Some(me), Some(rb)) = (me.upgrade(), weak_rb.upgrade()) else { return };
            tokio::spawn(async move {
                if let Err(error) = me.on_concord_chat(&rb, chat).await {
                    tracing::error!(bridge = %rb.id, error = %format!("{error:#}"), "concord handler failed");
                }
            });
        });
        *lock(&rb.attachment) = Some(rb.community.runtime.attach(&rb.id, rb.client.clone(), channel.clone(), on_chat));
    }

    /// Bounded catch-up after downtime: replay wraps newer than the stored
    /// cursor through the router (the mapping table dedupes). A channel with no
    /// cursor has never been tailed and starts live-only, deliberately, so a
    /// fresh bridge does not replay stored history into Discord.
    async fn backfill_missed(&self, rb: &Arc<Running>) -> anyhow::Result<()> {
        let channel = rb.channel();
        let stream_pks: Vec<String> = channel.streams.iter().map(|s| s.key.pk_hex()).collect();
        let Some(cursor) = self.store.cursor_get(&rb.link.community_id, &stream_pks).await? else { return Ok(()) };
        // A small overlap absorbs relay clock skew; dedupe eats the rest.
        let (chats, newest) = rb.client.backfill_channel(&channel, cursor.saturating_sub(60), 500).await?;
        let mut mirrored = 0;
        for chat in chats {
            let Some(router) = rb.router() else { break };
            match router.on_concord_chat(&chat, &rb.link).await {
                Ok(ids) if !ids.is_empty() => mirrored += 1,
                Ok(_) => {}
                Err(error) if is_missing_permissions(&error) => self.alert_missing_webhook_permission(rb).await,
                Err(error) => tracing::warn!(bridge = %rb.id, rumor = %chat.rumor_id(), error = %format!("{error:#}"), "backfill mirror failed"),
            }
        }
        if let Some(newest) = newest {
            for pk in &stream_pks {
                let _ = self.store.cursor_set(&rb.link.community_id, pk, newest).await;
            }
        }
        if mirrored > 0 {
            tracing::info!(bridge = %rb.id, mirrored, "backfilled missed messages");
        }
        Ok(())
    }

    /// Discord-side catch-up after downtime: replay what the Discord channel
    /// said since the newest message this bridge mirrored in either direction.
    ///
    /// The gateway only delivers what happens while connected, so every restart
    /// dropped whatever Discord said meanwhile — seven hours of it on
    /// 2026-09-23. A channel with nothing mirrored yet has no anchor and is left
    /// alone: history is the importer's job, not a restart's. Stops at
    /// `live_from_ms`, when routing attached, or it would race the live path.
    async fn catch_up_discord(&self, rb: &Arc<Running>, live_from_ms: u64) -> anyhow::Result<()> {
        if self.env.discord_bot_token.is_empty() || rb.router().is_none() {
            return Ok(());
        }
        let db = self.pool.get().await?;
        // A channel whose history import hasn't finished belongs to the
        // importer, which publishes oldest first: mid-run the largest mirrored
        // snowflake is wherever it had got to, and a catch-up from there races
        // it over the same messages with only a check-then-insert between them.
        let importing = db
            .query_opt(
                "SELECT 1 FROM imports i, jsonb_array_elements(i.plan->'channels') c
                 WHERE i.status IN ('publishing', 'wiring', 'history')
                   AND c->>'discordId' = $1
                   AND (c->>'history')::boolean AND c->>'historyDoneAt' IS NULL
                 LIMIT 1",
                &[&rb.link.discord_channel_id],
            )
            .await?;
        if importing.is_some() {
            return Ok(());
        }
        // The same for history the channel map asked for: the copy reads the
        // channel up to now, so what a catch-up would replay is in it anyway.
        let copying = db
            .query_opt(
                "SELECT 1 FROM bridges WHERE bridge_id = ($1::text)::uuid
                   AND history->>'direction' = 'discord' AND history->>'state' IN ('pending', 'running')",
                &[&rb.id],
            )
            .await?;
        if copying.is_some() {
            return Ok(());
        }
        // The anchor is the largest snowflake mirrored, never the newest row:
        // created_at is when WE wrote a row, and a history import writes old
        // messages now. The snowflake is Discord's own clock.
        //
        // Or the newest message a previous catch-up read, if later. Messages
        // it read and skipped (bots, commands, failures) leave no row, so a
        // channel whose newest traffic is never mirrored kept its anchor where
        // it was and re-read the same 500 messages on every boot (two bridges,
        // every boot of 2026-10-15/16). An operator's DISCORD_CATCHUP_SINCE
        // asks to replay from an older point on purpose, so it ignores this.
        let before_ms = self.env.catch_up_since_ms.unwrap_or(now_ms() as i64);
        let honour_mark = self.env.catch_up_since_ms.is_none();
        let anchor: Option<String> = db
            .query_one(
                "SELECT greatest(
                   (SELECT max(discord_message_id::numeric) FROM messages
                    WHERE tenant_id = 'default' AND discord_channel_id = $1 AND community_id = $2
                      AND created_at < to_timestamp($3::bigint / 1000.0)),
                   (SELECT (options->>'discordCaughtUpTo')::numeric FROM bridges
                    WHERE $4 AND bridge_id = ($5::text)::uuid AND options->>'discordCaughtUpTo' ~ '^[0-9]+$')
                 )::text AS anchor",
                &[&rb.link.discord_channel_id, &rb.link.community_id, &before_ms, &honour_mark, &rb.id],
            )
            .await?
            .get(0);
        drop(db);
        let Some(anchor) = anchor else { return Ok(()) };
        let adapter = self.adapter();
        // The bot was removed from the server: REST can only answer 403.
        if adapter.as_ref().and_then(|a| a.in_guild(&rb.link.discord_guild_id)) == Some(false) {
            return Ok(());
        }
        let last_known = adapter.and_then(|a| a.last_message_id(&rb.link.discord_channel_id));
        if !catch_up_needed(&anchor, last_known) {
            self.discord_calls.catch_ups_skipped.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        self.discord_calls.catch_ups_fetched.fetch_add(1, Ordering::Relaxed);
        let io = CatchUp { manager: self, rb };
        let result = replay_discord_since(&anchor, live_from_ms as i64, DISCORD_CATCHUP_MAX, &io).await;
        if result.mirrored > 0 {
            tracing::info!(bridge = %rb.id, mirrored = result.mirrored, "caught up missed Discord messages");
        }
        if result.capped {
            tracing::warn!(bridge = %rb.id, "Discord catch-up stopped at {DISCORD_CATCHUP_MAX} messages");
        }
        if let Some(read_to) = result.read_to.filter(|_| honour_mark) {
            self.pool
                .get()
                .await?
                .execute(
                    "UPDATE bridges SET options = options || jsonb_build_object('discordCaughtUpTo', $2::text) WHERE bridge_id = ($1::text)::uuid",
                    &[&rb.id, &read_to],
                )
                .await?;
        }
        Ok(())
    }
}

struct CatchUp<'a> {
    manager: &'a BridgeManager,
    rb: &'a Arc<Running>,
}

#[async_trait]
impl CatchUpIo for CatchUp<'_> {
    async fn fetch_after(&self, after_id: &str) -> Option<Vec<RestMessage>> {
        let m = self.manager;
        m.rest.bot_channel_messages_after(&m.env.discord_bot_token, &self.rb.link.discord_channel_id, after_id, 100).await.ok().flatten()
    }

    async fn already_mirrored(&self, message_id: &str) -> bool {
        let Ok(db) = self.manager.pool.get().await else { return false };
        db.query_opt(
            "SELECT 1 FROM messages WHERE tenant_id = 'default' AND discord_message_id = $1 AND community_id = $2 LIMIT 1",
            &[&message_id, &self.rb.link.community_id],
        )
        .await
        .is_ok_and(|r| r.is_some())
    }

    async fn mirror(&self, message: &RestMessage) -> bool {
        // A bridge stopped mid-replay has no router; the rest is moot.
        let Some(router) = self.rb.router() else { return false };
        let link = &self.rb.link;
        let inbound = rest_to_inbound(message, &link.discord_guild_id, &link.discord_channel_id);
        match router.on_discord_message(inbound, link).await {
            Ok(rumor) => rumor.is_some(),
            Err(error) => {
                tracing::warn!(bridge = %self.rb.id, message = %message.id, error = %format!("{error:#}"), "catch-up of Discord message failed");
                false
            }
        }
    }
}

impl BridgeManager {
    async fn on_concord_chat(&self, rb: &Arc<Running>, chat: OpenedChat) -> anyhow::Result<()> {
        if rb.status() == LiveStatus::PendingConfirm {
            let Some(code) = (chat.kind() == concord::kinds::MESSAGE).then(|| CONFIRM_RE.captures(chat.content().trim())).flatten() else {
                return Ok(());
            };
            if !code[1].eq_ignore_ascii_case(&rb.confirm_code) || !rb.client.is_authorized(chat.author(), perm::MANAGE_CHANNELS) {
                return Ok(());
            }
            // The whole group the channel was linked with goes live together:
            // its request named every channel in it (see `confirm_request`).
            // Bounded to the same community and code, so a group id can never
            // reach past what that message showed.
            let sql = format!(
                "UPDATE bridges SET status = 'active', status_detail = NULL, updated_at = now()
                 WHERE status = 'pending_confirm' AND (bridge_id = ($1::text)::uuid OR (
                   link_group IS NOT NULL
                   AND link_group = (SELECT link_group FROM bridges WHERE bridge_id = ($1::text)::uuid)
                   AND community_id = $2 AND confirm_code = $3))
                 RETURNING {BRIDGE_COLUMNS}"
            );
            let rows: Vec<BridgeRow> = self
                .pool
                .get()
                .await?
                .query(&sql, &[&rb.id, &rb.link.community_id, &rb.confirm_code])
                .await?
                .iter()
                .map(BridgeRow::from_row)
                .collect();
            for row in rows {
                let Some(target) = lock(&self.running).get(&row.bridge_id).cloned() else {
                    // Not running here (failing to start): it is active now,
                    // and routing attaches on its next start.
                    continue;
                };
                *lock(&target.status) = LiveStatus::Active;
                let master = unseal(&self.env.seal_key_hex, row.master_secret_sealed.as_deref().context("no master secret")?)?;
                if let Err(error) = self.attach_routing(&target, &master, &row.options) {
                    if error.is::<GatewayUnavailable>() {
                        // Confirmed while the gateway was down. The row stays
                        // active and routing attaches on reconnect. Don't sever,
                        // and don't claim it's live.
                        tracing::warn!(bridge = %target.id, "confirmed while Discord gateway down; will attach on reconnect");
                        continue;
                    }
                    return Err(error);
                }
                let _ = target
                    .client
                    .send_chat(&target.channel(), SendChat::message(target.primary(), "Bridge confirmed. This channel is now mirrored with Discord."))
                    .await;
            }
            return Ok(());
        }
        let Some(router) = rb.router() else { return Ok(()) };
        match router.on_concord_chat(&chat, &rb.link).await {
            Err(error) if is_missing_permissions(&error) => {
                self.alert_missing_webhook_permission(rb).await;
                Ok(())
            }
            other => other.map(drop),
        }
    }

    /// One-time alert that the bot cannot mirror into its Discord channel for
    /// want of Manage Webhooks. Claimed on the row first (survives restarts,
    /// fires once), then announced where people will see it: the Concord
    /// channel, which always works, and best effort the Discord channel itself
    /// (a plain bot message needs only Send Messages). The bridge stays active;
    /// mirroring resumes on its own once the permission is granted.
    async fn alert_missing_webhook_permission(&self, rb: &Arc<Running>) {
        let detail = "the bot is missing Manage Webhooks in the linked Discord channel; Armada messages can't mirror there until it's granted";
        let claimed = async {
            self.pool
                .get()
                .await?
                .query_opt(
                    "UPDATE bridges SET perm_alerted_at = now(), status_detail = $2
                     WHERE bridge_id = ($1::text)::uuid AND perm_alerted_at IS NULL RETURNING 1",
                    &[&rb.id, &detail],
                )
                .await
                .map_err(anyhow::Error::from)
        };
        if !matches!(claimed.await, Ok(Some(_))) {
            return;
        }
        tracing::warn!(bridge = %rb.id, "{detail}");
        let text = "Heads up: the Discord bridge bot is missing the \"Manage Webhooks\" permission in the linked channel, so \
                    messages from here aren't being mirrored to Discord. A Discord admin can grant the bot Manage Webhooks on \
                    that channel to restore it.";
        let _ = rb.client.send_chat(&rb.channel(), SendChat::message(rb.primary(), text)).await;
        if let Some(adapter) = self.adapter() {
            let _ = adapter
                .notice(&rb.link.discord_channel_id, "I can't mirror Armada messages into this channel until I'm granted the \"Manage Webhooks\" permission here.")
                .await;
        }
    }

    fn attach_routing(&self, rb: &Arc<Running>, master_secret_hex: &str, options: &Value) -> anyhow::Result<()> {
        // The boot path guards this earlier; this covers a live confirm that
        // races the gateway being down. Erroring — never severing — is the
        // point: a missing gateway is not the community going away.
        let adapter = self.adapter().ok_or(GatewayUnavailable)?;
        let mut router_options = RouterOptions { bridge_edits: options.get("edits") == Some(&Value::Bool(true)), ..Default::default() };
        if !self.env.blossom_server.is_empty() {
            let servers = bridge::blossom::blossom_servers(&self.env.blossom_server);
            router_options.blobs = Some(Arc::new(bridge::blossom::BlossomStore::new(servers)?));
        }
        if !self.env.klipy_api_key.is_empty() {
            router_options.klipy = Some(Arc::new(bridge::klipy::KlipyClient::new(self.env.klipy_api_key.clone(), reqwest::Client::new())));
        }
        let router = BridgeRouter::new(
            rb.client.clone(),
            PuppetCache::new(master_secret_hex),
            self.store.clone() as Arc<dyn MappingStore>,
            adapter.clone(),
            Arc::new(Kind0ProfileResolver::new(rb.client.relays().clone())),
            SelfIds { application_id: adapter.application_id(), webhook_ids: adapter.own_webhook_ids() },
            router_options,
        );
        *rb.router.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(router));
        lock(&self.by_discord_channel).insert(rb.link.discord_channel_id.clone(), rb.id.clone());
        let (me, rb) = (self.arc(), rb.clone());
        tokio::spawn(async move {
            me.announce_bridge(&rb).await;
            // After the welcome, so a copy of Armada history lands below it.
            me.resume_history(&rb).await;
        });
        Ok(())
    }

    /// One-time welcome in both directions when a bridge goes live. Once per
    /// bridge EVER, not per process: routing re-attaches on every restart, so
    /// the sent-ness is claimed on the row first. A crash between claim and
    /// send drops the welcome, the better failure than greeting on every deploy.
    async fn announce_bridge(&self, rb: &Arc<Running>) {
        let claimed = async {
            self.pool
                .get()
                .await?
                .query_opt("UPDATE bridges SET announced_at = now() WHERE bridge_id = ($1::text)::uuid AND announced_at IS NULL RETURNING 1", &[&rb.id])
                .await
                .map_err(anyhow::Error::from)
        };
        if !matches!(claimed.await, Ok(Some(_))) {
            return;
        }
        let _ = rb.client.send_chat(&rb.channel(), SendChat::message(rb.primary(), "This channel is now mirrored with Discord.")).await;
        if let Some(adapter) = self.adapter() {
            let message = WebhookMessage {
                username: "Armada Bridge".into(),
                content: "This channel is now mirrored with an Armada community. /help lists what this bot answers.".into(),
                ..Default::default()
            };
            let _ = bridge::router::WebhookSender::send(adapter.as_ref(), &rb.link, message).await;
        }
    }

    pub async fn stop(&self, bridge_id: &str, status: &str, detail: Option<&str>) -> anyhow::Result<()> {
        self.cancel_start_retry(bridge_id);
        if let Some(rb) = lock(&self.running).remove(bridge_id) {
            rb.halt();
            let mut by_channel = lock(&self.by_discord_channel);
            if by_channel.get(&rb.link.discord_channel_id) == Some(&rb.id) {
                by_channel.remove(&rb.link.discord_channel_id);
            }
        }
        let db = self.pool.get().await?;
        if status == "unlinked" {
            db.execute(
                "UPDATE bridges SET status = 'unlinked', status_detail = $2, invite_url_sealed = NULL,
                   master_secret_sealed = NULL, primary_sk_sealed = NULL, options = options - 'pausedFor' - 'resumeTo', updated_at = now()
                 WHERE bridge_id = ($1::text)::uuid",
                &[&bridge_id, &detail],
            )
            .await?;
        } else {
            db.execute(
                "UPDATE bridges SET status = $2, status_detail = $3, options = options - 'pausedFor' - 'resumeTo', updated_at = now()
                 WHERE bridge_id = ($1::text)::uuid",
                &[&bridge_id, &status, &detail],
            )
            .await?;
        }
        Ok(())
    }

    pub async fn resume(&self, bridge_id: &str) -> anyhow::Result<()> {
        let row = bridge_by_id(&self.pool, bridge_id).await?.context("no such bridge")?;
        // A pause the portal made records what it paused, so a pending link
        // stays pending (still owed its in-channel confirm) when resumed by hand.
        let resume_to = row.options.get(RESUME_TO).and_then(Value::as_str);
        let next = if row.status == "paused" && resume_to == Some("pending_confirm") {
            "pending_confirm"
        } else if row.status == "paused" {
            "active"
        } else if row.confirm_code.is_some() && !self.is_live(bridge_id) {
            "pending_confirm"
        } else {
            "active"
        };
        self.pool
            .get()
            .await?
            .execute(
                "UPDATE bridges SET status = $2, options = options - 'pausedFor' - 'resumeTo', updated_at = now() WHERE bridge_id = ($1::text)::uuid",
                &[&bridge_id, &next],
            )
            .await?;
        let fresh = bridge_by_id(&self.pool, bridge_id).await?.context("no such bridge")?;
        self.start_tracked(fresh, 0).await;
        Ok(())
    }

    /// `start` with failure treated as transient rather than terminal. A start
    /// that throws leaves the row in its status — still holding the
    /// one-bridge-per-channel slot, so no duplicate can be minted mid-outage —
    /// records when the failing streak began (in options, so it survives
    /// restarts), and retries with backoff. A sever only happens once the streak
    /// outlives START_FAILURE_SEVER_AFTER: a single relay window where nobody
    /// answered used to sever permanently, and severed rows are never retried.
    fn start_tracked(&self, row: BridgeRow, attempt: u32) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            if self.is_live(&row.bridge_id) {
                return;
            }
            match self.start(&row).await {
                Ok(()) => {
                    // Started: failing to clear the marker is not a failed start.
                    if let Err(error) = self.clear_start_failure(&row).await {
                        tracing::warn!(bridge = %row.bridge_id, error = %format!("{error:#}"), "could not clear start-failure marker");
                    }
                }
                Err(error) if error.is::<BotRemoved>() => {
                    if let Err(error) = self.pause_bot_removed(&row.bridge_id, &row.status).await {
                        tracing::error!(bridge = %row.bridge_id, error = %format!("{error:#}"), "could not pause a bridge whose server removed the bot");
                    }
                }
                Err(error) if error.is::<GatewayUnavailable>() => {
                    // Not a start failure: the community is fine, the local
                    // gateway is down. Retry without touching the sever streak.
                    tracing::warn!(bridge = %row.bridge_id, attempt = attempt + 1, "deferring start, Discord gateway down");
                    self.schedule_start_retry(&row.bridge_id, attempt);
                }
                Err(error) => {
                    // The bookkeeping is best-effort; the retry is not. A throw
                    // here once killed the process 70 minutes into a boot.
                    if let Err(bookkeeping) = self.handle_start_failure(&row, &format!("{error:#}"), attempt).await {
                        tracing::error!(bridge = %row.bridge_id, error = %bookkeeping, "could not record start failure; retrying anyway");
                        self.schedule_start_retry(&row.bridge_id, attempt);
                    }
                }
            }
        })
    }

    /// Pause a bridge whose Discord server the bot is no longer in, marked as
    /// the portal's pause so `resume_bot_removed` can lift it. A person's pause
    /// carries no mark and is never lifted for them.
    async fn pause_bot_removed(&self, bridge_id: &str, was: &str) -> anyhow::Result<()> {
        self.stop(bridge_id, "paused", Some(BOT_REMOVED_DETAIL)).await?;
        self.pool
            .get()
            .await?
            .execute(
                "UPDATE bridges SET options = (options - 'startFailedAt') || jsonb_build_object($2::text, $3::text, $4::text, $5::text)
                 WHERE bridge_id = ($1::text)::uuid",
                &[&bridge_id, &PAUSED_FOR, &BOT_REMOVED, &RESUME_TO, &was],
            )
            .await?;
        self.discord_calls.removed.fetch_add(1, Ordering::Relaxed);
        tracing::info!(bridge = %bridge_id, "paused: the bot was removed from its Discord server");
        Ok(())
    }

    /// Servers holding bridges the portal paused because the bot was removed.
    async fn bot_removed_guilds(&self) -> anyhow::Result<Vec<String>> {
        let rows = self
            .pool
            .get()
            .await?
            .query(
                "SELECT DISTINCT discord_guild_id FROM bridges
                 WHERE status = 'paused' AND options->>'pausedFor' = $1 AND discord_guild_id IS NOT NULL",
                &[&BOT_REMOVED],
            )
            .await?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }

    /// The bot is in `guild_id` again: put back every bridge there the portal
    /// paused for its absence, as it was, and return them to start. One whose
    /// channel has since been linked by another bridge stays paused: the
    /// one-bridge-per-channel index would refuse it, and the newer link wins.
    async fn resume_bot_removed(&self, guild_id: &str) -> anyhow::Result<Vec<BridgeRow>> {
        let sql = format!(
            "UPDATE bridges b SET status = CASE WHEN b.options->>'resumeTo' = 'pending_confirm' THEN 'pending_confirm' ELSE 'active' END,
               status_detail = NULL, options = b.options - 'pausedFor' - 'resumeTo', updated_at = now()
             WHERE b.status = 'paused' AND b.options->>'pausedFor' = $2 AND b.discord_guild_id = $1
               AND NOT EXISTS (
                 SELECT 1 FROM bridges o WHERE (o.discord_channel_id = b.discord_channel_id
                     OR (o.community_id = b.community_id AND o.concord_channel_id = b.concord_channel_id))
                   AND o.status IN ('pending_confirm', 'active') AND o.bridge_id <> b.bridge_id)
             RETURNING {}",
            BRIDGE_COLUMNS.replace("bridge_id::text", "b.bridge_id::text")
        );
        let rows: Vec<BridgeRow> = self.pool.get().await?.query(&sql, &[&guild_id, &BOT_REMOVED]).await?.iter().map(BridgeRow::from_row).collect();
        if !rows.is_empty() {
            tracing::info!(guild = guild_id, count = rows.len(), "bot is back in a Discord server; resuming its bridges");
        }
        Ok(rows)
    }

    /// GUILD_DELETE for a server the bot was removed from: pause what runs there.
    async fn on_guild_removed(&self, guild_id: &str) {
        let affected: Vec<(String, LiveStatus)> =
            lock(&self.running).values().filter(|rb| rb.link.discord_guild_id == guild_id).map(|rb| (rb.id.clone(), rb.status())).collect();
        for (id, status) in affected {
            let was = if status == LiveStatus::PendingConfirm { "pending_confirm" } else { "active" };
            if let Err(error) = self.pause_bot_removed(&id, was).await {
                tracing::error!(bridge = %id, error = %format!("{error:#}"), "could not pause a bridge whose server removed the bot");
            }
        }
    }

    /// GUILD_CREATE: on connect for every server, and when the bot is added to
    /// one. Boot handles the first kind itself; after it, this resumes.
    async fn on_guild_available(&self, guild_id: &str) {
        if !self.booted.load(Ordering::SeqCst) {
            return;
        }
        match self.resume_bot_removed(guild_id).await {
            Ok(rows) => {
                for row in rows {
                    self.start_tracked(row, 0).await;
                }
            }
            Err(error) => tracing::error!(guild = guild_id, error = %format!("{error:#}"), "could not resume bridges for a server the bot rejoined"),
        }
    }

    async fn handle_start_failure(&self, row: &BridgeRow, detail: &str, attempt: u32) -> anyhow::Result<()> {
        let db = self.pool.get().await?;
        // A marker that is not a timestamp counts as none, and is replaced.
        let streak = db
            .query_one(
                "SELECT CASE WHEN options->>'startFailedAt' ~ '^\\d{4}-\\d{2}-\\d{2}T'
                        THEN (options->>'startFailedAt')::timestamptz <= now() - $2::text::interval END AS expired
                 FROM bridges WHERE bridge_id = ($1::text)::uuid",
                &[&row.bridge_id, &START_FAILURE_SEVER_AFTER],
            )
            .await?;
        match streak.get::<_, Option<bool>>("expired") {
            Some(true) => return self.mark_severed(&row.bridge_id, detail).await,
            Some(false) => {
                db.execute("UPDATE bridges SET status_detail = $2, updated_at = now() WHERE bridge_id = ($1::text)::uuid", &[&row.bridge_id, &detail])
                    .await?;
            }
            None => {
                db.execute(
                    "UPDATE bridges SET options = options || jsonb_build_object('startFailedAt',
                       to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')),
                       status_detail = $2, updated_at = now()
                     WHERE bridge_id = ($1::text)::uuid",
                    &[&row.bridge_id, &detail],
                )
                .await?;
            }
        }
        tracing::warn!(bridge = %row.bridge_id, attempt = attempt + 1, "start failed, will retry: {detail}");
        self.schedule_start_retry(&row.bridge_id, attempt);
        Ok(())
    }

    fn schedule_start_retry(&self, bridge_id: &str, attempt: u32) {
        let mut timers = lock(&self.start_retries);
        if timers.get(bridge_id).is_some_and(|t| !t.is_finished()) {
            return;
        }
        let delay = jittered(START_RETRY_BASE, START_RETRY_MAX, attempt);
        let (me, id) = (self.me.clone(), bridge_id.to_owned());
        let timer = tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let Some(me) = me.upgrade() else { return };
            lock(&me.start_retries).remove(&id);
            if let Err(error) = me.retry_start(&id, attempt + 1).await {
                tracing::error!(bridge = %id, error = %format!("{error:#}"), "retry failed before starting; rescheduling");
                me.schedule_start_retry(&id, attempt + 1);
            }
        });
        timers.insert(bridge_id.to_owned(), timer);
    }

    async fn retry_start(&self, bridge_id: &str, attempt: u32) -> anyhow::Result<()> {
        if self.is_live(bridge_id) {
            return Ok(());
        }
        // Re-read the row: an operator may have paused or unlinked the bridge
        // while the retry was pending, and that decision wins.
        let Some(row) = bridge_by_id(&self.pool, bridge_id).await? else { return Ok(()) };
        if row.status == "active" || row.status == "pending_confirm" {
            self.start_tracked(row, attempt).await;
        }
        Ok(())
    }

    fn cancel_start_retry(&self, bridge_id: &str) {
        if let Some(timer) = lock(&self.start_retries).remove(bridge_id) {
            timer.abort();
        }
    }

    async fn clear_start_failure(&self, row: &BridgeRow) -> anyhow::Result<()> {
        self.cancel_start_retry(&row.bridge_id);
        if row.options.get("startFailedAt").is_none() {
            return Ok(());
        }
        tracing::info!(bridge = %row.bridge_id, "recovered from failing start");
        self.pool
            .get()
            .await?
            .execute(
                "UPDATE bridges SET options = options - 'startFailedAt', status_detail = NULL, updated_at = now() WHERE bridge_id = ($1::text)::uuid",
                &[&row.bridge_id],
            )
            .await?;
        Ok(())
    }

    async fn mark_severed(&self, bridge_id: &str, detail: &str) -> anyhow::Result<()> {
        self.cancel_start_retry(bridge_id);
        tracing::error!(bridge = %bridge_id, "severed: {detail}");
        // Drop the streak marker so a manual resume after a sever starts a
        // fresh grace window instead of instantly re-severing on one failure.
        self.pool
            .get()
            .await?
            .execute(
                "UPDATE bridges SET status = 'severed', status_detail = $2, options = options - 'startFailedAt', updated_at = now()
                 WHERE bridge_id = ($1::text)::uuid",
                &[&bridge_id, &detail],
            )
            .await?;
        Ok(())
    }

    fn help_text() -> &'static str {
        "Commands: /bridge confirm <code> approves a pending bridge link (Armada side)."
    }

    /// Any `/command` posted in a bridged channel is answered, never silently
    /// swallowed; unbridged channels stay silent.
    ///
    /// Only a human typing in Discord issues a command. Our webhook relays
    /// Armada messages verbatim, so a `/claim` sent from Armada arrives here as
    /// a webhook post; answering it — or any bot, our own replies included —
    /// let a reply that itself began with `/claim` re-trigger forever.
    fn handle_bot_command(&self, msg: &CommandMessage) -> bool {
        if msg.author_bot || msg.webhook_id.is_some() {
            return false;
        }
        let Some(command) = parse_bot_command(&msg.content) else { return false };
        if self.active_router_for(&msg.channel_id).is_none() {
            return false; // not ours: another bot may own it
        }
        let Some(adapter) = self.adapter() else { return false };
        let (channel, id) = (msg.channel_id.clone(), msg.id.clone());
        tokio::spawn(async move {
            let text = if command == "help" { Self::help_text().to_owned() } else { format!("Unknown command /{command}. {}", Self::help_text()) };
            if let Err(error) = adapter.reply(&channel, &id, &text).await {
                tracing::error!(%command, error = %format!("{error:#}"), "command reply failed");
            }
        });
        true
    }
}

/// The gateway's view of the manager. Weak, so the adapter does not keep a
/// stopped manager alive.
struct ManagerEvents(Weak<BridgeManager>);

macro_rules! route {
    ($self:ident, $channel:expr, |$router:ident, $link:ident| $call:expr) => {{
        let Some(manager) = $self.0.upgrade() else { return };
        let Some((rb, $router)) = manager.active_router_for($channel) else { return };
        let $link = &rb.link;
        if let Err(error) = $call {
            if is_missing_permissions(&error) {
                manager.alert_missing_webhook_permission(&rb).await;
            } else {
                tracing::error!(bridge = %rb.id, error = %format!("{error:#}"), "discord handler failed");
            }
        }
    }};
}

#[async_trait]
impl DiscordEvents for ManagerEvents {
    async fn on_message(&self, msg: DiscordInboundMessage) {
        let channel = msg.channel_id.clone();
        route!(self, &channel, |router, link| router.on_discord_message(msg, link).await)
    }
    fn on_bot_command(&self, msg: &CommandMessage) -> bool {
        self.0.upgrade().is_some_and(|m| m.handle_bot_command(msg))
    }
    async fn on_message_update(&self, msg: DiscordInboundMessage) {
        route!(self, &msg.channel_id, |router, link| router.on_discord_edit(&msg, link).await)
    }
    async fn on_message_delete(&self, del: DiscordMessageDelete) {
        route!(self, &del.channel_id, |router, link| router.on_discord_delete(&del, link).await)
    }
    async fn on_reaction_add(&self, r: DiscordReaction) {
        route!(self, &r.channel_id, |router, link| router.on_discord_reaction(&r, link).await)
    }
    async fn on_reaction_remove(&self, r: DiscordReaction) {
        route!(self, &r.channel_id, |router, link| router.on_discord_reaction_remove(&r, link).await)
    }
    async fn on_guild_available(&self, guild_id: String) {
        if let Some(manager) = self.0.upgrade() {
            manager.on_guild_available(&guild_id).await;
        }
    }
    async fn on_guild_removed(&self, guild_id: String) {
        if let Some(manager) = self.0.upgrade() {
            manager.on_guild_removed(&guild_id).await;
        }
    }
    async fn on_typing(&self, t: TypingEvent) {
        if t.bot {
            return;
        }
        route!(self, &t.channel_id, |router, link| router.on_discord_typing(&t.user_id, link).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEAL_KEY: &str = "abababababababababababababababababababababababababababababababab";

    async fn test_pool() -> Option<Pool> {
        let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://postgres:test@127.0.0.1:55432/bridge".into());
        let pool = bridge::db::connect(&url, 2).ok()?;
        if tokio::time::timeout(Duration::from_secs(3), pool.get()).await.ok()?.is_err() {
            eprintln!("skipping: no database at DATABASE_URL");
            return None;
        }
        bridge::db::migrate(&pool).await.unwrap();
        Some(pool)
    }

    fn env() -> PortalEnv {
        PortalEnv::from_env(|k| match k {
            "PORTAL_SEAL_KEY" => Some(SEAL_KEY.into()),
            "DATABASE_URL" => Some("postgres://unused".into()),
            _ => None,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn one_master_secret_per_community_and_guild() {
        let Some(pool) = test_pool().await else { return };
        let community = format!("test-shared-secret-{}", std::process::id());
        let mgr = BridgeManager::new(pool.clone(), env());
        let first = unseal(SEAL_KEY, &mgr.shared_master_secret(&community, "100000000000000001").await.unwrap()).unwrap();
        let again = unseal(SEAL_KEY, &mgr.shared_master_secret(&community, "100000000000000001").await.unwrap()).unwrap();
        assert_eq!(first, again);
        let p = |m: &str| bridge::puppets::derive_puppet(m, "200000000000000002").unwrap().pk;
        assert_eq!(p(&first), p(&again));
        let other = unseal(SEAL_KEY, &mgr.shared_master_secret(&community, "100000000000000009").await.unwrap()).unwrap();
        assert_ne!(first, other);
        pool.get().await.unwrap().execute("DELETE FROM guild_community_secrets WHERE community_id = $1", &[&community]).await.unwrap();
    }

    async fn insert_bridge(pool: &Pool, guild: &str, channel: &str, status: &str) -> String {
        let id: String = pool
            .get()
            .await
            .unwrap()
            .query_one(
                "INSERT INTO bridges (bridge_id, owner_discord_id, status, discord_guild_id, discord_channel_id, options)
                 VALUES (gen_random_uuid(), 'owner', $3, $1, $2, '{}') RETURNING bridge_id::text",
                &[&guild, &channel, &status],
            )
            .await
            .unwrap()
            .get(0);
        id
    }

    async fn status_of(pool: &Pool, id: &str) -> (String, Value) {
        let row = bridge_by_id(pool, id).await.unwrap().unwrap();
        (row.status, row.options)
    }

    #[tokio::test]
    async fn a_bot_removed_pause_is_lifted_when_the_bot_returns_and_a_persons_never_is() {
        let Some(pool) = test_pool().await else { return };
        let mgr = BridgeManager::new(pool.clone(), env());
        let guild = format!("9{}", std::process::id());
        let ch = |n: u32| format!("{guild}{n}");
        let active = insert_bridge(&pool, &guild, &ch(1), "active").await;
        let pending = insert_bridge(&pool, &guild, &ch(2), "pending_confirm").await;
        let by_hand = insert_bridge(&pool, &guild, &ch(3), "active").await;
        let taken = insert_bridge(&pool, &guild, &ch(4), "active").await;

        mgr.pause_bot_removed(&active, "active").await.unwrap();
        mgr.pause_bot_removed(&pending, "pending_confirm").await.unwrap();
        mgr.pause_bot_removed(&taken, "active").await.unwrap();
        mgr.pause_bot_removed(&by_hand, "active").await.unwrap();
        let (status, options) = status_of(&pool, &active).await;
        assert_eq!((status.as_str(), options[PAUSED_FOR].as_str()), ("paused", Some(BOT_REMOVED)));
        // A person pausing it themselves takes the pause over: no mark.
        mgr.stop(&by_hand, "paused", None).await.unwrap();
        assert!(status_of(&pool, &by_hand).await.1.get(PAUSED_FOR).is_none());
        // Meanwhile someone linked another bridge to one of the channels.
        insert_bridge(&pool, &guild, &ch(4), "active").await;

        assert!(mgr.bot_removed_guilds().await.unwrap().contains(&guild));
        let resumed: Vec<String> = mgr.resume_bot_removed(&guild).await.unwrap().into_iter().map(|r| r.bridge_id).collect();
        assert_eq!(resumed.len(), 2);
        assert_eq!(status_of(&pool, &active).await.0, "active");
        // Still owed its in-channel confirm.
        assert_eq!(status_of(&pool, &pending).await.0, "pending_confirm");
        assert!(status_of(&pool, &pending).await.1.get(RESUME_TO).is_none());
        assert_eq!(status_of(&pool, &by_hand).await.0, "paused");
        assert_eq!(status_of(&pool, &taken).await.0, "paused", "the newer link keeps the channel");

        pool.get().await.unwrap().execute("DELETE FROM bridges WHERE discord_guild_id = $1", &[&guild]).await.unwrap();
    }

    #[test]
    fn confirm_code_matches_only_the_whole_command() {
        assert_eq!(&CONFIRM_RE.captures("/bridge confirm 0a1B2c3D").unwrap()[1], "0a1B2c3D");
        assert!(CONFIRM_RE.captures("/bridge confirm 0a1b2c3d please").is_none());
        assert!(CONFIRM_RE.captures("say /bridge confirm 0a1b2c3d").is_none());
    }

    #[test]
    fn backoff_stays_within_half_to_full_cap() {
        for attempt in 0..10 {
            let d = jittered(START_RETRY_BASE, START_RETRY_MAX, attempt);
            let cap = (START_RETRY_BASE * 2u32.pow(attempt.min(6))).min(START_RETRY_MAX);
            assert!(d >= cap / 2 && d <= cap, "{attempt}: {d:?}");
        }
    }
}
