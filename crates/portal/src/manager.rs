//! BridgeManager: the portal's data plane. Owns one Discord gateway (one bot
//! application serves every bridge) and, per bridge, a headless Concord client.
//! Drives the lifecycle: draft -> pending_confirm (in-channel code) -> active
//! (routing attached) -> paused/severed/unlinked.
//!
//! The in-channel confirm is the Armada side's consent gate: only a member
//! holding MANAGE_CHANNELS (or the owner) can flip a bridge live, and the
//! portal cannot bypass it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use async_trait::async_trait;
use bridge::client::{BotCommand, BotCommandArg, ConcordClient, OpenedChat, SendChat, TaskGuard, now_ms, resolve_invite};
use bridge::discord::{CommandMessage, DiscordAdapter, DiscordEvents, TypingEvent};
use bridge::key_intake::intake_direct_invite_keys;
use bridge::profiles::Kind0ProfileResolver;
use bridge::puppets::PuppetCache;
use bridge::relays::{Hub, HubRegistry, RelayLike};
use bridge::router::{BridgeRouter, RouterOptions, SelfIds, WebhookMessage, is_missing_permissions};
use bridge::store::{MappingStore, PgMappingStore};
use bridge::transform::parse_bot_command;
use bridge::types::{ChannelLink, DiscordInboundMessage, DiscordMessageDelete, DiscordReaction};
use concord::community::ChannelView;
use concord::invite::{invite_delivery_relays, parse_invite_link, stock_relays};
use concord::roles::perm;
use deadpool_postgres::Pool;
use nostr::prelude::{Keys, SecretKey};
use rand::RngCore;
use regex::Regex;
use serde_json::{Value, json};
use tokio::task::JoinHandle;

use crate::catchup::{CatchUpIo, replay_discord_since};
use crate::discord_rest::{DiscordRest, RestMessage, rest_to_inbound};
use crate::env::PortalEnv;
use crate::relay_guard::filter_public_relays;
use crate::seal::{seal, unseal};

/// Every column a bridge row is read with. `bridge_id` is read as text and
/// compared as `($1::text)::uuid`, so no uuid type crosses the driver.
pub const BRIDGE_COLUMNS: &str = "bridge_id::text AS bridge_id, owner_discord_id, status, status_detail, invite_url_sealed, \
     master_secret_sealed, primary_sk_sealed, primary_pk, community_id, community_name, discord_guild_id, \
     discord_channel_id, concord_channel_id, confirm_code, options";

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

struct Running {
    id: String,
    client: Arc<ConcordClient>,
    link: ChannelLink,
    confirm_code: String,
    channel: Mutex<ChannelView>,
    status: Mutex<LiveStatus>,
    router: RwLock<Option<Arc<BridgeRouter>>>,
    chat_sub: Mutex<Option<TaskGuard>>,
    control_sub: Mutex<Option<TaskGuard>>,
}

impl Running {
    fn router(&self) -> Option<Arc<BridgeRouter>> {
        self.router.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn status(&self) -> LiveStatus {
        *self.status.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn channel(&self) -> ChannelView {
        self.channel.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn primary(&self) -> &Keys {
        self.client.primary()
    }
    /// Drop both subscriptions, ending their tasks.
    fn halt(&self) {
        self.chat_sub.lock().unwrap_or_else(|e| e.into_inner()).take();
        self.control_sub.lock().unwrap_or_else(|e| e.into_inner()).take();
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
    hubs: HubRegistry,
    adapter: RwLock<Option<Arc<DiscordAdapter>>>,
    running: Mutex<HashMap<String, Arc<Running>>>,
    by_discord_channel: Mutex<HashMap<String, String>>,
    /// Pending start-retry timers by bridge id; cancelled by `stop`.
    start_retries: Mutex<HashMap<String, JoinHandle<()>>>,
    /// Set once boot's `start_all` has run, so a LATE gateway connect knows to
    /// bring deferred bridges up rather than double-start them.
    booted: AtomicBool,
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
            hubs: HubRegistry::default(),
            adapter: RwLock::new(None),
            running: Mutex::default(),
            by_discord_channel: Mutex::default(),
            start_retries: Mutex::default(),
            booted: AtomicBool::new(false),
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

    /// Communities with live relay connections (operational visibility).
    pub fn relay_hubs(&self) -> usize {
        self.hubs.len()
    }

    pub async fn init(&self) -> anyhow::Result<()> {
        if self.env.discord_bot_token.is_empty() {
            tracing::warn!("DISCORD_TOKEN not set; bridges cannot go live");
        } else {
            self.connect_adapter(0).await;
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
                    *self.adapter.write().unwrap_or_else(|e| e.into_inner()) = Some(adapter);
                    tracing::info!("discord gateway up");
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
        tracing::info!("{live}/{total} bridges live in {}s", began.elapsed().as_secs());
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
    /// (channel id hex, name)
    pub channels: Vec<(String, String)>,
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

    async fn bootstrap_relays(&self, invite_url: &str) -> anyhow::Result<bridge::relays::Relays> {
        let link = parse_invite_link(invite_url).context("not a valid Armada invite URL")?;
        let relays = if link.bootstrap_relays.is_empty() { stock_relays() } else { link.bootstrap_relays };
        Ok(self.guarded(&Hub::new(Keys::generate()), &relays).await)
    }

    /// Resolve and fold a community for the wizard's pairing step (transient).
    pub async fn inspect_invite(&self, invite_url: &str) -> anyhow::Result<InspectedInvite> {
        let bootstrap = self.bootstrap_relays(invite_url).await?;
        let joined = resolve_invite(invite_url, &bootstrap).await?;
        let m = joined.membership;
        let relays = self.guarded(&Hub::new(Keys::generate()), &m.relays).await;
        let client = ConcordClient::new(m.clone(), Arc::new(relays), Keys::generate());
        client.sync_control().await?;
        Ok(InspectedInvite {
            community_id: m.community_id.clone(),
            name: m.name.clone(),
            relays: m.relays.clone(),
            channels: client.channels().into_iter().map(|c| (c.id_hex, c.name)).collect(),
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
        let (Some(invite_sealed), Some(master_sealed), Some(primary_sealed)) =
            (&row.invite_url_sealed, &row.master_secret_sealed, &row.primary_sk_sealed)
        else {
            bail!("bridge is missing sealed key material");
        };
        let invite_url = unseal(&self.env.seal_key_hex, invite_sealed)?;
        let bootstrap = stage("vetting bootstrap relays", STAGE_DNS, self.bootstrap_relays(&invite_url)).await?;
        let joined = stage("resolving the invite", STAGE_RELAY, resolve_invite(&invite_url, &bootstrap)).await?;
        let membership = joined.membership;

        let primary = Keys::new(SecretKey::from_hex(&unseal(&self.env.seal_key_hex, primary_sealed)?)?);
        let hub = self.hubs.get(&membership.community_id);
        let relays = stage("vetting community relays", STAGE_DNS, async { Ok(self.guarded(&hub, &membership.relays).await) }).await?;
        // NIP-42 as the bridge's own npub too: relays that gate kind 1059 serve
        // a giftwrap only to the pubkey it is addressed to, and the Direct
        // Invites carrying private-channel keys are addressed to this npub.
        // Under a random identity the bridge could never read its own key
        // deliveries — every private channel an import admitted it to failed
        // "concord channel not found" on every start (2026-09-24).
        relays.register_auth_keys(vec![primary.clone()]);

        // Fold the Control Plane first: it reads from the root the invite
        // carried, so the roster — and with it, who may vend a channel key — is
        // knowable before we accept any. The intake refuses anyone else.
        let preflight = ConcordClient::new(membership.clone(), Arc::new(relays.clone()), primary.clone());
        let folded = stage("folding the control plane", STAGE_RELAY, preflight.sync_control()).await?;
        let floor = relays.with_urls(invite_delivery_relays(&[]));
        floor.register_auth_keys(vec![primary.clone()]);
        let owner = membership.owner.clone();
        let intake = stage("scanning for direct invites", STAGE_RELAY, async {
            Ok(intake_direct_invite_keys(&[&relays, &floor], &primary, &membership, |pk| {
                folded.roster.is_authorized(pk, &owner, perm::MANAGE_CHANNELS)
            })
            .await)
        })
        .await?;
        let client = if intake.learned.is_empty() {
            preflight
        } else {
            let client = ConcordClient::new(intake.community, Arc::new(relays.clone()), primary.clone());
            stage("re-folding the control plane", STAGE_RELAY, client.sync_control()).await?;
            client
        };

        let channel = row
            .concord_channel_id
            .as_deref()
            .and_then(|id| client.channel(id))
            .context("concord channel not found (deleted, or key not held)")?;

        // Refresh display names each start, so renames heal. A failed lookup is
        // None, and writing None over a correct name blanked the dashboard on
        // one rate-limited boot; keep what we knew unless Discord answered.
        let adapter = self.adapter();
        let (discord_name, guild_name) = match &adapter {
            Some(a) => {
                // Cosmetic, so bounded and best-effort: a lookup queued behind
                // Discord's ratelimiter has no deadline of its own, and once
                // held a boot worker, and every bridge queued behind it, forever.
                let channel_name = async { tokio::time::timeout(STAGE_NAMES, a.channel_name(row.discord_channel_id.as_deref()?)).await.ok()?.ok() };
                let guild_name = async { tokio::time::timeout(STAGE_NAMES, a.guild_name(row.discord_guild_id.as_deref()?)).await.ok()?.ok() };
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
            link,
            confirm_code: row.confirm_code.clone().unwrap_or_default(),
            channel: Mutex::new(channel.clone()),
            status: Mutex::new(status),
            router: RwLock::new(None),
            chat_sub: Mutex::new(None),
            control_sub: Mutex::new(None),
        });
        self.subscribe_chat(&rb, &channel, true);
        // A rekey mints new stream keys; a REQ pinned to the old ones goes
        // silent while publishes (fresh channel lookup) keep working, so
        // re-subscribe whenever the fold changes the channel's stream set.
        let (me, weak_rb) = (self.me.clone(), Arc::downgrade(&rb));
        let control = client.subscribe_control(Some(Arc::new(move |_| {
            if let (Some(me), Some(rb)) = (me.upgrade(), weak_rb.upgrade()) {
                me.refresh_chat_subscription(&rb);
            }
        })));
        *lock(&rb.control_sub) = Some(control);

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
            let content = format!(
                "A Discord bridge requests to link this channel. Bridged messages LEAVE end-to-end encryption and are \
                 mirrored to Discord in plaintext. A member with Manage Channels can enable it by replying:\n/bridge confirm {}",
                rb.confirm_code
            );
            stage("posting the confirm request", STAGE_RELAY, client.send_chat(&channel, SendChat::message(rb.primary(), content))).await?;
        }
        lock(&self.running).insert(rb.id.clone(), rb);
        Ok(())
    }

    fn subscribe_chat(&self, rb: &Arc<Running>, channel: &ChannelView, with_cursor: bool) {
        let (me, weak_rb) = (self.me.clone(), Arc::downgrade(rb));
        let on_chat = Arc::new(move |chat: OpenedChat| {
            let (Some(me), Some(rb)) = (me.upgrade(), weak_rb.upgrade()) else { return };
            tokio::spawn(async move {
                if let Err(error) = me.on_concord_chat(&rb, chat).await {
                    tracing::error!(bridge = %rb.id, error = %format!("{error:#}"), "concord handler failed");
                }
            });
        });
        let on_cursor: Option<bridge::client::CursorHandler> = with_cursor.then(|| {
            let store = self.store.clone();
            let community = rb.link.community_id.clone();
            Arc::new(move |stream_pk: String, at: u64| {
                let (store, community) = (store.clone(), community.clone());
                tokio::spawn(async move {
                    let _ = store.cursor_set(&community, &stream_pk, at).await;
                });
            }) as bridge::client::CursorHandler
        });
        *lock(&rb.chat_sub) = Some(rb.client.subscribe_channel(channel, on_chat, on_cursor));
    }

    /// Tear down and rebuild the chat REQ when the channel's stream set changes.
    fn refresh_chat_subscription(&self, rb: &Arc<Running>) {
        // Channel left the fold: severance detection is separate work.
        let Some(fresh) = rb.client.channel(&rb.link.concord_channel_id_hex) else { return };
        let keys = |c: &ChannelView| c.streams.iter().map(|s| s.key.pk_hex()).collect::<Vec<_>>();
        if keys(&fresh) == keys(&rb.channel()) {
            return;
        }
        *lock(&rb.channel) = fresh.clone();
        self.subscribe_chat(rb, &fresh, true);
        tracing::info!(bridge = %rb.id, "stream keys rotated; chat subscription refreshed");
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
        // The anchor is the largest snowflake mirrored, never the newest row:
        // created_at is when WE wrote a row, and a history import writes old
        // messages now. The snowflake is Discord's own clock.
        let before_ms = self.env.catch_up_since_ms.unwrap_or(now_ms() as i64);
        let anchor: Option<String> = db
            .query_one(
                "SELECT max(discord_message_id::numeric)::text AS anchor FROM messages
                 WHERE tenant_id = 'default' AND discord_channel_id = $1 AND community_id = $2
                   AND created_at < to_timestamp($3::bigint / 1000.0)",
                &[&rb.link.discord_channel_id, &rb.link.community_id, &before_ms],
            )
            .await?
            .get(0);
        drop(db);
        let Some(anchor) = anchor else { return Ok(()) };
        let io = CatchUp { manager: self, rb };
        let result = replay_discord_since(&anchor, live_from_ms as i64, DISCORD_CATCHUP_MAX, &io).await;
        if result.mirrored > 0 {
            tracing::info!(bridge = %rb.id, mirrored = result.mirrored, "caught up missed Discord messages");
        }
        if result.capped {
            tracing::warn!(bridge = %rb.id, "Discord catch-up stopped at {DISCORD_CATCHUP_MAX} messages");
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
            let sql = format!(
                "UPDATE bridges SET status = 'active', status_detail = NULL, updated_at = now()
                 WHERE bridge_id = ($1::text)::uuid RETURNING {BRIDGE_COLUMNS}"
            );
            let row = BridgeRow::from_row(&self.pool.get().await?.query_one(&sql, &[&rb.id]).await?);
            *lock(&rb.status) = LiveStatus::Active;
            let master = unseal(&self.env.seal_key_hex, row.master_secret_sealed.as_deref().context("no master secret")?)?;
            if let Err(error) = self.attach_routing(rb, &master, &row.options) {
                if error.is::<GatewayUnavailable>() {
                    // Confirmed while the gateway was down. The row stays
                    // active and routing attaches on reconnect. Don't sever,
                    // and don't claim it's live.
                    tracing::warn!(bridge = %rb.id, "confirmed while Discord gateway down; will attach on reconnect");
                    return Ok(());
                }
                return Err(error);
            }
            let _ = rb.client.send_chat(&rb.channel(), SendChat::message(rb.primary(), "Bridge confirmed. This channel is now mirrored with Discord.")).await;
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
        tokio::spawn(async move { me.announce_bridge(&rb).await });
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
                   master_secret_sealed = NULL, primary_sk_sealed = NULL, updated_at = now()
                 WHERE bridge_id = ($1::text)::uuid",
                &[&bridge_id, &detail],
            )
            .await?;
        } else {
            db.execute(
                "UPDATE bridges SET status = $2, status_detail = $3, updated_at = now() WHERE bridge_id = ($1::text)::uuid",
                &[&bridge_id, &status, &detail],
            )
            .await?;
        }
        Ok(())
    }

    pub async fn resume(&self, bridge_id: &str) -> anyhow::Result<()> {
        let row = bridge_by_id(&self.pool, bridge_id).await?.context("no such bridge")?;
        let next = if row.status == "paused" {
            "active"
        } else if row.confirm_code.is_some() && !self.is_live(bridge_id) {
            "pending_confirm"
        } else {
            "active"
        };
        self.pool
            .get()
            .await?
            .execute("UPDATE bridges SET status = $2, updated_at = now() WHERE bridge_id = ($1::text)::uuid", &[&bridge_id, &next])
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
