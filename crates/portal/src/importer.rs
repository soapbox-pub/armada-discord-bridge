//! Server importer: snapshot a Discord guild, preview the mapping, then mint a
//! brand-new Armada community and publish its control-plane editions —
//! metadata, channels, roles, a public invite — and wire live bridges for the
//! selected text channels.
//!
//! Ownership: the USER's real Nostr key is the community owner (position 0,
//! baked into the community_id). The genesis authority chain is owner-signed in
//! the browser (the key never leaves the client): the owner signs the stock
//! Admin role, a grant handing that role to the portal's OPERATIONAL key, their
//! invite registry, and their guestbook join. The operational key then
//! publishes everything else citing that grant (`vac`), and the owner can
//! revoke it from Armada at any time.
//!
//! Every publish step checkpoints into the plan jsonb, so a crashed or failed
//! import resumes idempotently; a duplicate v1 edition is harmless.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, bail};
use async_trait::async_trait;
use bridge::blossom::BlobPort;
use bridge::client::now_ms;
use bridge::markup::discord_emoji_url;
use bridge::relays::{Hub, PublishRejected, RelayLike};
use bridge::router::BridgeRouter;
use bridge::types::ChannelLink;
use concord::community::Membership;
use concord::control::{
    build_channel_edition, build_grant_edition, build_metadata_edition, build_registry_edition, build_role_edition, cap_relays,
    seal_edition, with_channel_category, with_channel_position, ImagePointer,
};
use concord::derive::grant_locator;
use concord::edition::{Citation, EditionMeta, edition_hash};
use concord::invite::{InviteBundle, build_bundle_event, build_invite_url, inbox_relays_from, invite_delivery_relays, mint_token, parse_invite_link, stock_relays};
use concord::kinds::{self, Plane};
use concord::roles::{MemberGrant, Role, RoleScope, admin_role};
use concord::stream::{StreamKey, WrapOptions, seal_and_wrap, wrap_seal};
use concord::{hex32, random32, to_hex};
use deadpool_postgres::Pool;
use futures_util::future::BoxFuture;
use nostr::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::discord_rest::{DiscordRest, RestMessage, bot_install_url, rest_to_inbound};
use crate::import_plan::{
    EventTemplate, HISTORY_MESSAGE_CAP, ImportPlan, OwnerSignPurpose, OwnerSignTemplate, PlannedChannel, SignedSeal, build_import_plan,
};
use crate::manager::{BRIDGE_COLUMNS, BridgeManager, BridgeRow};
use crate::relay_guard::assert_public_relays;
use crate::seal::{seal, unseal};

/// Namespace for the Discord facts Concord has no field for (channel topic,
/// the originating channel type). Ours, not `armada.*`: CORD-02 §6 makes an
/// unknown custom member something every editor round-trips, so squatting on
/// another project's namespace would collide the day they define it.
pub const DISCORD_IMPORT_METADATA_KEY: &str = "discord.import";

/// The Armada client's stock blob host, used when BLOSSOM_SERVER is unset.
const DEFAULT_BLOSSOM: &str = "https://blossom.ditto.pub";

/// How recently an interrupted import must have progressed to auto-resume.
const RESUME_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Largest icon/banner we bother rehosting.
const MAX_ASSET_BYTES: usize = 8 * 1024 * 1024;

pub const IMPORT_COLUMNS: &str = "import_id::text AS import_id, owner_discord_id, discord_guild_id, discord_guild_name, status, \
     status_detail, plan, history_progress, owner_sk_sealed, community_sealed, community_id, invite_url_sealed, link_signer_sk_sealed, updated_at";

#[derive(Clone, Debug)]
pub struct ImportRow {
    pub import_id: String,
    pub owner_discord_id: String,
    pub discord_guild_id: String,
    pub discord_guild_name: Option<String>,
    pub status: String,
    pub status_detail: Option<String>,
    pub plan: ImportPlan,
    pub owner_sk_sealed: Option<Vec<u8>>,
    pub community_sealed: Option<Vec<u8>>,
    pub community_id: Option<String>,
    pub invite_url_sealed: Option<Vec<u8>>,
    pub link_signer_sk_sealed: Option<Vec<u8>>,
    pub updated_at: SystemTime,
}

impl ImportRow {
    fn from_row(r: &tokio_postgres::Row) -> anyhow::Result<ImportRow> {
        let mut plan: ImportPlan = serde_json::from_value(r.get("plan")).context("import plan does not parse")?;
        overlay_progress(&mut plan, &r.get("history_progress"));
        Ok(ImportRow {
            import_id: r.get("import_id"),
            owner_discord_id: r.get("owner_discord_id"),
            discord_guild_id: r.get("discord_guild_id"),
            discord_guild_name: r.get("discord_guild_name"),
            status: r.get("status"),
            status_detail: r.get("status_detail"),
            plan,
            owner_sk_sealed: r.get("owner_sk_sealed"),
            community_sealed: r.get("community_sealed"),
            community_id: r.get("community_id"),
            invite_url_sealed: r.get("invite_url_sealed"),
            link_signer_sk_sealed: r.get("link_signer_sk_sealed"),
            updated_at: r.get("updated_at"),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelToggle {
    pub discord_id: String,
    pub selected: Option<bool>,
    pub bridge: Option<bool>,
    pub history: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareBody {
    /// The user's Armada account (npub or 64-hex): the community OWNER.
    pub owner_npub: Option<String>,
    /// Community relay set; defaults to IMPORT_DEFAULT_RELAYS, then stock.
    pub relays: Option<Vec<String>>,
    pub channels: Option<Vec<ChannelToggle>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmBody {
    /// The owner-signed seals, in the same order as the prepared templates.
    pub signed_events: Option<Vec<SignedSeal>>,
}

pub enum Preview {
    NotPresent { install_url: String },
    Ready { import_id: String, plan: Box<ImportPlan>, default_relays: Vec<String> },
}

/// npub1… or bare 64-hex -> lowercase hex; `None` when unparseable.
pub fn parse_admin_pubkey(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if concord::is_hex64(trimmed) {
        return Some(trimmed.to_lowercase());
    }
    PublicKey::from_bech32(trimmed).ok().map(|pk| pk.to_hex())
}

/// The community identity and access secrets sealed into `community_sealed`.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommunitySecrets {
    owner_salt: String,
    community_root: String,
    /// The staff write key (CORD-02 §2). The op key is the only staff member
    /// the portal publishes as, so this is what lets it reach the Control Plane
    /// at all. Absent on rows sealed before the split: legacy communities whose
    /// plane is keyed by `community_root` alone until a Refounding mints the pair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    control_root: Option<String>,
}

/// What the importer needs from the bridge runtime: a trait so its pipeline
/// tests run without a gateway.
#[async_trait]
pub trait BridgeHost: Send + Sync {
    async fn provision_imported(&self, row: &BridgeRow) -> anyhow::Result<BridgeRow>;
    async fn start_imported(&self, row: &BridgeRow) -> anyhow::Result<()>;
    async fn resync_for(&self, discord_channel_id: &str) -> anyhow::Result<()>;
    fn channel_known(&self, discord_channel_id: &str, concord_channel_id_hex: &str) -> bool;
    fn router_for(&self, discord_channel_id: &str) -> Option<(Arc<BridgeRouter>, ChannelLink)>;
}

#[async_trait]
impl BridgeHost for BridgeManager {
    async fn provision_imported(&self, row: &BridgeRow) -> anyhow::Result<BridgeRow> {
        BridgeManager::provision_imported(self, row).await
    }
    async fn start_imported(&self, row: &BridgeRow) -> anyhow::Result<()> {
        BridgeManager::start_imported(self, row).await
    }
    async fn resync_for(&self, discord_channel_id: &str) -> anyhow::Result<()> {
        BridgeManager::resync_for(self, discord_channel_id).await
    }
    fn channel_known(&self, d: &str, c: &str) -> bool {
        BridgeManager::channel_known(self, d, c)
    }
    fn router_for(&self, d: &str) -> Option<(Arc<BridgeRouter>, ChannelLink)> {
        BridgeManager::router_for(self, d)
    }
}

pub type RelayFactory = Arc<dyn Fn(Vec<String>) -> Arc<dyn RelayLike> + Send + Sync>;
pub type HistoryFetch = Arc<dyn Fn(String, Option<String>) -> BoxFuture<'static, anyhow::Result<Option<Vec<RestMessage>>>> + Send + Sync>;
pub type RelayVetter = Arc<dyn Fn(Vec<String>) -> BoxFuture<'static, anyhow::Result<()>> + Send + Sync>;

/// The importer's outside world. Production wires real relays, Discord REST
/// and the relay guard; tests swap in an in-memory wire.
#[derive(Clone)]
pub struct ImporterIo {
    pub relays: RelayFactory,
    pub history: HistoryFetch,
    /// Vets user-typed relay hosts. The guard refuses a name it cannot
    /// resolve, which is right in production and would make every fixture
    /// relay a DNS lookup in tests.
    pub vet_relays: RelayVetter,
    /// How long to wait between a publish and re-checking it became readable.
    pub publish_retry: Duration,
    /// Where guild icons and banners are rehosted.
    pub blobs: Arc<dyn BlobPort>,
}

impl ImporterIo {
    pub fn production(bot_token: String, blossom_server: &str) -> anyhow::Result<ImporterIo> {
        let rest = DiscordRest::new();
        let servers = bridge::blossom::blossom_servers(if blossom_server.is_empty() { DEFAULT_BLOSSOM } else { blossom_server });
        Ok(ImporterIo {
            relays: Arc::new(|urls| Arc::new(Hub::new(Keys::generate()).relays(urls)) as Arc<dyn RelayLike>),
            history: Arc::new(move |channel, before| {
                let (rest, token) = (rest.clone(), bot_token.clone());
                Box::pin(async move { rest.bot_channel_messages_before(&token, &channel, before.as_deref(), 100).await })
            }),
            vet_relays: Arc::new(|relays| Box::pin(async move { assert_public_relays(&relays).await })),
            publish_retry: Duration::from_millis(1500),
            blobs: Arc::new(bridge::blossom::BlossomStore::new(servers)?),
        })
    }
}

pub struct Importer {
    pool: Pool,
    env: crate::env::PortalEnv,
    host: Arc<dyn BridgeHost>,
    io: ImporterIo,
    rest: DiscordRest,
    /// Imports with a pipeline running in this process.
    running: Mutex<HashSet<String>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn plan_json(plan: &ImportPlan) -> Value {
    serde_json::to_value(plan).expect("plans always serialize")
}

/// Apply `imports.history_progress` checkpoints, which are newer than the
/// plan for their channels (see migration 018).
fn overlay_progress(plan: &mut ImportPlan, progress: &Value) {
    let Some(progress) = progress.as_object() else { return };
    for c in plan.channels.iter_mut() {
        let Some(p) = progress.get(&c.discord_id) else { continue };
        if let Some(n) = p["imported"].as_u64() {
            c.history_imported = Some(n);
        }
        if let Some(cursor) = p["cursor"].as_str() {
            c.history_cursor = Some(cursor.to_owned());
        }
    }
}

impl Importer {
    pub fn new(pool: Pool, env: crate::env::PortalEnv, host: Arc<dyn BridgeHost>, io: ImporterIo) -> Arc<Importer> {
        Arc::new(Importer { pool, env, host, io, rest: DiscordRest::new(), running: Mutex::default() })
    }

    pub fn active_count(&self) -> usize {
        lock(&self.running).len()
    }

    async fn row(&self, import_id: &str, owner: Option<&str>) -> anyhow::Result<Option<ImportRow>> {
        let db = self.pool.get().await?;
        let row = match owner {
            Some(owner) => {
                let sql = format!("SELECT {IMPORT_COLUMNS} FROM imports WHERE import_id = ($1::text)::uuid AND owner_discord_id = $2");
                db.query_opt(&sql, &[&import_id, &owner]).await?
            }
            None => db.query_opt(&format!("SELECT {IMPORT_COLUMNS} FROM imports WHERE import_id = ($1::text)::uuid"), &[&import_id]).await?,
        };
        row.as_ref().map(ImportRow::from_row).transpose()
    }

    async fn set_status(&self, import_id: &str, status: &str, detail: Option<&str>) -> anyhow::Result<()> {
        self.pool
            .get()
            .await?
            .execute(
                "UPDATE imports SET status = $2, status_detail = $3, updated_at = now() WHERE import_id = ($1::text)::uuid",
                &[&import_id, &status, &detail],
            )
            .await?;
        Ok(())
    }

    async fn save_plan(&self, import_id: &str, plan: &ImportPlan) -> anyhow::Result<()> {
        self.pool
            .get()
            .await?
            .execute(
                "UPDATE imports SET plan = $2, history_progress = '{}', updated_at = now() WHERE import_id = ($1::text)::uuid",
                &[&import_id, &plan_json(plan)],
            )
            .await?;
        Ok(())
    }

    /// Checkpoint one channel's history progress without rewriting the plan,
    /// which can be ~150KB for a large guild.
    async fn save_progress(&self, import_id: &str, discord_id: &str, imported: u64, cursor: &str) -> anyhow::Result<()> {
        let entry = json!({ discord_id: { "imported": imported, "cursor": cursor } });
        self.pool
            .get()
            .await?
            .execute(
                "UPDATE imports SET history_progress = history_progress || $2, updated_at = now() WHERE import_id = ($1::text)::uuid",
                &[&import_id, &entry],
            )
            .await?;
        Ok(())
    }

    /// Snapshot the guild and store a previewed plan.
    pub async fn preview(&self, owner_discord_id: &str, guild_id: &str) -> anyhow::Result<Preview> {
        let token = &self.env.discord_bot_token;
        if token.is_empty() {
            bail!("bot token not configured");
        }
        let Some(snapshot) = self.rest.bot_guild_snapshot(token, guild_id).await? else {
            return Ok(Preview::NotPresent { install_url: bot_install_url(&self.env.discord_client_id, guild_id) });
        };
        let mut plan = build_import_plan(&snapshot);
        // Pre-flight Manage Webhooks in every live-bridgeable channel so the
        // review screen can warn before wiring. Sequential, to stay gentle on
        // the rate limiter.
        for channel in plan.channels.iter_mut().filter(|c| c.bridgeable) {
            if !self.rest.bot_can_manage_webhooks(token, &channel.discord_id).await.unwrap_or(true) {
                channel.bot_missing_webhook = Some(true);
            }
        }
        let row = self
            .pool
            .get()
            .await?
            .query_one(
                "INSERT INTO imports (owner_discord_id, discord_guild_id, discord_guild_name, plan) VALUES ($1, $2, $3, $4)
                 RETURNING import_id::text",
                &[&owner_discord_id, &guild_id, &snapshot.guild.name, &plan_json(&plan)],
            )
            .await?;
        let default_relays = if self.env.import_relays.is_empty() { stock_relays() } else { self.env.import_relays.clone() };
        Ok(Preview::Ready { import_id: row.get(0), plan: Box::new(plan), default_relays })
    }

    /// The row, with its invite URL once the import is done.
    pub async fn get(&self, import_id: &str, owner_discord_id: &str) -> anyhow::Result<Option<(ImportRow, Option<String>)>> {
        let Some(row) = self.row(import_id, Some(owner_discord_id)).await? else { return Ok(None) };
        let invite = match (&row.status[..], &row.invite_url_sealed) {
            ("done", Some(sealed)) => Some(unseal(&self.env.seal_key_hex, sealed)?),
            _ => None,
        };
        Ok(Some((row, invite)))
    }

    /// Apply the user's selections, mint the community under THEIR key, and
    /// return the seal templates the owner must sign in the browser.
    pub async fn prepare(&self, import_id: &str, owner_discord_id: &str, body: PrepareBody) -> anyhow::Result<(String, Vec<OwnerSignTemplate>)> {
        let row = self.row(import_id, Some(owner_discord_id)).await?.context("no such import")?;
        if row.status != "previewed" && row.status != "awaiting_sigs" {
            bail!("import is {}, not previewed", row.status);
        }
        let owner = parse_admin_pubkey(body.owner_npub.as_deref().unwrap_or("")).context("connect your Armada account (npub) first")?;

        // One live community per guild. A second one would wire a parallel
        // bridge onto the same Discord channels and silently steal them from
        // the members who joined the first — the duplicate-community stranding
        // the Lynch import hit. A failed import recovers with retry or
        // rerun_history, which reuse the existing community.
        let live = self
            .pool
            .get()
            .await?
            .query_opt(
                "SELECT status FROM bridges WHERE discord_guild_id = $1 AND status IN ('active', 'pending_confirm')
                   AND community_id IS DISTINCT FROM $2 LIMIT 1",
                &[&row.discord_guild_id, &row.community_id],
            )
            .await?;
        if live.is_some() {
            bail!(
                "this Discord server is already bridged to an Armada community; retry or re-run history on the existing import instead of importing it again"
            );
        }

        let mut plan = row.plan;
        for toggle in body.channels.unwrap_or_default() {
            let Some(channel) = plan.channels.iter_mut().find(|c| c.discord_id == toggle.discord_id) else { continue };
            if let Some(selected) = toggle.selected {
                channel.selected = selected;
            }
            if let Some(bridge) = toggle.bridge {
                channel.bridge = bridge && channel.bridgeable;
            }
            if let Some(history) = toggle.history {
                channel.history = history && channel.bridgeable;
            }
            if !channel.selected {
                channel.bridge = false;
            }
            if !channel.bridge {
                channel.history = false;
            }
        }
        if !plan.channels.iter().any(|c| c.selected) {
            bail!("select at least one channel");
        }

        let requested: Vec<String> = body.relays.unwrap_or_default().into_iter().map(|r| r.trim().to_owned()).filter(|r| !r.is_empty()).collect();
        // Scheme AND host: a scheme-only check let `ws://127.0.0.1:6379/`
        // through, and the server opened a socket to it on the caller's behalf.
        (self.io.vet_relays)(requested.clone()).await?;
        plan.relays = cap_relays(if !requested.is_empty() {
            requested
        } else if !self.env.import_relays.is_empty() {
            self.env.import_relays.clone()
        } else {
            stock_relays()
        });

        // Mint under the USER's key. Re-preparing (e.g. a different account
        // reconnected) re-mints from scratch: nothing has been published.
        let op = Keys::generate();
        let community = Membership::mint(&plan.community_name, &owner, plan.relays.clone(), now_ms());
        let cid = community.id();
        for channel in plan.channels.iter_mut() {
            channel.channel_id_hex = channel.selected.then(|| to_hex(&random32()));
            // A Private Channel is born with an independent key and the Role
            // that gates it (CORD-03 §1, CORD-04 §2), minted here so a resumed
            // import republishes the SAME pair instead of forking the channel.
            if channel.selected && channel.is_private() {
                channel.access_role_id_hex = Some(to_hex(&random32()));
                channel.key_sealed = Some(hex::encode(seal(&self.env.seal_key_hex, &to_hex(&random32()))?));
            }
        }
        for role in plan.roles.iter_mut() {
            role.role_id_hex = Some(to_hex(&random32()));
        }
        let token = mint_token();
        let link = Keys::generate();
        let admin_role_id = to_hex(&random32());

        // The owner's genesis signatures: Admin role, the op grant, their
        // invite registry, their guestbook join.
        let now = now_ms() / 1000;
        let v1 = EditionMeta { created_at: Some(now), ..EditionMeta::first(&owner, None) };
        let role_rumor = build_role_edition(&admin_role(&admin_role_id), &v1)?;
        let grant = MemberGrant { member: op.public_key().to_hex(), role_ids: vec![admin_role_id.clone()], control_wrap: None };
        let grant_rumor = build_grant_edition(&cid, &grant, &v1)?;
        let registry_rumor = build_registry_edition(&cid, &owner, &[link.public_key().to_hex()], &v1)?;
        let join_rumor = concord::guestbook::join(&owner, now_ms(), None);
        let op_bytes = hex32(&op.public_key().to_hex()).expect("a pubkey is 32 bytes");
        let grant_hash = edition_hash(&grant_locator(&cid, &op_bytes), 1, None, grant_rumor.content.as_bytes());

        let plaintext = |rumor: &concord::rumor::Rumor| EventTemplate { kind: kinds::SEAL_PLAINTEXT, content: rumor.to_json(), tags: vec![], created_at: rumor.created_at };
        let guestbook = community.current_guestbook_stream();
        let templates = vec![
            OwnerSignTemplate { purpose: OwnerSignPurpose::AdminRole, template: plaintext(&role_rumor) },
            OwnerSignTemplate { purpose: OwnerSignPurpose::OpGrant, template: plaintext(&grant_rumor) },
            OwnerSignTemplate { purpose: OwnerSignPurpose::InviteRegistry, template: plaintext(&registry_rumor) },
            OwnerSignTemplate {
                purpose: OwnerSignPurpose::OwnerJoin,
                template: EventTemplate {
                    kind: kinds::SEAL_ENCRYPTED,
                    content: concord::nip44::encrypt_str(&guestbook.conv_key, &join_rumor.to_json())?,
                    tags: vec![],
                    created_at: join_rumor.created_at,
                },
            },
        ];
        let cp = &mut plan.checkpoints;
        cp.community_id_hex = Some(community.community_id.clone());
        cp.owner_pk_hex = Some(owner.clone());
        cp.op_pk_hex = Some(op.public_key().to_hex());
        cp.admin_role_id_hex = Some(admin_role_id);
        cp.invite_link_signer_pk = Some(link.public_key().to_hex());
        cp.grant_hash_hex = Some(to_hex(&grant_hash));
        cp.owner_templates = Some(templates.clone());

        let secrets = CommunitySecrets {
            owner_salt: community.owner_salt.clone(),
            community_root: community.root.clone(),
            // Without this the op key could never publish an edition after the
            // first reload (CORD-02 §2).
            control_root: community.control_root.clone(),
        };
        let invite_url = build_invite_url(&self.env.invite_base_url, &link.public_key(), &token, &community.relays)?;
        let k = &self.env.seal_key_hex;
        self.pool
            .get()
            .await?
            .execute(
                "UPDATE imports SET owner_sk_sealed = $2, community_sealed = $3, community_id = $4, invite_url_sealed = $5,
                   link_signer_sk_sealed = $6, plan = $7, history_progress = '{}', status = 'awaiting_sigs', status_detail = NULL, updated_at = now()
                 WHERE import_id = ($1::text)::uuid",
                &[
                    &import_id,
                    &seal(k, &op.secret_key().to_secret_hex())?,
                    &seal(k, &serde_json::to_string(&secrets)?)?,
                    &community.community_id,
                    &seal(k, &invite_url)?,
                    &seal(k, &link.secret_key().to_secret_hex())?,
                    &plan_json(&plan),
                ],
            )
            .await?;
        Ok((owner, templates))
    }

    /// Verify the owner's signatures against the prepared templates and launch.
    pub async fn confirm(self: &Arc<Self>, import_id: &str, owner_discord_id: &str, body: ConfirmBody) -> anyhow::Result<()> {
        let row = self.row(import_id, Some(owner_discord_id)).await?.context("no such import")?;
        if row.status != "awaiting_sigs" {
            bail!("import is {}, not awaiting signatures", row.status);
        }
        let mut plan = row.plan;
        let templates = plan.checkpoints.owner_templates.clone().unwrap_or_default();
        let signed = body.signed_events.unwrap_or_default();
        if signed.len() != templates.len() {
            bail!("expected {} signed events, got {}", templates.len(), signed.len());
        }
        let owner = plan.checkpoints.owner_pk_hex.clone().unwrap_or_default();
        for (i, (t, s)) in templates.iter().zip(&signed).enumerate() {
            let t = &t.template;
            if s.kind != t.kind || s.content != t.content || s.created_at != t.created_at || s.tags != t.tags {
                bail!("signed event {i} does not match the prepared template ({:?})", templates[i].purpose);
            }
            if s.pubkey != owner {
                bail!("signed event {i} is signed by the wrong key");
            }
            if seal_event(s).is_none() {
                bail!("signed event {i} has an invalid signature");
            }
        }
        plan.checkpoints.owner_signed_seals = Some(signed);
        self.pool
            .get()
            .await?
            .execute(
                "UPDATE imports SET plan = $2, history_progress = '{}', status = 'publishing', status_detail = NULL, updated_at = now()
                 WHERE import_id = ($1::text)::uuid",
                &[&import_id, &plan_json(&plan)],
            )
            .await?;
        self.launch(import_id);
        Ok(())
    }
}

/// A browser-signed seal as an event, if its id and signature verify.
fn seal_event(s: &SignedSeal) -> Option<Event> {
    let event = Event::from_json(serde_json::to_string(s).ok()?).ok()?;
    event.verify().is_ok().then_some(event)
}

/// Rehost one Discord CDN image as a Concord encrypted-blob pointer (CORD-02
/// §6, Armada's WebCrypto layout): AES-256-GCM under a fresh key and 16-byte
/// nonce with the tag appended, the HOST stores ciphertext, and `hash` is the
/// SHA-256 of the PLAINTEXT so a swapped blob fails closed.
async fn rehost_encrypted_image(source: &str, blobs: &dyn BlobPort, uploader: &Keys) -> anyhow::Result<ImagePointer> {
    let (data, _) = blobs.download(source, MAX_ASSET_BYTES).await?;
    let (ciphertext, key) = concord::media::encrypt(&data);
    let uploaded = blobs.upload(&ciphertext, "application/octet-stream", uploader).await?;
    Ok(ImagePointer { url: uploaded.url, key: hex::encode(key.key), nonce: hex::encode(key.nonce), hash: hex::encode(Sha256::digest(&data)) })
}

fn stream_keys(streams: &[StreamKey]) -> Vec<Keys> {
    streams.iter().filter_map(|s| s.sk.clone().map(Keys::new)).collect()
}

impl Importer {
    /// Re-run a failed import from its checkpoints.
    pub async fn retry(self: &Arc<Self>, import_id: &str, owner_discord_id: &str) -> anyhow::Result<()> {
        let row = self.row(import_id, Some(owner_discord_id)).await?.context("no such import")?;
        if row.status != "failed" {
            bail!("import is {}, not failed", row.status);
        }
        if row.plan.checkpoints.owner_signed_seals.is_none() {
            bail!("import has no signatures; start over");
        }
        self.set_status(import_id, "publishing", None).await?;
        self.launch(import_id);
        Ok(())
    }

    /// Pick up imports a restart cut off mid-pipeline. Call once bridges are
    /// up: the wiring and history stages route through the live bridges.
    ///
    /// `launch` only ever ran from a request, so a process that died mid-import
    /// left the row in publishing/wiring/history for good — and `retry` refuses
    /// anything not `failed`, so the owner could not even restart it. A recent
    /// one is relaunched; an older one is marked failed with a detail saying
    /// why, since a history backfill starting weeks later on its own would be a
    /// surprise. Failed is retryable, so the choice stays the owner's.
    pub async fn resume_interrupted(self: &Arc<Self>) -> anyhow::Result<()> {
        let stranded = self
            .pool
            .get()
            .await?
            .query("SELECT import_id::text, updated_at FROM imports WHERE status IN ('minting', 'publishing', 'wiring', 'history')", &[])
            .await?;
        for row in stranded {
            let (id, updated_at): (String, SystemTime) = (row.get(0), row.get(1));
            if lock(&self.running).contains(&id) {
                continue;
            }
            if updated_at.elapsed().unwrap_or_default() <= RESUME_WINDOW {
                tracing::info!(import = %id, "resuming after restart");
                self.launch(&id);
                continue;
            }
            self.pool
                .get()
                .await?
                .execute(
                    "UPDATE imports SET status = 'failed',
                       status_detail = 'interrupted by a portal restart; retry to resume from where it stopped', updated_at = now()
                     WHERE import_id = ($1::text)::uuid AND status IN ('minting', 'publishing', 'wiring', 'history')",
                    &[&id],
                )
                .await?;
            tracing::warn!(import = %id, "stranded by a restart; marked failed (retryable)");
        }
        Ok(())
    }

    fn launch(self: &Arc<Self>, import_id: &str) {
        self.spawn_pipeline(import_id, false);
    }

    fn spawn_pipeline(self: &Arc<Self>, import_id: &str, history_only: bool) {
        if !lock(&self.running).insert(import_id.to_owned()) {
            return;
        }
        let (me, id) = (self.clone(), import_id.to_owned());
        tokio::spawn(async move {
            let result = if history_only { me.run_history_only(&id).await } else { me.run(&id).await };
            if let Err(error) = result {
                tracing::error!(import = %id, error = %format!("{error:#}"), "import failed");
                let _ = me.set_status(&id, "failed", Some(&format!("{error:#}"))).await;
            }
            lock(&me.running).remove(&id);
        });
    }

    async fn run(&self, import_id: &str) -> anyhow::Result<()> {
        let (community, op, mut plan) = self.load(import_id).await?;
        self.publish_editions(import_id, &community, &op, &mut plan).await?;
        self.wire_bridges(import_id, &community, &op, &mut plan).await?;
        self.import_history(import_id, &mut plan).await?;
        self.set_status(import_id, "done", None).await?;
        tracing::info!(import = %import_id, community = %community.community_id, "import done");
        Ok(())
    }

    /// Rebuild the community and operational key from the sealed genesis material.
    async fn load(&self, import_id: &str) -> anyhow::Result<(Membership, Keys, ImportPlan)> {
        let row = self.row(import_id, None).await?.context("import row vanished")?;
        let plan = row.plan;
        let cp = &plan.checkpoints;
        let (Some(op_sealed), Some(secrets_sealed), Some(cid), Some(owner)) =
            (&row.owner_sk_sealed, &row.community_sealed, &cp.community_id_hex, &cp.owner_pk_hex)
        else {
            bail!("import was never prepared");
        };
        let op = Keys::new(SecretKey::from_hex(&unseal(&self.env.seal_key_hex, op_sealed)?)?);
        let secrets: CommunitySecrets = serde_json::from_str(&unseal(&self.env.seal_key_hex, secrets_sealed)?)?;
        let b32 = |s: &str| hex32(s).context("sealed community secrets are malformed");
        let control_root = secrets.control_root.as_deref().map(b32).transpose()?;
        let community = Membership::genesis(
            owner,
            &b32(&secrets.owner_salt)?,
            &b32(&secrets.community_root)?,
            control_root.as_ref(),
            plan.relays.clone(),
            plan.community_name.clone(),
            0,
        );
        if &community.community_id != cid {
            bail!("sealed community secrets do not reproduce the checkpointed community id");
        }
        Ok((community, op, plan))
    }

    /// The citation every op-key action carries: the owner-signed grant.
    fn op_vac(community: &Membership, op: &Keys, plan: &ImportPlan) -> anyhow::Result<Citation> {
        let op_bytes = hex32(&op.public_key().to_hex()).expect("a pubkey is 32 bytes");
        let hash = plan.checkpoints.grant_hash_hex.as_deref().and_then(hex32).context("import has no grant hash")?;
        Ok(Citation { entity_id: grant_locator(&community.id(), &op_bytes), version: 1, edition_hash: hash })
    }

    /// Publish a durable event and DO NOT return until a relay hands it back.
    ///
    /// An any-accept publish reports success for a write that never persisted —
    /// a relay that ACKs then drops it, or propagation lag on the AUTH-gated
    /// community relays. The missing read-back is what let the importer mark
    /// channel editions (and the owner's control-key Grant) published when they
    /// never landed, minting bridge rows that point at a channel absent from
    /// every fold and leaving the owner unable to write the Control Plane.
    /// Erroring matches the bundle's semantics: `retry` resumes from the
    /// checkpoints, so a failed publish costs a retry, not a corrupt community.
    async fn publish_verified(&self, relays: &dyn RelayLike, event: &Event, label: &str) -> anyhow::Result<()> {
        // `authors` narrows nothing — the id fixes the author — but it is how
        // the pool knows which stream key to AUTH as on gated relays.
        let filter = Filter::new().id(event.id).author(event.pubkey);
        let landed = || async { relays.query(vec![filter.clone()]).await.is_ok_and(|e| !e.is_empty()) };
        // Check, then sleep: a relay that persists the write and answers for it
        // at once (the common case) costs a query, not a wall of waits.
        for _ in 0..5 {
            if landed().await {
                return Ok(());
            }
            let _ = relays.publish(event).await;
            if landed().await {
                return Ok(());
            }
            tokio::time::sleep(self.io.publish_retry).await;
        }
        bail!("{label} did not become readable on the community relays; retry the import")
    }

    fn owner_seal(plan: &ImportPlan, purpose: OwnerSignPurpose) -> anyhow::Result<Event> {
        let cp = &plan.checkpoints;
        let i = cp.owner_templates.iter().flatten().position(|t| t.purpose == purpose);
        let signed = i.and_then(|i| cp.owner_signed_seals.as_ref()?.get(i)).with_context(|| format!("missing owner signature for {purpose:?}"))?;
        seal_event(signed).with_context(|| format!("owner signature for {purpose:?} does not verify"))
    }

    /// Publish the owner's signed seals, then every op-key edition, then the invite.
    async fn publish_editions(&self, import_id: &str, community: &Membership, op: &Keys, plan: &mut ImportPlan) -> anyhow::Result<()> {
        self.set_status(import_id, "publishing", None).await?;
        let control = community.control_write_stream().context("the portal does not hold this community's control key")?;
        let guestbook = community.current_guestbook_stream();
        let relays = (self.io.relays)(community.relays.clone());
        relays.register_auth_keys([stream_keys(&community.control_streams()), stream_keys(&community.guestbook_streams())].concat());
        let relays = relays.as_ref();
        let cid = community.id();
        let vac = Self::op_vac(community, op, plan)?;
        let op_pk = op.public_key().to_hex();
        let op_v1 = EditionMeta::first(&op_pk, Some(&vac));

        // 1. The owner-signed authority chain, control plane first.
        let owner_steps = [
            (OwnerSignPurpose::AdminRole, "admin role edition"),
            (OwnerSignPurpose::OpGrant, "operator grant edition"),
            (OwnerSignPurpose::InviteRegistry, "invite registry edition"),
            (OwnerSignPurpose::OwnerJoin, "owner join"),
        ];
        for (purpose, label) in owner_steps {
            let cp = &plan.checkpoints;
            let done = match purpose {
                OwnerSignPurpose::AdminRole => cp.owner_role_published_at,
                OwnerSignPurpose::OpGrant => cp.owner_grant_published_at,
                OwnerSignPurpose::InviteRegistry => cp.owner_registry_published_at,
                OwnerSignPurpose::OwnerJoin => cp.owner_join_published_at,
            };
            if done.is_some() {
                continue;
            }
            let target = if purpose == OwnerSignPurpose::OwnerJoin { &guestbook } else { &control };
            let wrap = wrap_seal(&Self::owner_seal(plan, purpose)?, target, WrapOptions::default())?;
            self.publish_verified(relays, &wrap, label).await?;
            let cp = &mut plan.checkpoints;
            let at = Some(now_ms());
            match purpose {
                OwnerSignPurpose::AdminRole => cp.owner_role_published_at = at,
                OwnerSignPurpose::OpGrant => cp.owner_grant_published_at = at,
                OwnerSignPurpose::InviteRegistry => cp.owner_registry_published_at = at,
                OwnerSignPurpose::OwnerJoin => cp.owner_join_published_at = at,
            }
            self.save_plan(import_id, plan).await?;
        }

        // 1b. Hand the OWNER the staff write key (CORD-04 §3). The portal
        // minted `control_root` server-side and the owner joins through the
        // public invite, which carries `control_pk` but never the secret — so
        // without this they could read the Control Plane and never write it,
        // not even to revoke the op grant this chain exists to make revocable.
        // The role set is EMPTY on purpose: the owner's authority is position 0
        // and never came from a grant. This edition delivers a key, claims nothing.
        if plan.checkpoints.owner_control_key_published_at.is_none()
            && let Some(control_root) = community.control_root.as_deref().and_then(hex32)
        {
            let owner_pk = PublicKey::from_hex(&community.owner)?;
            let wrap = concord::rekey::seal_control_wrap(community.root_epoch, &control_root, op.secret_key(), &owner_pk)?;
            let grant = MemberGrant { member: community.owner.clone(), role_ids: vec![], control_wrap: Some(wrap) };
            let edition = seal_edition(&build_grant_edition(&cid, &grant, &op_v1)?, &control, op)?;
            self.publish_verified(relays, &edition, "owner control-key grant").await?;
            plan.checkpoints.owner_control_key_published_at = Some(now_ms());
            self.save_plan(import_id, plan).await?;
        }

        // 2. Server icon and banner, rehosted as encrypted blobs before the
        // metadata edition that references them. Best effort: an unreachable
        // CDN or blob host costs the images, never the import.
        if plan.checkpoints.assets_at.is_none() && plan.checkpoints.metadata_published_at.is_none() {
            let rehosted = async {
                if let Some(url) = &plan.guild.icon_url {
                    plan.checkpoints.icon_pointer = Some(rehost_encrypted_image(url, self.io.blobs.as_ref(), op).await?);
                }
                if let Some(url) = &plan.guild.banner_url {
                    plan.checkpoints.banner_pointer = Some(rehost_encrypted_image(url, self.io.blobs.as_ref(), op).await?);
                }
                anyhow::Ok(())
            };
            if let Err(error) = rehosted.await {
                tracing::error!(import = %import_id, error = %format!("{error:#}"), "icon/banner rehost failed");
                plan.checkpoints.assets_error = Some(format!("{error:#}"));
            }
            plan.checkpoints.assets_at = Some(now_ms());
            self.save_plan(import_id, plan).await?;
        }

        // 3. The op key's editions, each citing the grant.
        if plan.checkpoints.metadata_published_at.is_none() {
            let mut metadata = json!({ "name": plan.community_name });
            if let Some(d) = &plan.guild.description {
                metadata["description"] = json!(d);
            }
            metadata["relays"] = json!(community.relays);
            if let Some(icon) = &plan.checkpoints.icon_pointer {
                metadata["icon"] = serde_json::to_value(icon)?;
            }
            if let Some(banner) = &plan.checkpoints.banner_pointer {
                metadata["banner"] = serde_json::to_value(banner)?;
            }
            // A forward-compatible breadcrumb to the guild emoji pack under a
            // namespace we own; nothing in Armada reads it yet.
            if !plan.emojis.is_empty() {
                metadata["custom"] = json!({ DISCORD_IMPORT_METADATA_KEY: { "emojiPack": format!("30030:{op_pk}:discord-import") } });
            }
            let edition = seal_edition(&build_metadata_edition(&cid, &metadata, &op_v1)?, &control, op)?;
            self.publish_verified(relays, &edition, "community metadata edition").await?;
            plan.checkpoints.metadata_published_at = Some(now_ms());
            self.save_plan(import_id, plan).await?;
        }

        // Channel-access Roles sit below every imported Role. They are peers
        // (CORD-04 §3 lets Roles share a position), and op holds the stock
        // Admin at position 1, so it outranks them and may mint them.
        let access_role_position = plan.roles.len() as u32 + 2;
        let mut position = 0u64;
        for i in 0..plan.channels.len() {
            if !plan.channels[i].selected {
                continue;
            }
            let this_position = position;
            position += 1;
            if plan.channels[i].published_at.is_some() {
                continue;
            }
            let channel_id = plan.channels[i].channel_id_hex.clone().context("selected channel has no id")?;
            // The access Role publishes BEFORE the channel edition, the order
            // Armada's own createChannel takes: a Role scoped to a channel that
            // never appeared is inert, while a private channel whose Role mint
            // then failed is a room with no access list at all.
            if plan.channels[i].is_private() && plan.channels[i].access_role_published_at.is_none() {
                let role = Role {
                    role_id: plan.channels[i].access_role_id_hex.clone().context("private channel has no access role")?,
                    name: plan.channels[i].name.clone(),
                    position: access_role_position,
                    permissions: 0,
                    scope: RoleScope::Channel(channel_id.clone()),
                    color: 0,
                };
                let edition = seal_edition(&build_role_edition(&role, &op_v1)?, &control, op)?;
                self.publish_verified(relays, &edition, &format!("access role edition for #{}", role.name)).await?;
                plan.channels[i].access_role_published_at = Some(now_ms());
                self.save_plan(import_id, plan).await?;
            }
            let channel = &plan.channels[i];
            let mut metadata = json!({ "name": channel.name, "private": channel.is_private() });
            // The arrangement rides Armada's namespaced custom members, not bare
            // `category`/`position` keys, which Armada reads nothing of — an
            // import inventing its own spelling lands as a flat list.
            with_channel_position(&mut metadata, Some(this_position));
            with_channel_category(&mut metadata, channel.category.as_deref());
            // Discord facts Concord has no field for, under our namespace so a
            // client round-trips them: `topic` has no Concord equivalent, and
            // `type` records what the room was on Discord — every Concord
            // channel is callable, so a voice room is a naming convention here.
            if channel.topic.is_some() || channel.kind.is_some() {
                let mut facts = serde_json::Map::new();
                if let Some(topic) = &channel.topic {
                    facts.insert("topic".into(), json!(topic));
                }
                if channel.kind.is_some() {
                    facts.insert("type".into(), json!("voice"));
                }
                if !metadata.get("custom").is_some_and(Value::is_object) {
                    metadata["custom"] = json!({});
                }
                metadata["custom"][DISCORD_IMPORT_METADATA_KEY] = Value::Object(facts);
            }
            let id = hex32(&channel_id).context("channel id is malformed")?;
            let edition = seal_edition(&build_channel_edition(&id, &metadata, &op_v1)?, &control, op)?;
            self.publish_verified(relays, &edition, &format!("channel edition for #{}", channel.name)).await?;
            plan.channels[i].published_at = Some(now_ms());
            self.save_plan(import_id, plan).await?;
        }

        for i in 0..plan.roles.len() {
            if plan.roles[i].published_at.is_some() {
                continue;
            }
            let r = &plan.roles[i];
            let role = Role {
                role_id: r.role_id_hex.clone().context("role has no id")?,
                name: r.name.clone(),
                position: r.position,
                permissions: r.permissions,
                scope: RoleScope::Server,
                color: r.color,
            };
            let edition = seal_edition(&build_role_edition(&role, &op_v1)?, &control, op)?;
            self.publish_verified(relays, &edition, &format!("role edition \"{}\"", role.name)).await?;
            plan.roles[i].published_at = Some(now_ms());
            self.save_plan(import_id, plan).await?;
        }

        // Guild custom emoji: one kind-30030 NIP-30 pack members can add to
        // their palette, on stable CDN URLs so bridged reactions round-trip
        // back to the native Discord emoji.
        if !plan.emojis.is_empty() && plan.checkpoints.emoji_pack_published_at.is_none() {
            let mut tags = vec![Tag::parse(["d", "discord-import"])?, Tag::parse(["title".to_string(), format!("{} emoji", plan.community_name)])?];
            for e in &plan.emojis {
                tags.push(Tag::parse(["emoji".to_string(), e.name.clone(), discord_emoji_url(&e.id, e.animated)])?);
            }
            relays.publish(&EventBuilder::new(Kind::Custom(30030), "").tags(tags).finalize(op)?).await?;
            plan.checkpoints.emoji_pack_address = Some(format!("30030:{op_pk}:discord-import"));
            plan.checkpoints.emoji_pack_published_at = Some(now_ms());
            self.save_plan(import_id, plan).await?;
        }

        if plan.checkpoints.op_join_published_at.is_none() {
            let join = concord::guestbook::join(&op_pk, now_ms(), None);
            relays.publish(&seal_and_wrap(&join, Plane::Guestbook, &guestbook, op, WrapOptions::default())?).await?;
            plan.checkpoints.op_join_published_at = Some(now_ms());
            self.save_plan(import_id, plan).await?;
        }

        if plan.checkpoints.profile_published_at.is_none() {
            let profile = json!({
                "name": format!("{} importer", plan.community_name),
                "about": "Operational account of the Armada bridge portal: imported this community from Discord and runs its bridges. Holds an Admin role the owner can revoke.",
                "bot": true,
            });
            relays.publish(&EventBuilder::new(Kind::Metadata, profile.to_string()).finalize(op)?).await?;
            plan.checkpoints.profile_published_at = Some(now_ms());
            self.save_plan(import_id, plan).await?;
        }

        // 4. The public invite bundle at the owner's registered link. Wiring
        // resolves this bundle back FROM the relays, so only checkpoint once a
        // read-back proves it landed.
        let row = self.row(import_id, None).await?.context("import row vanished")?;
        let (Some(invite_sealed), Some(link_sealed)) = (&row.invite_url_sealed, &row.link_signer_sk_sealed) else {
            bail!("import lost its sealed invite material");
        };
        let link_keys = Keys::new(SecretKey::from_hex(&unseal(&self.env.seal_key_hex, link_sealed)?)?);
        let parsed = parse_invite_link(&unseal(&self.env.seal_key_hex, invite_sealed)?).context("stored invite URL no longer parses")?;
        let bundle = self.public_bundle(community, plan)?;
        let bundle_filter = Filter::new().kind(Kind::Custom(kinds::INVITE_BUNDLE)).author(link_keys.public_key()).limit(1);
        let mut visible = relays.query(vec![bundle_filter.clone()]).await.is_ok_and(|e| !e.is_empty());
        for _ in 0..4 {
            if visible {
                break;
            }
            let _ = relays.publish(&build_bundle_event(&bundle, &parsed.token, &link_keys)?).await;
            tokio::time::sleep(self.io.publish_retry).await;
            visible = relays.query(vec![bundle_filter.clone()]).await.is_ok_and(|e| !e.is_empty());
        }
        if !visible {
            bail!("invite bundle did not become readable on the community relays; retry the import");
        }
        if plan.checkpoints.invite_published_at.is_none() {
            plan.checkpoints.invite_published_at = Some(now_ms());
            self.save_plan(import_id, plan).await?;
        }

        // 5. The private-channel keys, handed to the OWNER as a Direct Invite
        // (CORD-05 §6). They cannot ride the public bundle — every joiner reads
        // it, so a key there gates nothing — and the owner never receives one
        // otherwise: they join through that same public link. Only the owner;
        // everyone else's access is a grant of the channel's Role, made from
        // Armada once real npubs exist.
        let private: Vec<&PlannedChannel> = plan.channels.iter().filter(|c| c.selected && c.is_private() && c.key_sealed.is_some()).collect();
        if !private.is_empty() && plan.checkpoints.owner_channel_keys_sent_at.is_none() {
            let mut keys = bundle.clone();
            keys.channels = private.iter().map(|c| self.bundle_channel(c)).collect::<anyhow::Result<_>>()?;
            keys.label = Some("Imported from Discord — private channel keys".into());
            let owner_pk = PublicKey::from_hex(&community.owner)?;
            let wrap = concord::direct_invite::send(&keys, op, &owner_pk, None)?;
            // The owner's giftwrap inbox, not the community relays: that is
            // where their client scans (10050 DM relays, else NIP-65 reads).
            let lookup = Filter::new().kinds([Kind::Custom(kinds::DM_RELAYS), Kind::Custom(kinds::RELAY_LIST)]).author(owner_pk).limit(4);
            let inbox = relays.query(vec![lookup]).await.map(|events| inbox_relays_from(&events, &owner_pk)).unwrap_or_default();
            let delivery = (self.io.relays)(invite_delivery_relays(&inbox));
            match delivery.publish(&wrap).await {
                Ok(()) => plan.checkpoints.owner_channel_keys_sent_at = Some(now_ms()),
                // Non-fatal: the community is published and the channels gated.
                // The owner's copy is recoverable by re-running the import —
                // the keys are checkpointed, not re-minted.
                Err(error) => plan.checkpoints.owner_channel_keys_error = Some(format!("{error:#}")),
            }
            self.save_plan(import_id, plan).await?;
        }
        Ok(())
    }

    fn public_bundle(&self, community: &Membership, plan: &ImportPlan) -> anyhow::Result<InviteBundle> {
        Ok(serde_json::from_value(json!({
            "community_id": community.community_id,
            "owner": community.owner,
            "owner_salt": community.owner_salt,
            "community_root": community.root,
            "root_epoch": 0,
            // Read access to the Control Plane, never write (CORD-02 §7).
            "control_pk": community.control_pk,
            "channels": [],
            "relays": community.relays,
            "name": plan.community_name,
            "creator_npub": community.owner,
            "label": "Imported from Discord",
        }))?)
    }

    fn bundle_channel(&self, c: &PlannedChannel) -> anyhow::Result<concord::invite::BundleChannel> {
        let sealed = hex::decode(c.key_sealed.as_deref().context("private channel has no key")?)?;
        Ok(concord::invite::BundleChannel {
            id: c.channel_id_hex.clone().context("channel has no id")?,
            key: unseal(&self.env.seal_key_hex, &sealed)?,
            epoch: 0,
            name: c.name.clone(),
        })
    }
}

/// Waits between attempts at one history message while relays refuse it, in
/// multiples of `ImporterIo::publish_retry`: 1.5s doubling to 48s by default,
/// about a minute and a half in all.
const HISTORY_BACKOFF_STEPS: u32 = 6;

/// Run `attempt` until relays stop refusing it, backing off from `base`,
/// doubling, for `steps` waits. Any other failure returns at once: it will
/// fail the same way however long we wait. Still refused after the last wait
/// is an error the caller must not skip past.
async fn with_relay_backoff<T, F, Fut>(base: Duration, steps: u32, mut attempt: F) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let mut step = 0;
    loop {
        match attempt().await {
            Err(error) if PublishRejected::in_chain(&error) && step < steps => {
                let wait = base * 2u32.pow(step);
                tracing::warn!(wait_s = wait.as_secs_f32(), error = %format!("{error:#}"), "relays refusing history; backing off");
                tokio::time::sleep(wait).await;
                step += 1;
            }
            other => return other,
        }
    }
}

impl Importer {
    /// Backfill the newest HISTORY_MESSAGE_CAP messages of every bridged channel
    /// that opted in, oldest to newest so replies resolve, through the SAME
    /// router the live bridge uses (puppets, transforms, rehosting, mapping).
    async fn import_history(&self, import_id: &str, plan: &mut ImportPlan) -> anyhow::Result<()> {
        let pending: Vec<usize> = (0..plan.channels.len())
            .filter(|&i| {
                let c = &plan.channels[i];
                c.selected && c.bridge && c.bridgeable && c.history && c.history_done_at.is_none()
            })
            .collect();
        if pending.is_empty() {
            return Ok(());
        }
        self.set_status(import_id, "history", None).await?;
        for i in pending {
            self.backfill_channel(import_id, plan, i).await?;
        }
        Ok(())
    }

    /// Re-run history for a finished import (recovery for the silent-skip
    /// bug): clears the done markers so opted-in channels backfill again,
    /// deduped against the messages table. Nothing is re-minted.
    pub async fn rerun_history(self: &Arc<Self>, import_id: &str, owner_discord_id: &str) -> anyhow::Result<()> {
        let row = self.row(import_id, Some(owner_discord_id)).await?.context("no such import")?;
        if row.status != "done" && row.status != "failed" {
            bail!("import is {}; only a finished import can re-run history", row.status);
        }
        let mut plan = row.plan;
        let mut any = false;
        for c in plan.channels.iter_mut().filter(|c| c.selected && c.bridge && c.bridgeable && c.history) {
            c.history_done_at = None;
            // Start over from the top: the cursor may have been advanced past
            // messages that never published. The per-community dedupe absorbs
            // the overlap.
            c.history_cursor = None;
            c.history_imported = Some(0);
            any = true;
        }
        if !any {
            bail!("no channels opted into history");
        }
        // Flip the status here, synchronously, so a client polling right after
        // this request never sees the stale 'done'.
        self.pool
            .get()
            .await?
            .execute(
                "UPDATE imports SET plan = $2, history_progress = '{}', status = 'history', status_detail = NULL, updated_at = now()
                 WHERE import_id = ($1::text)::uuid",
                &[&import_id, &plan_json(&plan)],
            )
            .await?;
        self.spawn_pipeline(import_id, true);
        Ok(())
    }

    async fn run_history_only(&self, import_id: &str) -> anyhow::Result<()> {
        let mut plan = self.row(import_id, None).await?.context("import row vanished")?.plan;
        self.import_history(import_id, &mut plan).await?;
        self.set_status(import_id, "done", None).await
    }

    async fn backfill_channel(&self, import_id: &str, plan: &mut ImportPlan, i: usize) -> anyhow::Result<()> {
        let discord_id = plan.channels[i].discord_id.clone();
        let name = plan.channels[i].name.clone();
        // Re-fold control so the running bridge knows the channels the import
        // just created; without this the router silently skips every history
        // message (the invisible-history bug).
        let _ = self.host.resync_for(&discord_id).await;
        let Some((router, link)) = self.host.router_for(&discord_id) else {
            tracing::warn!(import = %import_id, channel = %name, "no live bridge; history skipped");
            plan.channels[i].history_done_at = Some(now_ms());
            return self.save_plan(import_id, plan).await;
        };

        // Collect the newest cap-worth, stopping at the resume cursor
        // (everything at or below it already published on a prior run).
        let cursor = plan.channels[i].history_cursor.as_deref().and_then(|c| c.parse::<u64>().ok());
        let mut collected: Vec<RestMessage> = Vec::new();
        let mut before: Option<String> = None;
        'pages: while collected.len() < HISTORY_MESSAGE_CAP as usize {
            let Some(page) = (self.io.history)(discord_id.clone(), before.clone()).await? else { break };
            let Some(last) = page.last() else { break };
            before = Some(last.id.clone());
            for message in page {
                if cursor.is_some_and(|c| message.id.parse::<u64>().unwrap_or(0) <= c) {
                    break 'pages;
                }
                collected.push(message);
                if collected.len() >= HISTORY_MESSAGE_CAP as usize {
                    break 'pages;
                }
            }
        }
        collected.reverse(); // oldest first, so reply targets exist when cited

        let mut published = plan.channels[i].history_imported.unwrap_or(0);
        let mut skipped = 0;
        for message in collected {
            if message.kind != 0 && message.kind != 19 {
                continue;
            }
            // Scoped to this community: re-importing the same guild elsewhere
            // left rows for the same message id, which made every history
            // message look already imported and silently skipped the backfill.
            // `tenant_id` leads every index on messages: without it this check
            // walked the whole primary key, ~0.5s per message (2026-10-16).
            let exists = self
                .pool
                .get()
                .await?
                .query_opt(
                    "SELECT 1 FROM messages WHERE tenant_id = 'default' AND discord_message_id = $1 AND community_id = $2 LIMIT 1",
                    &[&message.id, &link.community_id],
                )
                .await?
                .is_some();
            if !exists {
                let inbound = rest_to_inbound(&message, &link.discord_guild_id, &discord_id);
                // Paced by the relays: one message in flight, and when they
                // refuse it (a rate limiter, an overloaded relay), the same
                // message again after a wait, never the next one. Skipping on
                // to a later message moved the resume cursor past the refused
                // one, so a rate-limited stretch of a large server's history
                // was lost for good. Before 2026-10-16 only servers of up to
                // 100 members were offered history, and imports were small.
                let sent = with_relay_backoff(self.io.publish_retry, HISTORY_BACKOFF_STEPS, || router.on_discord_message(inbound.clone(), &link)).await;
                let rumor = match sent {
                    Ok(rumor) => rumor,
                    Err(error) if PublishRejected::in_chain(&error) => {
                        // The cursor stays at the last message that landed.
                        self.save_plan(import_id, plan).await?;
                        return Err(error.context(format!("relays kept refusing #{name}'s history; re-run history to resume")));
                    }
                    Err(error) => {
                        tracing::warn!(import = %import_id, message = %message.id, error = %format!("{error:#}"), "history message failed");
                        None
                    }
                };
                if rumor.is_none() {
                    // A skip, not a success: do NOT count it or advance the
                    // cursor past it, or a resume never retries it — that was
                    // the silent-history-loss bug.
                    skipped += 1;
                    continue;
                }
                tokio::time::sleep(Duration::from_millis(25)).await; // relay pacing
            }
            published += 1;
            plan.channels[i].history_imported = Some(published);
            plan.channels[i].history_cursor = Some(message.id.clone());
            if published.is_multiple_of(20) {
                self.save_progress(import_id, &discord_id, published, &message.id).await?;
            }
        }
        if skipped > 0 {
            tracing::warn!(
                import = %import_id, channel = %name, skipped,
                "history messages skipped (bot/webhook-authored, empty after conversion, or channel not in bridge fold)",
            );
        }
        plan.channels[i].history_done_at = Some(now_ms());
        self.save_plan(import_id, plan).await
    }

    /// Let a bridge into a private channel the owner ticked for mirroring.
    ///
    /// 1. Grant the bridge's npub the channel-scoped access Role: the access
    ///    list Armada shows and revokes from. Without it the bridge would hold
    ///    a key nobody can see it holding, and a revoke would remove nothing.
    /// 2. Hand it the key as a Direct Invite (CORD-05 §6), published where the
    ///    bridge scans at boot. Nothing is persisted for it: the wrap is a
    ///    durable relay event, so a restart re-reads the same key.
    ///
    /// Rotation is still not covered: a rekey after a revoke mints an epoch the
    /// bridge does not follow, so it goes quiet on that channel until
    /// re-granted. That is the known bound on this feature.
    async fn admit_bridge_to_private_channel(&self, community: &Membership, op: &Keys, plan: &ImportPlan, i: usize, bridge_pk: &str) -> anyhow::Result<()> {
        let channel = &plan.channels[i];
        let control = community.control_write_stream().context("the portal does not hold this community's control key")?;
        let relays = (self.io.relays)(community.relays.clone());
        relays.register_auth_keys(stream_keys(&community.control_streams()));
        let vac = Self::op_vac(community, op, plan)?;
        let op_pk = op.public_key().to_hex();
        let grant = MemberGrant { member: bridge_pk.to_owned(), role_ids: vec![channel.access_role_id_hex.clone().context("no access role")?], control_wrap: None };
        let edition = seal_edition(&build_grant_edition(&community.id(), &grant, &EditionMeta::first(&op_pk, Some(&vac)))?, &control, op)?;
        relays.publish(&edition).await?;

        let mut bundle = self.public_bundle(community, plan)?;
        bundle.channels = vec![self.bundle_channel(channel)?];
        bundle.label = Some(format!("Bridge access — {}", channel.name));
        relays.publish(&concord::direct_invite::send(&bundle, op, &PublicKey::from_hex(bridge_pk)?, None)?).await
    }

    /// Create and activate a bridges row per selected text channel, with no
    /// consent gate: the portal custodially owns the community it just minted.
    async fn wire_bridges(&self, import_id: &str, community: &Membership, op: &Keys, plan: &mut ImportPlan) -> anyhow::Result<()> {
        self.set_status(import_id, "wiring", None).await?;
        let row = self.row(import_id, None).await?.context("import row vanished")?;
        let invite_url = unseal(&self.env.seal_key_hex, row.invite_url_sealed.as_deref().context("import lost its invite URL before wiring")?)?;
        for i in 0..plan.channels.len() {
            let c = &plan.channels[i];
            if !c.selected || !c.bridge || !c.bridgeable || c.bridge_id.is_some() {
                continue;
            }
            let discord_id = c.discord_id.clone();
            let db = self.pool.get().await?;
            // A channel someone already bridged by hand: one live bridge per
            // Discord channel is a database invariant (migration 017), so a
            // second activation would throw and take the import down. Note it
            // and move on; the owner can unlink the old bridge and re-run.
            let claimed = db
                .query_opt("SELECT 1 FROM bridges WHERE discord_channel_id = $1 AND status IN ('pending_confirm', 'active')", &[&discord_id])
                .await?;
            if claimed.is_some() {
                plan.channels[i].bridge_skipped = Some("another bridge already mirrors this Discord channel".into());
                self.save_plan(import_id, plan).await?;
                continue;
            }
            let sql = format!(
                "INSERT INTO bridges (owner_discord_id, status, invite_url_sealed, community_id, community_name,
                   discord_guild_id, discord_channel_id, concord_channel_id)
                 VALUES ($1, 'draft', $2, $3, $4, $5, $6, $7) RETURNING {BRIDGE_COLUMNS}"
            );
            let inserted = db
                .query_one(
                    &sql,
                    &[
                        &row.owner_discord_id,
                        &seal(&self.env.seal_key_hex, &invite_url)?,
                        &community.community_id,
                        &plan.community_name,
                        &row.discord_guild_id,
                        &discord_id,
                        &plan.channels[i].channel_id_hex,
                    ],
                )
                .await?;
            drop(db);
            let bridge = BridgeRow::from_row(&inserted);

            // Mint the identity first, so a private channel's key can reach it
            // before it boots — key intake happens once, at start.
            let provisioned = self.host.provision_imported(&bridge).await?;
            if plan.channels[i].is_private() && plan.channels[i].key_sealed.is_some() {
                let pk = provisioned.primary_pk.clone().context("provisioned bridge has no primary key")?;
                self.admit_bridge_to_private_channel(community, op, plan, i, &pk).await?;
            }
            // Resolving the invite inside start races relay propagation of the
            // fresh bundle; a couple of spaced retries absorb that.
            let mut last_error = None;
            for attempt in 0..3 {
                if attempt > 0 {
                    tokio::time::sleep(self.io.publish_retry * 2).await;
                }
                match self.host.start_imported(&provisioned).await {
                    Ok(()) => {
                        last_error = None;
                        break;
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            if let Some(error) = last_error {
                return Err(error);
            }
            plan.channels[i].bridge_id = Some(bridge.bridge_id.clone());
            // Wait until the running bridge's fold contains this channel, so the
            // backfill that follows doesn't skip every message.
            let channel_id = plan.channels[i].channel_id_hex.clone().unwrap_or_default();
            for attempt in 0..5 {
                let _ = self.host.resync_for(&discord_id).await;
                if self.host.channel_known(&discord_id, &channel_id) {
                    break;
                }
                if attempt < 4 {
                    tokio::time::sleep(self.io.publish_retry).await;
                }
            }
            self.save_plan(import_id, plan).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridge::client::ConcordClient;
    use bridge::relays::MemoryRelay;
    use concord::roles::perm;

    const SEAL_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    async fn test_pool() -> Option<Pool> {
        let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://postgres:test@127.0.0.1:55432/bridge".into());
        let pool = bridge::db::connect(&url, 4).ok()?;
        if tokio::time::timeout(Duration::from_secs(3), pool.get()).await.ok()?.is_err() {
            eprintln!("skipping: no database at DATABASE_URL");
            return None;
        }
        bridge::db::migrate(&pool).await.unwrap();
        Some(pool)
    }

    /// Provisions bridges the way the manager does, without starting anything.
    struct FakeHost {
        pool: Pool,
    }

    #[async_trait]
    impl BridgeHost for FakeHost {
        async fn provision_imported(&self, row: &BridgeRow) -> anyhow::Result<BridgeRow> {
            let pk = Keys::generate().public_key().to_hex();
            self.pool
                .get()
                .await?
                .execute("UPDATE bridges SET status = 'active', primary_pk = $2 WHERE bridge_id = ($1::text)::uuid", &[&row.bridge_id, &pk])
                .await?;
            Ok(crate::manager::bridge_by_id(&self.pool, &row.bridge_id).await?.unwrap())
        }
        async fn start_imported(&self, _: &BridgeRow) -> anyhow::Result<()> {
            Ok(())
        }
        async fn resync_for(&self, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
        fn channel_known(&self, _: &str, _: &str) -> bool {
            true
        }
        fn router_for(&self, _: &str) -> Option<(Arc<BridgeRouter>, ChannelLink)> {
            None
        }
    }

    struct NoBlobs;

    #[async_trait]
    impl BlobPort for NoBlobs {
        async fn download(&self, url: &str, _: usize) -> anyhow::Result<(Vec<u8>, String)> {
            bail!("unreachable CDN {url}")
        }
        async fn upload(&self, _: &[u8], _: &str, _: &Keys) -> anyhow::Result<bridge::blossom::Uploaded> {
            bail!("no blob host")
        }
    }

    /// Discord ids are prefixed with `p` (unique per run) so a failed run's
    /// leftover bridges never trip the one-bridge-per-channel guard.
    fn snapshot(guild_id: &str, p: &str) -> crate::discord_rest::GuildSnapshot {
        serde_json::from_value(json!({
            "guild": {
                "id": guild_id, "name": "Lynch Park", "icon": "abc", "approximate_member_count": 12,
                "roles": [
                    { "id": guild_id, "name": "@everyone", "permissions": "0", "color": 0, "hoist": false, "position": 0, "managed": false },
                    { "id": "11", "name": "Mods", "permissions": "8192", "color": 255, "hoist": true, "position": 2, "managed": false },
                ],
                "emojis": [{ "id": "77", "name": "blob" }],
            },
            "channels": [
                { "id": format!("{p}20"), "name": "Talk", "type": 4, "position": 0 },
                { "id": format!("{p}21"), "name": "general", "type": 0, "position": 0, "parent_id": format!("{p}20"), "topic": "hi" },
                { "id": format!("{p}22"), "name": "mods", "type": 0, "position": 1, "parent_id": format!("{p}20"),
                  "permission_overwrites": [{ "id": guild_id, "type": 0, "allow": "0", "deny": "1024" }] },
                { "id": format!("{p}23"), "name": "Lounge", "type": 2, "position": 2 },
            ],
        }))
        .unwrap()
    }

    fn sign(template: &EventTemplate, keys: &Keys) -> SignedSeal {
        let tags = template.tags.iter().map(|t| Tag::parse(t.clone()).unwrap()).collect::<Vec<_>>();
        let event = EventBuilder::new(Kind::Custom(template.kind), template.content.clone())
            .tags(tags)
            .custom_created_at(Timestamp::from(template.created_at))
            .finalize(keys)
            .unwrap();
        serde_json::from_str(&event.as_json()).unwrap()
    }

    #[tokio::test]
    async fn imports_a_guild_that_armada_reads_back_as_planned() {
        let Some(pool) = test_pool().await else { return };
        let guild_id = format!("9{}", std::process::id());
        let owner_discord = format!("test-importer-{}", std::process::id());
        let relay = MemoryRelay::new();
        let env = crate::env::PortalEnv::from_env(|k| match k {
            "PORTAL_SEAL_KEY" => Some(SEAL_KEY.into()),
            "DATABASE_URL" => Some("postgres://unused".into()),
            "INVITE_BASE_URL" => Some("https://armada.example".into()),
            _ => None,
        })
        .unwrap();
        let wire = relay.clone();
        let io = ImporterIo {
            relays: Arc::new(move |_| Arc::new(wire.clone()) as Arc<dyn RelayLike>),
            history: Arc::new(|_, _| Box::pin(async { Ok(Some(vec![])) })),
            vet_relays: Arc::new(|_| Box::pin(async { Ok(()) })),
            publish_retry: Duration::from_millis(5),
            blobs: Arc::new(NoBlobs),
        };
        let importer = Importer::new(pool.clone(), env, Arc::new(FakeHost { pool: pool.clone() }), io);

        let p = guild_id.clone();
        let plan = build_import_plan(&snapshot(&guild_id, &p));
        let import_id: String = pool
            .get()
            .await
            .unwrap()
            .query_one(
                "INSERT INTO imports (owner_discord_id, discord_guild_id, plan) VALUES ($1, $2, $3) RETURNING import_id::text",
                &[&owner_discord, &guild_id, &plan_json(&plan)],
            )
            .await
            .unwrap()
            .get(0);

        let owner = Keys::generate();
        let body = PrepareBody {
            owner_npub: Some(owner.public_key().to_bech32().unwrap()),
            relays: Some(vec!["wss://relay.test".into()]),
            channels: Some(vec![ChannelToggle { discord_id: format!("{p}22"), bridge: Some(true), ..Default::default() }]),
        };
        let (owner_hex, templates) = importer.prepare(&import_id, &owner_discord, body).await.unwrap();
        assert_eq!(owner_hex, owner.public_key().to_hex());

        // A signature from anyone but the owner is refused.
        let forged = ConfirmBody { signed_events: Some(templates.iter().map(|t| sign(&t.template, &Keys::generate())).collect()) };
        assert!(importer.confirm(&import_id, &owner_discord, forged).await.is_err());

        let signed = ConfirmBody { signed_events: Some(templates.iter().map(|t| sign(&t.template, &owner)).collect()) };
        importer.confirm(&import_id, &owner_discord, signed).await.unwrap();
        let mut status = String::new();
        for _ in 0..200 {
            let (row, _) = importer.get(&import_id, &owner_discord).await.unwrap().unwrap();
            status = row.status.clone();
            if status == "done" || status == "failed" {
                assert_eq!(status, "done", "{:?}", row.status_detail);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(status, "done");
        let (row, invite) = importer.get(&import_id, &owner_discord).await.unwrap().unwrap();
        let cp = &row.plan.checkpoints;
        assert!(cp.assets_error.is_some(), "an unreachable CDN costs the icon, not the import");
        assert!(cp.owner_channel_keys_sent_at.is_some());

        // A member joining through the minted invite sees what the plan promised.
        let joined = bridge::client::resolve_invite(&invite.unwrap(), &relay).await.unwrap();
        let member = ConcordClient::new(joined.membership.clone(), Arc::new(relay.clone()), Keys::generate());
        let folded = member.sync_control().await.unwrap();
        assert_eq!(folded.metadata.as_ref().unwrap().name, "Lynch Park");
        let names: Vec<String> = member.channels().into_iter().map(|c| c.name).collect();
        // Uncategorized channels lead (the plan sorts them before every category),
        // and the private one is folded but unreadable without its key.
        assert_eq!(names, ["Lounge-voice", "general"]);
        let mods = folded.channels.values().find(|c| c.name == "mods").unwrap();
        assert!(mods.private);
        assert_eq!(mods.category.as_deref(), Some("Talk"));
        let general = folded.channels.values().find(|c| c.name == "general").unwrap();
        assert_eq!(general.raw["custom"]["discord.import"]["topic"], "hi");
        let op = cp.op_pk_hex.clone().unwrap();
        assert!(folded.roster.has(&op, perm::ADMIN_ALL), "op holds the owner-granted Admin");
        assert!(folded.roster.roles.iter().any(|r| r.name == "Mods" && r.permissions == perm::MANAGE_MESSAGES));
        assert!(folded.is_public(), "the owner's invite registry is live");

        // The owner can open the staff key the op key handed them.
        let owner_grant = folded.roster.grants.iter().find(|g| g.member == owner.public_key().to_hex()).unwrap();
        let conv = concord::derive::conversation_key(owner.secret_key(), &PublicKey::from_hex(&op).unwrap());
        let plain = concord::nip44::decrypt_str(&conv, owner_grant.control_wrap.as_ref().unwrap()).unwrap();
        let (epoch, control_root) = concord::rekey::decode_control_wrap(&base64::Engine::decode(&base64::engine::general_purpose::STANDARD, plain).unwrap()).unwrap();
        let derived = concord::derive::control_signer_group_key(&control_root, &joined.membership.id(), epoch);
        assert_eq!(Some(derived.pk_hex()), joined.membership.control_pk);

        // And the private channel's key reached them, and only them.
        let keys = relay
            .published()
            .iter()
            .filter_map(|e| concord::direct_invite::unwrap(e, &owner))
            .find(|d| !d.bundle.channels.is_empty())
            .expect("the owner's Direct Invite");
        assert_eq!(keys.bundle.channels[0].name, "mods");

        // Both text channels were wired; the private one only because it was ticked.
        let bridges = pool
            .get()
            .await
            .unwrap()
            .query("SELECT discord_channel_id FROM bridges WHERE discord_guild_id = $1 ORDER BY discord_channel_id", &[&guild_id])
            .await
            .unwrap();
        assert_eq!(bridges.iter().map(|r| r.get::<_, String>(0)).collect::<Vec<_>>(), [format!("{p}21"), format!("{p}22")]);

        let db = pool.get().await.unwrap();
        db.execute("DELETE FROM bridges WHERE discord_guild_id = $1", &[&guild_id]).await.unwrap();
        db.execute("DELETE FROM imports WHERE discord_guild_id = $1", &[&guild_id]).await.unwrap();
        db.execute("DELETE FROM guild_community_secrets WHERE discord_guild_id = $1", &[&guild_id]).await.unwrap();
    }

    #[tokio::test]
    async fn history_checkpoints_overlay_the_plan_until_it_is_next_written() {
        let Some(pool) = test_pool().await else { return };
        let guild_id = format!("8{}", std::process::id());
        let env = crate::env::PortalEnv::from_env(|k| match k {
            "PORTAL_SEAL_KEY" => Some(SEAL_KEY.into()),
            "DATABASE_URL" => Some("postgres://unused".into()),
            _ => None,
        })
        .unwrap();
        let io = ImporterIo {
            relays: Arc::new(|_| Arc::new(MemoryRelay::new()) as Arc<dyn RelayLike>),
            history: Arc::new(|_, _| Box::pin(async { Ok(Some(vec![])) })),
            vet_relays: Arc::new(|_| Box::pin(async { Ok(()) })),
            publish_retry: Duration::from_millis(5),
            blobs: Arc::new(NoBlobs),
        };
        let importer = Importer::new(pool.clone(), env, Arc::new(FakeHost { pool: pool.clone() }), io);
        let mut plan = build_import_plan(&snapshot(&guild_id, &guild_id));
        let channel = format!("{guild_id}21");
        let import_id: String = pool
            .get()
            .await
            .unwrap()
            .query_one(
                "INSERT INTO imports (owner_discord_id, discord_guild_id, plan) VALUES ('test-progress', $1, $2) RETURNING import_id::text",
                &[&guild_id, &plan_json(&plan)],
            )
            .await
            .unwrap()
            .get(0);
        let read = async |importer: &Importer| {
            let plan = importer.row(&import_id, None).await.unwrap().unwrap().plan;
            let c = plan.channels.into_iter().find(|c| c.discord_id == channel).unwrap();
            (c.history_imported, c.history_cursor)
        };

        importer.save_progress(&import_id, &channel, 20, "120").await.unwrap();
        importer.save_progress(&import_id, &channel, 40, "140").await.unwrap();
        assert_eq!(read(&importer).await, (Some(40), Some("140".into())));
        let stored: Value = pool.get().await.unwrap().query_one("SELECT plan FROM imports WHERE import_id = ($1::text)::uuid", &[&import_id]).await.unwrap().get(0);
        assert!(stored.to_string().len() > 100 && !stored.to_string().contains("\"140\""), "a checkpoint leaves the plan alone");

        // A re-run resets progress in the plan; a stale checkpoint must not undo that.
        let c = plan.channels.iter_mut().find(|c| c.discord_id == channel).unwrap();
        (c.history_imported, c.history_cursor) = (Some(0), None);
        importer.save_plan(&import_id, &plan).await.unwrap();
        assert_eq!(read(&importer).await, (Some(0), None));

        pool.get().await.unwrap().execute("DELETE FROM imports WHERE import_id = ($1::text)::uuid", &[&import_id]).await.unwrap();
    }

    fn refused() -> anyhow::Error {
        PublishRejected { id: EventId::from_byte_array([0; 32]), tried: 1, why: "rate-limited".into() }.into()
    }

    #[tokio::test]
    async fn waits_out_relays_refusing_and_tries_the_same_message_again() {
        let calls = std::sync::atomic::AtomicU32::new(0);
        let result = with_relay_backoff(Duration::from_millis(1), 6, || async {
            let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n < 2 { Err(refused().context("router send")) } else { Ok(n) }
        })
        .await;
        assert_eq!(result.unwrap(), 2);
    }

    #[tokio::test]
    async fn does_not_wait_on_a_failure_that_will_repeat() {
        let calls = std::sync::atomic::AtomicU32::new(0);
        let result: anyhow::Result<()> = with_relay_backoff(Duration::from_secs(60), 6, || async {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            bail!("unconvertible message")
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn gives_up_refused_after_the_last_wait_and_says_so() {
        let calls = std::sync::atomic::AtomicU32::new(0);
        let result: anyhow::Result<()> = with_relay_backoff(Duration::from_millis(1), 3, || async {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(refused())
        })
        .await;
        assert!(PublishRejected::in_chain(&result.unwrap_err()));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 4);
    }

    #[test]
    fn parses_npubs_and_hex_owners() {
        let k = Keys::generate();
        assert_eq!(parse_admin_pubkey(&k.public_key().to_bech32().unwrap()), Some(k.public_key().to_hex()));
        assert_eq!(parse_admin_pubkey(&k.public_key().to_hex().to_uppercase()), Some(k.public_key().to_hex()));
        assert_eq!(parse_admin_pubkey("nsec1nope"), None);
    }
}
