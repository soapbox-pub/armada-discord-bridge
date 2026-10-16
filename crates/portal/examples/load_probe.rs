//! Read-only rehearsal of a portal boot against the real relays: every bridge
//! that would start is started on the relay side — invite, community runtime,
//! Direct Invite scan, live chat — and nothing is published, written, or sent
//! to Discord. Then it listens, and checks that every rumor the running portal
//! recorded in `messages` meanwhile reached the bridge it belongs to.
//!
//!   load_probe <listen-minutes>     (env: DATABASE_URL, PORTAL_SEAL_KEY)

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use bridge::client::{ConcordClient, resolve_invite};
use bridge::community::{Attachment, CommunityRuntime};
use bridge::key_intake::intake_direct_invite_keys;
use bridge::relays::{Hub, RelayLike, Relays};
use concord::community::Membership;
use concord::invite::{invite_delivery_relays, parse_invite_link, stock_relays};
use concord::roles::perm;
use nostr::prelude::*;
use portal::manager::{BRIDGE_COLUMNS, BridgeRow};
use portal::relay_guard::filter_public_relays;
use portal::seal::unseal;

const WORKERS: usize = 12;

async fn stage<T>(name: &str, secs: u64, fut: impl std::future::Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
    tokio::time::timeout(Duration::from_secs(secs), fut).await.map_err(|_| anyhow::anyhow!("{name} timed out"))?
}

struct Community {
    runtime: Arc<CommunityRuntime>,
    relays: Relays,
}

type Slot = Arc<tokio::sync::Mutex<Option<Arc<Community>>>>;

struct Probe {
    seal_key: String,
    bootstrap: Arc<Hub>,
    /// One hub for every community, as the portal runs them.
    communities: Arc<Hub>,
    slots: Mutex<HashMap<String, Slot>>,
    heard: Arc<Mutex<HashSet<String>>>,
    live: Mutex<Vec<(BridgeRow, Arc<ConcordClient>, Attachment)>>,
    failures: Mutex<HashMap<String, usize>>,
}

fn key(m: &Membership) -> String {
    let mut relays = m.relays.clone();
    relays.sort();
    format!("{}|{}|{}|{}|{}", m.community_id, m.root_epoch, m.root, m.control_pk.as_deref().unwrap_or(""), relays.join(" "))
}

impl Probe {
    async fn community(&self, m: &Membership) -> anyhow::Result<Arc<Community>> {
        let slot = self.slots.lock().unwrap().entry(key(m)).or_default().clone();
        let mut slot = slot.lock().await;
        if let Some(c) = slot.as_ref() {
            return Ok(c.clone());
        }
        let relays = self.communities.relays(filter_public_relays(&m.relays, &stock_relays()).await);
        let runtime = stage("folding the control plane", 90, CommunityRuntime::open(m.clone(), Arc::new(relays.clone()), None)).await?;
        anyhow::ensure!(runtime.folded().is_some_and(|f| !f.channels.is_empty()), "the control plane came back empty");
        let c = Arc::new(Community { runtime, relays });
        *slot = Some(c.clone());
        Ok(c)
    }

    async fn start(&self, row: &BridgeRow) -> anyhow::Result<()> {
        let invite = unseal(&self.seal_key, row.invite_url_sealed.as_deref().context("no invite")?)?;
        let primary = Keys::new(SecretKey::from_hex(&unseal(&self.seal_key, row.primary_sk_sealed.as_deref().context("no key")?)?)?);
        let link = parse_invite_link(&invite).context("bad invite")?;
        let urls = if link.bootstrap_relays.is_empty() { stock_relays() } else { link.bootstrap_relays };
        let bootstrap = self.bootstrap.relays(filter_public_relays(&urls, &stock_relays()).await);
        let membership = stage("resolving the invite", 90, resolve_invite(&invite, &bootstrap))
            .await
            .with_context(|| format!("bootstrap {:?}", bootstrap.urls()))?
            .membership;
        let community = self.community(&membership).await?;
        community.relays.register_auth_keys(vec![primary.clone()]);
        let folded = community.runtime.folded().context("no fold")?;
        let floor = community.relays.with_urls(invite_delivery_relays(&[]));
        floor.register_auth_keys(vec![primary.clone()]);
        let owner = membership.owner.clone();
        let intake = stage("scanning for direct invites", 90, async {
            Ok(intake_direct_invite_keys(&[&community.relays, &floor], &primary, &membership, |pk| {
                folded.roster.is_authorized(pk, &owner, perm::MANAGE_CHANNELS)
            })
            .await)
        })
        .await?;
        let client = community.runtime.client_for(intake.community, primary);
        let id = row.concord_channel_id.as_deref().context("no channel")?;
        let channel = match client.channel(id) {
            Some(c) => c,
            None => {
                stage("re-folding", 90, client.sync_control()).await?;
                client.channel(id).context("concord channel not found (deleted, or key not held)")?
            }
        };
        let heard = self.heard.clone();
        let attachment = community.runtime.attach(&row.bridge_id, client.clone(), channel, Arc::new(move |chat| {
            heard.lock().unwrap().insert(chat.rumor.id.clone());
        }));
        self.live.lock().unwrap().push((row.clone(), client, attachment));
        Ok(())
    }
}

fn relays_line(hub: &Hub) -> String {
    hub.stats()
        .iter()
        .map(|(url, s)| format!("{url} up={} reqs={} refused={} closed={} auth_rejected={} connect_failures={}", s.connected, s.reqs, s.refused, s.closed, s.auth_rejected, s.connect_failures))
        .collect::<Vec<_>>()
        .join("; ")
}

fn process_line() -> String {
    let fds = std::fs::read_dir("/proc/self/fd").map(|d| d.count()).unwrap_or(0);
    let sockets = std::fs::read_dir("/proc/self/fd")
        .map(|d| d.filter_map(|e| std::fs::read_link(e.ok()?.path()).ok()).filter(|p| p.to_string_lossy().starts_with("socket:")).count())
        .unwrap_or(0);
    let rss = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmRSS:")).map(|l| l.split_whitespace().nth(1).unwrap_or("0").parse::<u64>().unwrap_or(0) / 1024))
        .unwrap_or(0);
    format!("fds={fds} sockets={sockets} rss={rss}MB")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bridge::tls::install();
    bridge::fdlimit::raise()?;
    tracing_subscriber::fmt().with_ansi(false).with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn,relay_pool=info".into())).init();
    let minutes: u64 = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(10);
    let db = bridge::db::connect(&std::env::var("DATABASE_URL")?, 2)?;
    let sql = format!("SELECT {BRIDGE_COLUMNS} FROM bridges WHERE status IN ('pending_confirm', 'active')");
    let rows: Vec<BridgeRow> = db.get().await?.query(&sql, &[]).await?.iter().map(BridgeRow::from_row).collect();
    let probe = Arc::new(Probe {
        seal_key: std::env::var("PORTAL_SEAL_KEY")?,
        bootstrap: Hub::new(Keys::generate()),
        communities: Hub::with_query_limit(Keys::generate(), bridge::relays::SHARED_HUB_QUERY_CONCURRENCY),
        slots: Mutex::default(),
        heard: Arc::default(),
        live: Mutex::default(),
        failures: Mutex::default(),
    });

    let began = Instant::now();
    let total = rows.len();
    let queue = Arc::new(Mutex::new(rows));
    let done = Arc::new(AtomicUsize::new(0));
    let workers: Vec<_> = (0..WORKERS)
        .map(|_| {
            let (probe, queue, done) = (probe.clone(), queue.clone(), done.clone());
            tokio::spawn(async move {
                loop {
                    let Some(row) = queue.lock().unwrap().pop() else { break };
                    if let Err(error) = probe.start(&row).await {
                        let why = format!("{error:#}").chars().take(240).collect::<String>();
                        *probe.failures.lock().unwrap().entry(why).or_default() += 1;
                    }
                    let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if n % 100 == 0 {
                        eprintln!("PROBE {n}/{total} tried, {} live, {}s, {}", probe.live.lock().unwrap().len(), began.elapsed().as_secs(), process_line());
                    }
                }
            })
        })
        .collect();
    futures_util::future::join_all(workers).await;
    let live = probe.live.lock().unwrap().len();
    eprintln!("PROBE boot: {live}/{total} live in {}s, {}", began.elapsed().as_secs(), process_line());
    for (why, n) in probe.failures.lock().unwrap().iter() {
        eprintln!("PROBE failed x{n}: {why}");
    }
    eprintln!("PROBE relays: {}", relays_line(&probe.communities));

    // Listen, then check against what the running portal recorded meanwhile.
    let listen_from = chrono_now(&db).await?;
    for minute in 1..=minutes {
        tokio::time::sleep(Duration::from_secs(60)).await;
        eprintln!("PROBE listening {minute}/{minutes}m: heard {} rumors, {}", probe.heard.lock().unwrap().len(), process_line());
    }
    // Leave the portal a moment to finish recording the last ones.
    let rows = db
        .get()
        .await?
        .query(
            "SELECT DISTINCT concord_rumor_id, origin, discord_channel_id FROM messages
             WHERE tenant_id = 'default' AND created_at > $1::text::timestamptz AND created_at < now() - interval '30 seconds'",
            &[&listen_from],
        )
        .await?;
    let live_channels: HashSet<String> = probe.live.lock().unwrap().iter().filter_map(|(r, _, _)| r.discord_channel_id.clone()).collect();
    let heard = probe.heard.lock().unwrap().clone();
    let mut tally: HashMap<(String, bool), usize> = HashMap::new();
    let mut missed = Vec::new();
    for r in &rows {
        let (rumor, origin, channel): (String, String, String) = (r.get(0), r.get(1), r.get(2));
        if !live_channels.contains(&channel) {
            continue;
        }
        let got = heard.contains(&rumor);
        *tally.entry((origin.clone(), got)).or_default() += 1;
        if !got {
            missed.push(format!("{origin} {rumor} {channel}"));
        }
    }
    eprintln!("PROBE recorded by the portal while listening (origin, heard): {tally:?}");
    for m in missed.iter().take(20) {
        eprintln!("PROBE missed {m}");
    }
    eprintln!("PROBE relays: {}", relays_line(&probe.communities));
    eprintln!("PROBE communities={} {}", probe.slots.lock().unwrap().len(), process_line());
    Ok(())
}

async fn chrono_now(db: &deadpool_postgres::Pool) -> anyhow::Result<String> {
    Ok(db.get().await?.query_one("SELECT now()::text", &[]).await?.get(0))
}
