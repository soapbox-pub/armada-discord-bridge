//! The per-relay connection task.
//!
//! Subscriptions are not REQs. Relays cap REQs per connection (20 on all four
//! stock relays) and limit subscriptions per IP besides, so a process that
//! held a REQ per subscription, or a connection per community, met one limit
//! or the other: relay.dreamith.to refused ~170 subscriptions per boot at 78
//! communities (2026-10-16). Instead each subscription is placed in a [`Bin`],
//! a bin's subscriptions are merged into one REQ, and an arriving event is
//! handed to each subscription of its bin whose own filters match it. One-shot
//! queries take what [`MAX_REQS`] leaves, and wait their turn past it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use nostr::prelude::*;
use rand::Rng;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};

use crate::Shared;
use crate::wire;

/// REQs kept open on one connection, standing and one-shot. The stock relays
/// allow 20; the margin covers a bin's replacement, which goes out before the
/// REQ it replaces is closed.
const MAX_REQS: usize = 18;
/// Authors per bin, so that a bin's merged filters fit one REQ (wire.rs).
const BIN_AUTHORS: usize = 1000;
/// How long subscription changes are gathered before bins are re-sent: a
/// boot attaches communities one after another, and a re-send per attach
/// would replay the bin per attach.
const FLUSH_SETTLE: Duration = Duration::from_millis(200);

/// Relay messages larger than this are ignored.
const MAX_MESSAGE_SIZE: usize = 1 << 20;
/// Hard limit enforced by the websocket layer; exceeding it drops the connection.
const MAX_WS_MESSAGE_SIZE: usize = 16 << 20;
const PING_INTERVAL: Duration = Duration::from_secs(30);
const DEAD_AFTER: Duration = Duration::from_secs(90);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A connection that lived at least this long resets the backoff.
const STABLE_CONNECTION: Duration = Duration::from_secs(10);
/// Backoff for re-sending a subscription a relay closed for a transient
/// reason, doubling per refusal in a row.
const RESUBSCRIBE_MIN: Duration = Duration::from_secs(5);
const RESUBSCRIBE_MAX: Duration = Duration::from_secs(600);
/// How far before the newest seen event a resubscription starts.
const SINCE_OVERLAP_SECS: u64 = 60;

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub(crate) enum Cmd {
    Subscribe {
        sub_id: String,
        filters: Vec<Filter>,
    },
    Unsubscribe {
        sub_id: String,
    },
    Query {
        id: SubscriptionId,
        filters: Vec<Filter>,
        tx: mpsc::UnboundedSender<QueryMsg>,
    },
    CancelQuery {
        id: SubscriptionId,
    },
    Publish {
        event: Box<Event>,
        tx: oneshot::Sender<Result<(), String>>,
    },
    CancelPublish {
        id: EventId,
    },
    AuthKeysChanged,
}

pub(crate) enum QueryMsg {
    Event(Box<Event>),
    /// The relay answered: everything it holds has been sent.
    Eose,
    /// The relay is done with this query without answering it (CLOSED,
    /// unreachable, backing off).
    Done,
}

impl QueryMsg {
    pub(crate) fn is_final(&self) -> bool {
        !matches!(self, QueryMsg::Event(_))
    }
}

/// A subscription as the pool's caller made it.
struct RelaySub {
    filters: Vec<Filter>,
    bin: u64,
    /// What it counts for against [`BIN_AUTHORS`].
    weight: usize,
    /// An EOSE answered a REQ carrying it, so its stored events are in and a
    /// re-send may start it from the bin's newest event. Until then a re-send
    /// starts it from its own since: one cut short by another subscription
    /// joining its bin would otherwise lose the stored events not yet sent.
    live: bool,
}

/// Subscriptions sharing one REQ (several, for one oversized subscription).
///
/// Only subscriptions alike in whether this pool can AUTH as every author
/// they name share a bin. Control streams usually fail that (a bridge holds
/// no control signer key), and a relay that gates reads by NIP-42 refuses the
/// whole REQ for one such author: merged with the rest, one community's
/// control plane would silence every community's chat on that relay.
struct Bin {
    authable: bool,
    subs: BTreeSet<String>,
    weight: usize,
    /// The REQs on the wire: id, filters, and the subscriptions each carries.
    wire: Vec<(String, Vec<Filter>, BTreeSet<String>)>,
    /// Bumped by every re-send with new contents, which goes out under new
    /// ids: the EOSE of the REQ being replaced must not mark the
    /// subscriptions of its replacement live.
    generation: u64,
    newest: Option<Timestamp>,
    dirty: bool,
    sent_epoch: u64,
    awaiting_auth: bool,
    /// Closed by the relay for a transient reason: re-sent at this time.
    retry_at: Option<Instant>,
    /// Transient refusals in a row, for the backoff.
    refusals: u32,
}

impl Bin {
    fn new(authable: bool) -> Bin {
        Bin {
            authable,
            subs: BTreeSet::new(),
            weight: 0,
            wire: Vec::new(),
            generation: 0,
            newest: None,
            dirty: false,
            sent_epoch: 0,
            awaiting_auth: false,
            retry_at: None,
            refusals: 0,
        }
    }

    /// The subscriptions a REQ of this bin carries.
    fn carried(&self, wire_id: &str) -> Option<&BTreeSet<String>> {
        self.wire.iter().find(|(id, _, _)| id == wire_id).map(|(_, _, subs)| subs)
    }
}

struct PendingQuery {
    filters: Vec<Filter>,
    tx: mpsc::UnboundedSender<QueryMsg>,
    /// On the wire, rather than waiting for a slot under [`MAX_REQS`].
    sent: bool,
    sent_epoch: u64,
    retried: bool,
    awaiting_auth: Option<String>,
}

struct PendingPublish {
    event: Box<Event>,
    txs: Vec<oneshot::Sender<Result<(), String>>>,
    sent_epoch: u64,
    retried: bool,
    awaiting_auth: Option<String>,
}

/// NIP-42 state of one connection.
#[derive(Default)]
struct Conn {
    challenge: Option<String>,
    pending: HashMap<EventId, PublicKey>,
    /// The values of `pending`, for lookup by key.
    in_flight: HashSet<PublicKey>,
    acked: HashSet<PublicKey>,
    rejected: HashSet<PublicKey>,
    /// Bumped whenever the relay accepts an AUTH. A request sent at an older
    /// epoch that came back `auth-required` is worth re-sending.
    epoch: u64,
}

enum Outcome {
    Disconnected,
    Exit,
}

struct RelayTask {
    shared: Arc<Shared>,
    url: String,
    rx: mpsc::UnboundedReceiver<Cmd>,
    subs: HashMap<String, RelaySub>,
    bins: BTreeMap<u64, Bin>,
    next_bin: u64,
    /// Which bin each REQ on the wire belongs to.
    wire_ids: HashMap<String, u64>,
    /// When dirty bins are next re-sent.
    flush_at: Option<Instant>,
    queries: HashMap<SubscriptionId, PendingQuery>,
    publishes: HashMap<EventId, PendingPublish>,
    conn: Option<Conn>,
    out: Vec<String>,
    /// After a failed connect, when the next attempt may be made. Until then
    /// queries and publishes fail at once instead of waiting out their own
    /// timeouts, and nothing redials early: a task with no standing
    /// subscription used to skip the backoff entirely, so a pool that only
    /// queried redialed a relay refusing it (jskitty's 429s) on every query.
    down_until: Option<Instant>,
}

pub(crate) async fn run(shared: Arc<Shared>, url: String, rx: mpsc::UnboundedReceiver<Cmd>) {
    RelayTask {
        shared,
        url,
        rx,
        subs: HashMap::new(),
        bins: BTreeMap::new(),
        next_bin: 0,
        wire_ids: HashMap::new(),
        flush_at: None,
        queries: HashMap::new(),
        publishes: HashMap::new(),
        conn: None,
        out: Vec::new(),
        down_until: None,
    }
    .run()
    .await
}

/// Whether a CLOSED reason is worth asking again later: NIP-01's
/// `rate-limited:` and `error:` prefixes. `blocked:`, `restricted:`,
/// `invalid:` and the rest will say the same thing next time.
fn is_transient(reason: &str) -> bool {
    let reason = reason.trim_start().to_ascii_lowercase();
    reason.starts_with("rate-limited:") || reason.starts_with("error:")
}

/// Whether a relay's OK/CLOSED reason asks for authentication. Accepts
/// prefixed reasons such as `ERROR: auth-required: ...`.
pub(crate) fn is_auth_required(reason: &str) -> bool {
    reason.starts_with("auth-required:")
        || reason == "auth-required"
        || reason.contains(": auth-required:")
}

fn tls_connector() -> Connector {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let config = CONFIG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(config)
    });
    Connector::Rustls(config.clone())
}

fn jitter(d: Duration) -> Duration {
    let extra = rand::thread_rng().gen_range(0.0..0.5);
    d.mul_f64(1.0 + extra)
}

impl RelayTask {
    async fn run(mut self) {
        let mut backoff = BACKOFF_MIN;
        let mut idle_since = Instant::now();
        loop {
            while !self.has_work() {
                match tokio::time::timeout_at(idle_since + IDLE_TIMEOUT, self.rx.recv()).await {
                    Ok(Some(cmd)) => self.handle_cmd(cmd),
                    Ok(None) => return,
                    Err(_) => {
                        if self.try_exit() {
                            return;
                        }
                        idle_since = Instant::now();
                    }
                }
            }

            match self.connect().await {
                Ok(ws) => {
                    self.down_until = None;
                    let started = Instant::now();
                    self.conn = Some(Conn::default());
                    self.shared.set_connected(&self.url, true);
                    let outcome = self.run_connection(ws).await;
                    self.on_disconnect();
                    if let Outcome::Exit = outcome {
                        return;
                    }
                    if started.elapsed() >= STABLE_CONNECTION {
                        backoff = BACKOFF_MIN;
                    }
                }
                Err(e) => {
                    tracing::warn!(relay = %self.url, error = %e, "relay connection failed");
                    self.shared.stat(&self.url, |s| s.connect_failures += 1);
                    self.down_until = Some(Instant::now() + jitter(backoff));
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    self.fail_pending(&format!("connection failed: {e}"));
                }
            }

            if !self.has_work() {
                idle_since = Instant::now();
                continue;
            }
            let deadline = match self.down_until {
                Some(until) => until,
                None => {
                    let until = Instant::now() + jitter(backoff);
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    until
                }
            };
            loop {
                tokio::select! {
                    cmd = self.rx.recv() => match cmd {
                        Some(cmd) => self.handle_cmd(cmd),
                        None => return,
                    },
                    _ = tokio::time::sleep_until(deadline) => break,
                }
            }
        }
    }

    async fn connect(&self) -> Result<Ws, String> {
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_WS_MESSAGE_SIZE))
            .max_frame_size(Some(MAX_WS_MESSAGE_SIZE));
        let connector = if self.url.starts_with("wss://") {
            tls_connector()
        } else {
            Connector::Plain
        };
        let fut = tokio_tungstenite::connect_async_tls_with_config(
            self.url.as_str(),
            Some(config),
            true,
            Some(connector),
        );
        match tokio::time::timeout(CONNECT_TIMEOUT, fut).await {
            Ok(Ok((ws, _))) => Ok(ws),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("timed out".to_string()),
        }
    }

    async fn run_connection(&mut self, mut ws: Ws) -> Outcome {
        enum Ev {
            Cmd(Option<Cmd>),
            Ws(Option<Result<Message, tokio_tungstenite::tungstenite::Error>>),
            Tick,
            Resubscribe,
            Flush,
        }

        tracing::debug!(relay = %self.url, "connected");
        self.resend_all();
        let mut last_rx = Instant::now();
        let mut idle_since: Option<Instant> = None;
        let mut tick = tokio::time::interval_at(Instant::now() + PING_INTERVAL, PING_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            self.pump_queries();
            // Anything that changes what is open on the wire sends something.
            if !self.out.is_empty() {
                let reqs = self.open_reqs();
                self.shared.stat(&self.url, |s| s.reqs = reqs);
            }
            for msg in std::mem::take(&mut self.out) {
                if let Err(e) = ws.send(Message::Text(msg.into())).await {
                    tracing::debug!(relay = %self.url, error = %e, "send failed");
                    return Outcome::Disconnected;
                }
            }

            let next_retry = self.bins.values().filter_map(|b| b.retry_at).min();
            let flush_at = self.flush_at;
            let ev = tokio::select! {
                cmd = self.rx.recv() => Ev::Cmd(cmd),
                msg = ws.next() => Ev::Ws(msg),
                _ = tick.tick() => Ev::Tick,
                _ = tokio::time::sleep_until(next_retry.unwrap_or_else(Instant::now)), if next_retry.is_some() => Ev::Resubscribe,
                _ = tokio::time::sleep_until(flush_at.unwrap_or_else(Instant::now)), if flush_at.is_some() => Ev::Flush,
            };

            match ev {
                Ev::Cmd(Some(cmd)) => self.handle_cmd(cmd),
                Ev::Cmd(None) => {
                    let _ = ws.close(None).await;
                    return Outcome::Exit;
                }
                Ev::Ws(Some(Ok(msg))) => {
                    last_rx = Instant::now();
                    match msg {
                        Message::Text(text) => self.handle_text(text.as_str()),
                        Message::Close(_) => return Outcome::Disconnected,
                        _ => {}
                    }
                }
                Ev::Ws(Some(Err(e))) => {
                    tracing::debug!(relay = %self.url, error = %e, "websocket error");
                    return Outcome::Disconnected;
                }
                Ev::Ws(None) => return Outcome::Disconnected,
                Ev::Resubscribe => {
                    let now = Instant::now();
                    let due: Vec<u64> = self.bins.iter().filter(|(_, b)| b.retry_at.is_some_and(|t| t <= now)).map(|(id, _)| *id).collect();
                    for id in due {
                        self.send_bin(id);
                    }
                }
                Ev::Flush => self.flush(),
                Ev::Tick => {
                    if last_rx.elapsed() >= DEAD_AFTER {
                        tracing::warn!(relay = %self.url, "relay silent, reconnecting");
                        return Outcome::Disconnected;
                    }
                    if ws.send(Message::Ping(Default::default())).await.is_err() {
                        return Outcome::Disconnected;
                    }
                    if self.has_work() {
                        idle_since = None;
                    } else if idle_since.get_or_insert_with(Instant::now).elapsed() >= IDLE_TIMEOUT
                        && self.try_exit()
                    {
                        let _ = ws.close(None).await;
                        return Outcome::Exit;
                    }
                }
            }
        }
    }

    fn open_reqs(&self) -> usize {
        self.wire_ids.len() + self.queries.values().filter(|q| q.sent).count()
    }

    fn has_work(&self) -> bool {
        !self.subs.is_empty() || !self.queries.is_empty() || !self.publishes.is_empty()
    }

    /// Unregister this task if no command is waiting. Returns whether it did.
    fn try_exit(&mut self) -> bool {
        let shared = self.shared.clone();
        let cmd = {
            let mut st = shared.lock();
            match self.rx.try_recv() {
                Ok(cmd) => cmd,
                Err(_) => {
                    st.relays.remove(&self.url);
                    tracing::debug!(relay = %self.url, "closing idle relay");
                    return true;
                }
            }
        };
        self.handle_cmd(cmd);
        false
    }

    fn on_disconnect(&mut self) {
        self.conn = None;
        self.out.clear();
        for bin in self.bins.values_mut() {
            bin.awaiting_auth = false;
        }
        for q in self.queries.values_mut() {
            q.awaiting_auth = None;
            q.sent = false;
        }
        for p in self.publishes.values_mut() {
            p.awaiting_auth = None;
        }
        self.shared.set_connected(&self.url, false);
        tracing::debug!(relay = %self.url, "disconnected");
    }

    fn fail_pending(&mut self, reason: &str) {
        for (_, q) in self.queries.drain() {
            let _ = q.tx.send(QueryMsg::Done);
        }
        for (_, p) in self.publishes.drain() {
            for tx in p.txs {
                let _ = tx.send(Err(reason.to_string()));
            }
        }
    }

    fn epoch(&self) -> u64 {
        self.conn.as_ref().map_or(0, |c| c.epoch)
    }

    fn push(&mut self, msg: ClientMessage<'_>) {
        if self.conn.is_some() {
            self.out.push(msg.as_json());
        }
    }

    fn resend_all(&mut self) {
        // Settled like any change, not sent at once: the subscriptions that
        // queued while the connection opened are read only after this, and
        // would each cost the bin another replay.
        for bin in self.bins.values_mut() {
            bin.dirty = true;
        }
        self.schedule_flush();
        self.pump_queries();
        let publishes: Vec<EventId> = self.publishes.keys().copied().collect();
        for id in publishes {
            self.send_publish(&id);
        }
    }

    /// Place a subscription in the first bin of its kind with room for it.
    fn add_sub(&mut self, sub_id: String, filters: Vec<Filter>) {
        let authable = self.shared.can_auth_as(&self.url, &wire::pubkeys_of(&filters));
        // A filter that cannot be merged is a filter on the wire of its own,
        // and a REQ holds only so many (wire::WIRE_MAX_FILTERS).
        let weight = filters
            .iter()
            .map(|f| if wire::mergeable(f) { f.authors.as_ref().map_or(1, |a| a.len()) } else { BIN_AUTHORS / 8 })
            .sum::<usize>();
        let found = self
            .bins
            .iter()
            .find(|(_, b)| b.authable == authable && b.weight + weight <= BIN_AUTHORS)
            .map(|(id, _)| *id);
        let id = found.unwrap_or_else(|| {
            self.next_bin += 1;
            self.bins.insert(self.next_bin, Bin::new(authable));
            self.next_bin
        });
        let bin = self.bins.get_mut(&id).expect("found or made");
        bin.subs.insert(sub_id.clone());
        bin.weight += weight;
        bin.dirty = true;
        self.subs.insert(sub_id, RelaySub { filters, bin: id, weight, live: false });
        self.schedule_flush();
    }

    fn remove_sub(&mut self, sub_id: &str) {
        let Some(sub) = self.subs.remove(sub_id) else {
            return;
        };
        let Some(bin) = self.bins.get_mut(&sub.bin) else {
            return;
        };
        bin.subs.remove(sub_id);
        bin.weight -= sub.weight;
        if !bin.subs.is_empty() {
            bin.dirty = true;
            self.schedule_flush();
            return;
        }
        let bin = self.bins.remove(&sub.bin).expect("just read");
        for (wid, _, _) in bin.wire {
            self.wire_ids.remove(&wid);
            self.push(ClientMessage::close(SubscriptionId::new(wid)));
        }
    }

    fn schedule_flush(&mut self) {
        self.flush_at.get_or_insert_with(|| Instant::now() + FLUSH_SETTLE);
    }

    /// Re-send every bin whose subscriptions changed.
    fn flush(&mut self) {
        self.flush_at = None;
        let dirty: Vec<u64> = self.bins.iter().filter(|(_, b)| b.dirty).map(|(id, _)| *id).collect();
        for id in dirty {
            self.rebuild(id);
        }
    }

    /// Merge a bin's subscriptions into fresh REQs, send them, then close the
    /// ones they replace.
    fn rebuild(&mut self, id: u64) {
        let Some(bin) = self.bins.get(&id) else {
            return;
        };
        let floor = bin
            .newest
            .map(|n| Timestamp::from_secs(n.as_secs().saturating_sub(SINCE_OVERLAP_SECS)));
        let entries: Vec<(&str, &Filter, Option<Timestamp>)> = bin
            .subs
            .iter()
            .filter_map(|s| Some((s.as_str(), self.subs.get(s)?)))
            .flat_map(|(s, sub)| sub.filters.iter().map(move |f| (s, f, floor.filter(|_| sub.live))))
            .collect();
        let parts = wire::pack(wire::merge(entries));
        let bin = self.bins.get_mut(&id).expect("just read");
        bin.generation += 1;
        bin.dirty = false;
        let generation = bin.generation;
        let old = std::mem::replace(
            &mut bin.wire,
            parts
                .into_iter()
                .enumerate()
                .map(|(i, part)| {
                    let filters = part.iter().map(|c| c.filter.clone()).collect();
                    let subs = part.into_iter().flat_map(|c| c.subs).collect();
                    (format!("w.{id}.{generation}.{i}"), filters, subs)
                })
                .collect(),
        );
        for (wid, _, _) in &old {
            self.wire_ids.remove(wid);
        }
        for (wid, _, _) in &self.bins[&id].wire {
            self.wire_ids.insert(wid.clone(), id);
        }
        self.send_bin(id);
        for (wid, _, _) in old {
            self.push(ClientMessage::close(SubscriptionId::new(wid)));
        }
    }

    /// (Re-)send a bin's REQs as they stand.
    fn send_bin(&mut self, id: u64) {
        if self.conn.is_none() {
            return;
        }
        let epoch = self.epoch();
        let Some(bin) = self.bins.get_mut(&id) else {
            return;
        };
        bin.sent_epoch = epoch;
        bin.retry_at = None;
        bin.awaiting_auth = false;
        let reqs = bin
            .wire
            .iter()
            .map(|(wid, filters, _)| ClientMessage::req(SubscriptionId::new(wid), filters.clone()).as_json());
        self.out.extend(reqs);
    }

    /// Send waiting queries while there is room under [`MAX_REQS`].
    fn pump_queries(&mut self) {
        if self.conn.is_none() {
            return;
        }
        let room = MAX_REQS.saturating_sub(self.open_reqs());
        let waiting: Vec<SubscriptionId> = self
            .queries
            .iter()
            .filter(|(_, q)| !q.sent)
            .map(|(id, _)| id.clone())
            .take(room)
            .collect();
        for id in waiting {
            self.send_query(&id);
        }
    }

    fn send_query(&mut self, id: &SubscriptionId) {
        if self.conn.is_none() {
            return;
        }
        let epoch = self.epoch();
        let open = self.open_reqs();
        let Some(q) = self.queries.get_mut(id) else {
            return;
        };
        // Past the cap the relay would refuse it; it waits for a slot instead.
        if !q.sent && open >= MAX_REQS {
            return;
        }
        q.sent = true;
        q.sent_epoch = epoch;
        let msg = ClientMessage::req(id.clone(), q.filters.clone());
        self.push(msg);
    }

    fn send_publish(&mut self, id: &EventId) {
        if self.conn.is_none() {
            return;
        }
        let epoch = self.epoch();
        let Some(p) = self.publishes.get_mut(id) else {
            return;
        };
        p.sent_epoch = epoch;
        let msg = ClientMessage::event((*p.event).clone());
        self.push(msg);
    }

    fn backing_off(&self) -> bool {
        self.conn.is_none() && self.down_until.is_some_and(|until| Instant::now() < until)
    }

    fn handle_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::Subscribe { sub_id, filters } => {
                if self.subs.get(&sub_id).is_some_and(|s| s.filters == filters) {
                    return;
                }
                self.remove_sub(&sub_id);
                self.add_sub(sub_id, filters);
            }
            Cmd::Unsubscribe { sub_id } => self.remove_sub(&sub_id),
            Cmd::Query { id, filters, tx } => {
                if self.backing_off() {
                    let _ = tx.send(QueryMsg::Done);
                    return;
                }
                self.queries.insert(
                    id.clone(),
                    PendingQuery {
                        filters,
                        tx,
                        sent: false,
                        sent_epoch: 0,
                        retried: false,
                        awaiting_auth: None,
                    },
                );
                self.send_query(&id);
            }
            Cmd::CancelQuery { id } => {
                if self.queries.remove(&id).is_some_and(|q| q.sent) {
                    self.push(ClientMessage::close(id));
                }
            }
            Cmd::Publish { event, tx } => {
                if self.backing_off() {
                    let _ = tx.send(Err("relay unreachable; waiting to reconnect".to_string()));
                    return;
                }
                let id = event.id;
                if let Some(p) = self.publishes.get_mut(&id) {
                    p.txs.push(tx);
                    return;
                }
                self.publishes.insert(
                    id,
                    PendingPublish {
                        event,
                        txs: vec![tx],
                        sent_epoch: 0,
                        retried: false,
                        awaiting_auth: None,
                    },
                );
                self.send_publish(&id);
            }
            Cmd::CancelPublish { id } => {
                if let Some(p) = self.publishes.get_mut(&id) {
                    p.txs.retain(|tx| !tx.is_closed());
                    if p.txs.is_empty() {
                        self.publishes.remove(&id);
                    }
                }
            }
            Cmd::AuthKeysChanged => {
                self.send_auths();
                self.check_awaiting();
            }
        }
    }

    fn handle_text(&mut self, text: &str) {
        if text.len() > MAX_MESSAGE_SIZE {
            tracing::warn!(relay = %self.url, len = text.len(), "ignoring oversized message");
            return;
        }
        let msg = match RelayMessage::from_json(text) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::debug!(relay = %self.url, error = %e, "ignoring malformed message");
                return;
            }
        };
        match msg {
            RelayMessage::Event {
                subscription_id,
                event,
            } => self.on_event(&subscription_id, event.into_owned()),
            RelayMessage::Ok {
                event_id,
                status,
                message,
            } => self.on_ok(event_id, status, &message),
            RelayMessage::EndOfStoredEvents(id) => self.on_eose(&id),
            RelayMessage::Closed {
                subscription_id,
                message,
            } => self.on_closed(&subscription_id, &message),
            RelayMessage::Notice(message) => {
                tracing::info!(relay = %self.url, %message, "relay notice");
            }
            RelayMessage::Auth { challenge } => self.on_challenge(challenge.into_owned()),
            _ => {}
        }
    }

    /// A bin's event goes to each subscription it carries whose own filters
    /// match: the merged filters can match more than any one of them asked.
    fn on_event(&mut self, id: &SubscriptionId, event: Event) {
        if let Some(bin) = self.wire_ids.get(id.as_str()).and_then(|b| self.bins.get_mut(b)) {
            if bin.newest.is_none_or(|n| event.created_at > n) {
                bin.newest = Some(event.created_at);
            }
            let Some(carried) = bin.carried(id.as_str()) else {
                return;
            };
            let opts = MatchEventOptions::default();
            for sub_id in carried {
                if let Some(sub) = self.subs.get(sub_id)
                    && sub.filters.iter().any(|f| f.match_event(&event, opts))
                {
                    self.shared.deliver(&self.url, sub_id, event.clone());
                }
            }
        } else if let Some(q) = self.queries.get(id) {
            let _ = q.tx.send(QueryMsg::Event(Box::new(event)));
        }
    }

    fn on_eose(&mut self, id: &SubscriptionId) {
        if let Some(bin) = self.wire_ids.get(id.as_str()).and_then(|b| self.bins.get_mut(b)) {
            bin.refusals = 0;
            let carried = bin.carried(id.as_str()).cloned().unwrap_or_default();
            for sub_id in carried {
                if let Some(sub) = self.subs.get_mut(&sub_id) {
                    sub.live = true;
                    self.shared.emit(crate::PoolEvent::Eose {
                        relay: self.url.clone(),
                        sub_id,
                    });
                }
            }
        } else if let Some(q) = self.queries.remove(id) {
            let _ = q.tx.send(QueryMsg::Eose);
            self.push(ClientMessage::close(id.clone()));
        }
    }

    fn on_closed(&mut self, id: &SubscriptionId, reason: &str) {
        let auth = is_auth_required(reason);
        if let Some(&bin_id) = self.wire_ids.get(id.as_str())
            && let Some(sub) = self.bins.get_mut(&bin_id)
        {
            if auth {
                tracing::debug!(relay = %self.url, sub = %id, %reason, "subscription needs auth");
                sub.awaiting_auth = true;
            } else if is_transient(reason) {
                // Kept and re-sent, never dropped: a rate limiter or a full
                // connection says nothing about the subscription, and a
                // dropped one was not even re-sent on reconnect, so the relay
                // stayed silent for it for the life of the process. A
                // community boot meeting relay.dreamith.to's limiter cost it
                // its live chat on that relay this way (2026-10-16).
                let delay = jitter((RESUBSCRIBE_MIN * 2u32.pow(sub.refusals.min(7))).min(RESUBSCRIBE_MAX));
                sub.refusals += 1;
                sub.retry_at = Some(Instant::now() + delay);
                self.shared.stat(&self.url, |s| s.refused += 1);
                tracing::warn!(relay = %self.url, sub = %id, %reason, retry_in_s = delay.as_secs(), "subscription closed by relay; will re-send");
                return;
            } else {
                // Its subscriptions stay assigned and go out again with the
                // bin's next change; asking again now would hear the same.
                tracing::warn!(relay = %self.url, sub = %id, %reason, "subscription closed by relay");
                self.shared.stat(&self.url, |s| s.closed += 1);
                sub.wire.retain(|(wid, _, _)| wid != id.as_str());
                self.wire_ids.remove(id.as_str());
                return;
            }
        } else if let Some(q) = self.queries.get_mut(id) {
            if auth && !q.retried {
                q.awaiting_auth = Some(reason.to_string());
            } else {
                tracing::debug!(relay = %self.url, %reason, "query closed by relay");
                if let Some(q) = self.queries.remove(id) {
                    let _ = q.tx.send(QueryMsg::Done);
                }
                return;
            }
        } else {
            return;
        }
        self.send_auths();
        self.check_awaiting();
    }

    fn on_ok(&mut self, id: EventId, status: bool, reason: &str) {
        if let Some(conn) = &mut self.conn
            && let Some(pk) = conn.pending.remove(&id)
        {
            conn.in_flight.remove(&pk);
            if status {
                tracing::debug!(relay = %self.url, pubkey = %pk, "authenticated");
                conn.acked.insert(pk);
                conn.epoch += 1;
            } else {
                tracing::warn!(relay = %self.url, pubkey = %pk, %reason, "AUTH rejected");
                conn.rejected.insert(pk);
                self.shared.stat(&self.url, |s| s.auth_rejected += 1);
            }
            self.check_awaiting();
            return;
        }

        let Some(p) = self.publishes.get_mut(&id) else {
            return;
        };
        if status {
            if let Some(p) = self.publishes.remove(&id) {
                for tx in p.txs {
                    let _ = tx.send(Ok(()));
                }
            }
        } else if is_auth_required(reason) && !p.retried {
            p.awaiting_auth = Some(reason.to_string());
            self.send_auths();
            self.check_awaiting();
        } else if let Some(p) = self.publishes.remove(&id) {
            for tx in p.txs {
                let _ = tx.send(Err(reason.to_string()));
            }
        }
    }

    fn on_challenge(&mut self, challenge: String) {
        let Some(conn) = &mut self.conn else {
            return;
        };
        if conn.challenge.as_deref() != Some(challenge.as_str()) {
            let epoch = conn.epoch;
            *conn = Conn {
                challenge: Some(challenge),
                epoch,
                ..Conn::default()
            };
        }
        self.send_auths();
        self.check_awaiting();
    }

    /// Send AUTH for every in-scope key not yet sent on this connection.
    fn send_auths(&mut self) {
        let Some(challenge) = self.conn.as_ref().and_then(|c| c.challenge.clone()) else {
            return;
        };
        let Some(conn) = &mut self.conn else {
            return;
        };
        let keys = self.shared.keys_for(&self.url, |pk| {
            conn.acked.contains(pk) || conn.rejected.contains(pk) || conn.in_flight.contains(pk)
        });
        for keys in keys {
            let pk = keys.public_key();
            if !conn.in_flight.insert(pk) {
                continue;
            }
            let event = EventBuilder::new(Kind::Authentication, "")
                .tags([
                    Tag::custom("relay", [self.url.as_str()]),
                    Tag::custom("challenge", [challenge.as_str()]),
                ])
                .finalize(&keys);
            match event {
                Ok(event) => {
                    conn.pending.insert(event.id, pk);
                    self.out.push(ClientMessage::auth(event).as_json());
                }
                Err(e) => tracing::warn!(relay = %self.url, error = %e, "failed to sign AUTH"),
            }
        }
    }

    /// Once no AUTH is in flight, re-send requests the relay closed for
    /// auth-required if some key was accepted since they were sent; give up on
    /// one-shot requests that can make no further progress.
    fn check_awaiting(&mut self) {
        let Some(conn) = &self.conn else {
            return;
        };
        if conn.challenge.is_none() || !conn.pending.is_empty() {
            return;
        }
        let epoch = conn.epoch;

        let bins: Vec<u64> = self
            .bins
            .iter()
            .filter(|(_, b)| b.awaiting_auth && b.sent_epoch < epoch)
            .map(|(id, _)| *id)
            .collect();
        for id in bins {
            self.send_bin(id);
        }

        let mut retry = Vec::new();
        let mut give_up = Vec::new();
        for (id, q) in &mut self.queries {
            if q.awaiting_auth.take().is_some() {
                if q.sent_epoch < epoch {
                    q.retried = true;
                    retry.push(id.clone());
                } else {
                    give_up.push(id.clone());
                }
            }
        }
        for id in retry {
            self.send_query(&id);
        }
        for id in give_up {
            if let Some(q) = self.queries.remove(&id) {
                let _ = q.tx.send(QueryMsg::Done);
            }
        }

        let mut retry = Vec::new();
        let mut give_up = Vec::new();
        for (id, p) in &mut self.publishes {
            if let Some(reason) = p.awaiting_auth.take() {
                if p.sent_epoch < epoch {
                    p.retried = true;
                    retry.push(*id);
                } else {
                    give_up.push((*id, reason));
                }
            }
        }
        for id in retry {
            self.send_publish(&id);
        }
        for (id, reason) in give_up {
            if let Some(p) = self.publishes.remove(&id) {
                for tx in p.txs {
                    let _ = tx.send(Err(reason.clone()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_auth_required;

    #[test]
    fn auth_required_prefixes() {
        assert!(is_auth_required("auth-required: please"));
        assert!(is_auth_required("auth-required"));
        assert!(is_auth_required("ERROR: auth-required: please"));
        assert!(!is_auth_required(
            "blocked: auth-required is not the reason"
        ));
        assert!(!is_auth_required("restricted: no"));
    }
}
