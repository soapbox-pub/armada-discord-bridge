//! Relay access with Concord broadcast semantics: reads merge across every
//! community relay, and a publish succeeds when ANY relay accepts (Armada's
//! `broadcast`).
//!
//! Relays cap concurrent subscriptions per connection, and that cap is what
//! every design here has to fit under. A [`Hub`] — one set of connections —
//! serves one community (see the portal's `CommunityRuntime`), holding two
//! standing REQs whatever the community's size: one for the Control Plane and
//! one whose authors are every bridged channel's stream keys. Its one-shot
//! queries are bounded by [`HUB_QUERY_CONCURRENCY`].
//!
//! Both alternatives failed in production on 2026-10-16. A hub per community
//! with a REQ per bridge put ~130 standing REQs on one socket for a community
//! of 63 bridged channels; the stock relays answered "too many concurrent REQs"
//! (a NOTICE, the REQ silently dropped) and "too many subscriptions" by the
//! thousand. A hub per bridge, as the TypeScript ran, is ~5,000 sockets for
//! 1340 channels: it ran out of file descriptors at 250 bridges, and opening
//! that many at once draws 429s from relays that limit connection rate.
//!
//! NIP-42: relays that gate kind 1059 serve a REQ only to a connection that has
//! authenticated as every pubkey in its `authors`. Stream addresses are derived
//! keys the bridge holds, so their secrets are registered here and the pool
//! answers each challenge as all of them, scoped to the community's relays.
//!
//! Every event is signature-checked before anyone sees it: relay-pool leaves
//! that to its consumer, and a relay is not trusted to have done it.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use async_trait::async_trait;
use nostr::prelude::*;
use relay_pool::{Pool, PoolEvent};
use tokio::sync::mpsc;

pub const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
pub const PUBLISH_TIMEOUT: Duration = Duration::from_secs(8);
/// How long a settled query waits for the rest once one relay has answered.
/// Healthy relays answer well inside it (0.3-1s, 2026-10-16).
pub const SETTLE_GRACE: Duration = Duration::from_secs(2);

/// One-shot queries in flight per hub. Each is a REQ on every relay of the
/// hub, on top of its standing subscriptions: unbounded, a community's boot
/// (fold, Direct Invite scans, catch-up per bridge) put dozens on one socket
/// and met the same per-connection cap the standing REQs did.
pub const HUB_QUERY_CONCURRENCY: usize = 8;

/// Bound on the process-wide verified-signature memo.
const VERIFIED_MAX: usize = 200_000;

/// Every relay refused a publish (or none answered in time). Its own type so a
/// caller can tell relays pushing back, which is worth waiting out, from a
/// failure that will repeat however long it waits.
#[derive(Debug, thiserror::Error)]
#[error("no relay accepted event {id} ({tried} tried: {why})")]
pub struct PublishRejected {
    pub id: EventId,
    pub tried: usize,
    pub why: String,
}

impl PublishRejected {
    /// Whether `error`, anywhere in its chain, is a refused publish.
    pub fn in_chain(error: &anyhow::Error) -> bool {
        error.chain().any(|e| e.is::<PublishRejected>())
    }
}

/// The relay surface the Concord client needs. A trait so the router and
/// client tests can run against an in-memory wire.
#[async_trait]
pub trait RelayLike: Send + Sync {
    /// Merge results from every relay, deduped by id, newest first.
    async fn query(&self, filters: Vec<Filter>) -> anyhow::Result<Vec<Event>>;

    /// Like `query`, but stops waiting [`SETTLE_GRACE`] after the first relay
    /// answers; see [`Pool::query_settled`]. Only for a caller that hears
    /// what a late relay holds some other way, or can afford not to.
    async fn query_settled(&self, filters: Vec<Filter>) -> anyhow::Result<Vec<Event>> {
        self.query(filters).await
    }

    /// The first relay holding a match wins; see [`Pool::query_race`].
    async fn query_race(&self, filters: Vec<Filter>) -> Vec<Event> {
        self.query(filters).await.unwrap_or_default()
    }

    /// Any-accept broadcast; errors only when every relay refused.
    async fn publish(&self, event: &Event) -> anyhow::Result<()>;

    /// Standing REQ across relays, deduped by event id. Dropping the
    /// subscription ends it.
    fn subscribe(&self, filters: Vec<Filter>) -> Subscription;

    /// Keys to AUTH as on these relays (NIP-42), for streams this caller reads.
    fn register_auth_keys(&self, _keys: Vec<Keys>) {}
}

/// A live subscription; dropping it sends CLOSE.
///
/// The receiver is private on purpose. It used to be a public field, and a
/// task that read `sub.events` inside `async move` captured that field alone
/// (edition-2021 disjoint capture): the guard stayed behind in the calling
/// function and dropped when it returned, so every live subscription was
/// CLOSEd right after its REQ. In production that silenced Armada -> Discord
/// and live control folds for every bridge (2026-10-15). With only `recv`
/// exposed, reading events means owning the whole subscription.
pub struct Subscription {
    events: mpsc::UnboundedReceiver<Event>,
    _guard: Box<dyn Send + Sync>,
}

impl Subscription {
    pub fn new(events: mpsc::UnboundedReceiver<Event>, guard: impl Send + Sync + 'static) -> Self {
        Subscription { events, _guard: Box::new(guard) }
    }

    /// The next verified event; `None` once the subscription is gone.
    pub async fn recv(&mut self) -> Option<Event> {
        self.events.recv().await
    }
}

/// One shared set of relay connections, and the routing of its subscriptions.
pub struct Hub {
    pool: Pool,
    routes: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<Event>>>>,
    queries: tokio::sync::Semaphore,
}

impl Hub {
    /// `auth` is the identity offered first on every challenge; further keys
    /// are added with [`Relays::register_auth_keys`].
    pub fn new(auth: Keys) -> Arc<Hub> {
        let (pool, rx) = Pool::new(auth);
        let routes: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<Event>>>> = Arc::default();
        tokio::spawn(dispatch(rx, Arc::downgrade(&routes)));
        Arc::new(Hub { pool, routes, queries: tokio::sync::Semaphore::new(HUB_QUERY_CONCURRENCY) })
    }

    /// A handle reading and writing `urls` over this hub's connections.
    pub fn relays(self: &Arc<Self>, urls: Vec<String>) -> Relays {
        Relays { hub: self.clone(), urls }
    }

    pub fn connected(&self) -> Vec<String> {
        self.pool.connected()
    }
}

/// Route pool events to their subscriptions until the pool goes away.
async fn dispatch(mut rx: mpsc::UnboundedReceiver<PoolEvent>, routes: Weak<Mutex<HashMap<String, mpsc::UnboundedSender<Event>>>>) {
    while let Some(ev) = rx.recv().await {
        let PoolEvent::Event { sub_id, event, .. } = ev else { continue };
        let Some(routes) = routes.upgrade() else { return };
        if !verify_once(&event) {
            continue;
        }
        let tx = routes.lock().unwrap_or_else(|e| e.into_inner()).get(&sub_id).cloned();
        if let Some(tx) = tx {
            let _ = tx.send(event);
        }
    }
}

/// Verify an event's id and signature, remembering signatures already checked.
///
/// The id is recomputed every time — it is what binds the id to the content —
/// but a signature over an id is remembered: community history arrives once
/// per relay per reader, and re-verifying each copy was about a quarter of all
/// boot CPU in the TypeScript bridge (2026-09-24 profile).
pub fn verify_once(event: &Event) -> bool {
    static VERIFIED: Mutex<Option<HashSet<(EventId, Signature)>>> = Mutex::new(None);
    if !event.verify_id() {
        return false;
    }
    let key = (event.id, event.sig);
    {
        let memo = VERIFIED.lock().unwrap_or_else(|e| e.into_inner());
        if memo.as_ref().is_some_and(|m| m.contains(&key)) {
            return true;
        }
    }
    if !event.verify_signature() {
        return false;
    }
    let mut memo = VERIFIED.lock().unwrap_or_else(|e| e.into_inner());
    let memo = memo.get_or_insert_with(HashSet::new);
    if memo.len() >= VERIFIED_MAX {
        memo.clear();
    }
    memo.insert(key);
    true
}

/// A relay list over a shared [`Hub`].
#[derive(Clone)]
pub struct Relays {
    hub: Arc<Hub>,
    urls: Vec<String>,
}

impl Relays {
    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    /// The same connections aimed at a different relay list.
    pub fn with_urls(&self, urls: Vec<String>) -> Relays {
        Relays { hub: self.hub.clone(), urls }
    }
}

fn newest_first(mut events: Vec<Event>) -> Vec<Event> {
    events.sort_by_key(|e| std::cmp::Reverse(e.created_at));
    events
}

#[async_trait]
impl RelayLike for Relays {
    async fn query(&self, filters: Vec<Filter>) -> anyhow::Result<Vec<Event>> {
        let _slot = self.hub.queries.acquire().await?;
        let events = self.hub.pool.query(&self.urls, filters, QUERY_TIMEOUT).await;
        Ok(newest_first(events.into_iter().filter(verify_once).collect()))
    }

    async fn query_settled(&self, filters: Vec<Filter>) -> anyhow::Result<Vec<Event>> {
        let _slot = self.hub.queries.acquire().await?;
        let events = self.hub.pool.query_settled(&self.urls, filters, QUERY_TIMEOUT, SETTLE_GRACE).await;
        Ok(newest_first(events.into_iter().filter(verify_once).collect()))
    }

    async fn query_race(&self, filters: Vec<Filter>) -> Vec<Event> {
        let Ok(_slot) = self.hub.queries.acquire().await else { return vec![] };
        let events = self.hub.pool.query_race(&self.urls, filters, QUERY_TIMEOUT).await;
        newest_first(events.into_iter().filter(verify_once).collect())
    }

    async fn publish(&self, event: &Event) -> anyhow::Result<()> {
        match self.hub.pool.publish_any(&self.urls, event, PUBLISH_TIMEOUT).await {
            Ok(_) => Ok(()),
            Err(rejected) => {
                let why = rejected.iter().map(|(r, e)| format!("{r}: {e}")).collect::<Vec<_>>().join("; ");
                Err(PublishRejected { id: event.id, tried: self.urls.len(), why }.into())
            }
        }
    }

    fn subscribe(&self, filters: Vec<Filter>) -> Subscription {
        let sub_id = hex::encode(rand::random::<[u8; 12]>());
        let (tx, rx) = mpsc::unbounded_channel();
        self.hub.routes.lock().unwrap_or_else(|e| e.into_inner()).insert(sub_id.clone(), tx);
        self.hub.pool.subscribe(&sub_id, &self.urls, filters);
        Subscription::new(rx, Unsubscribe { hub: self.hub.clone(), sub_id })
    }

    fn register_auth_keys(&self, keys: Vec<Keys>) {
        self.hub.pool.register_auth_keys(&self.urls, keys);
    }
}

struct Unsubscribe {
    hub: Arc<Hub>,
    sub_id: String,
}

impl Drop for Unsubscribe {
    fn drop(&mut self) {
        self.hub.pool.unsubscribe(&self.sub_id);
        self.hub.routes.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.sub_id);
    }
}

/// An in-memory relay for tests: stores what is published, answers queries by
/// filter match, and delivers to standing subscriptions.
#[derive(Clone, Default)]
pub struct MemoryRelay {
    inner: Arc<Mutex<MemoryState>>,
}

#[derive(Default)]
struct MemoryState {
    events: Vec<Event>,
    subs: Vec<(u64, Vec<Filter>, mpsc::UnboundedSender<Event>)>,
    next_sub: u64,
    refuse: bool,
    max_subs: Option<usize>,
    refused_subs: usize,
}

/// Closes a memory subscription when dropped, as a real relay's CLOSE would:
/// a fake whose subscriptions outlive their handles hides exactly the bug of
/// dropping one too early.
struct MemoryUnsubscribe {
    state: Weak<Mutex<MemoryState>>,
    id: u64,
}

impl Drop for MemoryUnsubscribe {
    fn drop(&mut self) {
        if let Some(state) = self.state.upgrade() {
            state.lock().unwrap_or_else(|e| e.into_inner()).subs.retain(|(id, _, _)| *id != self.id);
        }
    }
}

impl MemoryRelay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything published, oldest first.
    pub fn published(&self) -> Vec<Event> {
        self.inner.lock().unwrap().events.clone()
    }

    /// Refuse every publish from now on.
    pub fn refuse_publishes(&self, refuse: bool) {
        self.inner.lock().unwrap().refuse = refuse;
    }

    /// Refuse standing subscriptions past `max` at once, as real relays do per
    /// connection; a refused one is closed straight away.
    pub fn cap_subscriptions(&self, max: usize) {
        self.inner.lock().unwrap().max_subs = Some(max);
    }

    /// Subscriptions refused for the cap so far.
    pub fn refused_subscriptions(&self) -> usize {
        self.inner.lock().unwrap().refused_subs
    }

    /// Standing subscriptions currently open.
    pub fn open_subscriptions(&self) -> usize {
        let mut st = self.inner.lock().unwrap();
        st.subs.retain(|(_, _, tx)| !tx.is_closed());
        st.subs.len()
    }

    /// Store an event as if published, delivering it to subscriptions.
    pub fn inject(&self, event: Event) {
        let mut st = self.inner.lock().unwrap();
        st.subs.retain(|(_, _, tx)| !tx.is_closed());
        for (_, filters, tx) in &st.subs {
            if filters.iter().any(|f| f.match_event(&event, MatchEventOptions::default())) {
                let _ = tx.send(event.clone());
            }
        }
        st.events.push(event);
    }
}

#[async_trait]
impl RelayLike for MemoryRelay {
    async fn query(&self, filters: Vec<Filter>) -> anyhow::Result<Vec<Event>> {
        let st = self.inner.lock().unwrap();
        let mut out: Vec<Event> = Vec::new();
        for f in &filters {
            let mut matched: Vec<Event> =
                st.events.iter().filter(|e| f.match_event(e, MatchEventOptions::default())).cloned().collect();
            matched.sort_by_key(|e| std::cmp::Reverse(e.created_at));
            if let Some(limit) = f.limit {
                matched.truncate(limit);
            }
            for e in matched {
                if !out.iter().any(|o| o.id == e.id) {
                    out.push(e);
                }
            }
        }
        Ok(newest_first(out))
    }

    async fn publish(&self, event: &Event) -> anyhow::Result<()> {
        if self.inner.lock().unwrap().refuse {
            return Err(PublishRejected { id: event.id, tried: 1, why: "refusing".into() }.into());
        }
        self.inject(event.clone());
        Ok(())
    }

    fn subscribe(&self, filters: Vec<Filter>) -> Subscription {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut st = self.inner.lock().unwrap();
        st.subs.retain(|(_, _, tx)| !tx.is_closed());
        if st.max_subs.is_some_and(|max| st.subs.len() >= max) {
            st.refused_subs += 1;
            return Subscription::new(rx, ());
        }
        for e in &st.events {
            if filters.iter().any(|f| f.match_event(e, MatchEventOptions::default())) {
                let _ = tx.send(e.clone());
            }
        }
        let id = st.next_sub;
        st.next_sub += 1;
        st.subs.push((id, filters, tx));
        Subscription::new(rx, MemoryUnsubscribe { state: Arc::downgrade(&self.inner), id })
    }
}
