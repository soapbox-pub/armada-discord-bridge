//! One community's presence on its relays, shared by every bridge into it.
//!
//! A community with 63 bridged channels is one Control Plane fold, one
//! control subscription and one chat subscription, not 63 of each: relays cap
//! subscriptions (see relays.rs for the designs that broke on that), and the
//! fold is the same work for every bridge of the community. Its connections
//! are the hub's, which the portal shares among every community.
//!
//! What is NOT shared is key custody. Each bridge keeps its own
//! [`Membership`]: a private channel's key is vended to one bridge's npub by a
//! Direct Invite, and that is consent for that bridge only, so pooling learned
//! keys would let any bridge into the community read a room it was never let
//! into. The merged REQ only names stream addresses; each arriving wrap is
//! opened against the view of each bridge that holds that stream, and no
//! other.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use concord::community::{ChannelView, Membership};
use concord::control::FoldedControl;
use concord::kinds;
use nostr::prelude::*;
use tokio::sync::Notify;

use crate::client::{ChatHandler, ConcordClient, CursorHandler, OpenedChat, TaskGuard, channel_addresses, now_ms, open_chat};
use crate::recent::RecentIds;
use crate::relays::RelayLike;

/// How long attach/detach/rekey changes are gathered before the chat REQ is
/// replaced. A boot attaches a community's bridges one after another, and a
/// replacement per attach would be a REQ per bridge again, only spread out.
pub const RESUBSCRIBE_SETTLE: Duration = Duration::from_millis(500);

/// Stream addresses per filter of the merged chat REQ. Some relays cap the
/// size of one filter's `authors`; filters within a REQ are not the scarce
/// resource that standing REQs are.
const AUTHORS_PER_FILTER: usize = 100;

struct Member {
    token: u64,
    client: Arc<ConcordClient>,
    channel_id: String,
    view: ChannelView,
    /// Outlives any one REQ: every replacement replays the last minute.
    seen: RecentIds,
    on_chat: ChatHandler,
}

pub struct CommunityRuntime {
    me: Weak<CommunityRuntime>,
    control: Arc<ConcordClient>,
    on_cursor: Option<CursorHandler>,
    members: Mutex<HashMap<String, Member>>,
    next_token: Mutex<u64>,
    /// The stream addresses the current chat REQ names, and the REQ.
    chat: Mutex<Option<(BTreeSet<PublicKey>, TaskGuard)>>,
    resubscribe: Arc<Notify>,
    /// The control REQ, replaced when the community takes a new root: it
    /// names the old root's Control Plane, Guestbook and next rotation address.
    control_sub: Mutex<Option<TaskGuard>>,
    /// Woken when a wrap lands at the next base rotation's address.
    refound: Arc<Notify>,
    /// Told the id of each attached bridge a Refounding removed.
    on_excluded: Mutex<Option<ExcludedHandler>>,
    /// What each base rotation address held when last fetched for a start.
    base_wraps: tokio::sync::Mutex<HashMap<PublicKey, (std::time::Instant, Vec<Event>)>>,
    tasks: Mutex<Vec<TaskGuard>>,
}

/// Called with a bridge id when a Refounding left that bridge out.
pub type ExcludedHandler = Arc<dyn Fn(String) + Send + Sync>;

/// How long a start may reuse what a base rotation address held when another
/// start of the same community fetched it. A Refounding landing meanwhile is
/// heard by the control REQ, whose follow-up fetches afresh.
const BASE_WRAPS_FRESH: Duration = Duration::from_secs(120);

/// How long a Refounding's chunks are given to land before it is read.
const REFOUND_SETTLE: Duration = Duration::from_millis(1500);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Where a bridged channel's posts arrive: its read streams and, once a
/// Writers ledger restricts it, each writer address.
fn stream_pks(view: &ChannelView) -> Vec<PublicKey> {
    channel_addresses(view)
}

impl CommunityRuntime {
    /// Fold the community's Control Plane from `base` (any member's
    /// membership; only its base is read) and keep it folded live.
    /// `on_cursor` is called per durable chat wrap that opened for a bridge.
    pub async fn open(base: Membership, relays: Arc<dyn RelayLike>, on_cursor: Option<CursorHandler>) -> anyhow::Result<Arc<CommunityRuntime>> {
        let control = ConcordClient::new(base, relays, Keys::generate());
        control.sync_control().await?;
        let rt = Arc::new_cyclic(|me| CommunityRuntime {
            me: me.clone(),
            control,
            on_cursor,
            members: Mutex::default(),
            next_token: Mutex::new(0),
            chat: Mutex::new(None),
            resubscribe: Arc::default(),
            control_sub: Mutex::new(None),
            refound: Arc::default(),
            on_excluded: Mutex::new(None),
            base_wraps: tokio::sync::Mutex::default(),
            tasks: Mutex::default(),
        });
        rt.restart_control();
        let (weak, notify) = (Arc::downgrade(&rt), rt.resubscribe.clone());
        let resubscriber = TaskGuard::spawn(async move {
            loop {
                notify.notified().await;
                tokio::time::sleep(RESUBSCRIBE_SETTLE).await;
                let Some(rt) = weak.upgrade() else { return };
                rt.resubscribe_now();
            }
        });
        let (weak, notify) = (Arc::downgrade(&rt), rt.refound.clone());
        let refounder = TaskGuard::spawn(async move {
            loop {
                notify.notified().await;
                tokio::time::sleep(REFOUND_SETTLE).await;
                let Some(rt) = weak.upgrade() else { return };
                rt.follow_refounding().await;
            }
        });
        *lock(&rt.tasks) = vec![resubscriber, refounder];
        Ok(rt)
    }

    /// (Re)open the control REQ on the root the fold reader holds now.
    fn restart_control(&self) {
        let weak = self.me.clone();
        let refound = self.refound.clone();
        let sub = self.control.subscribe_control(
            Some(Arc::new(move |_| {
                if let Some(rt) = weak.upgrade() {
                    rt.refresh_views();
                }
            })),
            Some(Arc::new(move || refound.notify_one())),
        );
        *lock(&self.control_sub) = Some(sub);
    }

    /// Who to tell when a Refounding removes an attached bridge.
    pub fn set_on_excluded(&self, handler: ExcludedHandler) {
        *lock(&self.on_excluded) = Some(handler);
    }

    /// A Refounding landed: each attached bridge follows it with its own
    /// identity, since only it can open its blob, and the first new root one
    /// takes moves the shared fold. A bridge left out is reported: it holds
    /// only planes the community has left, so nothing it mirrors would reach
    /// anyone.
    pub async fn follow_refounding(&self) {
        let members: Vec<(String, Arc<ConcordClient>)> = lock(&self.members).iter().map(|(id, m)| (id.clone(), m.client.clone())).collect();
        let mut excluded = Vec::new();
        for (id, client) in members {
            let intake = client.adopt_base_rotations().await;
            if intake.adopted.is_some()
                && let Err(error) = self.adopt_base(&intake.community).await
            {
                tracing::warn!(error = %format!("{error:#}"), "refolding at the new root failed; the live subscription will catch up");
            }
            if intake.excluded.is_some() {
                excluded.push(id);
            }
        }
        let handler = lock(&self.on_excluded).clone();
        for id in excluded {
            tracing::warn!(bridge = %id, "a Refounding removed this bridge from its community");
            if let Some(handler) = &handler {
                handler(id);
            }
        }
        self.refresh_views();
    }

    /// Follow the community's Refoundings for a starting bridge, with its own
    /// key, from wraps this community fetched for its other starts.
    ///
    /// Every bridge into a community asks the same rotation address, and a
    /// boot starts them back to back: per bridge, it was the slowest stage of
    /// a start (0.59s, 2208 times, 2026-11-11). One fetch per address now
    /// serves them all. Live following (`follow_refounding`) never reads
    /// from here.
    pub async fn intake_base_rotations(&self, identity: &Keys, community: &Membership, folded: &FoldedControl) -> crate::key_intake::BaseIntake {
        let relays = self.relays().clone();
        crate::key_intake::walk_base_rotations(
            |address| {
                let relays = relays.clone();
                async move {
                    // Held across the fetch, so the community's other starts wait
                    // for this one rather than all asking at once.
                    let mut cache = self.base_wraps.lock().await;
                    if let Some((at, wraps)) = cache.get(&address.pk)
                        && at.elapsed() < BASE_WRAPS_FRESH
                    {
                        return wraps.clone();
                    }
                    let wraps = crate::key_intake::fetch_base_rotations(relays.as_ref(), address.clone()).await;
                    cache.insert(address.pk, (std::time::Instant::now(), wraps.clone()));
                    wraps
                }
            },
            identity,
            community,
            folded,
        )
        .await
    }

    /// Move the shared fold to a root a bridge verified (its own rotation
    /// blob, judged against this fold): re-subscribe to the new epoch's
    /// Control Plane, Guestbook and next rotation address, and refold. False
    /// when `from` holds no newer root. Never from an invite's word alone: a
    /// bundle can name any root, and this fold serves every bridge here.
    pub async fn adopt_base(&self, from: &Membership) -> anyhow::Result<bool> {
        if !self.control.take_base_from(from) {
            return Ok(false);
        }
        self.restart_control();
        self.control.sync_control().await?;
        self.refresh_views();
        Ok(true)
    }

    pub fn relays(&self) -> &Arc<dyn RelayLike> {
        self.control.relays()
    }

    pub fn folded(&self) -> Option<Arc<FoldedControl>> {
        self.control.folded()
    }

    /// A client for one bridge: its own membership and identity, this
    /// community's relays and fold.
    pub fn client_for(&self, membership: Membership, primary: Keys) -> Arc<ConcordClient> {
        ConcordClient::sharing_fold(membership, primary, &self.control)
    }

    /// Bridges attached.
    pub fn bridges(&self) -> usize {
        lock(&self.members).len()
    }

    /// Start delivering `channel`'s chat to `on_chat`, read with `client`'s
    /// keys. Delivery ends when the returned attachment drops.
    pub fn attach(self: &Arc<Self>, bridge_id: &str, client: Arc<ConcordClient>, channel: ChannelView, on_chat: ChatHandler) -> Attachment {
        let token = {
            let mut next = lock(&self.next_token);
            *next += 1;
            *next
        };
        let member = Member { token, client, channel_id: channel.id_hex.clone(), view: channel, seen: RecentIds::default(), on_chat };
        lock(&self.members).insert(bridge_id.to_owned(), member);
        self.resubscribe.notify_one();
        Attachment { runtime: self.clone(), bridge_id: bridge_id.to_owned(), token }
    }

    /// Re-read every attached bridge's channel: a bridge's client took a new
    /// key (see `ConcordClient::follow_channel_keys`).
    pub fn refresh(&self) {
        self.refresh_views();
    }

    /// Follow a rekey: the fold changed, and a bridge whose channel now has a
    /// different stream set would go silent on a REQ pinned to the old one.
    fn refresh_views(&self) {
        let mut changed = false;
        for (id, m) in lock(&self.members).iter_mut() {
            // Channel left the fold: severance detection is separate work.
            let Some(fresh) = m.client.channel(&m.channel_id) else { continue };
            if stream_pks(&fresh) != stream_pks(&m.view) {
                m.view = fresh;
                changed = true;
                tracing::info!(bridge = %id, "stream keys or writer addresses moved; chat subscription refreshed");
            } else {
                // Same addresses, newer metadata (a rename, a sealed name opened).
                m.view = fresh;
            }
        }
        if changed {
            self.resubscribe.notify_one();
        }
    }

    /// Replace the chat REQ with one naming every attached stream, if that set
    /// changed. The new REQ goes out before the old one closes, and replays
    /// the last minute, so nothing in between is missed; `seen` eats the
    /// overlap.
    pub fn resubscribe_now(&self) {
        let pks: BTreeSet<PublicKey> = lock(&self.members).values().flat_map(|m| stream_pks(&m.view)).collect();
        let mut chat = lock(&self.chat);
        if chat.as_ref().is_some_and(|(current, _)| *current == pks) {
            return;
        }
        if pks.is_empty() {
            *chat = None;
            return;
        }
        // Live tail only: without a floor, relays replay stored history into
        // the router on every subscribe. Catch-up after downtime is cursor
        // work. A small overlap absorbs clock skew.
        let since = Timestamp::from_secs((now_ms() / 1000).saturating_sub(60));
        let all: Vec<PublicKey> = pks.iter().copied().collect();
        let filters = all
            .chunks(AUTHORS_PER_FILTER)
            .map(|chunk| Filter::new().kinds([Kind::Custom(kinds::WRAP), Kind::Custom(kinds::WRAP_EPHEMERAL)]).authors(chunk.to_vec()).since(since))
            .collect();
        let mut sub = self.relays().subscribe(filters);
        let weak = self.me.clone();
        let pump = TaskGuard::spawn(async move {
            while let Some(wrap) = sub.recv().await {
                let Some(rt) = weak.upgrade() else { return };
                rt.deliver(&wrap);
            }
        });
        *chat = Some((pks, pump));
    }

    fn deliver(&self, wrap: &Event) {
        let mut out: Vec<(ChatHandler, OpenedChat)> = Vec::new();
        let mut opened = false;
        for m in lock(&self.members).values_mut() {
            if !stream_pks(&m.view).contains(&wrap.pubkey) {
                continue;
            }
            let Some(chat) = open_chat(wrap, &m.view) else { continue };
            opened = true;
            if m.seen.insert(&chat.rumor.id) {
                out.push((m.on_chat.clone(), chat));
            }
        }
        if opened
            && wrap.kind == Kind::Custom(kinds::WRAP)
            && let Some(cursor) = &self.on_cursor
        {
            cursor(wrap.pubkey.to_hex(), wrap.created_at.as_secs());
        }
        // Handlers run outside the lock: they may attach or detach.
        for (on_chat, chat) in out {
            on_chat(chat);
        }
    }
}

/// One bridge's place in a [`CommunityRuntime`]; dropping it detaches.
pub struct Attachment {
    runtime: Arc<CommunityRuntime>,
    bridge_id: String,
    token: u64,
}

impl Attachment {
    /// The bridge's channel as currently keyed (follows rekeys).
    pub fn channel(&self) -> Option<ChannelView> {
        lock(&self.runtime.members).get(&self.bridge_id).filter(|m| m.token == self.token).map(|m| m.view.clone())
    }
}

impl Drop for Attachment {
    fn drop(&mut self) {
        let mut members = lock(&self.runtime.members);
        // A re-attach under the same id replaced us; it is not ours to remove.
        if members.get(&self.bridge_id).is_some_and(|m| m.token == self.token) {
            members.remove(&self.bridge_id);
            drop(members);
            self.runtime.resubscribe.notify_one();
        }
    }
}
