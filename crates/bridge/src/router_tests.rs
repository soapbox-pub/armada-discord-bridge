//! Router tests: a real Concord client over an in-memory relay, with Discord,
//! Blossom and the GIF prober faked at their ports.

use std::collections::{BTreeMap, HashMap};

use concord::community::Membership;
use concord::control::{FoldedChannel, FoldedControl};
use concord::roles::{MemberGrant, Role, RoleScope, perm};
use concord::rumor::Rumor;
use concord::stream::{Opened, StreamKey, open_wrap};
use nostr::prelude::{Event, Kind};
use sha2::{Digest, Sha256};

use super::*;
use crate::blossom::Uploaded;
use crate::net::ProbeResult;
use crate::relays::MemoryRelay;
use crate::store::MemoryMappingStore;

const MASTER: &str = "abababababababababababababababababababababababababababababababab";
const USER: &str = "80351110224678912";

#[derive(Default)]
struct FakeWebhooks {
    sent: Mutex<Vec<WebhookMessage>>,
    deleted: Mutex<Vec<String>>,
    edited: Mutex<Vec<(String, String)>>,
    reactions: Mutex<Vec<(String, String)>>,
    unreacted: Mutex<Vec<(String, String)>>,
    typing: AtomicUsize,
    seq: AtomicUsize,
}

#[async_trait]
impl WebhookSender for FakeWebhooks {
    async fn send(&self, _: &ChannelLink, message: WebhookMessage) -> anyhow::Result<String> {
        self.sent.lock().unwrap().push(message);
        Ok((9000 + self.seq.fetch_add(1, Ordering::SeqCst)).to_string())
    }
    async fn delete(&self, _: &ChannelLink, id: &str) -> anyhow::Result<()> {
        self.deleted.lock().unwrap().push(id.into());
        Ok(())
    }
    async fn edit(&self, _: &ChannelLink, id: &str, content: &str) -> anyhow::Result<()> {
        self.edited.lock().unwrap().push((id.into(), content.into()));
        Ok(())
    }
    async fn react(&self, _: &ChannelLink, id: &str, emoji: &str) -> anyhow::Result<()> {
        self.reactions.lock().unwrap().push((id.into(), emoji.into()));
        Ok(())
    }
    async fn unreact(&self, _: &ChannelLink, id: &str, emoji: &str) -> anyhow::Result<()> {
        self.unreacted.lock().unwrap().push((id.into(), emoji.into()));
        Ok(())
    }
    async fn send_typing(&self, _: &ChannelLink) -> anyhow::Result<()> {
        self.typing.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// Blobs by URL; uploads land at `https://blossom.example/<sha256>`.
#[derive(Default)]
struct FakeBlobs {
    blobs: Mutex<HashMap<String, (Vec<u8>, String)>>,
    uploads: Mutex<Vec<(Vec<u8>, String)>>,
    downloads: AtomicUsize,
}

#[async_trait]
impl BlobPort for FakeBlobs {
    async fn download(&self, url: &str, max_bytes: usize) -> anyhow::Result<(Vec<u8>, String)> {
        self.downloads.fetch_add(1, Ordering::SeqCst);
        let blob = self.blobs.lock().unwrap().get(url).cloned().ok_or_else(|| anyhow::anyhow!("404 {url}"))?;
        anyhow::ensure!(blob.0.len() <= max_bytes, "over cap");
        Ok(blob)
    }
    async fn upload(&self, data: &[u8], mime: &str, _: &Keys) -> anyhow::Result<Uploaded> {
        self.uploads.lock().unwrap().push((data.to_vec(), mime.into()));
        let sha256 = hex::encode(Sha256::digest(data));
        Ok(Uploaded { url: format!("https://blossom.example/{sha256}"), sha256 })
    }
}

struct NoProbe;

#[async_trait]
impl Prober for NoProbe {
    async fn probe(&self, _: &str) -> Option<ProbeResult> {
        None
    }
}

struct Harness {
    relay: MemoryRelay,
    client: Arc<ConcordClient>,
    channel: ChannelView,
    store: Arc<MemoryMappingStore>,
    webhooks: Arc<FakeWebhooks>,
    blobs: Arc<FakeBlobs>,
    puppets: PuppetCache,
    link: ChannelLink,
    router: BridgeRouter,
}

fn folded(owner: &str, channel_id: &str) -> FoldedControl {
    let channel = FoldedChannel {
        channel_id_hex: channel_id.into(),
        name: "general".into(),
        private: false,
        deleted: false,
        forum: false,
        category: None,
        position: None,
        raw: serde_json::Value::Null,
    };
    FoldedControl { owner: owner.into(), channels: BTreeMap::from([(channel_id.to_owned(), channel)]), ..Default::default() }
}

fn harness_with(configure: impl FnOnce(&mut RouterOptions, &Arc<FakeBlobs>)) -> Harness {
    let owner = Keys::generate();
    let membership = Membership::mint("Test", &owner.public_key().to_hex(), vec!["wss://relay.example".into()], 0);
    let channel_id = hex::encode([7u8; 32]);
    let relay = MemoryRelay::new();
    let client = ConcordClient::new(membership.clone(), Arc::new(relay.clone()), Keys::generate());
    client.set_folded(folded(&membership.owner, &channel_id));
    let channel = client.channel(&channel_id).expect("public channel derives from the root");
    let store = Arc::new(MemoryMappingStore::default());
    let webhooks = Arc::new(FakeWebhooks::default());
    let blobs = Arc::new(FakeBlobs::default());
    let mut options = RouterOptions { prober: Arc::new(NoProbe), ..Default::default() };
    configure(&mut options, &blobs);
    let link = ChannelLink {
        discord_guild_id: "g1".into(),
        discord_channel_id: "c1".into(),
        community_id: membership.community_id.clone(),
        concord_channel_id_hex: channel_id,
        enabled: true,
    };
    let self_ids = SelfIds { application_id: "app1".into(), webhook_ids: Arc::new(RwLock::new(HashSet::from(["wh1".to_owned()]))) };
    let router = BridgeRouter::new(
        client.clone(),
        PuppetCache::new(MASTER),
        store.clone(),
        webhooks.clone(),
        Arc::new(crate::profiles::Kind0ProfileResolver::new(Arc::new(relay.clone()))),
        self_ids,
        options,
    );
    Harness { relay, client, channel, store, webhooks, blobs, puppets: PuppetCache::new(MASTER), link, router }
}

fn harness() -> Harness {
    harness_with(|_, _| {})
}

fn with_blobs() -> Harness {
    harness_with(|o, blobs| o.blobs = Some(blobs.clone() as Arc<dyn BlobPort>))
}

fn discord_msg() -> DiscordInboundMessage {
    DiscordInboundMessage {
        id: "111222333".into(),
        channel_id: "c1".into(),
        guild_id: "g1".into(),
        author: DiscordUserRef { id: USER.into(), display: "mk".into(), avatar_url: None, bot: false },
        content: "hello armada".into(),
        ..Default::default()
    }
}

impl Harness {
    /// Every chat rumor published into the channel, opened, oldest first.
    fn chats(&self) -> Vec<Opened> {
        let key: StreamKey = (&self.channel.current().key).into();
        self.relay
            .published()
            .iter()
            .filter(|e| e.pubkey == key.pk && e.kind == Kind::Custom(kinds::WRAP))
            .map(|e| open_wrap(e, &key).unwrap())
            .collect()
    }

    fn published_of_kind(&self, kind: u16) -> Vec<Event> {
        self.relay.published().into_iter().filter(|e| e.kind == Kind::Custom(kind)).collect()
    }

    /// A member's rumor in this channel, as the subscription would deliver it.
    fn chat(&self, author: &Keys, kind: u16, content: &str, extra: Vec<Vec<String>>) -> OpenedChat {
        let mut tags = concord::stream::channel_binding_tags(&self.channel.id_hex, 0);
        tags.extend(extra);
        let rumor = Rumor::new(kind, content, tags, &author.public_key().to_hex(), Some(now_ms()), None);
        OpenedChat { ms: rumor.created_at * 1000, rumor, channel_id_hex: self.channel.id_hex.clone(), epoch: 0 }
    }

    fn rows(&self) -> Vec<MessageMappingRow> {
        self.store.rows.lock().unwrap().clone()
    }

    fn sent(&self) -> Vec<WebhookMessage> {
        self.webhooks.sent.lock().unwrap().clone()
    }

    /// Make `member` a MANAGE_MESSAGES moderator in the fold.
    fn promote(&self, member: &Keys) {
        let mut f = (*self.client.folded().unwrap()).clone();
        let role_id = hex::encode([9u8; 32]);
        f.roster.roles.push(Role { role_id: role_id.clone(), name: "Mod".into(), position: 2, permissions: perm::MANAGE_MESSAGES, scope: RoleScope::Server, color: 0 });
        f.roster.grants.push(MemberGrant { member: member.public_key().to_hex(), role_ids: vec![role_id], control_wrap: None });
        self.client.set_folded(f);
    }

    fn ban(&self, pk: &str) {
        let mut f = (*self.client.folded().unwrap()).clone();
        f.banned.insert(pk.into());
        self.client.set_folded(f);
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}

// ── Discord -> Concord ──────────────────────────────────────────────────────

#[tokio::test]
async fn bridges_a_discord_message_as_a_puppet_rumor_with_proxy_tag_and_mapping() {
    let h = harness();
    let rumor_id = h.router.on_discord_message(discord_msg(), &h.link).await.unwrap().expect("bridged");
    let chats = h.chats();
    assert_eq!(chats.len(), 1);
    let opened = &chats[0];
    assert_eq!(opened.rumor.content, "hello armada");
    assert_eq!(opened.author(), h.puppets.get(USER).unwrap().pk);
    assert!(opened.rumor.tags.contains(&s(&["proxy", "https://discord.com/channels/g1/c1/111222333", "web"])));
    let rows = h.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].discord_message_id.as_str(), rows[0].concord_rumor_id.as_str(), rows[0].origin), ("111222333", rumor_id.as_str(), Origin::Discord));
}

#[tokio::test]
async fn swaps_a_gif_picker_link_for_its_media_and_tags_exactly_that_url() {
    let h = harness();
    let page = "https://klipy.com/gifs/monday-again-1";
    let msg = DiscordInboundMessage {
        content: page.into(),
        embeds: vec![EmbedIn { url: Some(page.into()), media_url: Some("https://static.klipy.com/monday.gif".into()) }],
        ..discord_msg()
    };
    h.router.on_discord_message(msg, &h.link).await.unwrap();
    let opened = &h.chats()[0];
    assert_eq!(opened.rumor.content, "https://static.klipy.com/monday.gif");
    let imeta = opened.rumor.tags.iter().find(|t| t[0] == "imeta").unwrap();
    assert_eq!(imeta, &s(&["imeta", "url https://static.klipy.com/monday.gif", "m image/gif"]));

    // Prose containing a link is left alone, and untagged: a tag naming a URL
    // the content does not contain is an orphan Armada appends a second embed for.
    let prose = DiscordInboundMessage {
        id: "111222334".into(),
        content: "look at https://klipy.com/gifs/x".into(),
        embeds: vec![EmbedIn { url: Some("https://klipy.com/gifs/x".into()), media_url: Some("https://static.klipy.com/x.gif".into()) }],
        ..discord_msg()
    };
    h.router.on_discord_message(prose, &h.link).await.unwrap();
    let last = h.chats().pop().unwrap();
    assert_eq!(last.rumor.content, "look at https://klipy.com/gifs/x");
    assert!(!last.rumor.tags.iter().any(|t| t[0] == "imeta"));
}

#[tokio::test]
async fn skips_own_webhooks_own_application_other_bots_and_disabled_links() {
    let h = harness();
    let cases = [
        DiscordInboundMessage { webhook_id: Some("wh1".into()), ..discord_msg() },
        DiscordInboundMessage { application_id: Some("app1".into()), ..discord_msg() },
        DiscordInboundMessage { author: DiscordUserRef { bot: true, ..discord_msg().author }, ..discord_msg() },
    ];
    for msg in cases {
        assert_eq!(h.router.on_discord_message(msg, &h.link).await.unwrap(), None);
    }
    let disabled = ChannelLink { enabled: false, ..h.link.clone() };
    assert_eq!(h.router.on_discord_message(discord_msg(), &disabled).await.unwrap(), None);
    assert!(h.chats().is_empty());
}

#[tokio::test]
async fn publishes_the_puppet_profile_once_and_again_when_it_changes() {
    let h = harness();
    h.router.on_discord_message(discord_msg(), &h.link).await.unwrap();
    h.router.on_discord_message(DiscordInboundMessage { id: "2".into(), ..discord_msg() }, &h.link).await.unwrap();
    assert_eq!(h.published_of_kind(0).len(), 1);
    let renamed = DiscordInboundMessage { id: "3".into(), author: DiscordUserRef { display: "mk2".into(), ..discord_msg().author }, ..discord_msg() };
    h.router.on_discord_message(renamed, &h.link).await.unwrap();
    let profiles = h.published_of_kind(0);
    assert_eq!(profiles.len(), 2);
    assert!(profiles[1].content.contains("\"mk2\""));
}

#[tokio::test]
async fn publishes_one_guestbook_join_per_puppet() {
    let h = harness();
    h.router.on_discord_message(discord_msg(), &h.link).await.unwrap();
    h.router.on_discord_message(DiscordInboundMessage { id: "2".into(), ..discord_msg() }, &h.link).await.unwrap();
    let gb: StreamKey = h.client.community().current_guestbook_stream();
    assert_eq!(h.relay.published().iter().filter(|e| e.pubkey == gb.pk).count(), 1);
}

#[tokio::test]
async fn refuses_to_publish_for_a_banned_puppet() {
    let h = harness();
    h.ban(&h.puppets.get(USER).unwrap().pk);
    assert!(h.router.on_discord_message(discord_msg(), &h.link).await.is_err());
    assert!(h.chats().is_empty());
}

// ── Concord -> Discord ──────────────────────────────────────────────────────

#[tokio::test]
async fn mirrors_a_member_message_through_the_webhook_with_a_mapping_row() {
    let h = harness();
    let alice = Keys::generate();
    let chat = h.chat(&alice, kinds::MESSAGE, "hello discord", vec![]);
    let ids = h.router.on_concord_chat(&chat, &h.link).await.unwrap();
    assert_eq!(ids.len(), 1);
    let sent = h.sent();
    assert_eq!(sent[0].content, "hello discord");
    assert_eq!(sent[0].username, fallback_profile(&alice.public_key().to_hex()).name);
    let rows = h.rows();
    assert_eq!((rows[0].origin, rows[0].concord_rumor_id.as_str(), rows[0].part_index), (Origin::Concord, chat.rumor_id(), 0));
    // Mapped now, so a relay echo is not mirrored twice.
    assert!(h.router.on_concord_chat(&chat, &h.link).await.unwrap().is_empty());
}

#[tokio::test]
async fn splits_long_messages_and_caps_the_fan_out() {
    let h = harness();
    let alice = Keys::generate();
    let two = h.chat(&alice, kinds::MESSAGE, &"word ".repeat(600), vec![]);
    assert_eq!(h.router.on_concord_chat(&two, &h.link).await.unwrap().len(), 2);
    assert_eq!(h.rows().iter().map(|r| r.part_index).collect::<Vec<_>>(), [0, 1]);

    let flood = h.chat(&alice, kinds::MESSAGE, &"x".repeat(30_000), vec![]);
    let ids = h.router.on_concord_chat(&flood, &h.link).await.unwrap();
    assert_eq!(ids.len(), MAX_DISCORD_PARTS);
    let last = h.sent().pop().unwrap();
    assert!(last.content.ends_with("… 5 more parts not mirrored"), "{}", &last.content[last.content.len() - 40..]);
    assert!(last.content.encode_utf16().count() <= DISCORD_MAX_CHARS);
}

#[tokio::test]
async fn never_echoes_proxied_puppet_banned_or_primary_rumors() {
    let h = harness();
    let alice = Keys::generate();
    let proxied = h.chat(&alice, kinds::MESSAGE, "x", vec![proxy_tag("g", "c", "m")]);
    let puppet = h.router.puppets.get(USER).unwrap();
    let from_puppet = h.chat(&puppet.keys, kinds::MESSAGE, "x", vec![]);
    let from_primary = h.chat(h.client.primary(), kinds::MESSAGE, "x", vec![]);
    let bob = Keys::generate();
    h.ban(&bob.public_key().to_hex());
    let from_banned = h.chat(&bob, kinds::MESSAGE, "x", vec![]);
    for chat in [proxied, from_puppet, from_primary, from_banned] {
        assert!(h.router.on_concord_chat(&chat, &h.link).await.unwrap().is_empty());
    }
    assert!(h.sent().is_empty());
}

#[tokio::test]
async fn mirrors_custom_discord_emoji_as_native_markup() {
    let h = harness();
    let tags = vec![s(&["emoji", "blob", "https://cdn.discordapp.com/emojis/123.png"])];
    let chat = h.chat(&Keys::generate(), kinds::MESSAGE, "hi :blob:", tags);
    h.router.on_concord_chat(&chat, &h.link).await.unwrap();
    assert_eq!(h.sent()[0].content, "hi <:blob:123>");
}

// ── Replies ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn discord_reply_to_a_mirrored_armada_message_carries_a_q_tag() {
    let h = harness();
    let alice = Keys::generate();
    let original = h.chat(&alice, kinds::MESSAGE, "question?", vec![]);
    let mirrored = h.router.on_concord_chat(&original, &h.link).await.unwrap();
    let reply = DiscordInboundMessage { id: "5".into(), referenced_message_id: Some(mirrored[0].clone()), ..discord_msg() };
    h.router.on_discord_message(reply, &h.link).await.unwrap();
    let opened = h.chats().pop().unwrap();
    assert!(opened.rumor.tags.contains(&vec!["q".into(), original.rumor_id().into(), String::new(), alice.public_key().to_hex()]));

    // A reply to a bridged Discord message names the puppet as author.
    let again = DiscordInboundMessage { id: "6".into(), referenced_message_id: Some("5".into()), ..discord_msg() };
    h.router.on_discord_message(again, &h.link).await.unwrap();
    let q = h.chats().pop().unwrap().rumor.tags.into_iter().find(|t| t[0] == "q").unwrap();
    assert_eq!(q[3], h.puppets.get(USER).unwrap().pk);
}

#[tokio::test]
async fn concord_reply_renders_an_escaped_jump_link_embed() {
    let h = harness();
    let alice = Keys::generate();
    let original = h.chat(&alice, kinds::MESSAGE, "first", vec![]);
    h.router.on_concord_chat(&original, &h.link).await.unwrap();
    let reply = h.chat(&Keys::generate(), kinds::MESSAGE, "second", vec![s(&["q", original.rumor_id(), "", ""])]);
    h.router.on_concord_chat(&reply, &h.link).await.unwrap();
    let embed = &h.sent()[1].embeds[0];
    assert!(embed.contains("https://discord.com/channels/g1/c1/9000"), "{embed}");
    assert!(embed.starts_with("Replying to nostr:"), "{embed}");
}

// ── Deletes ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn discord_delete_of_a_bridged_message_publishes_a_puppet_kind_5() {
    let h = harness();
    let rumor_id = h.router.on_discord_message(discord_msg(), &h.link).await.unwrap().unwrap();
    let del = DiscordMessageDelete { id: "111222333".into(), channel_id: "c1".into(), guild_id: "g1".into() };
    h.router.on_discord_delete(&del, &h.link).await.unwrap().expect("tombstoned");
    let tomb = h.chats().pop().unwrap();
    assert_eq!(tomb.rumor.kind, kinds::DELETE);
    assert_eq!(tomb.rumor.tag_value("e"), Some(rumor_id.as_str()));
    assert!(has_proxy_tag(&tomb.rumor.tags));

    // A mirror of an Armada member's message stops at Discord.
    let theirs = h.chat(&Keys::generate(), kinds::MESSAGE, "x", vec![]);
    let ids = h.router.on_concord_chat(&theirs, &h.link).await.unwrap();
    let del = DiscordMessageDelete { id: ids[0].clone(), channel_id: "c1".into(), guild_id: "g1".into() };
    assert_eq!(h.router.on_discord_delete(&del, &h.link).await.unwrap(), None);
}

#[tokio::test]
async fn concord_delete_honors_the_author_and_moderators_only() {
    let h = harness();
    let (alice, stranger, moderator) = (Keys::generate(), Keys::generate(), Keys::generate());
    let original = h.chat(&alice, kinds::MESSAGE, &"word ".repeat(600), vec![]);
    let ids = h.router.on_concord_chat(&original, &h.link).await.unwrap();
    let delete = |who: &Keys| h.chat(who, kinds::DELETE, "", vec![s(&["e", original.rumor_id()])]);

    h.router.on_concord_chat(&delete(&stranger), &h.link).await.unwrap();
    assert!(h.webhooks.deleted.lock().unwrap().is_empty());
    h.router.on_concord_chat(&delete(&alice), &h.link).await.unwrap();
    assert_eq!(*h.webhooks.deleted.lock().unwrap(), ids);

    h.webhooks.deleted.lock().unwrap().clear();
    h.promote(&moderator);
    h.router.on_concord_chat(&delete(&moderator), &h.link).await.unwrap();
    assert_eq!(*h.webhooks.deleted.lock().unwrap(), ids);
}

// ── Reactions ───────────────────────────────────────────────────────────────

fn reaction(user: &str, name: &str, id: Option<&str>) -> DiscordReaction {
    DiscordReaction {
        message_id: "111222333".into(),
        channel_id: "c1".into(),
        guild_id: "g1".into(),
        emoji: DiscordEmoji { name: Some(name.into()), id: id.map(str::to_owned), animated: false },
        user: DiscordUserRef { id: user.into(), display: "r".into(), avatar_url: None, bot: false },
    }
}

use crate::types::DiscordEmoji;

#[tokio::test]
async fn discord_reactions_publish_and_tombstone_puppet_kind_7s() {
    let h = harness();
    let target = h.router.on_discord_message(discord_msg(), &h.link).await.unwrap().unwrap();
    let rid = h.router.on_discord_reaction(&reaction("42", "🔥", None), &h.link).await.unwrap().unwrap();
    let r = h.chats().pop().unwrap();
    assert_eq!((r.rumor.kind, r.rumor.content.as_str(), r.rumor.tag_value("e")), (kinds::REACTION, "🔥", Some(target.as_str())));

    // Custom emoji are NIP-30 shortcodes carrying the CDN image.
    h.router.on_discord_reaction(&reaction("42", "blob", Some("123")), &h.link).await.unwrap();
    let custom = h.chats().pop().unwrap();
    assert_eq!(custom.rumor.content, ":blob:");
    assert!(custom.rumor.tags.contains(&s(&["emoji", "blob", "https://cdn.discordapp.com/emojis/123.png"])));

    h.router.on_discord_reaction_remove(&reaction("42", "🔥", None), &h.link).await.unwrap().unwrap();
    let tomb = h.chats().pop().unwrap();
    assert_eq!((tomb.rumor.kind, tomb.rumor.tag_value("e"), tomb.rumor.tag_value("k")), (kinds::DELETE, Some(rid.as_str()), Some("7")));

    // Bots and unmapped messages are skipped.
    let bot = DiscordReaction { user: DiscordUserRef { bot: true, ..reaction("1", "🔥", None).user }, ..reaction("1", "🔥", None) };
    assert_eq!(h.router.on_discord_reaction(&bot, &h.link).await.unwrap(), None);
    let unmapped = DiscordReaction { message_id: "999".into(), ..reaction("1", "🔥", None) };
    assert_eq!(h.router.on_discord_reaction(&unmapped, &h.link).await.unwrap(), None);
}

#[tokio::test]
async fn concord_reactions_collapse_into_one_bot_reaction() {
    let h = harness();
    let original = h.chat(&Keys::generate(), kinds::MESSAGE, "x", vec![]);
    let ids = h.router.on_concord_chat(&original, &h.link).await.unwrap();
    let (a, b) = (Keys::generate(), Keys::generate());
    let like_a = h.chat(&a, kinds::REACTION, "+", vec![s(&["e", original.rumor_id()])]);
    let like_b = h.chat(&b, kinds::REACTION, "👍", vec![s(&["e", original.rumor_id()])]);
    h.router.on_concord_chat(&like_a, &h.link).await.unwrap();
    h.router.on_concord_chat(&like_b, &h.link).await.unwrap();
    assert_eq!(*h.webhooks.reactions.lock().unwrap(), vec![(ids[0].clone(), "👍".into()); 2]);
    // Shortcodes with no Discord image and plain text never reach Discord.
    h.router.on_concord_chat(&h.chat(&a, kinds::REACTION, ":blob:", vec![s(&["e", original.rumor_id()])]), &h.link).await.unwrap();
    h.router.on_concord_chat(&h.chat(&a, kinds::REACTION, "nice", vec![s(&["e", original.rumor_id()])]), &h.link).await.unwrap();
    assert_eq!(h.webhooks.reactions.lock().unwrap().len(), 2);

    h.router.on_concord_chat(&h.chat(&a, kinds::DELETE, "", vec![s(&["e", like_a.rumor_id()])]), &h.link).await.unwrap();
    assert!(h.webhooks.unreacted.lock().unwrap().is_empty(), "b still reacts");
    h.router.on_concord_chat(&h.chat(&b, kinds::DELETE, "", vec![s(&["e", like_b.rumor_id()])]), &h.link).await.unwrap();
    assert_eq!(*h.webhooks.unreacted.lock().unwrap(), vec![(ids[0].clone(), "👍".into())]);
}

// ── Edits ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn edits_do_nothing_by_default() {
    let h = harness();
    h.router.on_discord_message(discord_msg(), &h.link).await.unwrap();
    assert_eq!(h.router.on_discord_edit(&DiscordInboundMessage { content: "edited".into(), ..discord_msg() }, &h.link).await.unwrap(), None);
    let alice = Keys::generate();
    let original = h.chat(&alice, kinds::MESSAGE, "x", vec![]);
    h.router.on_concord_chat(&original, &h.link).await.unwrap();
    h.router.on_concord_chat(&h.chat(&alice, kinds::EDIT, "y", vec![s(&["e", original.rumor_id()])]), &h.link).await.unwrap();
    assert!(h.webhooks.edited.lock().unwrap().is_empty());
}

#[tokio::test]
async fn edits_cross_both_ways_when_enabled_author_only() {
    let h = harness_with(|o, _| o.bridge_edits = true);
    let target = h.router.on_discord_message(discord_msg(), &h.link).await.unwrap().unwrap();
    h.router.on_discord_edit(&DiscordInboundMessage { content: "edited".into(), ..discord_msg() }, &h.link).await.unwrap().unwrap();
    let edit = h.chats().pop().unwrap();
    assert_eq!((edit.rumor.kind, edit.rumor.content.as_str(), edit.rumor.tag_value("e")), (kinds::EDIT, "edited", Some(target.as_str())));

    let alice = Keys::generate();
    let original = h.chat(&alice, kinds::MESSAGE, "x", vec![]);
    let ids = h.router.on_concord_chat(&original, &h.link).await.unwrap();
    h.router.on_concord_chat(&h.chat(&Keys::generate(), kinds::EDIT, "hijack", vec![s(&["e", original.rumor_id()])]), &h.link).await.unwrap();
    assert!(h.webhooks.edited.lock().unwrap().is_empty());
    h.router.on_concord_chat(&h.chat(&alice, kinds::EDIT, "fixed", vec![s(&["e", original.rumor_id()])]), &h.link).await.unwrap();
    assert_eq!(*h.webhooks.edited.lock().unwrap(), vec![(ids[0].clone(), "fixed".into())]);
}

// ── Attachments ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn rehosts_discord_attachments_with_imeta_tags() {
    let h = with_blobs();
    let cdn = "https://cdn.discordapp.com/attachments/1/2/cat.png?ex=1";
    h.blobs.blobs.lock().unwrap().insert(cdn.into(), (b"png".to_vec(), "application/octet-stream".into()));
    let msg = DiscordInboundMessage {
        content: String::new(),
        attachments: vec![DiscordAttachmentIn { url: cdn.into(), filename: Some("cat.png".into()) }],
        ..discord_msg()
    };
    h.router.on_discord_message(msg, &h.link).await.unwrap();
    let opened = h.chats().pop().unwrap();
    let sha = hex::encode(Sha256::digest(b"png"));
    let url = format!("https://blossom.example/{sha}.png");
    assert_eq!(opened.rumor.content, url);
    let imeta = opened.rumor.tags.iter().find(|t| t[0] == "imeta").unwrap();
    assert_eq!(imeta, &vec!["imeta".into(), format!("url {url}"), "m image/png".into(), format!("x {sha}"), "size 3".into(), "name cat.png".into()]);

    // A failed rehost keeps the CDN link so the message still bridges.
    let gone = DiscordInboundMessage {
        id: "2".into(),
        content: String::new(),
        attachments: vec![DiscordAttachmentIn { url: "https://cdn.discordapp.com/gone.png".into(), filename: None }],
        ..discord_msg()
    };
    h.router.on_discord_message(gone, &h.link).await.unwrap();
    assert_eq!(h.chats().pop().unwrap().rumor.content, "https://cdn.discordapp.com/gone.png");
}

#[tokio::test]
async fn decrypts_concord_attachments_before_handing_them_to_discord() {
    let h = with_blobs();
    let (ct, key) = concord::media::encrypt(b"secret image");
    let url = "https://blossom.example/abc";
    h.blobs.blobs.lock().unwrap().insert(url.into(), (ct, "application/octet-stream".into()));
    let imeta = vec![
        "imeta".to_string(),
        format!("url {url}"),
        "m image/png".into(),
        format!("ox {}", hex::encode(Sha256::digest(b"secret image"))),
        "encryption-algorithm aes-gcm".into(),
        format!("decryption-key {}", hex::encode(key.key)),
        format!("decryption-nonce {}", hex::encode(key.nonce)),
    ];
    let chat = h.chat(&Keys::generate(), kinds::MESSAGE, url, vec![imeta]);
    h.router.on_concord_chat(&chat, &h.link).await.unwrap();
    let sent = h.sent().pop().unwrap();
    // A media-only message is just the file, never URL plus file.
    assert_eq!(sent.content, "");
    assert_eq!(sent.files.len(), 1);
    assert_eq!(sent.files[0].data, b"secret image");
    assert_eq!(sent.files[0].name, "abc.png");
}

#[tokio::test]
async fn never_attaches_a_blob_it_cannot_decrypt() {
    let h = with_blobs();
    let url = "https://blossom.example/abc";
    h.blobs.blobs.lock().unwrap().insert(url.into(), (b"ciphertext".to_vec(), "image/png".into()));
    let imeta = s(&["imeta", "url https://blossom.example/abc", "m image/png", "encryption-algorithm chacha", "decryption-key 00"]);
    let chat = h.chat(&Keys::generate(), kinds::MESSAGE, url, vec![imeta]);
    h.router.on_concord_chat(&chat, &h.link).await.unwrap();
    let sent = h.sent().pop().unwrap();
    assert!(sent.files.is_empty());
    assert_eq!(sent.content, url);
    assert_eq!(h.blobs.downloads.load(Ordering::SeqCst), 0, "fails closed before downloading");
}

#[tokio::test]
async fn caps_imeta_download_attempts_not_successes() {
    let h = with_blobs();
    let tags: Vec<Vec<String>> = (0..50).map(|i| vec!["imeta".into(), format!("url https://dead.example/{i}")]).collect();
    let chat = h.chat(&Keys::generate(), kinds::MESSAGE, "x", tags);
    h.router.on_concord_chat(&chat, &h.link).await.unwrap();
    assert_eq!(h.blobs.downloads.load(Ordering::SeqCst), MAX_IMETA_DOWNLOADS);
}

// ── Typing ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn typing_crosses_both_ways_throttled() {
    let h = harness();
    h.router.on_discord_typing(USER, &h.link).await.unwrap();
    h.router.on_discord_typing(USER, &h.link).await.unwrap();
    assert_eq!(h.relay.published().iter().filter(|e| e.kind == Kind::Custom(kinds::WRAP_EPHEMERAL)).count(), 1);

    let alice = Keys::generate();
    h.router.on_concord_chat(&h.chat(&alice, kinds::TYPING, "", vec![]), &h.link).await.unwrap();
    h.router.on_concord_chat(&h.chat(&alice, kinds::TYPING, "", vec![]), &h.link).await.unwrap();
    assert_eq!(h.webhooks.typing.load(Ordering::SeqCst), 1);
}

// ── GIF pickers ─────────────────────────────────────────────────────────────

struct FakeKlipy {
    asked: Mutex<Vec<String>>,
    answer: Option<crate::klipy::KlipyGif>,
}

#[async_trait]
impl GifResolver for FakeKlipy {
    async fn resolve_gif(&self, page: &str, _: u64) -> Option<crate::klipy::KlipyGif> {
        self.asked.lock().unwrap().push(page.into());
        self.answer.clone()
    }
}

fn klipy(url: &str, dim: Option<(u32, u32)>) -> Arc<FakeKlipy> {
    let answer = crate::klipy::KlipyGif { url: url.into(), width: dim.map(|d| d.0), height: dim.map(|d| d.1), size: None };
    Arc::new(FakeKlipy { asked: Mutex::default(), answer: Some(answer) })
}

const REAL_GIF: &str = "https://static.klipy.com/ii/a/b/REAL.gif";

#[tokio::test]
async fn resolves_a_klipy_send_through_the_items_api_and_rehosts_the_real_gif() {
    let k = klipy(REAL_GIF, Some((300, 200)));
    let h = harness_with(|o, blobs| {
        o.blobs = Some(blobs.clone() as Arc<dyn BlobPort>);
        o.klipy = Some(k.clone() as Arc<dyn GifResolver>);
    });
    h.blobs.blobs.lock().unwrap().insert(REAL_GIF.into(), (b"GIF89a...".to_vec(), "image/gif".into()));
    // No embed: Discord can attach it later, and the slug is all the lookup needs.
    h.router.on_discord_message(DiscordInboundMessage { content: "https://klipy.com/gifs/monday-1".into(), ..discord_msg() }, &h.link).await.unwrap();
    assert_eq!(*k.asked.lock().unwrap(), ["https://klipy.com/gifs/monday-1"]);
    let opened = h.chats().pop().unwrap();
    let sha = hex::encode(Sha256::digest(b"GIF89a..."));
    assert_eq!(opened.rumor.content, format!("https://blossom.example/{sha}.gif"));
    let imeta: Vec<&Vec<String>> = opened.rumor.tags.iter().filter(|t| t[0] == "imeta").collect();
    assert_eq!(imeta.len(), 1);
    assert!(imeta[0].contains(&"m image/gif".to_string()) && imeta[0].contains(&"dim 300x200".to_string()));
    assert_eq!(h.blobs.uploads.lock().unwrap()[0].1, "image/gif");
}

#[tokio::test]
async fn links_the_real_klipy_gif_when_it_cannot_be_rehosted_and_never_rehosts_a_non_gif() {
    let k = klipy(REAL_GIF, None);
    let h = harness_with(|o, blobs| {
        o.blobs = Some(blobs.clone() as Arc<dyn BlobPort>);
        o.klipy = Some(k.clone() as Arc<dyn GifResolver>);
    });
    // The CDN serves a placeholder, not a GIF: it must not be rehosted.
    h.blobs.blobs.lock().unwrap().insert(REAL_GIF.into(), (b"<html>".to_vec(), "image/gif".into()));
    h.router.on_discord_message(DiscordInboundMessage { content: "https://klipy.com/gifs/monday-1".into(), ..discord_msg() }, &h.link).await.unwrap();
    assert!(h.blobs.uploads.lock().unwrap().is_empty());
    let opened = h.chats().pop().unwrap();
    assert_eq!(opened.rumor.content, REAL_GIF);
    assert_eq!(opened.rumor.tags.iter().find(|t| t[0] == "imeta").unwrap(), &s(&["imeta", &format!("url {REAL_GIF}"), "m image/gif"]));

    // A Klipy link inside prose is left to the ordinary path.
    k.asked.lock().unwrap().clear();
    h.router.on_discord_message(DiscordInboundMessage { id: "2".into(), content: "lol https://klipy.com/gifs/monday-1".into(), ..discord_msg() }, &h.link).await.unwrap();
    assert!(k.asked.lock().unwrap().is_empty());
}

struct ScriptedProbe {
    answer: Option<ProbeResult>,
    probed: Mutex<Vec<String>>,
}

#[async_trait]
impl Prober for ScriptedProbe {
    async fn probe(&self, url: &str) -> Option<ProbeResult> {
        self.probed.lock().unwrap().push(url.into());
        self.answer.clone()
    }
}

fn probe(answer: Option<(bool, &str)>) -> ScriptedProbe {
    ScriptedProbe { answer: answer.map(|(ok, mime)| ProbeResult { ok, mime: mime.into() }), probed: Mutex::default() }
}

#[tokio::test]
async fn gif_variants_are_probed_and_the_mp4_kept_when_none_verifies() {
    use crate::markup::resolve_gif_variant;
    let (gif_ok, dead, html) = (probe(Some((true, "image/gif"))), probe(Some((false, ""))), probe(Some((true, "text/html"))));
    assert_eq!(resolve_gif_variant("https://p", "https://cdn/x.gif", &dead).await, "https://cdn/x.gif");
    assert_eq!(resolve_gif_variant("https://tenor.com/view/x", "https://media.tenor.com/a.mp4", &gif_ok).await, "https://media.tenor.com/a.gif");
    // Never on Klipy: its CDN answers every missing rendition with a
    // placeholder GIF, so a probe that says yes proves nothing.
    assert_eq!(resolve_gif_variant("https://klipy.com/gifs/x", "https://static.klipy.com/a.mp4", &gif_ok).await, "https://static.klipy.com/a.mp4");
    // A 200 that serves html is not a gif.
    assert_eq!(resolve_gif_variant("https://tenor.com/view/x", "https://media.tenor.com/a.mp4", &html).await, "https://media.tenor.com/a.mp4");
    assert_eq!(resolve_gif_variant("https://p/x", "https://cdn/a.mp4", &dead).await, "https://cdn/a.mp4");

    // The media URL is an OpenGraph value off a page the author chose: the
    // guard's refusal must read as "no", not as an absent content type.
    let refuse = probe(None);
    let metadata = "http://169.254.169.254/latest/meta-data/x.mp4";
    assert_eq!(resolve_gif_variant("https://tenor.com/view/x", metadata, &refuse).await, metadata);
    assert_eq!(*refuse.probed.lock().unwrap(), ["http://169.254.169.254/latest/meta-data/x.gif", "https://tenor.com/view/x.gif"]);
}

// ── Threads, ordering, attachments ──────────────────────────────────────────

#[tokio::test]
async fn flattens_a_thread_reply_with_a_parent_jump_link() {
    let h = harness();
    let alice = Keys::generate();
    let parent = h.chat(&alice, kinds::MESSAGE, "parent", vec![]);
    h.router.on_concord_chat(&parent, &h.link).await.unwrap();
    let a = alice.public_key().to_hex();
    let tags = vec![
        s(&["K", "9"]), s(&["E", parent.rumor_id(), "", &a]), s(&["P", &a]),
        s(&["k", "9"]), s(&["e", parent.rumor_id(), "", &a]), s(&["p", &a]),
    ];
    let reply = h.chat(&Keys::generate(), kinds::COMMENT, "thread reply", tags);
    assert_eq!(h.router.on_concord_chat(&reply, &h.link).await.unwrap().len(), 1);
    let sent = &h.sent()[1];
    assert_eq!(sent.content, "thread reply");
    assert!(sent.embeds[0].contains("/9000"));
    // Mapped, so reactions and deletes on the comment resolve too.
    assert!(h.rows().iter().any(|r| r.concord_rumor_id == reply.rumor_id()));
}

#[tokio::test]
async fn mirrors_concurrent_rumors_one_at_a_time_in_order() {
    let h = harness();
    let alice = Keys::generate();
    let chats: Vec<OpenedChat> = (1..=5).map(|n| h.chat(&alice, kinds::MESSAGE, &format!("msg {n}"), vec![])).collect();
    futures_util::future::join_all(chats.iter().map(|c| h.router.on_concord_chat(c, &h.link))).await;
    assert_eq!(h.sent().iter().map(|m| m.content.as_str()).collect::<Vec<_>>(), ["msg 1", "msg 2", "msg 3", "msg 4", "msg 5"]);
}

#[tokio::test]
async fn keeps_a_sender_chosen_filename_out_of_the_multipart_header() {
    let h = with_blobs();
    let url = "https://blossom.example/abc123";
    h.blobs.blobs.lock().unwrap().insert(url.into(), (b"png".to_vec(), "image/png".into()));
    let imeta = s(&["imeta", "url https://blossom.example/abc123", "m image/png", "size 3", "name ../../etc/\"passwd\r\n.png"]);
    h.router.on_concord_chat(&h.chat(&Keys::generate(), kinds::MESSAGE, "pic", vec![imeta]), &h.link).await.unwrap();
    let name = &h.sent()[0].files[0].name;
    assert!(!name.contains(['/', '"', '\r', '\n']), "{name}");
    assert!(!name.starts_with('.') && name.ends_with(".png"), "{name}");
}

#[tokio::test]
async fn keeps_the_url_when_the_blob_is_too_large_to_attach() {
    let h = with_blobs();
    let url = "https://blossom.example/abc123";
    let imeta = s(&["imeta", "url https://blossom.example/abc123", "m image/gif", "size 99999999"]);
    h.router.on_concord_chat(&h.chat(&Keys::generate(), kinds::MESSAGE, url, vec![imeta]), &h.link).await.unwrap();
    let sent = &h.sent()[0];
    assert_eq!(sent.content, url);
    assert!(sent.files.is_empty());
    assert_eq!(h.blobs.downloads.load(Ordering::SeqCst), 0, "an admittedly oversized blob is not even fetched");
}

#[tokio::test]
async fn backdates_a_history_message_and_its_join() {
    let h = harness();
    let ms = 1_709_294_400_000; // 2024-03-01T12:00:00Z
    h.router.on_discord_message(DiscordInboundMessage { timestamp_ms: Some(ms), ..discord_msg() }, &h.link).await.unwrap();
    assert_eq!(h.chats()[0].ms, ms);
    let gb: StreamKey = h.client.community().current_guestbook_stream();
    let join = h.relay.published().into_iter().find(|e| e.pubkey == gb.pk).unwrap();
    assert_eq!(open_wrap(&join, &gb).unwrap().ms, ms);
}
