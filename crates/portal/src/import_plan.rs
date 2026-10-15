//! Server-import planning: normalize a Discord guild snapshot into an
//! ImportPlan — the channels, roles, and metadata the importer will mint on
//! Armada, plus an honest report of what is skipped. Pure mapping, no I/O; the
//! plan is stored as the imports row's jsonb and doubles as the pipeline's
//! checkpoint ledger.
//!
//! That jsonb was first written by the TypeScript portal, so the serde shape
//! here is a wire format, not a convenience: camelCase field names, absent
//! optionals omitted rather than null, Concord permissions as a decimal
//! string. Every field a row might predate is optional or defaulted, so an
//! older row still parses.

use std::collections::HashMap;

use concord::control::ImagePointer;
use concord::roles::{NAME_MAX_BYTES, perm};
use serde::{Deserialize, Serialize};

use crate::discord_rest::{GuildSnapshot, SnapshotChannel};

/// Discord permission bits (topics/permissions). Only the ones we map or read.
mod d {
    pub const CREATE_INSTANT_INVITE: u64 = 1 << 0;
    pub const KICK_MEMBERS: u64 = 1 << 1;
    pub const BAN_MEMBERS: u64 = 1 << 2;
    pub const ADMINISTRATOR: u64 = 1 << 3;
    pub const MANAGE_CHANNELS: u64 = 1 << 4;
    pub const MANAGE_GUILD: u64 = 1 << 5;
    pub const VIEW_AUDIT_LOG: u64 = 1 << 7;
    pub const VIEW_CHANNEL: u64 = 1 << 10;
    pub const MANAGE_MESSAGES: u64 = 1 << 13;
    pub const MENTION_EVERYONE: u64 = 1 << 17;
    pub const MANAGE_ROLES: u64 = 1 << 28;
}

/// Discord bit → Concord bit, per the plan's permission map.
const BIT_MAP: [(u64, u64); 9] = [
    (d::MANAGE_ROLES, perm::MANAGE_ROLES),
    (d::MANAGE_CHANNELS, perm::MANAGE_CHANNELS),
    (d::MANAGE_GUILD, perm::MANAGE_METADATA),
    (d::KICK_MEMBERS, perm::KICK),
    (d::BAN_MEMBERS, perm::BAN),
    (d::MANAGE_MESSAGES, perm::MANAGE_MESSAGES),
    (d::CREATE_INSTANT_INVITE, perm::CREATE_INVITE),
    (d::VIEW_AUDIT_LOG, perm::VIEW_AUDIT_LOG),
    (d::MENTION_EVERYONE, perm::MENTION_EVERYONE),
];

// Discord channel types (resources/channel).
const TEXT: u32 = 0;
const VOICE: u32 = 2;
const CATEGORY: u32 = 4;
const ANNOUNCEMENT: u32 = 5;
const STAGE: u32 = 13;
const FORUM: u32 = 15;
const MEDIA: u32 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelKind {
    Voice,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedChannel {
    pub discord_id: String,
    #[serde(default)]
    pub discord_type: u32,
    /// Final Concord channel name (voice suffix applied, 64-byte capped).
    pub name: String,
    /// Discord channel topic, recorded under `custom["discord.import"].topic`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// Parent category name, published as `custom["armada.category"].name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// "voice" for imported voice/stage rooms (`custom["discord.import"].type`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ChannelKind>,
    /// Discord denied @everyone VIEW_CHANNEL, so this imports as a CORD-03
    /// Private Channel: its own random key (never derived from the community
    /// root) plus a channel-scoped Role that is its access list (CORD-04 §2).
    ///
    /// The key lands with the OWNER alone. Discord's per-channel allow list names
    /// Discord roles held by Discord accounts, and an import has no npub for any
    /// of them — members arrive later, through the invite. Vending the key to
    /// anyone else at import time would mean vending it to everyone who joins,
    /// which is a public channel with extra steps. The owner distributes it from
    /// Armada, which is where the grant and the rekey-on-revoke live.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private: Option<bool>,
    /// The channel-scoped Role that gates a private channel (minted at prepare).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_role_id_hex: Option<String>,
    /// Its independent 32-byte key, sealed with the portal KMS key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_sealed: Option<String>,
    /// Unix ms when the access Role edition was accepted by a relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_role_published_at: Option<u64>,
    /// Only GuildText channels can be live-bridged (webhook mirroring).
    #[serde(default)]
    pub bridgeable: bool,
    /// Pre-flight: the bot lacks Manage Webhooks in this channel, so a live
    /// bridge could not mirror Armada messages into it. Set on the review screen
    /// (Importer.preview) so the owner can fix Discord perms before wiring, not
    /// discover the gap once the channel silently stops mirroring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bot_missing_webhook: Option<bool>,
    /// User toggle: create a live bridge for this channel.
    #[serde(default)]
    pub bridge: bool,
    /// User toggle: include this channel in the import at all.
    #[serde(default)]
    pub selected: bool,
    /// User toggle: backfill message history (bridged text channels only).
    #[serde(default)]
    pub history: bool,
    /// Backfill progress: messages published so far + resume cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_imported: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_done_at: Option<u64>,
    /// Minted at import time (hex32); checkpoint for the edition publish.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id_hex: Option<String>,
    /// Unix ms when the channel edition was accepted by a relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<u64>,
    /// Set once a bridges row was created and activated for this channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_id: Option<String>,
    /// Why a live bridge was asked for but not wired. One live bridge per Discord
    /// channel is a database invariant (migration 017), so a channel someone had
    /// already bridged by hand is skipped here rather than aborting the import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_skipped: Option<String>,
    /// Fields this version does not know, carried through a re-save so a
    /// newer writer's checkpoints are never silently dropped.
    #[serde(flatten, default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl PlannedChannel {
    pub fn is_private(&self) -> bool {
        self.private == Some(true)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedRole {
    pub discord_id: String,
    pub name: String,
    #[serde(default)]
    pub color: u32,
    /// Concord position (lower = higher authority; 1 is the stock Admin).
    pub position: u32,
    /// Concord permission bits, a decimal string on the wire (jsonb has no
    /// 64-bit integer the TypeScript side could read back exactly).
    #[serde(with = "decimal_u64")]
    pub permissions: u64,
    /// Discord-only permissions this role loses, for the preview's honesty.
    #[serde(default)]
    pub dropped: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_id_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_at: Option<u64>,
    /// Fields this version does not know, carried through a re-save so a
    /// newer writer's checkpoints are never silently dropped.
    #[serde(flatten, default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SkippedKind {
    Channel,
    Role,
    Feature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedItem {
    pub kind: SkippedKind,
    pub name: String,
    pub reason: String,
}

impl SkippedItem {
    fn new(kind: SkippedKind, name: impl Into<String>, reason: impl Into<String>) -> SkippedItem {
        SkippedItem { kind, name: name.into(), reason: reason.into() }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OwnerSignPurpose {
    AdminRole,
    OpGrant,
    InviteRegistry,
    OwnerJoin,
}

/// An unsigned nostr event. Its fields are the event's own (`created_at`, not
/// camelCase): the browser signs exactly this object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventTemplate {
    pub kind: u16,
    pub content: String,
    pub tags: Vec<Vec<String>>,
    pub created_at: u64,
}

/// An unsigned seal template the community owner signs in their browser.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerSignTemplate {
    pub purpose: OwnerSignPurpose,
    pub template: EventTemplate,
}

/// A signed event as it comes back from the browser (NIP-07 / local nsec).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSeal {
    pub kind: u16,
    pub content: String,
    pub tags: Vec<Vec<String>>,
    pub created_at: u64,
    pub pubkey: String,
    pub id: String,
    pub sig: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportCheckpoints {
    /// Set once mintCommunity ran; identity + access secrets live sealed in the row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community_id_hex: Option<String>,
    /// The community owner: the USER's real pubkey (position 0, supreme).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_pk_hex: Option<String>,
    /// The portal's operational key: holds a revocable Admin grant, does the bulk publishing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_pk_hex: Option<String>,
    /// The stock Admin role the owner mints and grants to the operational key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_role_id_hex: Option<String>,
    /// selfHash of the owner-signed grant edition — the vac citation every op action carries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_hash_hex: Option<String>,
    /// Templates awaiting the owner's signature, then the signed seals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_templates: Option<Vec<OwnerSignTemplate>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_signed_seals: Option<Vec<SignedSeal>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_role_published_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_grant_published_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_registry_published_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_join_published_at: Option<u64>,
    /// The Grant edition that hands the owner the staff write key (CORD-04 §3).
    /// The portal mints the `control_root` server-side, so without this delivery
    /// the owner holds `control_pk` (read) but could never publish a Control
    /// edition from Armada — not even to revoke the op grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_control_key_published_at: Option<u64>,
    /// Encrypted-blob pointers (CORD-02 §6) for the rehosted icon/banner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_pointer: Option<ImagePointer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner_pointer: Option<ImagePointer>,
    /// Set when icon/banner rehosting was attempted (success or noted failure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assets_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assets_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_published_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_join_published_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_published_at: Option<u64>,
    /// Public invite link: bundle published under this signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_link_signer_pk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_published_at: Option<u64>,
    /// The Direct Invite that handed the owner their private-channel keys.
    /// `Error` records a delivery that failed after everything else landed — the
    /// community is intact, the owner is just missing their copy, and re-running
    /// the import retries with the SAME checkpointed keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_channel_keys_sent_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_channel_keys_error: Option<String>,
    /// kind 30030 guild emoji pack, addressable at `30030:<opPk>:discord-import`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emoji_pack_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emoji_pack_published_at: Option<u64>,
    /// Fields this version does not know, carried through a re-save so a
    /// newer writer's checkpoints are never silently dropped.
    #[serde(flatten, default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// History import gates.
pub const HISTORY_MEMBER_CAP: u64 = 100;
pub const HISTORY_MESSAGE_CAP: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedEmoji {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub animated: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedGuild {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner_url: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPlan {
    pub guild: PlannedGuild,
    /// Community name (defaults to the guild name, 64-byte capped).
    pub community_name: String,
    /// approximate_member_count at snapshot time; gates history import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_count: Option<u64>,
    /// False for servers above HISTORY_MEMBER_CAP members.
    #[serde(default)]
    pub history_allowed: bool,
    /// Guild custom emoji, published as a kind 30030 pack.
    #[serde(default)]
    pub emojis: Vec<PlannedEmoji>,
    #[serde(default)]
    pub channels: Vec<PlannedChannel>,
    #[serde(default)]
    pub roles: Vec<PlannedRole>,
    #[serde(default)]
    pub skipped: Vec<SkippedItem>,
    /// Filled at confirm time.
    #[serde(default)]
    pub relays: Vec<String>,
    /// Armada pubkey (hex) granted the Admin role; optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_pk_hex: Option<String>,
    #[serde(default)]
    pub checkpoints: ImportCheckpoints,
    /// Fields this version does not know, carried through a re-save so a
    /// newer writer's checkpoints are never silently dropped.
    #[serde(flatten, default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// u64 as a decimal string. Reads a bare number too, which nothing writes
/// today but costs nothing to accept.
mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(value: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<u64, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Str(String),
            Num(u64),
        }
        match Repr::deserialize(de)? {
            Repr::Str(s) => s.parse().map_err(D::Error::custom),
            Repr::Num(n) => Ok(n),
        }
    }
}

/// Truncate to the protocol's 64-byte name cap without splitting a code point.
pub fn cap_name(name: &str) -> String {
    if name.len() <= NAME_MAX_BYTES {
        return name.to_owned();
    }
    let mut end = 0;
    for (i, ch) in name.char_indices() {
        if i + ch.len_utf8() > NAME_MAX_BYTES {
            break;
        }
        end = i + ch.len_utf8();
    }
    name[..end].to_owned()
}

/// Discord sends permission sets as decimal strings. A malformed one grants
/// nothing rather than failing the whole plan.
fn bits(s: &str) -> u64 {
    s.parse().unwrap_or(0)
}

fn label(c: &SnapshotChannel) -> String {
    format!("#{}", c.name)
}

/// Whether a channel is private on the Discord side: an @everyone (role id ==
/// guild id) overwrite denying VIEW_CHANNEL, on the channel itself or inherited
/// from its category when the channel doesn't explicitly re-allow it.
///
/// These used to be dropped ("READ access in Concord is key possession, which
/// v1 does not distribute" — plan Q2). Armada 0.45.0 ships role-gated Private
/// Channels, so they now import as one: see `PlannedChannel::private` for who
/// ends up holding the key.
fn is_private(channel: &SnapshotChannel, guild_id: &str, categories: &HashMap<&str, &SnapshotChannel>) -> bool {
    let everyone_of = |c: &SnapshotChannel| {
        c.permission_overwrites.iter().find(|o| o.id == guild_id && o.kind == 0).cloned()
    };
    if let Some(own) = everyone_of(channel) {
        if bits(&own.deny) & d::VIEW_CHANNEL != 0 {
            return true;
        }
        if bits(&own.allow) & d::VIEW_CHANNEL != 0 {
            return false;
        }
    }
    let parent = channel.parent_id.as_deref().and_then(|p| categories.get(p)).and_then(|c| everyone_of(c));
    parent.is_some_and(|p| bits(&p.deny) & d::VIEW_CHANNEL != 0)
}

fn voice_name(name: &str) -> String {
    let n = name.len();
    if n >= 5 && name.is_char_boundary(n - 5) && name[n - 5..].eq_ignore_ascii_case("voice") {
        name.to_owned()
    } else {
        format!("{name}-voice")
    }
}

/// The first `units` UTF-16 code units, as JavaScript's `slice` counts them
/// (rows written by the TS portal were cut that way), never splitting a char.
fn truncate_utf16(s: &str, units: usize) -> &str {
    let mut used = 0;
    for (i, ch) in s.char_indices() {
        used += ch.len_utf16();
        if used > units {
            return &s[..i];
        }
    }
    s
}

fn plan_channels(snapshot: &GuildSnapshot, skipped: &mut Vec<SkippedItem>) -> Vec<PlannedChannel> {
    let categories: HashMap<&str, &SnapshotChannel> =
        snapshot.channels.iter().filter(|c| c.kind == CATEGORY).map(|c| (c.id.as_str(), c)).collect();
    let category_of = |c: &SnapshotChannel| c.parent_id.as_deref().and_then(|p| categories.get(p)).copied();

    let mut ordered: Vec<&SnapshotChannel> = snapshot.channels.iter().collect();
    ordered.sort_by_key(|c| (category_of(c).map_or(-1, |cat| cat.position), c.position));

    let mut out = Vec::new();
    for channel in ordered {
        if channel.kind == CATEGORY {
            continue; // carried as custom.category on children
        }
        if channel.kind == FORUM || channel.kind == MEDIA {
            skipped.push(SkippedItem::new(SkippedKind::Channel, label(channel), "forum/media channels are not supported yet"));
            continue;
        }
        let voice = channel.kind == VOICE || channel.kind == STAGE;
        if !voice && channel.kind != TEXT && channel.kind != ANNOUNCEMENT {
            let reason = format!("unsupported channel type {}", channel.kind);
            skipped.push(SkippedItem::new(SkippedKind::Channel, label(channel), reason));
            continue;
        }
        let private = is_private(channel, &snapshot.guild.id, &categories);
        // A private channel CAN be mirrored, but never by default: doing so vends
        // its key to the bridge's custodial npub and copies a deliberately gated
        // room into Discord in plaintext. That is a choice the owner makes per
        // channel, on the review screen, not one an import makes for them.
        //
        // (The bridge takes delivery of the key at boot as a Direct Invite — see
        // keyIntake — which the wiring step sends before starting it. What is
        // still unhandled is CORD-06 rotation: after a revoke-driven rekey the
        // bridge holds a superseded key and goes quiet until it is re-granted.)
        let bridgeable = channel.kind == TEXT;
        let topic = channel.topic.as_deref().map(str::trim).filter(|t| !t.is_empty());
        out.push(PlannedChannel {
            discord_id: channel.id.clone(),
            discord_type: channel.kind,
            name: cap_name(&if voice { voice_name(&channel.name) } else { channel.name.clone() }),
            topic: topic.map(|t| truncate_utf16(t, 1024).to_owned()),
            category: category_of(channel).map(|c| c.name.clone()),
            kind: voice.then_some(ChannelKind::Voice),
            private: private.then_some(true),
            bridgeable,
            bridge: bridgeable && !private,
            selected: true,
            history: false, // flipped on below when the member gate allows
            ..PlannedChannel::default()
        });
    }
    out
}

/// Human labels for the Discord bits we deliberately drop, preview copy.
const DISCORD_ONLY: [(u64, &str); 20] = [
    (1 << 6, "Add Reactions"),
    (1 << 8, "Priority Speaker"),
    (1 << 11, "Send Messages"),
    (1 << 12, "Send TTS Messages"),
    (1 << 14, "Embed Links"),
    (1 << 15, "Attach Files"),
    (1 << 16, "Read Message History"),
    (1 << 18, "Use External Emojis"),
    (1 << 20, "Connect"),
    (1 << 21, "Speak"),
    (1 << 22, "Mute Members"),
    (1 << 23, "Deafen Members"),
    (1 << 24, "Move Members"),
    (1 << 25, "Use Voice Activity"),
    (1 << 26, "Change Nickname"),
    (1 << 27, "Manage Nicknames"),
    (1 << 29, "Manage Webhooks"),
    (1 << 30, "Manage Expressions"),
    (1 << 34, "Manage Events"),
    (1 << 38, "Manage Threads"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappedPermissions {
    pub permissions: u64,
    pub dropped: Vec<String>,
}

pub fn map_role_permissions(discord_bits: u64) -> MappedPermissions {
    if discord_bits & d::ADMINISTRATOR != 0 {
        return MappedPermissions { permissions: perm::ADMIN_ALL, dropped: Vec::new() };
    }
    let permissions = BIT_MAP.iter().filter(|(d_bit, _)| discord_bits & d_bit != 0).fold(0, |acc, (_, c_bit)| acc | c_bit);
    let dropped =
        DISCORD_ONLY.iter().filter(|(bit, _)| discord_bits & bit != 0).map(|(_, name)| (*name).to_owned()).collect();
    MappedPermissions { permissions, dropped }
}

/// Concord holds 100 roles per community; position 1 is reserved for the stock
/// Admin role the importer mints, so 99 slots remain for imported roles.
pub const MAX_IMPORTED_ROLES: usize = 99;

fn plan_roles(snapshot: &GuildSnapshot, skipped: &mut Vec<SkippedItem>) -> Vec<PlannedRole> {
    let mut candidates = Vec::new();
    // Highest Discord position = highest authority; walk top-down so Concord
    // positions (lower = higher) preserve the hierarchy below the stock Admin.
    let mut roles: Vec<_> = snapshot.guild.roles.iter().collect();
    roles.sort_by_key(|r| std::cmp::Reverse(r.position));
    for role in roles {
        if role.id == snapshot.guild.id {
            continue; // @everyone is the memberhood itself
        }
        if role.managed {
            skipped.push(SkippedItem::new(SkippedKind::Role, &role.name, "managed role (bot/integration/booster)"));
            continue;
        }
        let MappedPermissions { permissions, dropped } = map_role_permissions(bits(&role.permissions));
        if permissions == 0 && !role.hoist {
            skipped.push(SkippedItem::new(
                SkippedKind::Role,
                &role.name,
                "no mappable permissions and not displayed separately",
            ));
            continue;
        }
        candidates.push(PlannedRole {
            discord_id: role.id.clone(),
            name: cap_name(&role.name),
            color: role.color,
            position: 0, // assigned below
            permissions,
            dropped,
            ..PlannedRole::default()
        });
    }
    if candidates.len() > MAX_IMPORTED_ROLES {
        for dropped in candidates.split_off(MAX_IMPORTED_ROLES) {
            skipped.push(SkippedItem::new(SkippedKind::Role, dropped.name, "community role cap (100) reached"));
        }
    }
    for (i, role) in candidates.iter_mut().enumerate() {
        role.position = i as u32 + 2; // 2..n, below the stock Admin at 1
    }
    candidates
}

fn is_word(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub fn build_import_plan(snapshot: &GuildSnapshot) -> ImportPlan {
    let mut skipped = Vec::new();
    let mut channels = plan_channels(snapshot, &mut skipped);
    let roles = plan_roles(snapshot, &mut skipped);

    let member_count = snapshot.guild.approximate_member_count;
    let history_allowed = member_count.is_some_and(|n| n <= HISTORY_MEMBER_CAP);
    if history_allowed {
        // Follows the bridge default, so a private channel doesn't arrive with
        // history pre-ticked under an unticked bridge it depends on.
        for channel in channels.iter_mut().filter(|c| c.bridgeable && c.bridge) {
            channel.history = true;
        }
    } else {
        skipped.push(SkippedItem::new(
            SkippedKind::Feature,
            "Message history",
            format!("not currently available for servers with more than {HISTORY_MEMBER_CAP} members"),
        ));
    }

    let emojis = snapshot
        .guild
        .emojis
        .iter()
        .filter(|e| e.available != Some(false) && is_word(&e.name))
        .map(|e| PlannedEmoji { id: e.id.clone(), name: e.name.clone(), animated: e.animated == Some(true) })
        .collect();

    skipped.extend([
        SkippedItem::new(
            SkippedKind::Feature,
            "Members",
            "members join via the Armada invite; bridged senders appear as puppets",
        ),
        SkippedItem::new(SkippedKind::Feature, "Stickers, soundboard", "no Armada equivalent yet"),
        SkippedItem::new(SkippedKind::Feature, "Onboarding, welcome screen, integrations", "no Armada equivalent"),
    ]);

    let guild = &snapshot.guild;
    let gid = &guild.id;
    let banner_url = match (&guild.banner, &guild.splash) {
        (Some(banner), _) if !banner.is_empty() => {
            Some(format!("https://cdn.discordapp.com/banners/{gid}/{banner}.png?size=1024"))
        }
        (_, Some(splash)) if !splash.is_empty() => {
            Some(format!("https://cdn.discordapp.com/splashes/{gid}/{splash}.png?size=1024"))
        }
        _ => None,
    };
    ImportPlan {
        guild: PlannedGuild {
            id: gid.clone(),
            name: guild.name.clone(),
            description: guild.description.clone(),
            icon_url: guild
                .icon
                .as_deref()
                .filter(|i| !i.is_empty())
                .map(|icon| format!("https://cdn.discordapp.com/icons/{gid}/{icon}.png?size=512")),
            banner_url,
        },
        community_name: cap_name(&guild.name),
        member_count,
        history_allowed,
        emojis,
        channels,
        roles,
        skipped,
        relays: Vec::new(),
        admin_pk_hex: None,
        checkpoints: ImportCheckpoints::default(),
        extra: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discord_rest::{ChannelOverwrite, SnapshotGuild, SnapshotRole};

    const GUILD_ID: &str = "100";
    const VIEW: u64 = 1 << 10;

    fn role(id: &str, name: &str, position: i64) -> SnapshotRole {
        SnapshotRole { id: id.into(), name: name.into(), permissions: "0".into(), position, ..SnapshotRole::default() }
    }

    fn channel(id: &str, name: &str, kind: u32) -> SnapshotChannel {
        SnapshotChannel { id: id.into(), name: name.into(), kind, ..SnapshotChannel::default() }
    }

    fn everyone(allow: u64, deny: u64) -> Vec<ChannelOverwrite> {
        vec![ChannelOverwrite { id: GUILD_ID.into(), kind: 0, allow: allow.to_string(), deny: deny.to_string() }]
    }

    fn snapshot(channels: Vec<SnapshotChannel>, roles: Vec<SnapshotRole>) -> GuildSnapshot {
        let mut all = vec![role(GUILD_ID, "@everyone", 0)];
        all.extend(roles);
        GuildSnapshot {
            guild: SnapshotGuild {
                id: GUILD_ID.into(),
                name: "Test Fleet".into(),
                description: Some("hello".into()),
                icon: Some("abc".into()),
                roles: all,
                ..SnapshotGuild::default()
            },
            channels,
        }
    }

    // ── channel planning ──

    #[test]
    fn imports_text_and_announcement_channels_bridges_only_text() {
        let plan = build_import_plan(&snapshot(vec![channel("1", "general", 0), channel("2", "news", 5)], vec![]));
        let got: Vec<_> = plan.channels.iter().map(|c| (c.name.as_str(), c.bridgeable, c.bridge)).collect();
        assert_eq!(got, [("general", true, true), ("news", false, false)]);
    }

    #[test]
    fn imports_voice_and_stage_channels_as_voice_rooms_with_custom_kind() {
        let plan =
            build_import_plan(&snapshot(vec![channel("1", "hangout", 2), channel("2", "The Voice", 13)], vec![]));
        let got: Vec<_> = plan.channels.iter().map(|c| (c.name.as_str(), c.kind)).collect();
        assert_eq!(
            got,
            [
                ("hangout-voice", Some(ChannelKind::Voice)),
                ("The Voice", Some(ChannelKind::Voice)), // already ends in "voice": no suffix
            ]
        );
    }

    #[test]
    fn records_the_category_name_and_orders_by_category_then_position() {
        let plan = build_import_plan(&snapshot(
            vec![
                SnapshotChannel { position: 1, ..channel("9", "Ops", 4) },
                SnapshotChannel { position: 1, parent_id: Some("9".into()), ..channel("2", "logistics", 0) },
                SnapshotChannel { position: 0, parent_id: Some("9".into()), ..channel("3", "briefing", 0) },
                channel("1", "general", 0),
            ],
            vec![],
        ));
        let got: Vec<_> = plan.channels.iter().map(|c| (c.name.as_str(), c.category.as_deref())).collect();
        assert_eq!(got, [("general", None), ("briefing", Some("Ops")), ("logistics", Some("Ops"))]);
    }

    #[test]
    fn plans_a_private_channel_gated_mirrorable_but_off_by_default() {
        let plan = build_import_plan(&snapshot(
            vec![SnapshotChannel { permission_overwrites: everyone(0, VIEW), ..channel("1", "mods-only", 0) }],
            vec![],
        ));
        // Offered, never assumed: mirroring a gated room copies it into Discord in
        // plaintext, so the owner has to tick it themselves. History follows the
        // bridge flag, so it must not arrive pre-ticked either.
        let got: Vec<_> =
            plan.channels.iter().map(|c| (c.name.as_str(), c.private, c.bridgeable, c.bridge, c.history)).collect();
        assert_eq!(got, [("mods-only", Some(true), true, false, false)]);
    }

    #[test]
    fn inherits_privacy_from_the_category_unless_the_channel_re_allows() {
        let plan = build_import_plan(&snapshot(
            vec![
                SnapshotChannel { permission_overwrites: everyone(0, VIEW), ..channel("9", "Staff", 4) },
                SnapshotChannel { parent_id: Some("9".into()), ..channel("1", "staff-chat", 0) },
                SnapshotChannel {
                    parent_id: Some("9".into()),
                    permission_overwrites: everyone(VIEW, 0),
                    ..channel("2", "made-public", 0)
                },
            ],
            vec![],
        ));
        let got: Vec<_> = plan.channels.iter().map(|c| (c.name.as_str(), c.is_private())).collect();
        assert_eq!(got, [("staff-chat", true), ("made-public", false)]);
    }

    #[test]
    fn skips_forum_channels_with_a_reason() {
        let plan = build_import_plan(&snapshot(vec![channel("1", "help", 15)], vec![]));
        assert!(plan.channels.is_empty());
        assert!(plan.skipped.iter().find(|s| s.name == "#help").unwrap().reason.contains("forum"));
    }

    // ── role planning ──

    #[test]
    fn maps_administrator_to_admin_all_with_nothing_dropped() {
        assert_eq!(map_role_permissions(1 << 3), MappedPermissions { permissions: perm::ADMIN_ALL, dropped: vec![] });
    }

    #[test]
    fn maps_individual_bits_and_reports_dropped_discord_only_ones() {
        let bits = (1 << 1) | (1 << 2) | (1 << 13) | (1 << 22); // kick, ban, manage messages, mute
        let MappedPermissions { permissions, dropped } = map_role_permissions(bits);
        assert_eq!(permissions, perm::KICK | perm::BAN | perm::MANAGE_MESSAGES);
        assert_eq!(dropped, ["Mute Members"]);
    }

    #[test]
    fn skips_everyone_managed_roles_and_permissionless_unhoisted_roles() {
        let plan = build_import_plan(&snapshot(
            vec![],
            vec![
                SnapshotRole { managed: true, permissions: (1u64 << 3).to_string(), ..role("2", "Some Bot", 3) },
                role("3", "Cosmetic", 2),
                SnapshotRole { hoist: true, ..role("4", "Hoisted Badge", 1) },
            ],
        ));
        assert_eq!(plan.roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["Hoisted Badge"]);
        let reason = |name: &str| plan.skipped.iter().find(|s| s.name == name).unwrap().reason.clone();
        assert!(reason("Some Bot").contains("managed"));
        assert!(reason("Cosmetic").contains("no mappable"));
    }

    #[test]
    fn preserves_hierarchy_higher_discord_position_is_lower_concord_position_from_2() {
        let plan = build_import_plan(&snapshot(
            vec![],
            vec![
                SnapshotRole { permissions: (1u64 << 1).to_string(), ..role("2", "Mod", 1) },
                SnapshotRole { permissions: (1u64 << 3).to_string(), ..role("3", "Chief", 5) },
            ],
        ));
        let got: Vec<_> = plan.roles.iter().map(|r| (r.name.as_str(), r.position)).collect();
        assert_eq!(got, [("Chief", 2), ("Mod", 3)]);
    }

    #[test]
    fn caps_imported_roles_at_99_and_reports_the_overflow() {
        let many = (0..120)
            .map(|i| SnapshotRole {
                permissions: (1u64 << 1).to_string(),
                ..role(&format!("r{i}"), &format!("Role {i}"), 200 - i)
            })
            .collect();
        let plan = build_import_plan(&snapshot(vec![], many));
        assert_eq!(plan.roles.len(), MAX_IMPORTED_ROLES);
        assert_eq!(plan.skipped.iter().filter(|s| s.reason.contains("role cap")).count(), 120 - MAX_IMPORTED_ROLES);
    }

    // ── names and metadata ──

    #[test]
    fn caps_names_at_64_bytes_without_splitting_code_points() {
        assert_eq!(cap_name(&"a".repeat(80)).len(), 64);
        let emoji = "🚀".repeat(40); // 4 bytes each
        assert!(cap_name(&emoji).len() <= 64);
        assert!(cap_name(&emoji).ends_with('🚀'));
        assert_eq!(cap_name(&format!("{}é", "a".repeat(63))), "a".repeat(63));
    }

    #[test]
    fn carries_guild_metadata_and_always_reports_unimported_features() {
        let plan = build_import_plan(&snapshot(vec![], vec![]));
        assert_eq!(plan.community_name, "Test Fleet");
        assert!(plan.guild.icon_url.as_deref().unwrap().contains("cdn.discordapp.com"));
        assert!(plan.skipped.iter().any(|s| s.name == "Message history"));
        assert!(plan.skipped.iter().any(|s| s.name == "Members"));
    }

    #[test]
    fn ticks_history_for_bridged_channels_under_the_member_cap() {
        let mut snap = snapshot(
            vec![
                channel("1", "general", 0),
                SnapshotChannel { permission_overwrites: everyone(0, VIEW), ..channel("2", "mods", 0) },
            ],
            vec![],
        );
        snap.guild.approximate_member_count = Some(HISTORY_MEMBER_CAP);
        let plan = build_import_plan(&snap);
        assert!(plan.history_allowed);
        assert_eq!(plan.channels.iter().map(|c| c.history).collect::<Vec<_>>(), [true, false]);
        assert!(!plan.skipped.iter().any(|s| s.name == "Message history"));
    }

    // ── the jsonb wire format ──

    #[test]
    fn serializes_in_the_shape_the_typescript_portal_wrote() {
        let plan = build_import_plan(&snapshot(
            vec![channel("1", "hangout", 2)],
            vec![SnapshotRole { permissions: (1u64 << 3).to_string(), ..role("2", "Chief", 1) }],
        ));
        let v = serde_json::to_value(&plan).unwrap();
        assert_eq!(v["communityName"], "Test Fleet");
        assert_eq!(v["historyAllowed"], false);
        assert!(v.get("memberCount").is_none());
        assert!(v.get("adminPkHex").is_none());
        assert_eq!(v["checkpoints"], serde_json::json!({}));
        assert_eq!(v["guild"]["iconUrl"], "https://cdn.discordapp.com/icons/100/abc.png?size=512");
        assert!(v["guild"].get("bannerUrl").is_none());
        let ch = &v["channels"][0];
        assert_eq!(ch["discordId"], "1");
        assert_eq!(ch["discordType"], 2);
        assert_eq!(ch["kind"], "voice");
        assert!(ch.get("private").is_none());
        assert!(ch.get("topic").is_none());
        assert_eq!(v["roles"][0]["permissions"], perm::ADMIN_ALL.to_string());
        assert_eq!(v["skipped"][0]["kind"], "feature");
    }

    /// A row as the TypeScript portal stored it, mid-import.
    const TS_ROW: &str = r#"{
      "guild": {"id": "100", "name": "Test Fleet", "description": "hello", "iconUrl": "https://cdn.discordapp.com/icons/100/abc.png?size=512"},
      "communityName": "Test Fleet",
      "memberCount": 12,
      "historyAllowed": true,
      "emojis": [{"id": "7", "name": "wave", "animated": false}],
      "channels": [
        {"discordId": "1", "discordType": 0, "name": "mods", "private": true, "accessRoleIdHex": "aa", "keySealed": "bb",
         "accessRolePublishedAt": 1790190000000, "bridgeable": true, "botMissingWebhook": true, "bridge": false,
         "selected": true, "history": false, "historyImported": 3, "historyCursor": "99", "historyDoneAt": 1790190000001,
         "channelIdHex": "cc", "publishedAt": 1790190000002, "bridgeId": "b-1", "bridgeSkipped": "already bridged"}
      ],
      "roles": [{"discordId": "2", "name": "Chief", "color": 16711680, "position": 2, "permissions": "1023", "dropped": [], "roleIdHex": "dd", "publishedAt": 1}],
      "skipped": [{"kind": "role", "name": "Some Bot", "reason": "managed role (bot/integration/booster)"}],
      "relays": ["wss://relay.ditto.pub"],
      "adminPkHex": "ee",
      "checkpoints": {
        "communityIdHex": "c1", "ownerPkHex": "o1", "opPkHex": "p1", "adminRoleIdHex": "a1", "grantHashHex": "g1",
        "ownerTemplates": [{"purpose": "op-grant", "template": {"kind": 34550, "content": "x", "tags": [["d", "y"]], "created_at": 1790190000}}],
        "ownerSignedSeals": [{"kind": 34550, "content": "x", "tags": [], "created_at": 1790190000, "pubkey": "pk", "id": "id", "sig": "sig"}],
        "ownerRolePublishedAt": 1, "ownerGrantPublishedAt": 2, "ownerRegistryPublishedAt": 3, "ownerJoinPublishedAt": 4,
        "ownerControlKeyPublishedAt": 5,
        "iconPointer": {"url": "https://b.example/x", "key": "k", "nonce": "n", "hash": "h"},
        "assetsAt": 6, "assetsError": "banner: 404", "metadataPublishedAt": 7, "opJoinPublishedAt": 8,
        "profilePublishedAt": 9, "inviteLinkSignerPk": "ls", "invitePublishedAt": 10,
        "ownerChannelKeysSentAt": 11, "ownerChannelKeysError": "relay down",
        "emojiPackAddress": "30030:p1:discord-import", "emojiPackPublishedAt": 12
      }
    }"#;

    #[test]
    fn round_trips_a_row_the_typescript_portal_stored() {
        let original: serde_json::Value = serde_json::from_str(TS_ROW).unwrap();
        let plan: ImportPlan = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(plan.roles[0].permissions, 1023);
        assert_eq!(plan.checkpoints.owner_templates.as_ref().unwrap()[0].purpose, OwnerSignPurpose::OpGrant);
        assert_eq!(plan.checkpoints.icon_pointer.as_ref().unwrap().nonce, "n");
        assert_eq!(serde_json::to_value(&plan).unwrap(), original);
    }

    #[test]
    fn parses_older_rows_missing_later_fields_and_ignores_unknown_ones() {
        let plan: ImportPlan = serde_json::from_str(
            r#"{"guild": {"id": "1", "name": "g"}, "communityName": "g",
                "channels": [{"discordId": "5", "name": "general", "somethingNew": 1}],
                "roles": [], "skipped": [], "checkpoints": {}}"#,
        )
        .unwrap();
        assert!(plan.emojis.is_empty() && plan.relays.is_empty() && !plan.history_allowed);
        assert!(!plan.channels[0].selected && plan.channels[0].private.is_none());
    }
}

#[cfg(test)]
mod unknown_fields {
    use super::*;

    #[test]
    fn a_resave_keeps_fields_this_version_does_not_know() {
        let raw = serde_json::json!({
            "guild": { "id": "1", "name": "g" }, "communityName": "g", "historyAllowed": false,
            "emojis": [], "channels": [], "roles": [], "skipped": [], "relays": [],
            "checkpoints": { "futureStepAt": 5 }, "futurePlanField": true,
        });
        let plan: ImportPlan = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(serde_json::to_value(&plan).unwrap()["checkpoints"]["futureStepAt"], 5);
        assert_eq!(serde_json::to_value(&plan).unwrap()["futurePlanField"], true);
    }
}
