//! The transport-agnostic shapes the router speaks: Discord events as the
//! gateway or REST history delivers them, and the mapping rows that tie a
//! Discord message to a Concord rumor. Twilight types never cross into the
//! router; the adapter converts at the edge.

use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelLink {
    pub discord_guild_id: String,
    pub discord_channel_id: String,
    pub community_id: String,
    pub concord_channel_id_hex: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscordUserRef {
    pub id: String,
    /// Server nickname if known, else the global display name, else the username.
    pub display: String,
    pub avatar_url: Option<String>,
    pub bot: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscordAttachmentIn {
    pub url: String,
    pub filename: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscordMentionIn {
    pub id: String,
    pub display: String,
}

/// An unfurled embed; GIF-picker messages hide the real media URL here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EmbedIn {
    pub url: Option<String>,
    pub media_url: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscordInboundMessage {
    pub id: String,
    pub channel_id: String,
    pub guild_id: String,
    pub author: DiscordUserRef,
    pub content: String,
    pub attachments: Vec<DiscordAttachmentIn>,
    pub mentions: Vec<DiscordMentionIn>,
    /// Channel id -> name, for `<#id>` mentions.
    pub channel_names: HashMap<String, String>,
    pub embeds: Vec<EmbedIn>,
    pub webhook_id: Option<String>,
    pub application_id: Option<String>,
    /// message_reference: the Discord message this one replies to.
    pub referenced_message_id: Option<String>,
    /// Original send time (epoch ms). Live gateway traffic omits it (now);
    /// history backfill sets it so the rumor carries the historical timestamp.
    pub timestamp_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscordMessageDelete {
    pub id: String,
    pub channel_id: String,
    pub guild_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscordEmoji {
    /// Unicode emoji have only a name; custom emoji carry an id.
    pub name: Option<String>,
    pub id: Option<String>,
    pub animated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscordReaction {
    pub message_id: String,
    pub channel_id: String,
    pub guild_id: String,
    pub emoji: DiscordEmoji,
    pub user: DiscordUserRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Discord,
    Concord,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Discord => "discord",
            Origin::Concord => "concord",
        }
    }

    pub fn parse(s: &str) -> Option<Origin> {
        match s {
            "discord" => Some(Origin::Discord),
            "concord" => Some(Origin::Concord),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageMappingRow {
    pub discord_message_id: String,
    pub discord_channel_id: String,
    pub concord_rumor_id: String,
    pub concord_channel_id: String,
    pub community_id: String,
    pub origin: Origin,
    /// Discord user id (discord origin) or Concord pubkey hex (concord origin).
    pub author_ref: String,
    pub part_index: i32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReactionMappingRow {
    /// The kind 7 rumor id.
    pub rumor_id: String,
    /// The Discord message the reaction sits on.
    pub discord_message_id: String,
    /// Unicode emoji as-is, or `name:id` for a custom one (what the bot reacts with).
    pub emoji: String,
    pub origin: Origin,
    /// Discord user id or Concord pubkey of the reactor.
    pub author_ref: String,
}
