//! Minimal Discord REST helpers for the portal: OAuth exchange (user side)
//! and bot-token lookups (guild presence, channel lists). No gateway here;
//! the BridgeManager owns the gateway connection.

use std::time::Duration;

use anyhow::{Context, bail};
use bridge::types::{DiscordAttachmentIn, DiscordInboundMessage, DiscordMentionIn, DiscordUserRef, EmbedIn};
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const API: &str = "https://discord.com/api/v10";

/// Manage Webhooks + View Channel + Send Messages + Read History + Add Reactions + Manage Messages.
pub const BOT_PERMISSIONS: &str = "536947776";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscordUser {
    pub id: String,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthGuild {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    pub permissions: String,
}

const MANAGE_GUILD: u64 = 1 << 5;
const ADMINISTRATOR: u64 = 1 << 3;

pub fn can_manage(guild: &OAuthGuild) -> bool {
    let bits: u64 = guild.permissions.parse().unwrap_or(0);
    bits & MANAGE_GUILD != 0 || bits & ADMINISTRATOR != 0
}

fn query(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new()).extend_pairs(pairs).finish()
}

pub fn oauth_url(client_id: &str, redirect_uri: &str, state: &str) -> String {
    let q = query(&[
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        // `guilds.members.read` is deliberately absent: the only thing that ever
        // needed a member's roles was the claim feature, and asking for a scope
        // nothing spends is a consent screen users are right to distrust.
        ("scope", "identify guilds"),
        ("state", state),
    ]);
    format!("{API}/oauth2/authorize?{q}")
}

pub fn bot_install_url(client_id: &str, guild_id: &str) -> String {
    let q = query(&[("client_id", client_id), ("scope", "bot"), ("permissions", BOT_PERMISSIONS), ("guild_id", guild_id)]);
    format!("https://discord.com/oauth2/authorize?{q}")
}

/// Longest single 429 wait we honor; Discord's global bans can claim hours.
const MAX_RATELIMIT_WAIT_MS: f64 = 60_000.0;
/// Total 429 waiting per request before giving up and surfacing the 429.
const RATELIMIT_BUDGET_MS: f64 = 5.0 * 60_000.0;

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct GuildChannel {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type")]
    pub kind: u32,
    #[serde(default)]
    pub position: i64,
}

// ── Full-guild snapshot (server import) ─────────────────────────────────────

/// One channel permission overwrite: role (type 0) or member (type 1).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelOverwrite {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: u32,
    #[serde(default)]
    pub allow: String,
    #[serde(default)]
    pub deny: String,
}

/// A guild channel with everything the import mapper reads.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotChannel {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type")]
    pub kind: u32,
    #[serde(default)]
    pub position: i64,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub topic: Option<String>,
    #[serde(default)]
    pub permission_overwrites: Vec<ChannelOverwrite>,
}

/// A guild role as returned inline on the guild object.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRole {
    pub id: String,
    pub name: String,
    pub permissions: String,
    #[serde(default)]
    pub color: u32,
    #[serde(default)]
    pub hoist: bool,
    #[serde(default)]
    pub position: i64,
    #[serde(default)]
    pub managed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotEmoji {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub animated: Option<bool>,
    #[serde(default)]
    pub managed: Option<bool>,
    #[serde(default)]
    pub available: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotGuild {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub banner: Option<String>,
    #[serde(default)]
    pub splash: Option<String>,
    #[serde(default)]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub approximate_member_count: Option<u64>,
    #[serde(default)]
    pub roles: Vec<SnapshotRole>,
    #[serde(default)]
    pub emojis: Vec<SnapshotEmoji>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuildSnapshot {
    pub guild: SnapshotGuild,
    pub channels: Vec<SnapshotChannel>,
}

// ── Message history (server import backfill) ─────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct RestAuthor {
    pub id: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub global_name: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(default)]
    pub bot: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct RestAttachment {
    pub url: String,
    #[serde(default)]
    pub filename: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct RestMediaRef {
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct RestEmbed {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub video: Option<RestMediaRef>,
    #[serde(default)]
    pub image: Option<RestMediaRef>,
    #[serde(default)]
    pub thumbnail: Option<RestMediaRef>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct RestMention {
    pub id: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub global_name: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct RestMessageReference {
    #[serde(default)]
    pub message_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct RestMessage {
    pub id: String,
    /// 0 = DEFAULT, 19 = REPLY; everything else is a system message.
    #[serde(rename = "type")]
    pub kind: u32,
    #[serde(default)]
    pub content: Option<String>,
    pub timestamp: String,
    pub author: RestAuthor,
    #[serde(default)]
    pub attachments: Vec<RestAttachment>,
    #[serde(default)]
    pub embeds: Vec<RestEmbed>,
    #[serde(default)]
    pub mentions: Vec<RestMention>,
    #[serde(default)]
    pub message_reference: Option<RestMessageReference>,
    #[serde(default)]
    pub webhook_id: Option<String>,
    #[serde(default)]
    pub application_id: Option<String>,
}

/// A response whose body has been read: the 429 loop has to read a body to
/// learn how long to wait, so every response leaves it in this shape.
struct Fetched {
    status: StatusCode,
    body: Vec<u8>,
}

impl Fetched {
    fn json<T: DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        serde_json::from_slice(&self.body).with_context(|| format!("discord {path}: unexpected response body"))
    }
}

/// Discord ids are snowflakes. Interpolating anything else into a request path
/// would let a crafted id (`../users/@me`) steer an authenticated bot request
/// at a route the caller never meant to touch.
fn snowflake(id: &str) -> anyhow::Result<&str> {
    if id.is_empty() || id.len() > 20 || !id.bytes().all(|b| b.is_ascii_digit()) {
        bail!("not a Discord id: {id:?}");
    }
    Ok(id)
}

/// The Discord REST client. `api` is injectable so tests can serve it locally.
#[derive(Clone, Debug)]
pub struct DiscordRest {
    pub http: reqwest::Client,
    pub api: String,
}

impl Default for DiscordRest {
    fn default() -> Self {
        DiscordRest::new()
    }
}

impl DiscordRest {
    pub fn new() -> DiscordRest {
        DiscordRest::with_api(API)
    }

    pub fn with_api(api: impl Into<String>) -> DiscordRest {
        DiscordRest { http: reqwest::Client::new(), api: api.into().trim_end_matches('/').to_owned() }
    }

    pub async fn exchange_code(
        &self,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        code: &str,
    ) -> anyhow::Result<String> {
        #[derive(Deserialize)]
        struct Token {
            access_token: String,
        }
        let res = self
            .http
            .post(format!("{}/oauth2/token", self.api))
            .form(&[
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("grant_type", "authorization_code"),
                ("redirect_uri", redirect_uri),
                ("code", code),
            ])
            .send()
            .await?;
        if !res.status().is_success() {
            bail!("oauth token exchange failed: {}", res.status().as_u16());
        }
        Ok(res.json::<Token>().await?.access_token)
    }

    /// GET that waits out Discord 429s instead of failing: sleeps for the
    /// `retry_after` the API reports (JSON body, falling back to the Retry-After
    /// header) and retries, until the per-request budget runs out. History
    /// backfill pages one route hundreds of times, so rate limits here are
    /// routine, and imports used to die on the first one.
    async fn discord_fetch(&self, path: &str, query: &[(&str, &str)], authorization: &str) -> anyhow::Result<Fetched> {
        let mut waited_ms = 0.0;
        loop {
            let res = self
                .http
                .get(format!("{}{path}", self.api))
                .query(query)
                .header(reqwest::header::AUTHORIZATION, authorization)
                .send()
                .await?;
            let status = res.status();
            let header_secs = res
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<f64>().ok());
            let body = res.bytes().await?.to_vec();
            if status != StatusCode::TOO_MANY_REQUESTS {
                return Ok(Fetched { status, body });
            }
            // A non-JSON 429 (Cloudflare) leaves the header value standing.
            let body_secs = serde_json::from_slice::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("retry_after").and_then(serde_json::Value::as_f64));
            let mut retry_after_ms = body_secs.or(header_secs).map_or(f64::NAN, |s| s * 1000.0);
            if !retry_after_ms.is_finite() || retry_after_ms <= 0.0 {
                retry_after_ms = 5_000.0;
            }
            retry_after_ms = retry_after_ms.min(MAX_RATELIMIT_WAIT_MS);
            if waited_ms + retry_after_ms > RATELIMIT_BUDGET_MS {
                return Ok(Fetched { status, body });
            }
            waited_ms += retry_after_ms;
            tokio::time::sleep(Duration::from_secs_f64(retry_after_ms / 1000.0)).await;
        }
    }

    async fn user_get<T: DeserializeOwned>(&self, access_token: &str, path: &str) -> anyhow::Result<T> {
        let res = self.discord_fetch(path, &[], &format!("Bearer {access_token}")).await?;
        if !res.status.is_success() {
            bail!("discord {path} failed: {}", res.status.as_u16());
        }
        res.json(path)
    }

    pub async fn fetch_me(&self, access_token: &str) -> anyhow::Result<DiscordUser> {
        self.user_get(access_token, "/users/@me").await
    }

    pub async fn fetch_my_guilds(&self, access_token: &str) -> anyhow::Result<Vec<OAuthGuild>> {
        self.user_get(access_token, "/users/@me/guilds").await
    }

    async fn bot_get<T: DeserializeOwned>(
        &self,
        bot_token: &str,
        path: &str,
        query: &[(&str, &str)],
    ) -> anyhow::Result<Option<T>> {
        let res = self.discord_fetch(path, query, &format!("Bot {bot_token}")).await?;
        if res.status == StatusCode::FORBIDDEN || res.status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !res.status.is_success() {
            bail!("discord bot {path} failed: {}", res.status.as_u16());
        }
        res.json(path).map(Some)
    }

    /// Whether the bot can manage webhooks in a channel — the permission the live
    /// bridge needs to mirror Armada messages into Discord as personas. A 403 is
    /// the bot lacking it; anything else (200, or a 404 for a channel that has
    /// since gone) is not flagged here, so the import preview only warns on a
    /// genuine permission gap.
    pub async fn bot_can_manage_webhooks(&self, bot_token: &str, channel_id: &str) -> anyhow::Result<bool> {
        let path = format!("/channels/{}/webhooks", snowflake(channel_id)?);
        let res = self.discord_fetch(&path, &[], &format!("Bot {bot_token}")).await?;
        Ok(res.status != StatusCode::FORBIDDEN)
    }

    /// Text channels of a guild, or None when the bot is not a member yet.
    pub async fn bot_guild_text_channels(
        &self,
        bot_token: &str,
        guild_id: &str,
    ) -> anyhow::Result<Option<Vec<GuildChannel>>> {
        let path = format!("/guilds/{}/channels", snowflake(guild_id)?);
        let Some(channels) = self.bot_get::<Vec<GuildChannel>>(bot_token, &path, &[]).await? else {
            return Ok(None);
        };
        let mut text: Vec<GuildChannel> = channels.into_iter().filter(|c| c.kind == 0).collect();
        text.sort_by_key(|c| c.position);
        Ok(Some(text))
    }

    /// Read a guild's full structure (settings, roles, channels with overwrites)
    /// with the bot token. None when the bot is not installed in the guild.
    /// Two REST calls; roles, emojis, and member counts arrive inline.
    pub async fn bot_guild_snapshot(&self, bot_token: &str, guild_id: &str) -> anyhow::Result<Option<GuildSnapshot>> {
        let guild_id = snowflake(guild_id)?;
        let guild_path = format!("/guilds/{guild_id}");
        let Some(guild) = self.bot_get(bot_token, &guild_path, &[("with_counts", "true")]).await? else {
            return Ok(None);
        };
        let Some(channels) = self.bot_get(bot_token, &format!("{guild_path}/channels"), &[]).await? else {
            return Ok(None);
        };
        Ok(Some(GuildSnapshot { guild, channels }))
    }

    /// One page of channel history, NEWEST first, strictly before `before_id`
    /// (None for the newest page). Empty when the channel has no more; None
    /// when the bot cannot read the channel.
    pub async fn bot_channel_messages_before(
        &self,
        bot_token: &str,
        channel_id: &str,
        before_id: Option<&str>,
        limit: u32,
    ) -> anyhow::Result<Option<Vec<RestMessage>>> {
        let path = format!("/channels/{}/messages", snowflake(channel_id)?);
        let limit = limit.to_string();
        let mut q = vec![("limit", limit.as_str())];
        if let Some(before) = before_id.filter(|b| !b.is_empty()) {
            q.push(("before", before));
        }
        self.bot_get(bot_token, &path, &q).await
    }

    /// One page of channel history strictly AFTER `after_id`: the oldest `limit`
    /// messages past it, NEWEST first like every history page (so the next page
    /// is after this page's first id). None when the bot cannot read the
    /// channel.
    pub async fn bot_channel_messages_after(
        &self,
        bot_token: &str,
        channel_id: &str,
        after_id: &str,
        limit: u32,
    ) -> anyhow::Result<Option<Vec<RestMessage>>> {
        let path = format!("/channels/{}/messages", snowflake(channel_id)?);
        let limit = limit.to_string();
        self.bot_get(bot_token, &path, &[("limit", limit.as_str()), ("after", after_id)]).await
    }
}

/// A REST history message -> the router's inbound shape (same as gateway).
pub fn rest_to_inbound(message: &RestMessage, guild_id: &str, channel_id: &str) -> DiscordInboundMessage {
    let author = &message.author;
    DiscordInboundMessage {
        id: message.id.clone(),
        channel_id: channel_id.to_owned(),
        guild_id: guild_id.to_owned(),
        content: message.content.clone().unwrap_or_default(),
        author: DiscordUserRef {
            id: author.id.clone(),
            display: display_name(author.global_name.as_deref(), &author.username),
            avatar_url: author
                .avatar
                .as_deref()
                .filter(|a| !a.is_empty())
                .map(|a| format!("https://cdn.discordapp.com/avatars/{}/{a}.png", author.id)),
            bot: author.bot == Some(true),
        },
        webhook_id: message.webhook_id.clone(),
        application_id: message.application_id.clone(),
        referenced_message_id: message.message_reference.as_ref().and_then(|r| r.message_id.clone()),
        timestamp_ms: parse_timestamp_ms(&message.timestamp).and_then(|ms| u64::try_from(ms).ok()),
        attachments: message
            .attachments
            .iter()
            .map(|a| DiscordAttachmentIn { url: a.url.clone(), filename: Some(a.filename.clone()) })
            .collect(),
        embeds: message
            .embeds
            .iter()
            .map(|e| EmbedIn {
                url: e.url.clone(),
                media_url: [&e.video, &e.image, &e.thumbnail]
                    .into_iter()
                    .find_map(|m| m.as_ref().and_then(|m| m.url.clone())),
            })
            .collect(),
        mentions: message
            .mentions
            .iter()
            .map(|m| DiscordMentionIn { id: m.id.clone(), display: display_name(m.global_name.as_deref(), &m.username) })
            .collect(),
        ..DiscordInboundMessage::default()
    }
}

/// `global_name || username`: an empty global name falls through too.
fn display_name(global_name: Option<&str>, username: &str) -> String {
    global_name.filter(|g| !g.is_empty()).unwrap_or(username).to_owned()
}

/// Epoch ms of an ISO 8601 / RFC 3339 timestamp, as Discord sends them
/// (`2026-09-23T19:00:00.123000+00:00`), or a bare `YYYY-MM-DD` (midnight
/// UTC). A date-time without an offset is read as UTC — JavaScript's
/// `Date.parse` would read it as host-local time, which is a guess no server
/// should be making. Fractional seconds past milliseconds are truncated.
pub fn parse_timestamp_ms(s: &str) -> Option<i64> {
    let b = s.trim().as_bytes();
    let num = |range: std::ops::Range<usize>| -> Option<i64> {
        let digits = b.get(range)?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(digits).ok()?.parse().ok()
    };
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    if b.len() == 10 {
        return Some(days * 86_400_000);
    }

    if !matches!(b[10], b'T' | b't' | b' ') || b.len() < 16 || b[13] != b':' {
        return None;
    }
    let (hour, minute) = (num(11..13)?, num(14..16)?);
    let mut i = 16;
    let mut second = 0;
    let mut millis = 0;
    if b.get(i) == Some(&b':') {
        second = num(i + 1..i + 3)?;
        i += 3;
        if b.get(i) == Some(&b'.') {
            let start = i + 1;
            i = start;
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            if i == start {
                return None;
            }
            let frac = &b[start..i.min(start + 3)];
            millis = frac.iter().fold(0, |acc, d| acc * 10 + i64::from(d - b'0')) * 10_i64.pow(3 - frac.len() as u32);
        }
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let offset_min = match b.get(i) {
        None => 0,
        Some(b'Z' | b'z') if i + 1 == b.len() => 0,
        Some(&sign @ (b'+' | b'-')) if b.len() == i + 6 && b[i + 3] == b':' => {
            let (oh, om) = (num(i + 1..i + 3)?, num(i + 4..i + 6)?);
            if oh > 23 || om > 59 {
                return None;
            }
            let off = oh * 60 + om;
            if sign == b'-' { -off } else { off }
        }
        _ => return None,
    };
    let local = days * 86_400_000 + ((hour * 60 + minute) * 60 + second) * 1000 + millis;
    Some(local - offset_min * 60_000)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::extract::{Query, State};
    use axum::http::{HeaderMap, StatusCode as AxStatus};
    use axum::routing::get;

    use super::*;

    #[test]
    fn can_manage_needs_manage_guild_or_administrator() {
        let guild = |p: &str| OAuthGuild { permissions: p.into(), ..OAuthGuild::default() };
        assert!(can_manage(&guild("32")));
        assert!(can_manage(&guild("8")));
        assert!(can_manage(&guild(&((1u64 << 40) | 8).to_string())));
        assert!(!can_manage(&guild("16")));
        assert!(!can_manage(&guild("garbage")));
    }

    #[test]
    fn builds_encoded_authorize_urls() {
        let url = oauth_url("123", "https://p.example/cb?x=1", "s&t");
        assert_eq!(
            url,
            "https://discord.com/api/v10/oauth2/authorize?client_id=123&redirect_uri=https%3A%2F%2Fp.example%2Fcb%3Fx%3D1\
             &response_type=code&scope=identify+guilds&state=s%26t"
        );
        assert_eq!(
            bot_install_url("123", "456"),
            "https://discord.com/oauth2/authorize?client_id=123&scope=bot&permissions=536947776&guild_id=456"
        );
    }

    #[test]
    fn parses_discord_and_iso_timestamps() {
        assert_eq!(parse_timestamp_ms("2026-09-23"), Some(1_790_121_600_000));
        assert_eq!(parse_timestamp_ms("2026-09-23T19:00:00.123+02:00"), Some(1_790_182_800_123));
        assert_eq!(parse_timestamp_ms("2026-09-23T17:00:00.123000+00:00"), Some(1_790_182_800_123));
        assert_eq!(parse_timestamp_ms("2026-09-23T17:00:00.1Z"), Some(1_790_182_800_100));
        assert_eq!(parse_timestamp_ms("2026-09-23T12:00:00-05:00"), Some(1_790_182_800_000));
        assert_eq!(parse_timestamp_ms("2026-09-23T17:00Z"), Some(1_790_182_800_000));
        assert_eq!(parse_timestamp_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_timestamp_ms("2024-02-29"), Some(1_709_164_800_000));
        for bad in ["", "2026-02-29", "2026-13-01", "2026-09-23T24:00:00Z", "2026-09-23T10:00:00.Z", "2026-09-23Tx", "soon"] {
            assert_eq!(parse_timestamp_ms(bad), None, "{bad}");
        }
    }

    #[test]
    fn converts_rest_messages_to_router_shape() {
        let message: RestMessage = serde_json::from_value(serde_json::json!({
            "id": "5", "type": 19, "content": "hi", "timestamp": "2026-09-23T17:00:00.123000+00:00",
            "author": {"id": "42", "username": "user", "global_name": "", "avatar": "av", "bot": true},
            "attachments": [{"url": "https://cdn/x.png", "filename": "x.png", "size": 3}],
            "embeds": [{"url": "https://tenor/x", "image": {"url": "https://img"}, "thumbnail": {"url": "https://thumb"}}],
            "mentions": [{"id": "7", "username": "bob", "global_name": "Bob"}],
            "message_reference": {"message_id": "4"},
            "application_id": null
        }))
        .unwrap();
        let inbound = rest_to_inbound(&message, "1", "2");
        assert_eq!(inbound.guild_id, "1");
        assert_eq!(inbound.channel_id, "2");
        assert_eq!(inbound.author.display, "user"); // empty global name falls through
        assert_eq!(inbound.author.avatar_url.as_deref(), Some("https://cdn.discordapp.com/avatars/42/av.png"));
        assert!(inbound.author.bot);
        assert_eq!(inbound.timestamp_ms, Some(1_790_182_800_123));
        assert_eq!(inbound.referenced_message_id.as_deref(), Some("4"));
        assert_eq!(inbound.application_id, None);
        assert_eq!(inbound.attachments[0].filename.as_deref(), Some("x.png"));
        assert_eq!(inbound.embeds[0].media_url.as_deref(), Some("https://img"));
        assert_eq!(inbound.mentions[0].display, "Bob");
    }

    async fn serve(router: Router) -> DiscordRest {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        DiscordRest::with_api(format!("http://{addr}"))
    }

    #[tokio::test]
    async fn waits_out_429s_then_returns_the_page() {
        let hits = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .route(
                "/channels/{id}/messages",
                get(|State(hits): State<Arc<AtomicUsize>>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>| async move {
                    assert_eq!(headers["authorization"], "Bot tok");
                    match hits.fetch_add(1, Ordering::SeqCst) {
                        0 => (AxStatus::TOO_MANY_REQUESTS, [("retry-after", "30")], r#"{"retry_after": 0.01}"#.to_owned()),
                        // A non-JSON 429 (Cloudflare): the header stands.
                        1 => (AxStatus::TOO_MANY_REQUESTS, [("retry-after", "0.02")], "cloudflare says no".to_owned()),
                        _ => {
                            assert_eq!(q["limit"], "50");
                            assert_eq!(q["after"], "10");
                            let page = r#"[{"id":"11","type":0,"content":"x","timestamp":"2026-09-23T17:00:00Z","author":{"id":"1","username":"u"}}]"#;
                            (AxStatus::OK, [("x-ok", "1")], page.to_owned())
                        }
                    }
                }),
            )
            .with_state(hits.clone());
        let rest = serve(router).await;
        let started = std::time::Instant::now();
        let page = rest.bot_channel_messages_after("tok", "2", "10", 50).await.unwrap().unwrap();
        assert_eq!(page[0].id, "11");
        assert_eq!(hits.load(Ordering::SeqCst), 3);
        // The body's retry_after won over the header's 30 s.
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn treats_403_and_404_as_absent_and_other_failures_as_errors() {
        let router = Router::new()
            .route("/guilds/1/channels", get(|| async { AxStatus::FORBIDDEN }))
            .route("/guilds/2/channels", get(|| async { AxStatus::NOT_FOUND }))
            .route("/guilds/3/channels", get(|| async { AxStatus::INTERNAL_SERVER_ERROR }))
            .route(
                "/guilds/4/channels",
                get(|| async {
                    r#"[{"id":"a","name":"b","type":0,"position":2},{"id":"c","name":"d","type":2,"position":0},
                        {"id":"e","name":"f","type":0,"position":1}]"#
                }),
            )
            .route("/channels/5/webhooks", get(|| async { AxStatus::FORBIDDEN }))
            .route("/channels/6/webhooks", get(|| async { AxStatus::NOT_FOUND }));
        let rest = serve(router).await;
        assert_eq!(rest.bot_guild_text_channels("t", "1").await.unwrap(), None);
        assert_eq!(rest.bot_guild_text_channels("t", "2").await.unwrap(), None);
        assert!(rest.bot_guild_text_channels("t", "3").await.is_err());
        let text = rest.bot_guild_text_channels("t", "4").await.unwrap().unwrap();
        assert_eq!(text.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), ["e", "a"]);
        assert!(!rest.bot_can_manage_webhooks("t", "5").await.unwrap());
        assert!(rest.bot_can_manage_webhooks("t", "6").await.unwrap());
    }

    #[tokio::test]
    async fn refuses_ids_that_are_not_snowflakes() {
        let rest = DiscordRest::with_api("http://127.0.0.1:9");
        assert!(rest.bot_guild_snapshot("t", "../users/@me").await.is_err());
        assert!(rest.bot_channel_messages_before("t", "1/../2", None, 100).await.is_err());
    }
}
