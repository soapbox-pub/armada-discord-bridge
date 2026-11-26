//! The Role Discord members are given on Armada (`bridge::auto_role`): its
//! setting per (community, Discord server), the `/bridge role` command that
//! sets it, and the admitter routers ask to grant it.
//!
//! The portal mints an npub per bridged channel, so a community may hold
//! several bridge identities. Whichever of them holds Manage roles above the
//! Role signs the Grant; an admin gives that permission to any one of them.

use std::collections::HashSet;
use std::sync::{Arc, LazyLock, Mutex, Weak};

use async_trait::async_trait;
use bridge::auto_role::{Admit, RoleSetting, bridged_role_in, explain};
use bridge::client::{ConcordClient, OpenedChat, SendChat, now_ms};
use bridge::puppets::derive_puppet;
use bridge::types::ChannelLink;
use concord::grant::{is_plain, may_grant, role_named};
use concord::roles::{Role, perm};
use nostr::nips::nip19::ToBech32;
use nostr::prelude::PublicKey;
use regex::Regex;

use super::{BridgeManager, Running, lock};
use crate::seal::unseal;

pub static ROLE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^/bridge role(?:\s+(.+))?$").unwrap());

/// Commands only run live: a catch-up replays a little history.
const COMMAND_MAX_AGE_MS: u64 = 10 * 60_000;
/// How far back `/bridge role <name>` reaches for members already posting.
const BACKFILL_DAYS: i32 = 30;
/// At most this many Grants for members already posting, per setting.
const BACKFILL_MAX: i64 = 500;

/// Gives puppets the bridged Role for the routers of one portal.
pub struct RoleAdmitter {
    pub manager: Weak<BridgeManager>,
    /// (puppet, Role) pairs a Grant was published for, or failed, this run.
    tried: Mutex<HashSet<String>>,
}

impl RoleAdmitter {
    pub fn new(manager: Weak<BridgeManager>) -> RoleAdmitter {
        RoleAdmitter { manager, tried: Mutex::default() }
    }
}

#[async_trait]
impl Admit for RoleAdmitter {
    async fn admit(&self, link: &ChannelLink, puppet_pk: &str) -> Option<String> {
        let m = self.manager.upgrade()?;
        let setting = m.role_setting(&link.community_id, &link.discord_guild_id).await.ok()?;
        let clients = m.community_clients(&link.community_id, &link.discord_channel_id);
        let f = clients.first()?.folded()?;
        let role = bridged_role_in(&f, &setting)?;
        if f.roster.roles_of(puppet_pk).any(|r| r.role_id == role.role_id) {
            return Some(role.name);
        }
        // Only a Role that lets members view and post in this channel is worth
        // a Grant here: one per Discord member is a Control Plane edition each.
        if f.ranked {
            let private = f.channels.get(&link.concord_channel_id_hex).is_some_and(|c| c.private);
            let lets = f.roster.role_channel_permissions(&role, &link.concord_channel_id_hex, private);
            if lets & (perm::VIEW_CHANNEL | perm::SEND_MESSAGES) != perm::VIEW_CHANNEL | perm::SEND_MESSAGES {
                return None;
            }
        }
        m.grant_with_any(&clients, puppet_pk, &role, &self.tried).await.then_some(role.name)
    }
}

impl BridgeManager {
    /// The setting for a (community, Discord server) pairing.
    pub(super) async fn role_setting(&self, community_id: &str, guild_id: &str) -> anyhow::Result<RoleSetting> {
        let row = self
            .pool
            .get()
            .await?
            .query_opt("SELECT bridged_role FROM guild_community_secrets WHERE community_id = $1 AND discord_guild_id = $2", &[&community_id, &guild_id])
            .await?;
        Ok(RoleSetting::from_column(row.and_then(|r| r.get(0))))
    }

    async fn set_role_setting(&self, community_id: &str, guild_id: &str, setting: &RoleSetting) -> anyhow::Result<()> {
        self.pool
            .get()
            .await?
            .execute(
                "UPDATE guild_community_secrets SET bridged_role = $3 WHERE community_id = $1 AND discord_guild_id = $2",
                &[&community_id, &guild_id, &setting.to_column()],
            )
            .await?;
        Ok(())
    }

    /// Every running bridge's client in a community, the one bridging
    /// `discord_channel_id` first: any of them may sign a Grant there.
    pub(super) fn community_clients(&self, community_id: &str, discord_channel_id: &str) -> Vec<Arc<ConcordClient>> {
        let mut bridges: Vec<Arc<Running>> = lock(&self.running).values().filter(|rb| rb.link.community_id == community_id).cloned().collect();
        bridges.sort_by_key(|rb| rb.link.discord_channel_id != discord_channel_id);
        bridges.into_iter().map(|rb| rb.client.clone()).collect()
    }

    /// Grant `role` to `member` with the first client that may. True when a
    /// Grant was published. A Grant is tried once per (member, Role) per run;
    /// when none of the bridges may make it yet, it is tried again later.
    async fn grant_with_any(&self, clients: &[Arc<ConcordClient>], member: &str, role: &Role, tried: &Mutex<HashSet<String>>) -> bool {
        let key = format!("{member}:{}", role.role_id);
        if !lock(tried).insert(key.clone()) {
            return false;
        }
        for client in clients {
            client.take_staff_key();
            if client.grant_blocked(role).is_some() {
                continue;
            }
            return match client.grant_role(member, role).await {
                Ok(()) => {
                    tracing::info!(member = %&member[..8], role = %role.name, "gave a Discord member the bridged role");
                    true
                }
                Err(error) => {
                    tracing::warn!(member = %&member[..8], role = %role.name, error = %format!("{error:#}"), "couldn't give a Discord member the bridged role");
                    false
                }
            };
        }
        lock(tried).remove(&key);
        false
    }

    /// `/bridge role [<name> | off | auto]` in an active bridge's Armada
    /// channel. True when the message was one, answered or not.
    pub(super) async fn on_role_command(&self, rb: &Arc<Running>, chat: &OpenedChat) -> bool {
        if chat.kind() != concord::kinds::MESSAGE {
            return false;
        }
        let Some(captures) = ROLE_RE.captures(chat.content().trim()) else { return false };
        if now_ms().saturating_sub(chat.ms) > COMMAND_MAX_AGE_MS {
            return true;
        }
        let arg = captures.get(1).map(|m| m.as_str().trim().to_owned()).unwrap_or_default();
        let reply = match self.role_command(rb, chat.author(), &arg).await {
            Ok(reply) => reply,
            Err(error) => format!("Couldn't change the bridged role: {error:#}"),
        };
        let _ = rb.client.send_chat(&rb.channel(), SendChat::message(rb.primary(), reply)).await;
        true
    }

    async fn role_command(&self, rb: &Arc<Running>, author: &str, arg: &str) -> anyhow::Result<String> {
        let link = &rb.link;
        let f = rb.client.folded().ok_or_else(|| anyhow::anyhow!("the community isn't folded yet"))?;
        let npub = PublicKey::from_hex(&rb.client.primary_pk()).ok().and_then(|pk| pk.to_bech32().ok()).unwrap_or_default();
        let fallback = bridge::auto_role::FALLBACK_NAMES.iter().map(|n| format!("“{n}”")).collect::<Vec<_>>().join(" or ");
        let clients = self.community_clients(&link.community_id, &link.discord_channel_id);
        let describe = |setting: &RoleSetting| -> String {
            match (bridged_role_in(&f, setting), setting) {
                (None, RoleSetting::Off) => "Discord members aren't given a Role. /bridge role <name> gives them one.".into(),
                (None, RoleSetting::Auto) => format!("Discord members aren't given a Role: none is set, and there's no plain Role named {fallback}. /bridge role <name> sets one."),
                (None, RoleSetting::Role(_)) => "The Role set for Discord members no longer exists. /bridge role <name> sets another.".into(),
                (Some(r), _) => {
                    for client in &clients {
                        client.take_staff_key();
                    }
                    // The closest any of the community's bridges comes to granting it.
                    let blocked = clients.iter().map(|c| c.grant_blocked(&r)).min_by_key(|b| b.map_or(0, |b| 5 - b as u8));
                    match blocked.flatten() {
                        None => format!("Discord members are given {} when their posts need it.", r.name),
                        Some(why) => format!("Discord members should be given {}, but the bridge can't grant it: {}.", r.name, explain(why, &npub)),
                    }
                }
            }
        };
        if arg.is_empty() {
            return Ok(describe(&self.role_setting(&link.community_id, &link.discord_guild_id).await?));
        }
        if f.banned.contains(author) || !f.roster.is_authorized(author, &f.owner, perm::MANAGE_ROLES) {
            return Ok("Only members who can manage roles can choose the Role Discord members get.".into());
        }
        let setting = match arg.to_lowercase().as_str() {
            "off" | "none" => RoleSetting::Off,
            "auto" | "default" => RoleSetting::Auto,
            _ => {
                let Some(r) = role_named(&f, arg) else { return Ok(format!("There's no Role named “{arg}”.")) };
                if !is_plain(&r) {
                    return Ok(format!("{} carries moderation or management permissions; the bridge only hands out plain Roles.", r.name));
                }
                // The command can't hand out a Role its caller couldn't grant themselves.
                if !may_grant(&f, author, &r) {
                    return Ok(format!("You can't grant {} yourself, so you can't have the bridge grant it.", r.name));
                }
                RoleSetting::Role(r.role_id)
            }
        };
        self.set_role_setting(&link.community_id, &link.discord_guild_id, &setting).await?;
        let mut reply = describe(&setting);
        if let (RoleSetting::Role(_), Some(role)) = (&setting, bridged_role_in(&f, &setting)) {
            let given = self.grant_to_recent(rb, &clients, &role).await?;
            if given > 0 {
                reply.push_str(&format!(" Gave it to {given} Discord {} who posted here recently.", if given == 1 { "member" } else { "members" }));
            }
        }
        Ok(reply)
    }

    /// Give `role` to the Discord members of this pairing who posted lately
    /// and lack it, once a Role is set by name.
    async fn grant_to_recent(&self, rb: &Arc<Running>, clients: &[Arc<ConcordClient>], role: &Role) -> anyhow::Result<usize> {
        let link = &rb.link;
        let db = self.pool.get().await?;
        let master_sealed: Vec<u8> = db
            .query_one("SELECT master_secret_sealed FROM guild_community_secrets WHERE community_id = $1 AND discord_guild_id = $2", &[&link.community_id, &link.discord_guild_id])
            .await?
            .get(0);
        let master = unseal(&self.env.seal_key_hex, &master_sealed)?;
        let authors = db
            .query(
                "SELECT DISTINCT author_ref FROM messages
                 WHERE community_id = $1 AND origin = 'discord' AND created_at > now() - make_interval(days => $3)
                   AND discord_channel_id IN (SELECT discord_channel_id FROM bridges WHERE community_id = $1 AND discord_guild_id = $2)
                 LIMIT $4",
                &[&link.community_id, &link.discord_guild_id, &BACKFILL_DAYS, &BACKFILL_MAX],
            )
            .await?;
        let tried = Mutex::default();
        let mut given = 0;
        for row in authors {
            let Ok(puppet) = derive_puppet(&master, row.get(0)) else { continue };
            let f = rb.client.folded();
            if f.is_some_and(|f| f.banned.contains(&puppet.pk) || f.roster.roles_of(&puppet.pk).any(|r| r.role_id == role.role_id)) {
                continue;
            }
            if self.grant_with_any(clients, &puppet.pk, role, &tried).await {
                given += 1;
            }
        }
        Ok(given)
    }
}
