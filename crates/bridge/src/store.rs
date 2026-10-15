//! Mapping rows between Discord messages and Concord rumors, and the catch-up
//! cursors. Postgres in production; an in-memory store for tests. Rows are
//! scoped by `tenant_id`, which is always 'default' today.

use std::sync::Mutex;

use async_trait::async_trait;
use deadpool_postgres::Pool;

use crate::types::{ChannelLink, MessageMappingRow, Origin, ReactionMappingRow};

#[async_trait]
pub trait MappingStore: Send + Sync {
    async fn insert(&self, row: &MessageMappingRow) -> anyhow::Result<()>;
    async fn by_rumor_id(&self, rumor_id: &str) -> anyhow::Result<Vec<MessageMappingRow>>;
    async fn by_discord_id(&self, discord_message_id: &str) -> anyhow::Result<Vec<MessageMappingRow>>;
    async fn insert_reaction(&self, row: &ReactionMappingRow) -> anyhow::Result<()>;
    async fn reaction_by_discord(&self, message_id: &str, user_id: &str, emoji: &str) -> anyhow::Result<Option<ReactionMappingRow>>;
    async fn reaction_by_rumor_id(&self, rumor_id: &str) -> anyhow::Result<Option<ReactionMappingRow>>;
    async fn delete_reaction(&self, rumor_id: &str) -> anyhow::Result<()>;
    /// Concord-origin reactions still mirrored onto this message with this emoji.
    async fn count_concord_reactions(&self, message_id: &str, emoji: &str) -> anyhow::Result<i64>;
}

const TENANT: &str = "default";

pub struct PgMappingStore {
    pool: Pool,
}

impl PgMappingStore {
    pub fn new(pool: Pool) -> Self {
        PgMappingStore { pool }
    }

    /// Newest processed wrap timestamp across a channel's stream addresses, or
    /// `None` when this channel has never been tailed. Fresh bridges do NOT
    /// backfill: restored delivery must not replay history into Discord. The
    /// pool merges relays, so cursors live under one sentinel relay_url.
    pub async fn cursor_get(&self, community_id: &str, stream_pks: &[String]) -> anyhow::Result<Option<u64>> {
        if stream_pks.is_empty() {
            return Ok(None);
        }
        let row = self
            .pool
            .get()
            .await?
            .query_one(
                "SELECT max(last_seen_at)::bigint AS at FROM cursors
                 WHERE tenant_id = $1 AND community_id = $2 AND stream_pk = ANY($3) AND relay_url = 'pool'",
                &[&TENANT, &community_id, &stream_pks],
            )
            .await?;
        Ok(row.get::<_, Option<i64>>("at").map(|at| at.max(0) as u64))
    }

    /// Advance (never rewind) the high-water mark for one stream address.
    pub async fn cursor_set(&self, community_id: &str, stream_pk: &str, last_seen_at: u64) -> anyhow::Result<()> {
        self.pool
            .get()
            .await?
            .execute(
                "INSERT INTO cursors (tenant_id, community_id, stream_pk, relay_url, last_seen_at)
                 VALUES ($1, $2, $3, 'pool', $4)
                 ON CONFLICT (tenant_id, community_id, stream_pk, relay_url)
                 DO UPDATE SET last_seen_at = GREATEST(cursors.last_seen_at, EXCLUDED.last_seen_at)",
                &[&TENANT, &community_id, &stream_pk, &(last_seen_at as i64)],
            )
            .await?;
        Ok(())
    }

    /// Upsert the community and link rows for an env-provisioned bridge.
    pub async fn ensure_link(&self, link: &ChannelLink, relays: &[String], name: Option<&str>) -> anyhow::Result<()> {
        let db = self.pool.get().await?;
        db.execute(
            "INSERT INTO communities (tenant_id, community_id, relays, name) VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id, community_id) DO UPDATE SET relays = EXCLUDED.relays, name = EXCLUDED.name",
            &[&TENANT, &link.community_id, &relays, &name],
        )
        .await?;
        db.execute(
            "INSERT INTO channel_links (tenant_id, discord_guild_id, discord_channel_id, community_id, concord_channel_id, enabled)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_id, discord_channel_id, concord_channel_id) DO UPDATE SET enabled = EXCLUDED.enabled",
            &[&TENANT, &link.discord_guild_id, &link.discord_channel_id, &link.community_id, &link.concord_channel_id_hex, &link.enabled],
        )
        .await?;
        Ok(())
    }
}

fn message_row(r: &tokio_postgres::Row) -> anyhow::Result<MessageMappingRow> {
    let origin: String = r.get("origin");
    Ok(MessageMappingRow {
        discord_message_id: r.get("discord_message_id"),
        discord_channel_id: r.get("discord_channel_id"),
        concord_rumor_id: r.get("concord_rumor_id"),
        concord_channel_id: r.get("concord_channel_id"),
        community_id: r.get("community_id"),
        origin: Origin::parse(&origin).ok_or_else(|| anyhow::anyhow!("bad origin {origin}"))?,
        author_ref: r.get("author_ref"),
        part_index: r.get("part_index"),
    })
}

fn reaction_row(r: &tokio_postgres::Row) -> anyhow::Result<ReactionMappingRow> {
    let origin: String = r.get("origin");
    Ok(ReactionMappingRow {
        rumor_id: r.get("rumor_id"),
        discord_message_id: r.get("discord_message_id"),
        emoji: r.get("emoji"),
        origin: Origin::parse(&origin).ok_or_else(|| anyhow::anyhow!("bad origin {origin}"))?,
        author_ref: r.get("author_ref"),
    })
}

const MESSAGE_COLUMNS: &str =
    "discord_message_id, discord_channel_id, concord_rumor_id, concord_channel_id, community_id, origin, author_ref, part_index";

#[async_trait]
impl MappingStore for PgMappingStore {
    async fn insert(&self, row: &MessageMappingRow) -> anyhow::Result<()> {
        self.pool
            .get()
            .await?
            .execute(
                "INSERT INTO messages (tenant_id, discord_message_id, discord_channel_id, concord_rumor_id,
                   concord_channel_id, community_id, origin, author_ref, part_index)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING",
                &[
                    &TENANT,
                    &row.discord_message_id,
                    &row.discord_channel_id,
                    &row.concord_rumor_id,
                    &row.concord_channel_id,
                    &row.community_id,
                    &row.origin.as_str(),
                    &row.author_ref,
                    &row.part_index,
                ],
            )
            .await?;
        Ok(())
    }

    async fn by_rumor_id(&self, rumor_id: &str) -> anyhow::Result<Vec<MessageMappingRow>> {
        let sql = format!("SELECT {MESSAGE_COLUMNS} FROM messages WHERE tenant_id = $1 AND concord_rumor_id = $2");
        self.pool.get().await?.query(&sql, &[&TENANT, &rumor_id]).await?.iter().map(message_row).collect()
    }

    async fn by_discord_id(&self, discord_message_id: &str) -> anyhow::Result<Vec<MessageMappingRow>> {
        let sql = format!("SELECT {MESSAGE_COLUMNS} FROM messages WHERE tenant_id = $1 AND discord_message_id = $2");
        self.pool.get().await?.query(&sql, &[&TENANT, &discord_message_id]).await?.iter().map(message_row).collect()
    }

    async fn insert_reaction(&self, row: &ReactionMappingRow) -> anyhow::Result<()> {
        self.pool
            .get()
            .await?
            .execute(
                "INSERT INTO reaction_mappings (tenant_id, rumor_id, discord_message_id, emoji, origin, author_ref)
                 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
                &[&TENANT, &row.rumor_id, &row.discord_message_id, &row.emoji, &row.origin.as_str(), &row.author_ref],
            )
            .await?;
        Ok(())
    }

    async fn reaction_by_discord(&self, message_id: &str, user_id: &str, emoji: &str) -> anyhow::Result<Option<ReactionMappingRow>> {
        let rows = self
            .pool
            .get()
            .await?
            .query(
                "SELECT rumor_id, discord_message_id, emoji, origin, author_ref FROM reaction_mappings
                 WHERE tenant_id = $1 AND discord_message_id = $2 AND author_ref = $3 AND emoji = $4 LIMIT 1",
                &[&TENANT, &message_id, &user_id, &emoji],
            )
            .await?;
        rows.first().map(reaction_row).transpose()
    }

    async fn reaction_by_rumor_id(&self, rumor_id: &str) -> anyhow::Result<Option<ReactionMappingRow>> {
        let rows = self
            .pool
            .get()
            .await?
            .query(
                "SELECT rumor_id, discord_message_id, emoji, origin, author_ref FROM reaction_mappings
                 WHERE tenant_id = $1 AND rumor_id = $2 LIMIT 1",
                &[&TENANT, &rumor_id],
            )
            .await?;
        rows.first().map(reaction_row).transpose()
    }

    async fn delete_reaction(&self, rumor_id: &str) -> anyhow::Result<()> {
        self.pool
            .get()
            .await?
            .execute("DELETE FROM reaction_mappings WHERE tenant_id = $1 AND rumor_id = $2", &[&TENANT, &rumor_id])
            .await?;
        Ok(())
    }

    async fn count_concord_reactions(&self, message_id: &str, emoji: &str) -> anyhow::Result<i64> {
        let row = self
            .pool
            .get()
            .await?
            .query_one(
                "SELECT count(*) AS n FROM reaction_mappings
                 WHERE tenant_id = $1 AND discord_message_id = $2 AND emoji = $3 AND origin = 'concord'",
                &[&TENANT, &message_id, &emoji],
            )
            .await?;
        Ok(row.get("n"))
    }
}

/// In-memory store for tests and dry runs.
#[derive(Default)]
pub struct MemoryMappingStore {
    pub rows: Mutex<Vec<MessageMappingRow>>,
    pub reactions: Mutex<Vec<ReactionMappingRow>>,
}

#[async_trait]
impl MappingStore for MemoryMappingStore {
    async fn insert(&self, row: &MessageMappingRow) -> anyhow::Result<()> {
        self.rows.lock().unwrap().push(row.clone());
        Ok(())
    }

    async fn by_rumor_id(&self, rumor_id: &str) -> anyhow::Result<Vec<MessageMappingRow>> {
        Ok(self.rows.lock().unwrap().iter().filter(|r| r.concord_rumor_id == rumor_id).cloned().collect())
    }

    async fn by_discord_id(&self, discord_message_id: &str) -> anyhow::Result<Vec<MessageMappingRow>> {
        Ok(self.rows.lock().unwrap().iter().filter(|r| r.discord_message_id == discord_message_id).cloned().collect())
    }

    async fn insert_reaction(&self, row: &ReactionMappingRow) -> anyhow::Result<()> {
        self.reactions.lock().unwrap().push(row.clone());
        Ok(())
    }

    async fn reaction_by_discord(&self, message_id: &str, user_id: &str, emoji: &str) -> anyhow::Result<Option<ReactionMappingRow>> {
        Ok(self
            .reactions
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.discord_message_id == message_id && r.author_ref == user_id && r.emoji == emoji)
            .cloned())
    }

    async fn reaction_by_rumor_id(&self, rumor_id: &str) -> anyhow::Result<Option<ReactionMappingRow>> {
        Ok(self.reactions.lock().unwrap().iter().find(|r| r.rumor_id == rumor_id).cloned())
    }

    async fn delete_reaction(&self, rumor_id: &str) -> anyhow::Result<()> {
        self.reactions.lock().unwrap().retain(|r| r.rumor_id != rumor_id);
        Ok(())
    }

    async fn count_concord_reactions(&self, message_id: &str, emoji: &str) -> anyhow::Result<i64> {
        Ok(self
            .reactions
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.origin == Origin::Concord && r.discord_message_id == message_id && r.emoji == emoji)
            .count() as i64)
    }
}
