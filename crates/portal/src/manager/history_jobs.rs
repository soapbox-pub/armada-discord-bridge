//! History the channel map asked for, copied once a bridge is live.
//!
//! Discord into Armada is the importer's copy, for any bridge: Armada orders
//! by the original time, so it interleaves correctly even into a channel that
//! already has messages. Armada into Discord is narrower, because Discord
//! cannot backdate: every copied message is a webhook post made now. The map
//! offers it only for a Discord channel that is empty (or that it creates),
//! and the copy says in the channel what it is and which dates it spans.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use bridge::router::is_missing_permissions;
use futures_util::future::BoxFuture;
use serde_json::{Value, json};

use super::{BridgeManager, GatewayUnavailable, Running, bridge_by_id, lock};
use crate::discord_rest::RestMessage;
use crate::history::{Copied, copy_discord_message, newest_messages, utc_date};
use crate::import_plan::HISTORY_MESSAGE_CAP;

/// Most Armada messages copied into a Discord channel. Far below the Discord
/// cap: each is a webhook post, and Discord lets a webhook make roughly thirty
/// a minute, so this is already a quarter of an hour of posting.
pub const ARMADA_HISTORY_CAP: usize = 500;

/// First wait while relays refuse a copied message; it doubles from here.
const RELAY_RETRY: Duration = Duration::from_millis(1500);

impl BridgeManager {
    /// Start, or pick back up, the history copy a live bridge was linked with.
    /// Called each time routing attaches, so a restart or a resume continues
    /// a copy that was cut off.
    pub(super) async fn resume_history(&self, rb: &Arc<Running>) {
        let Ok(Some(row)) = bridge_by_id(&self.pool, &rb.id).await else { return };
        let history = row.history;
        let direction = history["direction"].as_str().unwrap_or_default();
        if !matches!(history["state"].as_str(), Some("pending" | "running")) || !matches!(direction, "discord" | "armada") {
            return;
        }
        if !lock(&self.history_running).insert(rb.id.clone()) {
            return;
        }
        let _ = self.set_history(&rb.id, json!({ "state": "running", "detail": null })).await;
        tracing::info!(bridge = %rb.id, direction, "copying history");
        let result = if direction == "discord" { self.copy_discord_history(rb, &history).await } else { self.copy_armada_history(rb, &history).await };
        let outcome = match result {
            Ok(imported) => {
                tracing::info!(bridge = %rb.id, imported, "history copied");
                json!({ "state": "done", "imported": imported, "detail": null })
            }
            // Paused or unlinked mid-copy: not a failure. A resume attaches
            // routing again, and that picks the copy up from its cursor.
            Err(_) if !self.is_live(&rb.id) => json!({ "state": "pending", "detail": "the bridge stopped; the copy continues when it resumes" }),
            Err(error) => {
                tracing::warn!(bridge = %rb.id, error = %format!("{error:#}"), "history copy failed");
                json!({ "state": "failed", "detail": format!("{error:#}") })
            }
        };
        let _ = self.set_history(&rb.id, outcome).await;
        lock(&self.history_running).remove(&rb.id);
    }

    async fn set_history(&self, bridge_id: &str, patch: Value) -> anyhow::Result<()> {
        self.pool
            .get()
            .await?
            .execute("UPDATE bridges SET history = history || $2, updated_at = now() WHERE bridge_id = ($1::text)::uuid", &[&bridge_id, &patch])
            .await?;
        Ok(())
    }

    async fn copy_discord_history(&self, rb: &Arc<Running>, history: &Value) -> anyhow::Result<u64> {
        let router = rb.router().context("the bridge is not routing")?;
        if self.env.discord_bot_token.is_empty() {
            bail!("bot token not configured");
        }
        let (rest, token, channel) = (self.rest.clone(), self.env.discord_bot_token.clone(), rb.link.discord_channel_id.clone());
        let page_before = move |before: Option<String>| -> BoxFuture<'static, anyhow::Result<Option<Vec<RestMessage>>>> {
            let (rest, token, channel) = (rest.clone(), token.clone(), channel.clone());
            Box::pin(async move { rest.bot_channel_messages_before(&token, &channel, before.as_deref(), 100).await })
        };
        let cursor = history["cursor"].as_str().and_then(|c| c.parse::<u64>().ok());
        let messages = newest_messages(&page_before, cursor, HISTORY_MESSAGE_CAP as usize).await?;
        let mut imported = history["imported"].as_u64().unwrap_or(0);
        for message in messages {
            if !self.is_live(&rb.id) {
                bail!("the bridge stopped");
            }
            match copy_discord_message(&self.pool, &router, &rb.link, &message, RELAY_RETRY).await? {
                Copied::Skipped => continue,
                Copied::Present => {}
                Copied::Published => tokio::time::sleep(Duration::from_millis(25)).await,
            }
            imported += 1;
            if imported.is_multiple_of(20) {
                self.set_history(&rb.id, json!({ "imported": imported, "cursor": message.id })).await?;
            }
        }
        Ok(imported)
    }

    async fn copy_armada_history(&self, rb: &Arc<Running>, history: &Value) -> anyhow::Result<u64> {
        let router = rb.router().context("the bridge is not routing")?;
        let adapter = self.adapter().ok_or(GatewayUnavailable)?;
        let (chats, _) = rb.client.backfill_channel(&rb.channel(), 0, ARMADA_HISTORY_CAP).await?;
        let chats: Vec<_> = chats.into_iter().filter(|c| c.kind() != concord::kinds::TYPING).collect();
        let messages = chats.iter().filter(|c| matches!(c.kind(), concord::kinds::MESSAGE | concord::kinds::COMMENT)).count();
        let (Some(first), Some(last)) = (chats.first(), chats.last()) else { return Ok(0) };
        if messages == 0 {
            return Ok(0);
        }
        let channel = &rb.link.discord_channel_id;
        let mut copied = history["imported"].as_u64().unwrap_or(0);
        let opening = if copied == 0 {
            format!(
                "Copying {messages} earlier messages from Armada, first posted between {} and {}. Discord shows them as sent today.",
                utc_date(first.ms),
                utc_date(last.ms)
            )
        } else {
            "Continuing the copy of earlier Armada messages.".to_owned()
        };
        let _ = adapter.notice(channel, &opening).await;
        for chat in &chats {
            if !self.is_live(&rb.id) {
                bail!("the bridge stopped");
            }
            // Already-mirrored rumors come back empty: the router dedupes on
            // the mapping table, which is also what makes a resumed copy safe.
            match router.on_concord_chat(chat, &rb.link).await {
                Ok(ids) if !ids.is_empty() => {
                    copied += 1;
                    if copied.is_multiple_of(20) {
                        self.set_history(&rb.id, json!({ "imported": copied })).await?;
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Ok(_) => {}
                Err(error) if is_missing_permissions(&error) => {
                    self.alert_missing_webhook_permission(rb).await;
                    return Err(error.context("the bot cannot post into the Discord channel"));
                }
                Err(error) => tracing::warn!(bridge = %rb.id, rumor = %chat.rumor_id(), error = %format!("{error:#}"), "history mirror failed"),
            }
        }
        let _ = adapter.notice(channel, "End of the copied Armada history.").await;
        Ok(copied)
    }
}
