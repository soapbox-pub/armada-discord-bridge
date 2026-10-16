//! Copying a Discord channel's past messages into Armada, shared by the server
//! importer and by history requested for any bridge from the channel map.

use std::time::Duration;

use bridge::relays::PublishRejected;
use bridge::router::BridgeRouter;
use bridge::types::ChannelLink;
use deadpool_postgres::Pool;
use futures_util::future::BoxFuture;

use crate::discord_rest::{RestMessage, rest_to_inbound};

/// Waits between attempts at one history message while relays refuse it, in
/// multiples of the caller's base wait: 1.5s doubling to 48s by default,
/// about a minute and a half in all.
pub const HISTORY_BACKOFF_STEPS: u32 = 6;

/// Run `attempt` until relays stop refusing it, backing off from `base`,
/// doubling, for `steps` waits. Any other failure returns at once: it will
/// fail the same way however long we wait. Still refused after the last wait
/// is an error the caller must not skip past.
pub async fn with_relay_backoff<T, F, Fut>(base: Duration, steps: u32, mut attempt: F) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let mut step = 0;
    loop {
        match attempt().await {
            Err(error) if PublishRejected::in_chain(&error) && step < steps => {
                let wait = base * 2u32.pow(step);
                tracing::warn!(wait_s = wait.as_secs_f32(), error = %format!("{error:#}"), "relays refusing history; backing off");
                tokio::time::sleep(wait).await;
                step += 1;
            }
            other => return other,
        }
    }
}

/// One page of history strictly before a message id, newest first, as
/// `DiscordRest::bot_channel_messages_before` returns it.
pub type PageBefore<'a> = &'a (dyn Fn(Option<String>) -> BoxFuture<'static, anyhow::Result<Option<Vec<RestMessage>>>> + Send + Sync);

/// The newest `cap` messages of a channel, stopping at `cursor` (everything at
/// or below it was copied on an earlier run), OLDEST first so that a reply's
/// target exists by the time the reply is copied.
pub async fn newest_messages(page_before: PageBefore<'_>, cursor: Option<u64>, cap: usize) -> anyhow::Result<Vec<RestMessage>> {
    let mut collected: Vec<RestMessage> = Vec::new();
    let mut before: Option<String> = None;
    'pages: while collected.len() < cap {
        let Some(page) = page_before(before.clone()).await? else { break };
        let Some(last) = page.last() else { break };
        before = Some(last.id.clone());
        for message in page {
            if cursor.is_some_and(|c| message.id.parse::<u64>().unwrap_or(0) <= c) {
                break 'pages;
            }
            collected.push(message);
            if collected.len() >= cap {
                break 'pages;
            }
        }
    }
    collected.reverse();
    Ok(collected)
}

/// What became of one message.
#[derive(Debug, PartialEq, Eq)]
pub enum Copied {
    /// Published into Armada now.
    Published,
    /// Already in this community: an earlier run, or the live bridge.
    Present,
    /// Not copied, and not to be counted as done: a bot or webhook post, a
    /// system message, empty after conversion, or a failure. The caller must
    /// not move its resume cursor past it on that account.
    Skipped,
}

/// Copy one Discord message through the live router (puppets, transforms,
/// rehosting, mapping), deduplicated against the community's mapping rows.
///
/// Paced by the relays: when they refuse the message (a rate limiter, an
/// overloaded relay) the same message is tried again after a wait, never the
/// next one. Skipping on to a later message moved the resume cursor past the
/// refused one, so a rate-limited stretch of a large server's history was
/// lost for good. A refusal that outlasts the backoff is returned as the
/// error, for the caller to stop on.
pub async fn copy_discord_message(pool: &Pool, router: &BridgeRouter, link: &ChannelLink, message: &RestMessage, retry_base: Duration) -> anyhow::Result<Copied> {
    if message.kind != 0 && message.kind != 19 {
        return Ok(Copied::Skipped);
    }
    // Scoped to this community: re-importing the same guild elsewhere left
    // rows for the same message id, which made every history message look
    // already imported and silently skipped the backfill. `tenant_id` leads
    // every index on messages: without it this check walked the whole primary
    // key, ~0.5s per message (2026-10-16).
    let exists = pool
        .get()
        .await?
        .query_opt(
            "SELECT 1 FROM messages WHERE tenant_id = 'default' AND discord_message_id = $1 AND community_id = $2 LIMIT 1",
            &[&message.id, &link.community_id],
        )
        .await?
        .is_some();
    if exists {
        return Ok(Copied::Present);
    }
    let inbound = rest_to_inbound(message, &link.discord_guild_id, &link.discord_channel_id);
    match with_relay_backoff(retry_base, HISTORY_BACKOFF_STEPS, || router.on_discord_message(inbound.clone(), link)).await {
        Ok(Some(_)) => Ok(Copied::Published),
        Ok(None) => Ok(Copied::Skipped),
        Err(error) if PublishRejected::in_chain(&error) => Err(error),
        Err(error) => {
            tracing::warn!(message = %message.id, error = %format!("{error:#}"), "history message failed");
            Ok(Copied::Skipped)
        }
    }
}

/// `YYYY-MM-DD` (UTC) of a Unix time in milliseconds.
pub fn utc_date(ms: u64) -> String {
    // Howard Hinnant's civil_from_days.
    let z = (ms / 86_400_000) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use nostr::prelude::EventId;

    use super::*;

    fn refused() -> anyhow::Error {
        PublishRejected { id: EventId::from_byte_array([0; 32]), tried: 1, why: "rate-limited".into() }.into()
    }

    #[tokio::test]
    async fn waits_out_relays_refusing_and_tries_the_same_message_again() {
        let calls = AtomicU32::new(0);
        let result = with_relay_backoff(Duration::from_millis(1), 6, || async {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            if n < 2 { Err(refused().context("router send")) } else { Ok(n) }
        })
        .await;
        assert_eq!(result.unwrap(), 2);
    }

    #[tokio::test]
    async fn does_not_wait_on_a_failure_that_will_repeat() {
        let calls = AtomicU32::new(0);
        let result: anyhow::Result<()> = with_relay_backoff(Duration::from_secs(60), 6, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("unconvertible message")
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn gives_up_refused_after_the_last_wait_and_says_so() {
        let calls = AtomicU32::new(0);
        let result: anyhow::Result<()> = with_relay_backoff(Duration::from_millis(1), 3, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err(refused())
        })
        .await;
        assert!(PublishRejected::in_chain(&result.unwrap_err()));
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    fn message(id: u64) -> RestMessage {
        RestMessage { id: id.to_string(), timestamp: "2026-09-23T17:00:00Z".into(), ..Default::default() }
    }

    /// A channel of messages 1..=250 served in pages of 100, newest first.
    fn pages() -> impl Fn(Option<String>) -> BoxFuture<'static, anyhow::Result<Option<Vec<RestMessage>>>> + Send + Sync {
        |before: Option<String>| {
            let below = before.map_or(251, |b| b.parse::<u64>().unwrap());
            Box::pin(async move { Ok(Some((1..below).rev().take(100).map(message).collect())) })
        }
    }

    #[tokio::test]
    async fn collects_the_newest_cap_oldest_first_and_stops_at_the_cursor() {
        let fetch = Arc::new(pages());
        let ids = |v: Vec<RestMessage>| v.into_iter().map(|m| m.id.parse::<u64>().unwrap()).collect::<Vec<_>>();
        let newest = ids(newest_messages(fetch.as_ref(), None, 150).await.unwrap());
        assert_eq!(newest, (101..=250).collect::<Vec<_>>());
        let resumed = ids(newest_messages(fetch.as_ref(), Some(240), 150).await.unwrap());
        assert_eq!(resumed, (241..=250).collect::<Vec<_>>());
        assert_eq!(newest_messages(fetch.as_ref(), None, 1000).await.unwrap().len(), 250);
    }

    #[test]
    fn dates_are_utc_calendar_days() {
        assert_eq!(utc_date(0), "1970-01-01");
        assert_eq!(utc_date(1_709_164_800_000), "2024-02-29");
        assert_eq!(utc_date(1_790_182_800_123), "2026-09-23");
    }
}
