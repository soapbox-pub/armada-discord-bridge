//! Discord-side catch-up: replay what a Discord channel said while the portal
//! was not listening. The loop lives here, apart from BridgeManager, so its
//! edges — ordering, the live cutoff, the cap — are testable without a
//! gateway, a database or a relay.

use async_trait::async_trait;
use bridge::transform::parse_bot_command;

use crate::discord_rest::{RestMessage, parse_timestamp_ms};

#[async_trait]
pub trait CatchUpIo: Send + Sync {
    /// One page strictly after `after_id`, newest first; None if unreadable.
    async fn fetch_after(&self, after_id: &str) -> Option<Vec<RestMessage>>;
    /// Whether this message already has a mapping row (mirrored before).
    async fn already_mirrored(&self, message_id: &str) -> bool;
    /// Mirror one message; true when it was published.
    async fn mirror(&self, message: &RestMessage) -> bool;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CatchUpResult {
    pub mirrored: usize,
    /// True when the cap cut the replay short of the live cutoff.
    pub capped: bool,
}

const PAGE_SIZE: usize = 100;

fn snowflake(id: &str) -> u64 {
    id.parse().unwrap_or(0)
}

/// Replay messages after `anchor_id`, oldest first, up to (not including) the
/// first one posted at or after `live_from_ms` — from then on the gateway
/// delivers, and replaying past it would race the live path into publishing
/// the same message twice. At most `max` messages are read.
///
/// System messages are skipped, and so are bot commands: the live gateway
/// hands those to the command handler rather than the router, and one that
/// arrived while nobody was listening gets no late reply.
pub async fn replay_discord_since<Io: CatchUpIo + ?Sized>(
    anchor_id: &str,
    live_from_ms: i64,
    max: usize,
    io: &Io,
) -> CatchUpResult {
    let mut after = anchor_id.to_owned();
    let mut mirrored = 0;
    let mut seen = 0;
    loop {
        let Some(page) = io.fetch_after(&after).await.filter(|p| !p.is_empty()) else {
            return CatchUpResult { mirrored, capped: false };
        };
        // Pages arrive newest first; replay oldest first so reply targets exist
        // by the time a message cites them.
        let mut oldest_first: Vec<&RestMessage> = page.iter().collect();
        oldest_first.sort_by_key(|m| snowflake(&m.id));
        for message in oldest_first {
            // An unparseable timestamp is not evidence the message is live, so
            // it replays, as it did under the TypeScript `Date.parse` (NaN).
            if parse_timestamp_ms(&message.timestamp).is_some_and(|ms| ms >= live_from_ms) {
                return CatchUpResult { mirrored, capped: false };
            }
            if seen >= max {
                return CatchUpResult { mirrored, capped: true };
            }
            seen += 1;
            after.clone_from(&message.id);
            if message.kind != 0 && message.kind != 19 {
                continue;
            }
            if parse_bot_command(message.content.as_deref().unwrap_or("")).is_some() {
                continue;
            }
            if io.already_mirrored(&message.id).await {
                continue;
            }
            if io.mirror(message).await {
                mirrored += 1;
            }
        }
        if page.len() < PAGE_SIZE {
            return CatchUpResult { mirrored, capped: false };
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::discord_rest::RestAuthor;

    fn t0() -> i64 {
        parse_timestamp_ms("2026-09-23T19:00:00Z").unwrap()
    }

    fn msg(id: u64) -> RestMessage {
        RestMessage {
            id: id.to_string(),
            kind: 0,
            content: Some(format!("message {id}")),
            // T0 + id seconds; ids in these tests stay under an hour.
            timestamp: format!("2026-09-23T19:{:02}:{:02}.000Z", id / 60, id % 60),
            author: RestAuthor { id: "42".into(), username: "someone".into(), ..RestAuthor::default() },
            ..RestMessage::default()
        }
    }

    fn range(from: u64, to: u64) -> Vec<RestMessage> {
        (from..=to).map(msg).collect()
    }

    fn ids(messages: &[RestMessage]) -> Vec<String> {
        messages.iter().map(|m| m.id.clone()).collect()
    }

    /// A channel whose history is `messages`, served like Discord: 100 per page, newest first.
    #[derive(Default)]
    struct Channel {
        messages: Vec<RestMessage>,
        mirrored_ids: Vec<String>,
        /// Ids `mirror` reports as not published (e.g. empty after conversion).
        unpublishable: Vec<String>,
        unreadable: bool,
        published: Mutex<Vec<String>>,
        fetches: Mutex<Vec<String>>,
    }

    impl Channel {
        fn new(messages: Vec<RestMessage>) -> Channel {
            Channel { messages, ..Channel::default() }
        }

        fn published(&self) -> Vec<String> {
            self.published.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl CatchUpIo for Channel {
        async fn fetch_after(&self, after_id: &str) -> Option<Vec<RestMessage>> {
            if self.unreadable {
                return None;
            }
            self.fetches.lock().unwrap().push(after_id.to_owned());
            let after = snowflake(after_id);
            let mut page: Vec<RestMessage> = self.messages.iter().filter(|m| snowflake(&m.id) > after).cloned().collect();
            page.sort_by_key(|m| snowflake(&m.id));
            page.truncate(100);
            page.reverse();
            Some(page)
        }

        async fn already_mirrored(&self, id: &str) -> bool {
            self.mirrored_ids.iter().any(|m| m == id) || self.published.lock().unwrap().iter().any(|m| m == id)
        }

        async fn mirror(&self, message: &RestMessage) -> bool {
            if self.unreadable {
                panic!("must not be called");
            }
            self.published.lock().unwrap().push(message.id.clone());
            !self.unpublishable.contains(&message.id)
        }
    }

    #[tokio::test]
    async fn replays_everything_after_the_anchor_oldest_first_across_pages() {
        let ch = Channel::new(range(1, 250));
        let result = replay_discord_since("10", t0() + 10_000_000, 500, &ch).await;
        assert_eq!(ch.published(), ids(&range(11, 250)));
        assert_eq!(result, CatchUpResult { mirrored: 240, capped: false });
        // Each page picks up after the newest id of the one before.
        assert_eq!(*ch.fetches.lock().unwrap(), vec!["10", "110", "210"]);
    }

    #[tokio::test]
    async fn stops_at_the_live_cutoff_leaving_later_messages_to_the_gateway() {
        let ch = Channel::new(range(1, 50));
        // Message 30 was posted at T0+30s: the moment routing attached.
        replay_discord_since("0", t0() + 30_000, 500, &ch).await;
        assert_eq!(ch.published(), ids(&range(1, 29)));
    }

    #[tokio::test]
    async fn skips_what_is_already_mirrored_system_messages_and_bot_commands() {
        let ch = Channel {
            mirrored_ids: vec!["4".into()],
            ..Channel::new(vec![
                msg(1),
                RestMessage { kind: 7, ..msg(2) },
                RestMessage { content: Some("/help".into()), ..msg(3) },
                msg(4),
                RestMessage { kind: 19, ..msg(5) },
            ])
        };
        let result = replay_discord_since("0", t0() + 10_000_000, 500, &ch).await;
        assert_eq!(ch.published(), vec!["1", "5"]);
        assert_eq!(result.mirrored, 2);
    }

    #[tokio::test]
    async fn reads_at_most_max_messages_and_says_so() {
        let ch = Channel::new(range(1, 300));
        let result = replay_discord_since("0", t0() + 10_000_000, 120, &ch).await;
        assert_eq!(ch.published(), ids(&range(1, 120)));
        assert!(result.capped);
    }

    #[tokio::test]
    async fn counts_only_messages_the_router_actually_published() {
        let ch = Channel { unpublishable: vec!["2".into()], ..Channel::new(range(1, 3)) };
        let result = replay_discord_since("0", t0() + 10_000_000, 500, &ch).await;
        assert_eq!(result.mirrored, 2);
    }

    #[tokio::test]
    async fn does_nothing_for_a_channel_it_cannot_read() {
        let ch = Channel { unreadable: true, ..Channel::default() };
        let result = replay_discord_since("0", t0(), 500, &ch).await;
        assert_eq!(result, CatchUpResult { mirrored: 0, capped: false });
    }
}
