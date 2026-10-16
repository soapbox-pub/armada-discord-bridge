//! What the gateway has told us about the servers and text channels the bot is
//! in: their names, and each channel's newest message id.
//!
//! Discord pushes all of it — a GUILD_CREATE per server on connect, then
//! updates — and a boot used to fetch the same facts over REST, three calls per
//! bridge (channel name, server name, catch-up), about 4,000 against the
//! global limit of 50 a second, every restart.
//!
//! Bounded on purpose (see the discord module on why there is no gateway
//! cache): one entry per server and per text channel the bot can see, removed
//! when they go. No messages, users or members.

use std::collections::{HashMap, HashSet};

struct Channel {
    guild: u64,
    name: String,
    last_message_id: Option<u64>,
}

#[derive(Default)]
pub struct Directory {
    guilds: HashMap<u64, String>,
    channels: HashMap<u64, Channel>,
    /// Servers READY listed whose GUILD_CREATE has not arrived yet.
    pending: HashSet<u64>,
}

impl Directory {
    /// READY: these servers' GUILD_CREATEs are on their way.
    pub fn expect(&mut self, guilds: impl IntoIterator<Item = u64>) {
        self.pending.extend(guilds.into_iter().filter(|g| !self.guilds.contains_key(g)));
    }

    /// GUILD_CREATE for a server that is unavailable (an outage): nothing more
    /// is coming for it now, so it no longer holds up [`Directory::is_loaded`].
    pub fn guild_unavailable(&mut self, guild: u64) {
        self.pending.remove(&guild);
    }

    /// GUILD_CREATE: the server's name and every text channel, replacing what
    /// was known (it arrives again after a re-identify).
    pub fn guild_created(&mut self, guild: u64, name: String, text_channels: impl IntoIterator<Item = (u64, String, Option<u64>)>) {
        self.pending.remove(&guild);
        self.guilds.insert(guild, name);
        let fresh: Vec<(u64, String, Option<u64>)> = text_channels.into_iter().collect();
        let keep: HashSet<u64> = fresh.iter().map(|(id, _, _)| *id).collect();
        self.channels.retain(|id, c| c.guild != guild || keep.contains(id));
        for (id, name, last) in fresh {
            self.channel_upserted(guild, id, name, last);
        }
    }

    pub fn guild_renamed(&mut self, guild: u64, name: String) {
        if let Some(known) = self.guilds.get_mut(&guild) {
            *known = name;
        }
    }

    /// The bot left the server, or it was deleted.
    pub fn guild_removed(&mut self, guild: u64) {
        self.pending.remove(&guild);
        self.guilds.remove(&guild);
        self.channels.retain(|_, c| c.guild != guild);
    }

    /// A text channel was created or updated. `last_message_id` only ever
    /// rises: an update can carry an older one than a message already seen.
    pub fn channel_upserted(&mut self, guild: u64, id: u64, name: String, last_message_id: Option<u64>) {
        let entry = self.channels.entry(id).or_insert(Channel { guild, name: String::new(), last_message_id: None });
        entry.guild = guild;
        entry.name = name;
        entry.last_message_id = entry.last_message_id.max(last_message_id);
    }

    /// Deleted, or no longer a text channel.
    pub fn channel_removed(&mut self, id: u64) {
        self.channels.remove(&id);
    }

    pub fn message_created(&mut self, channel: u64, message: u64) {
        if let Some(c) = self.channels.get_mut(&channel) {
            c.last_message_id = c.last_message_id.max(Some(message));
        }
    }

    pub fn channel_name(&self, channel: u64) -> Option<&str> {
        self.channels.get(&channel).map(|c| c.name.as_str())
    }

    pub fn guild_name(&self, guild: u64) -> Option<&str> {
        self.guilds.get(&guild).map(String::as_str)
    }

    /// The newest message the channel has had, as far as the gateway has said;
    /// `None` for a channel it has not described or one that never had any.
    pub fn last_message_id(&self, channel: u64) -> Option<u64> {
        self.channels.get(&channel)?.last_message_id
    }

    /// Whether every server READY listed has been described.
    pub fn is_loaded(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    pub fn len(&self) -> (usize, usize) {
        (self.guilds.len(), self.channels.len())
    }
}

#[cfg(test)]
mod tests {
    use super::Directory;

    fn loaded() -> Directory {
        let mut d = Directory::default();
        d.expect([1, 2]);
        d.guild_created(1, "One".into(), [(10, "general".into(), Some(100)), (11, "quiet".into(), None)]);
        d
    }

    #[test]
    fn describes_what_guild_create_said() {
        let d = loaded();
        assert_eq!(d.guild_name(1), Some("One"));
        assert_eq!(d.channel_name(10), Some("general"));
        assert_eq!(d.last_message_id(10), Some(100));
        assert_eq!(d.last_message_id(11), None);
        assert_eq!(d.channel_name(99), None);
    }

    #[test]
    fn is_loaded_once_every_expected_server_arrived_or_is_unavailable() {
        let mut d = loaded();
        assert!(!d.is_loaded());
        d.guild_unavailable(2);
        assert!(d.is_loaded());
        // A server already described is not waited for again on re-identify.
        d.expect([1]);
        assert!(d.is_loaded());
    }

    #[test]
    fn last_message_id_only_rises() {
        let mut d = loaded();
        d.message_created(10, 150);
        d.message_created(10, 120);
        assert_eq!(d.last_message_id(10), Some(150));
        // A channel update carrying an older id does not undo a newer message.
        d.channel_upserted(1, 10, "renamed".into(), Some(100));
        assert_eq!(d.last_message_id(10), Some(150));
        assert_eq!(d.channel_name(10), Some("renamed"));
        d.message_created(11, 5);
        assert_eq!(d.last_message_id(11), Some(5));
        // Messages in channels it does not describe (threads, DMs) add nothing.
        d.message_created(99, 7);
        assert_eq!(d.len(), (1, 2));
    }

    #[test]
    fn forgets_what_goes_away() {
        let mut d = loaded();
        d.channel_removed(11);
        assert_eq!(d.channel_name(11), None);
        // A fresh GUILD_CREATE drops channels it no longer lists.
        d.guild_created(1, "One".into(), [(12, "new".into(), None)]);
        assert_eq!(d.channel_name(10), None);
        assert_eq!(d.channel_name(12), Some("new"));
        d.guild_removed(1);
        assert_eq!(d.len(), (0, 0));
    }
}
