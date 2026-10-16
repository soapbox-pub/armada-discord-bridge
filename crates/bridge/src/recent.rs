//! A bounded memory of recently delivered rumor ids.
//!
//! Live chat is deduplicated per bridge, and the duplicates it has to catch
//! are close together: the same rumor from several relays, and the minute
//! every chat REQ replacement replays. A window of [`RECENT_RUMORS`] covers
//! that many times over.
//!
//! It was a `HashSet<String>` of 65,536 hex ids, cleared when full. That is
//! ~7MB per bridge at capacity, ~7GB across a thousand bridges — past the
//! portal's memory cap — and clearing forgot the window it exists to keep.
//! Ids are now 32 bytes and evicted oldest first.

use std::collections::{HashSet, VecDeque};

use sha2::{Digest, Sha256};

/// Rumor ids remembered per bridge.
pub const RECENT_RUMORS: usize = 2048;

pub struct RecentIds {
    cap: usize,
    set: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

impl RecentIds {
    pub fn new(cap: usize) -> RecentIds {
        RecentIds { cap: cap.max(1), set: HashSet::new(), order: VecDeque::new() }
    }

    /// Remember `id`; false if it was already remembered.
    pub fn insert(&mut self, id: &str) -> bool {
        let key = key(id);
        if !self.set.insert(key) {
            return false;
        }
        self.order.push_back(key);
        if self.order.len() > self.cap
            && let Some(old) = self.order.pop_front()
        {
            self.set.remove(&old);
        }
        true
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

impl Default for RecentIds {
    fn default() -> Self {
        RecentIds::new(RECENT_RUMORS)
    }
}

/// A rumor id is 64 hex digits; anything else is hashed rather than refused,
/// so a malformed id still dedupes against itself.
fn key(id: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    if hex::decode_to_slice(id, &mut out).is_ok() {
        return out;
    }
    Sha256::digest(id.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupes_and_forgets_oldest_first() {
        let mut r = RecentIds::new(2);
        let (a, b, c) = ("aa".repeat(32), "bb".repeat(32), "cc".repeat(32));
        assert!(r.insert(&a));
        assert!(!r.insert(&a));
        assert!(r.insert(&b));
        assert!(r.insert(&c));
        assert_eq!(r.len(), 2);
        // a was evicted, b and c are still remembered.
        assert!(!r.insert(&b));
        assert!(!r.insert(&c));
        assert!(r.insert(&a));
    }

    #[test]
    fn hex_case_and_malformed_ids() {
        let mut r = RecentIds::default();
        assert!(r.insert(&"AB".repeat(32)));
        assert!(!r.insert(&"ab".repeat(32)));
        assert!(r.insert("not hex"));
        assert!(!r.insert("not hex"));
    }
}
