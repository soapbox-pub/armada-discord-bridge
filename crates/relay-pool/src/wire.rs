//! Packing many subscriptions into few REQs.
//!
//! Relays cap concurrent REQs per connection — 20 on all four of Armada's
//! stock relays (NIP-11, 2026-10-16) — and that cap covers one-shot queries
//! too. A process bridging a hundred communities cannot hold a REQ per
//! subscription per connection, and one connection per community ran into
//! the relays' per-IP limits instead. So a relay task packs every
//! subscription's filters into a handful of REQs, and routes what arrives
//! back to each subscription by matching that subscription's own filters.
//!
//! The REQs themselves are bounded too: strfry refuses websocket messages over
//! 128KiB, ditto-relay REQs over 100 filters and 20,000 filter values. Two of
//! the stock relays (jskitty.com, asia.vectorapp.io) refuse REQs of more than
//! 20 filters with "bad req: arr too big", though NIP-11 says nothing of it:
//! measured 2026-10-16, after a rehearsal at 50 left both relays silent.

use std::collections::{BTreeMap, BTreeSet};

use nostr::prelude::*;

/// Filters per REQ: inside the 20 two stock relays allow.
pub(crate) const WIRE_MAX_FILTERS: usize = 16;
/// Serialized size per REQ: inside strfry's 128KiB websocket message limit.
pub(crate) const WIRE_MAX_BYTES: usize = 96 * 1024;
/// Authors per merged filter: ~16KB of hex.
pub(crate) const AUTHORS_PER_FILTER: usize = 250;

/// One filter on the wire, and the subscriptions it carries.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Carried {
    pub filter: Filter,
    pub subs: BTreeSet<String>,
}

/// A filter that is only kinds, authors and since can share a filter with
/// others like it. Anything else (ids, tags, limit, until, search) means
/// something only as written, so it goes on the wire as is.
pub(crate) fn mergeable(f: &Filter) -> bool {
    f.ids.is_none()
        && f.search.is_none()
        && f.until.is_none()
        && f.limit.is_none()
        && f.generic_tags.is_empty()
        && f.authors.as_ref().is_some_and(|a| !a.is_empty())
}

/// Merge `(subscription, filter, floor)` triples into as few filters as carry
/// the same events. A filter is sent from the later of its own `since` and its
/// floor; a floor of `None` sends it as written.
///
/// Merged filters may match events a subscription did not ask for (an
/// earlier `since`, or another subscription's author under the same kinds);
/// routing re-checks each subscription's own filters, so that costs only
/// bandwidth.
///
/// Filters of the same kinds that have a floor share the earliest of them.
/// Grouped by exact floor instead, every subscription still replaying (each
/// with its own `since`) was a filter of its own, and a boot's merged REQ
/// carried one per community. Filters with no floor stay apart from those
/// with one: merged, one new control subscription would replay the whole
/// history of every other subscription in its bin.
pub(crate) fn merge<'a>(entries: impl IntoIterator<Item = (&'a str, &'a Filter, Option<Timestamp>)>) -> Vec<Carried> {
    /// Kinds, and whether the group has a floor.
    type Key = (Option<Vec<u16>>, bool);
    /// The group's floor, and the subscriptions asking for each author.
    type Group = (Option<Timestamp>, BTreeMap<PublicKey, BTreeSet<String>>);
    let mut groups: BTreeMap<Key, Group> = BTreeMap::new();
    let mut out = Vec::new();
    for (sub, f, floor) in entries {
        let floor = match (f.since, floor) {
            (Some(own), Some(floor)) => Some(own.max(floor)),
            (own, floor) => floor.or(own),
        };
        if !mergeable(f) {
            let mut f = f.clone();
            f.since = floor;
            out.push(Carried { filter: f, subs: BTreeSet::from([sub.to_owned()]) });
            continue;
        }
        let kinds = f.kinds.as_ref().map(|k| k.iter().map(|k| k.as_u16()).collect());
        let (since, authors) = groups.entry((kinds, floor.is_some())).or_insert((floor, BTreeMap::new()));
        *since = (*since).min(floor);
        for pk in f.authors.iter().flatten() {
            authors.entry(*pk).or_default().insert(sub.to_owned());
        }
    }
    for ((kinds, _), (floor, authors)) in groups {
        let authors: Vec<(PublicKey, BTreeSet<String>)> = authors.into_iter().collect();
        for chunk in authors.chunks(AUTHORS_PER_FILTER) {
            let mut f = Filter::new().authors(chunk.iter().map(|(pk, _)| *pk));
            if let Some(kinds) = &kinds {
                f = f.kinds(kinds.iter().map(|k| Kind::from(*k)));
            }
            f.since = floor;
            let subs = chunk.iter().flat_map(|(_, s)| s.iter().cloned()).collect();
            out.push(Carried { filter: f, subs });
        }
    }
    out
}

/// Pack filters into REQs within [`WIRE_MAX_FILTERS`] and [`WIRE_MAX_BYTES`].
pub(crate) fn pack(filters: Vec<Carried>) -> Vec<Vec<Carried>> {
    let mut reqs: Vec<Vec<Carried>> = Vec::new();
    let mut bytes = 0;
    for c in filters {
        let size = c.filter.as_json().len() + 1;
        let fits = reqs.last().is_some_and(|r| r.len() < WIRE_MAX_FILTERS && bytes + size <= WIRE_MAX_BYTES);
        if !fits {
            reqs.push(Vec::new());
            bytes = 0;
        }
        bytes += size;
        reqs.last_mut().expect("just pushed").push(c);
    }
    reqs
}

/// Pubkeys a request is about: the ones a NIP-42-gating relay wants this
/// connection authenticated as before it answers.
pub(crate) fn pubkeys_of(filters: &[Filter]) -> BTreeSet<PublicKey> {
    let p = SingleLetterTag::from_char('p').expect("a lowercase letter");
    let mut out = BTreeSet::new();
    for f in filters {
        out.extend(f.authors.iter().flatten().copied());
        out.extend(f.generic_tags.get(&p).into_iter().flatten().filter_map(|v| PublicKey::from_hex(v).ok()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pks(n: usize) -> Vec<PublicKey> {
        (0..n).map(|_| Keys::generate().public_key()).collect()
    }

    #[test]
    fn merges_authors_across_subscriptions_with_the_same_shape() {
        let (a, b) = (pks(3), pks(2));
        let fa = Filter::new().kind(Kind::GiftWrap).authors(a.clone());
        let fb = Filter::new().kind(Kind::GiftWrap).authors(b.clone());
        let other = Filter::new().kind(Kind::TextNote).authors(b.clone());
        let tagged = Filter::new().kind(Kind::GiftWrap).pubkey(a[0]).limit(4);
        let merged = merge([("a", &fa, None), ("b", &fb, None), ("b", &other, None), ("c", &tagged, None)]);
        assert_eq!(merged.len(), 3, "{merged:?}");
        let wraps = merged.iter().find(|c| c.filter.kinds == fa.kinds && c.filter.authors.is_some()).unwrap();
        assert_eq!(wraps.filter.authors.as_ref().unwrap().len(), 5);
        assert_eq!(wraps.subs, BTreeSet::from(["a".to_owned(), "b".to_owned()]));
        // A filter with a tag and a limit means something only as written.
        assert!(merged.iter().any(|c| c.filter == tagged && c.subs == BTreeSet::from(["c".to_owned()])));
    }

    #[test]
    fn floors_merge_to_the_earliest_and_no_floor_stays_apart() {
        let a = Filter::new().kind(Kind::GiftWrap).authors(pks(1));
        let b = Filter::new().kind(Kind::GiftWrap).authors(pks(1)).since(Timestamp::from_secs(500));
        let c = Filter::new().kind(Kind::GiftWrap).authors(pks(1)).since(Timestamp::from_secs(300));
        let merged = merge([("a", &a, None), ("b", &b, None), ("c", &c, None)]);
        assert_eq!(merged.len(), 2, "{merged:?}");
        assert!(merged.iter().any(|m| m.filter.since.is_none() && m.subs.len() == 1));
        assert!(merged.iter().any(|m| m.filter.since == Some(Timestamp::from_secs(300)) && m.subs.len() == 2));
        let raised = merge([("a", &a, Some(Timestamp::from_secs(900))), ("b", &b, Some(Timestamp::from_secs(900)))]);
        assert_eq!(raised.len(), 1);
        assert_eq!(raised[0].filter.since, Some(Timestamp::from_secs(900)));
        // A floor never lowers a filter's own since.
        let kept = merge([("b", &b, Some(Timestamp::from_secs(100)))]);
        assert_eq!(kept[0].filter.since, Some(Timestamp::from_secs(500)));
    }

    #[test]
    fn splits_large_author_sets_and_packs_within_the_relays_limits() {
        let authors = pks(3000);
        let f = Filter::new().kinds([Kind::GiftWrap, Kind::Custom(21059)]).authors(authors.clone());
        let merged = merge([("a", &f, None)]);
        assert_eq!(merged.len(), 3000usize.div_ceil(AUTHORS_PER_FILTER));
        let reqs = pack(merged);
        assert!(reqs.len() >= 2);
        let mut carried = BTreeSet::new();
        for req in &reqs {
            let filters: Vec<Filter> = req.iter().map(|c| c.filter.clone()).collect();
            let json = ClientMessage::req(SubscriptionId::new("w00000000"), filters).as_json();
            assert!(json.len() <= WIRE_MAX_BYTES + 64, "REQ of {} bytes", json.len());
            assert!(req.len() <= WIRE_MAX_FILTERS);
            for c in req {
                carried.extend(c.filter.authors.iter().flatten().copied());
            }
        }
        assert_eq!(carried, authors.into_iter().collect());
    }

    #[test]
    fn pubkeys_include_authors_and_p_tags() {
        let (a, p) = (pks(2), pks(1));
        let got = pubkeys_of(&[Filter::new().authors(a.clone()), Filter::new().pubkey(p[0])]);
        assert_eq!(got, a.into_iter().chain(p).collect());
    }
}
