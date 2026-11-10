//! Rank keys (CORD-04 §3): Role order as fractional keys over `0-9A-Za-z`,
//! compared byte by byte, 1 to 32 bytes and never ending in `0`, so a key
//! strictly between any two always exists. Channel and Category positions
//! (CORD-03) use the same keys. A port of Armada's `rankKey.ts` (itself from
//! Vector's `community/rank.rs`).

use std::collections::{BTreeSet, HashMap};

pub const MAX_RANK_KEY_BYTES: usize = 32;

const DIGITS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn digit(c: u8) -> Option<usize> {
    DIGITS.iter().position(|d| *d == c)
}

/// A well-formed rank key.
pub fn is_rank_key(key: &str) -> bool {
    let b = key.as_bytes();
    !b.is_empty() && b.len() <= MAX_RANK_KEY_BYTES && b.iter().all(|c| digit(*c).is_some()) && b[b.len() - 1] != b'0'
}

/// A key strictly between `lo` and `hi` (`None` is the open end on that side),
/// or `None` when the keys are malformed, out of order, or the gap no longer
/// fits in 32 bytes.
pub fn rank_between(lo: Option<&str>, hi: Option<&str>) -> Option<String> {
    let low = lo.unwrap_or("");
    if !low.is_empty() && !is_rank_key(low) {
        return None;
    }
    if let Some(h) = hi
        && (!is_rank_key(h) || low >= h) {
            return None;
        }
    // Appending steps up a digit rather than halving the gap: ~61 keys per byte instead of 6.
    let key = if hi.is_none() && !low.is_empty() { after(low.as_bytes()) } else { midpoint(low.as_bytes(), hi.map(str::as_bytes)) };
    let key = String::from_utf8(key).expect("digits are ascii");
    (key.len() <= MAX_RANK_KEY_BYTES).then_some(key)
}

fn after(lo: &[u8]) -> Vec<u8> {
    let Some(&first) = lo.first() else { return vec![DIGITS[1]] };
    let a = digit(first).expect("validated");
    if a + 1 < DIGITS.len() {
        return vec![DIGITS[a + 1]];
    }
    let mut out = vec![first];
    out.extend(after(&lo[1..]));
    out
}

fn midpoint(lo: &[u8], hi: Option<&[u8]>) -> Vec<u8> {
    if let Some(hi) = hi {
        let mut n = 0;
        while n < hi.len() && lo.get(n).copied().unwrap_or(b'0') == hi[n] {
            n += 1;
        }
        if n > 0 {
            let mut out = hi[..n].to_vec();
            let rest_lo = if lo.len() > n { &lo[n..] } else { &[][..] };
            out.extend(midpoint(rest_lo, Some(&hi[n..])));
            return out;
        }
    }
    let a = lo.first().and_then(|c| digit(*c)).unwrap_or(0);
    let b = match hi {
        None => DIGITS.len(),
        Some(h) => digit(h[0]).expect("validated"),
    };
    if b - a > 1 {
        return vec![DIGITS[(a + b).div_ceil(2)]];
    }
    if let Some(h) = hi
        && h.len() > 1 {
            return vec![h[0]];
        }
    let mut out = vec![DIGITS[a]];
    out.extend(midpoint(if lo.is_empty() { lo } else { &lo[1..] }, None));
    out
}

/// Order-preserving dense ranks: each distinct key maps to 1 + its index in
/// byte order, so equal keys are peers. 0 stays the owner's.
pub fn dense_ranks<'a>(keys: impl IntoIterator<Item = &'a str>) -> HashMap<String, u32> {
    let sorted: BTreeSet<&str> = keys.into_iter().collect();
    sorted.into_iter().enumerate().map(|(i, k)| (k.to_owned(), i as u32 + 1)).collect()
}

/// `n` keys in ascending order, evenly spread over the key space: what an
/// importer assigns when it lays out a whole order at once.
pub fn spread(n: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(n);
    for _ in 0..n {
        let next = rank_between(out.last().map(String::as_str), None).expect("appending always fits for a few thousand keys");
        out.push(next);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_validated() {
        assert!(is_rank_key("V"));
        assert!(is_rank_key("a1"));
        assert!(!is_rank_key(""));
        assert!(!is_rank_key("a0"));
        assert!(!is_rank_key("a-"));
        assert!(!is_rank_key(&"a".repeat(33)));
    }

    #[test]
    fn between_is_strictly_between() {
        for (lo, hi) in [(None, None), (Some("V"), None), (None, Some("V")), (Some("V"), Some("W")), (Some("z"), None), (Some("1"), Some("2"))] {
            let k = rank_between(lo, hi).unwrap();
            assert!(is_rank_key(&k), "{k}");
            if let Some(lo) = lo {
                assert!(k.as_str() > lo, "{k} > {lo}");
            }
            if let Some(hi) = hi {
                assert!(k.as_str() < hi, "{k} < {hi}");
            }
        }
        assert_eq!(rank_between(Some("W"), Some("V")), None);
    }

    #[test]
    fn spread_ascends() {
        let keys = spread(200);
        assert!(keys.windows(2).all(|w| w[0] < w[1]));
        assert!(keys.iter().all(|k| is_rank_key(k)));
    }

    #[test]
    fn dense_ranks_are_peers_for_equal_keys() {
        let r = dense_ranks(["b", "a", "b", "c"]);
        assert_eq!((r["a"], r["b"], r["c"]), (1, 2, 3));
    }
}
