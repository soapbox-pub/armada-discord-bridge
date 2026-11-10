//! A restricted Channel's Writers ledger (CORD-03 §1, vsk 18): which writer
//! address takes posts when, who certifies its writers, and which writers it no
//! longer vouches for. A port of Armada's `writers.ts` (from Vector's
//! `community/v2/writers.rs`).
//!
//! A Channel is restricted while `@everyone` can't send there. Posts then go to
//! a writer address whose secret only its writers hold, each carrying a
//! certificate from the epoch's certifier, so a member the Roster stopped
//! letting post can't keep posting with a key they kept. Readers hold every post
//! the ledger doesn't stand behind.

use nostr::prelude::SecretKey;
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::kinds;
use crate::rumor::Rumor;
use crate::strict;
use crate::{Bytes32, hex32, is_hex64, to_hex};

/// At most this many entries, and retired windows (CORD-03 §1).
pub const MAX_LEDGER: usize = 64;
pub const MAX_RETIRED: usize = 64;
const MAX_EPOCH: u64 = 1 << 53;
/// How far a ledger entry may sit from its edition's own time (CORD-03 §1).
pub const LEDGER_ENTRY_SKEW_MS: u64 = 10 * 60_000;
/// CORD-02 §5's horizon: an entry dated past it is refused.
pub const LEDGER_HORIZON_MS: u64 = 60 * 60_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Spell {
    Writer { epoch: u64, pk: String, root: u64, by: String, certifier: Option<String> },
    Open,
    Stop { writer: String },
    Other,
}

impl Spell {
    fn moves(&self) -> bool {
        matches!(self, Spell::Writer { .. } | Spell::Open)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LedgerEntry {
    pub at: u64,
    pub spell: Spell,
    /// Unknown fields, carried through an editor's editions. `from` on a stop.
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetiredWriter {
    pub epoch: u64,
    pub pk: String,
    pub from: u64,
    pub to: u64,
    pub certifier: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ledger {
    pub channel: String,
    pub entries: Vec<LedgerEntry>,
    pub retired: Vec<RetiredWriter>,
    pub extra: Map<String, Value>,
}

/// One writer address's window: when it opened and, once moved past, closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Window {
    pub epoch: u64,
    pub pk: String,
    pub from: u64,
    pub to: Option<u64>,
    pub certifier: Option<String>,
}

fn is_point(hex: &Value) -> Option<String> {
    let s = hex.as_str().filter(|s| is_hex64(s))?;
    XOnlyPublicKey::from_slice(&hex32(s)?).ok()?;
    Some(s.to_lowercase())
}

fn epoch_of(v: &Value) -> Option<u64> {
    v.as_u64().filter(|e| *e > 0 && *e < MAX_EPOCH)
}

/// When an entry takes effect: its own date, or for a stop the departure it records if earlier.
pub fn effective_at(e: &LedgerEntry) -> u64 {
    match e.spell {
        Spell::Stop { .. } => e.extra.get("from").and_then(Value::as_u64).map_or(e.at, |f| f.min(e.at)),
        _ => e.at,
    }
}

/// Parse a ledger, or `None` when it is malformed (CORD-03 §1).
pub fn parse_ledger(content: &str) -> Option<Ledger> {
    let top = strict::parse_value(content)?;
    let top = top.as_object()?;
    let channel = top.get("channel")?.as_str().filter(|s| is_hex64(s))?.to_lowercase();
    let ledger = top.get("ledger")?.as_array()?;
    let extra: Map<String, Value> =
        strict::fields(top).filter(|(k, _)| !matches!(k.as_str(), "channel" | "ledger" | "retired")).map(|(k, v)| (k.clone(), v.clone())).collect();
    let mut retired = Vec::new();
    if let Some(raw) = top.get("retired") {
        for r in raw.as_array()? {
            let r = r.as_array().filter(|r| r.len() == 4 || r.len() == 5)?;
            retired.push(RetiredWriter {
                epoch: epoch_of(&r[0])?,
                pk: is_point(&r[1])?,
                from: r[2].as_u64()?,
                to: r[3].as_u64()?,
                certifier: if r.len() == 5 { Some(is_point(&r[4])?) } else { None },
            });
        }
    }
    if ledger.len() > MAX_LEDGER || retired.len() > MAX_RETIRED {
        return None;
    }
    let mut entries = Vec::new();
    for raw in ledger {
        let o = raw.as_object()?;
        let at = o.get("at")?.as_u64()?;
        let g = |k: &str| o.get(k);
        let none = |ks: &[&str]| ks.iter().all(|k| g(k).is_none());
        let mut rest: Map<String, Value> = strict::fields(o)
            .filter(|(k, _)| !matches!(k.as_str(), "at" | "stop" | "open" | "epoch" | "writer" | "root" | "by" | "certifier"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let certifier = g("certifier");
        let spell = if none(&["open", "epoch", "writer", "root", "by"]) && g("stop").is_some() {
            if let Some(c) = certifier {
                rest.insert("certifier".into(), c.clone());
            }
            Spell::Stop { writer: is_point(g("stop")?)? }
        } else if none(&["open", "epoch", "writer", "root", "by", "stop"]) {
            if let Some(c) = certifier {
                rest.insert("certifier".into(), c.clone());
            }
            Spell::Other
        } else if g("open") == Some(&Value::Bool(true)) && none(&["epoch", "writer", "root", "by", "stop"]) {
            if let Some(c) = certifier {
                rest.insert("certifier".into(), c.clone());
            }
            Spell::Open
        } else if none(&["open", "stop"]) && g("epoch").is_some() && g("writer").is_some() && g("root").is_some() && g("by").is_some() {
            let by = g("by")?.as_str().filter(|s| is_hex64(s))?.to_lowercase();
            let certifier = match certifier {
                Some(c) => Some(is_point(c)?),
                None => None,
            };
            Spell::Writer { epoch: epoch_of(g("epoch")?)?, pk: is_point(g("writer")?)?, root: g("root")?.as_u64()?, by, certifier }
        } else {
            return None;
        };
        entries.push(LedgerEntry { at, spell, extra: rest });
    }
    let out = Ledger { channel, entries, retired, extra };
    well_formed(&out).then_some(out)
}

fn well_formed(l: &Ledger) -> bool {
    if l.entries.windows(2).any(|w| w[0].at > w[1].at) {
        return false;
    }
    for (i, e) in l.entries.iter().enumerate() {
        if matches!(e.spell, Spell::Stop { .. }) && l.entries[..i].iter().rev().find(|e| e.spell.moves()).is_some_and(|e| e.spell == Spell::Open) {
            return false;
        }
    }
    if l.retired.iter().any(|r| r.from > r.to) {
        return false;
    }
    writer_windows(l).windows(2).all(|w| w[0].epoch < w[1].epoch)
}

/// Every writer address, retired then live, with when its window opened and closed.
pub fn writer_windows(l: &Ledger) -> Vec<Window> {
    let mut out: Vec<Window> =
        l.retired.iter().map(|r| Window { epoch: r.epoch, pk: r.pk.clone(), from: r.from, to: Some(r.to), certifier: r.certifier.clone() }).collect();
    for (i, e) in l.entries.iter().enumerate() {
        if let Spell::Writer { epoch, pk, certifier, .. } = &e.spell {
            let next = l.entries[i + 1..].iter().find(|n| n.spell.moves());
            out.push(Window { epoch: *epoch, pk: pk.clone(), from: e.at, to: next.map(|n| n.at), certifier: certifier.clone() });
        }
    }
    out
}

/// `l` with `entry` appended verbatim; at the cap the oldest entry goes, a
/// writer one into `retired` (CORD-03 §1). `None` when that leaves it malformed.
fn ledger_with(l: &Ledger, entry: &LedgerEntry) -> Option<Ledger> {
    let mut grown = l.clone();
    grown.entries.push(entry.clone());
    if grown.entries.len() > MAX_LEDGER {
        let gone = grown.entries.remove(0);
        if let Spell::Writer { epoch, pk, certifier, .. } = gone.spell {
            // Its window runs to the next entry that moves posts; the live one never retires.
            let to = grown.entries.iter().find(|e| e.spell.moves())?.at;
            grown.retired.push(RetiredWriter { epoch, pk, from: gone.at, to, certifier });
            if grown.retired.len() > MAX_RETIRED {
                grown.retired.remove(0);
            }
        }
    }
    (well_formed(&grown) && grown.entries.len() <= MAX_LEDGER && grown.retired.len() <= MAX_RETIRED).then_some(grown)
}

/// Whether `next` is `prev` with exactly one entry appended verbatim, the
/// oldest moving to `retired` at the cap (CORD-03 §1).
pub fn ledger_extends(next: &Ledger, prev: &Ledger) -> bool {
    let Some(last) = next.entries.last() else { return false };
    ledger_with(prev, last).is_some_and(|g| g.channel == next.channel && g.entries == next.entries && g.retired == next.retired)
}

/// An empty ledger for a Channel.
pub fn empty_ledger(channel_id_hex: &str) -> Ledger {
    Ledger { channel: channel_id_hex.to_lowercase(), entries: Vec::new(), retired: Vec::new(), extra: Map::new() }
}

/// `l` with `spell` appended at `at`, never before the last entry.
pub fn ledger_appended(l: &Ledger, at: u64, spell: Spell) -> Option<Ledger> {
    let when = l.entries.last().map_or(at, |last| at.max(last.at));
    ledger_with(l, &LedgerEntry { at: when, spell, extra: Map::new() })
}

/// A ledger's content as Vector writes it: every object's keys sorted, unknown
/// fields carried (serde_json's default map is sorted, so building through it sorts).
pub fn ledger_to_json(l: &Ledger) -> String {
    let entries: Vec<Value> = l
        .entries
        .iter()
        .map(|e| {
            let mut o: std::collections::BTreeMap<String, Value> = e.extra.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            o.insert("at".into(), Value::from(e.at));
            match &e.spell {
                Spell::Writer { epoch, pk, root, by, certifier } => {
                    o.insert("epoch".into(), Value::from(*epoch));
                    o.insert("writer".into(), Value::from(pk.clone()));
                    o.insert("root".into(), Value::from(*root));
                    o.insert("by".into(), Value::from(by.clone()));
                    if let Some(c) = certifier {
                        o.insert("certifier".into(), Value::from(c.clone()));
                    }
                }
                Spell::Open => {
                    o.insert("open".into(), Value::Bool(true));
                }
                Spell::Stop { writer } => {
                    o.insert("stop".into(), Value::from(writer.clone()));
                }
                Spell::Other => {}
            }
            serde_json::to_value(o).expect("maps serialize")
        })
        .collect();
    let mut top: std::collections::BTreeMap<String, Value> = l.extra.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    top.insert("channel".into(), Value::from(l.channel.clone()));
    top.insert("ledger".into(), Value::Array(entries));
    if !l.retired.is_empty() {
        let r: Vec<Value> = l
            .retired
            .iter()
            .map(|r| {
                let mut v = vec![Value::from(r.epoch), Value::from(r.pk.clone()), Value::from(r.from), Value::from(r.to)];
                if let Some(c) = &r.certifier {
                    v.push(Value::from(c.clone()));
                }
                Value::Array(v)
            })
            .collect();
        top.insert("retired".into(), Value::Array(r));
    }
    sorted(serde_json::to_value(top).expect("maps serialize")).to_string()
}

/// Every object's keys sorted, recursively (the `preserve_order` map keeps insertion order).
fn sorted(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<(String, Value)> = m.into_iter().collect();
            keys.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(keys.into_iter().map(|(k, v)| (k, sorted(v))).collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(sorted).collect()),
        v => v,
    }
}

/// Whether a kind moves to the writer address with posting; reactions,
/// deletions and voice signals stay at the read address.
pub fn rides_writer_address(kind: u16) -> bool {
    !matches!(kind, kinds::REACTION | kinds::DELETE | kinds::VOICE_PRESENCE | kinds::VOICE_DIRECTIVE)
}

/// The writer window taking posts now, when the ledger restricts the Channel.
pub fn current_writer(l: &Ledger) -> Option<Window> {
    if !ledger_restricted(l) {
        return None;
    }
    writer_windows(l).into_iter().find(|w| w.to.is_none())
}

/// Whether posts land at a writer address now.
pub fn ledger_restricted(l: &Ledger) -> bool {
    l.entries.iter().rev().find(|e| e.spell.moves()).is_some_and(|e| matches!(e.spell, Spell::Writer { .. }))
}

/// The epoch a newly minted writer secret takes; `None` once the range is spent.
pub fn next_writer_epoch(l: &Ledger) -> Option<u64> {
    let next = writer_windows(l).iter().map(|w| w.epoch).max().unwrap_or(0) + 1;
    (next < MAX_EPOCH).then_some(next)
}

/// Whether `writer` was stopped at writer `epoch` by `at_ms` (CORD-03 §1).
pub fn stopped(l: &Ledger, epoch: u64, writer: &str, at_ms: u64) -> bool {
    let names = |e: &LedgerEntry| effective_at(e) <= at_ms && matches!(&e.spell, Spell::Stop { writer: w } if w == writer);
    if let Some(start) = l.entries.iter().position(|e| matches!(e.spell, Spell::Writer { epoch: x, .. } if x == epoch)) {
        for e in &l.entries[start + 1..] {
            if e.spell.moves() {
                break;
            }
            if names(e) {
                return true;
            }
        }
        return false;
    }
    let Some(r) = l.retired.iter().find(|x| x.epoch == epoch) else { return false };
    for e in &l.entries {
        if e.spell.moves() {
            break;
        }
        if e.at >= r.from && e.at <= r.to && names(e) {
            return true;
        }
    }
    false
}

/// Whether a post at the read address dated `at_ms` stands: inside no writer window, live or retired.
pub fn read_address_takes(l: &Ledger, at_ms: u64) -> bool {
    if l.retired.iter().any(|r| at_ms >= r.from && at_ms < r.to) {
        return false;
    }
    !l.entries.iter().rev().find(|e| e.at <= at_ms && e.spell.moves()).is_some_and(|e| matches!(e.spell, Spell::Writer { .. }))
}

/// Whether a post at writer `epoch`'s address dated `at_ms` stands by the window.
pub fn writer_address_takes(l: &Ledger, epoch: u64, at_ms: u64) -> bool {
    writer_windows(l).iter().any(|w| w.epoch == epoch && w.to.is_none_or(|to| at_ms < to))
}

/// The certifier of writer `epoch`, live or retired.
pub fn certifier_of(l: &Ledger, epoch: u64) -> Option<String> {
    writer_windows(l).into_iter().find(|w| w.epoch == epoch).and_then(|w| w.certifier)
}

const CERT_LABEL: &[u8] = b"concord/writer-cert";

/// What a writer certificate signs (CORD-03 §1, A.7).
pub fn cert_digest(community_id: &Bytes32, channel_id: &Bytes32, epoch: u64, writer: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(CERT_LABEL);
    h.update(community_id);
    h.update(channel_id);
    h.update(epoch.to_be_bytes());
    h.update(writer);
    h.finalize().into()
}

/// The id of the never-published kind-3320 event a certificate signs.
pub fn cert_event_id(certifier: &str, digest: &Bytes32) -> Bytes32 {
    let r = Rumor { id: String::new(), pubkey: certifier.to_owned(), created_at: 0, kind: kinds::WRITER_CERT, tags: vec![vec!["digest".into(), to_hex(digest)]], content: String::new() };
    hex32(&r.compute_id()).expect("hash is 32 bytes")
}

pub fn verify_writer_cert(certifier: &str, digest: &Bytes32, cert_hex: &str) -> bool {
    if cert_hex.len() != 128 || !cert_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let Some(pk) = hex32(certifier).and_then(|b| XOnlyPublicKey::from_slice(&b).ok()) else { return false };
    let Ok(sig_bytes) = hex::decode(cert_hex) else { return false };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else { return false };
    Secp256k1::verification_only().verify_schnorr(&sig, &cert_event_id(certifier, digest), &pk).is_ok()
}

pub fn sign_writer_cert(certifier: &SecretKey, digest: &Bytes32) -> String {
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, certifier);
    let pk = kp.x_only_public_key().0;
    let id = cert_event_id(&to_hex(&pk.serialize()), digest);
    // BIP-340 with fresh auxiliary randomness, as nostr signs events.
    let aux = crate::random32();
    to_hex(secp.sign_schnorr_with_aux_rand(&id, &kp, &aux).as_ref())
}

/// Whether a restricted Channel's post stands by the ledger (CORD-03 §1): at a
/// writer address (its `wepoch`), within the window, certified for its author
/// if the epoch names a certifier, and not stopped; at the read address,
/// outside any writer window. The owner's and a manager's posts stand
/// regardless — the caller's judgement, not the ledger's.
pub fn post_stands(l: &Ledger, community_id: &Bytes32, author: &str, ms: u64, tags: &[Vec<String>]) -> bool {
    let Some(wepoch) = crate::rumor::tag_value(tags, "wepoch") else { return read_address_takes(l, ms) };
    let Some(epoch) = crate::parse_tag_decimal(wepoch) else { return false };
    if !writer_address_takes(l, epoch, ms) || stopped(l, epoch, author, ms) {
        return false;
    }
    let Some(certifier) = certifier_of(l, epoch) else { return true };
    let Some(cert) = crate::rumor::tag_value(tags, "wcert") else { return false };
    let (Some(channel), Some(writer)) = (hex32(&l.channel), hex32(author)) else { return false };
    verify_writer_cert(&certifier, &cert_digest(community_id, &channel, epoch, &writer), cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::prelude::Keys;

    fn pk(k: &Keys) -> String {
        k.public_key().to_hex()
    }

    #[test]
    fn a_ledger_round_trips_and_extends_by_one_entry() {
        let (w, c, by) = (Keys::generate(), Keys::generate(), Keys::generate());
        let chan = "11".repeat(32);
        let l = ledger_appended(&empty_ledger(&chan), 1_000, Spell::Writer { epoch: 1, pk: pk(&w), root: 0, by: pk(&by), certifier: Some(pk(&c)) }).unwrap();
        let parsed = parse_ledger(&ledger_to_json(&l)).unwrap();
        assert_eq!(parsed, l);
        assert!(ledger_restricted(&l));
        let stop = ledger_appended(&l, 2_000, Spell::Stop { writer: pk(&w) }).unwrap();
        assert!(ledger_extends(&stop, &l));
        assert!(!ledger_extends(&l, &stop));
        let open = ledger_appended(&stop, 3_000, Spell::Open).unwrap();
        assert!(!ledger_restricted(&open));
        assert!(read_address_takes(&open, 3_000));
        assert!(!read_address_takes(&open, 1_500));
    }

    #[test]
    fn a_certificate_signs_for_one_writer() {
        let (cert_key, writer) = (Keys::generate(), Keys::generate());
        let d = cert_digest(&[1; 32], &[2; 32], 3, &writer.public_key().to_bytes());
        let sig = sign_writer_cert(cert_key.secret_key(), &d);
        assert!(verify_writer_cert(&pk(&cert_key), &d, &sig));
        let other = cert_digest(&[1; 32], &[2; 32], 3, &[9; 32]);
        assert!(!verify_writer_cert(&pk(&cert_key), &other, &sig));
    }

    #[test]
    fn posts_stand_by_window_cert_and_stop() {
        let (w, c, by, author) = (Keys::generate(), Keys::generate(), Keys::generate(), Keys::generate());
        let chan = [7u8; 32];
        let cid = [5u8; 32];
        let l = ledger_appended(&empty_ledger(&to_hex(&chan)), 1_000, Spell::Writer { epoch: 1, pk: pk(&w), root: 0, by: pk(&by), certifier: Some(pk(&c)) }).unwrap();
        let cert = sign_writer_cert(c.secret_key(), &cert_digest(&cid, &chan, 1, &author.public_key().to_bytes()));
        let tags = vec![vec!["wepoch".into(), "1".into()], vec!["wcert".into(), cert]];
        assert!(post_stands(&l, &cid, &pk(&author), 5_000, &tags));
        assert!(!post_stands(&l, &cid, &pk(&author), 5_000, &tags[..1]), "the certificate is required");
        assert!(!post_stands(&l, &cid, &pk(&author), 5_000, &[]), "the read address is closed");
        let stopped_l = ledger_appended(&l, 4_000, Spell::Stop { writer: pk(&author) }).unwrap();
        assert!(!post_stands(&stopped_l, &cid, &pk(&author), 5_000, &tags));
        assert!(post_stands(&stopped_l, &cid, &pk(&author), 3_000, &tags), "a stop isn't retroactive");
    }
}
