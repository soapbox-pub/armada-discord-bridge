//! Rekeys and Refoundings — CORD-06, the receiving side. A rotation delivers
//! per-recipient blobs (kind 3303, chunked) at an address derived from the PRIOR
//! secret; a member finding no blob across ALL chunks of a rotation that could
//! have named them knows they were removed.
//!
//! Blob plaintexts are fixed-width, carried as base64 inside NIP-44 (Armada's
//! signer APIs are string-only):
//! - channel rotation: 72 = `scope_id[32] ‖ epoch_be[8] ‖ new_key[32]`;
//! - base rotation: 104 adds `new_control_pk[32]`; 136 (staff) adds `new_control_root[32]`;
//! - a 72-byte base blob is the legacy pre-split form.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use crate::derive::{control_signer_group_key, epoch_key_commitment, recipient_locator};
use crate::edition::Citation;
use crate::stream::Opened;
use crate::{Bytes32, hex32, is_hex64, kinds, nip44, parse_tag_decimal, to_hex};

pub const ROOT_SCOPE_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// How many channel epochs past the held one to watch.
pub const CHANNEL_REKEY_LOOKAHEAD: u64 = 8;

#[derive(Debug, thiserror::Error)]
pub enum RekeyError {
    #[error("not a rekey rumor")]
    NotRekey,
    #[error("malformed {0}")]
    Field(&'static str),
    #[error("blob is {0} bytes, which is not a valid form")]
    Width(usize),
    #[error("blob scope or epoch does not match the rotation")]
    Splice,
    #[error("control_root does not derive to its control_pk")]
    ControlMismatch,
    #[error("blob failed to decrypt")]
    Decrypt,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Blob {
    pub locator: String,
    pub wrapped: String,
}

#[derive(Clone, Debug)]
pub struct ParsedRekey {
    pub rotator: String,
    pub scope_hex: String,
    pub new_epoch: u64,
    pub prev_epoch: u64,
    pub prev_commit: String,
    pub chunk_index: u64,
    pub chunk_count: u64,
    pub blobs: Vec<Blob>,
    pub ms: u64,
    /// A Severing Refounding (CORD-06 §3).
    pub severed: bool,
    pub authority: Option<Citation>,
}

/// The most blobs a reader takes from one rekey event (CORD-06 §1); writers send at most 80.
pub const MAX_REKEY_BLOBS_RECEIVED: usize = 120;

/// The value of a tag that may appear at most once: `Err` when it repeats.
fn unique_tag<'a>(tags: &'a [Vec<String>], name: &str) -> Result<Option<&'a str>, RekeyError> {
    let mut found = None;
    for t in tags.iter().filter(|t| t.len() >= 2 && t[0] == name) {
        if found.is_some() {
            return Err(RekeyError::Field("repeated tag"));
        }
        found = Some(t[1].as_str());
    }
    Ok(found)
}

/// Parse an opened rekey event into its rotation fields (Armada `parseRekey`,
/// Vector `parse_rekey_chunk`): machinery tags at most once, strict decimals,
/// exactly one `chunk` tag, `newepoch` above `prevepoch`, and blobs read as
/// serde reads a `Vec<RekeyBlob>`.
pub fn parse_rekey(opened: &Opened) -> Result<ParsedRekey, RekeyError> {
    let r = &opened.rumor;
    if r.kind != kinds::REKEY || opened.seal_kind() != kinds::SEAL_ENCRYPTED {
        return Err(RekeyError::NotRekey);
    }
    let scope = unique_tag(&r.tags, "scope")?.filter(|s| is_hex64(s)).ok_or(RekeyError::Field("scope"))?;
    let new_epoch = unique_tag(&r.tags, "newepoch")?.and_then(parse_tag_decimal).ok_or(RekeyError::Field("newepoch"))?;
    let prev_epoch = unique_tag(&r.tags, "prevepoch")?.and_then(parse_tag_decimal).ok_or(RekeyError::Field("prevepoch"))?;
    if new_epoch <= prev_epoch {
        return Err(RekeyError::Field("newepoch"));
    }
    let prev_commit = unique_tag(&r.tags, "prevcommit")?.filter(|s| is_hex64(s)).ok_or(RekeyError::Field("prevcommit"))?;
    let chunks: Vec<&Vec<String>> = r.tags.iter().filter(|t| t.len() >= 3 && t[0] == "chunk").collect();
    let [chunk] = chunks.as_slice() else { return Err(RekeyError::Field("chunk")) };
    let chunk_index = parse_tag_decimal(&chunk[1]).ok_or(RekeyError::Field("chunk"))?;
    let chunk_count = parse_tag_decimal(&chunk[2]).ok_or(RekeyError::Field("chunk"))?;
    if chunk_index < 1 || chunk_count < 1 || chunk_index > chunk_count || chunk_count > u32::MAX as u64 {
        return Err(RekeyError::Field("chunk"));
    }
    // CORD-06 §3: present means exactly "1".
    let severed = match unique_tag(&r.tags, "sever")? {
        None => false,
        Some("1") => true,
        Some(_) => return Err(RekeyError::Field("sever")),
    };
    let raw = crate::strict::parse_value(&r.content).ok_or(RekeyError::Field("content"))?;
    let list = raw.as_array().filter(|a| a.len() <= MAX_REKEY_BLOBS_RECEIVED).ok_or(RekeyError::Field("content"))?;
    let mut blobs = Vec::with_capacity(list.len());
    for b in list {
        if crate::strict::repeated_keys(b) {
            return Err(RekeyError::Field("content"));
        }
        let (Some(locator), Some(wrapped)) = (b.get("locator").and_then(|v| v.as_str()), b.get("wrapped").and_then(|v| v.as_str())) else {
            return Err(RekeyError::Field("content"));
        };
        blobs.push(Blob { locator: locator.to_owned(), wrapped: wrapped.to_owned() });
    }
    Ok(ParsedRekey {
        rotator: r.pubkey.clone(),
        scope_hex: scope.to_lowercase(),
        new_epoch,
        prev_epoch,
        prev_commit: prev_commit.to_lowercase(),
        chunk_index,
        chunk_count,
        blobs,
        ms: opened.ms,
        severed,
        authority: Citation::from_tags(&r.tags),
    })
}

/// One rotation's chunks, correlated by (rotator, scope, newepoch, prevcommit).
#[derive(Clone, Debug)]
pub struct Rotation {
    pub rotator: String,
    pub scope_hex: String,
    pub new_epoch: u64,
    pub prev_epoch: u64,
    pub prev_commit: String,
    /// The largest `n` any chunk declares: an extension raises it (CORD-06 §1).
    pub chunk_count: u64,
    /// One entry per chunk index; chunks claiming the same index union their blobs.
    pub chunks: BTreeMap<u64, ParsedRekey>,
    /// Any chunk marked it severing, so an unmarked chunk can't launder the mark away.
    pub severed: bool,
    pub authority: Option<Citation>,
}

impl Rotation {
    /// A missing chunk is never a removal.
    pub fn is_complete(&self) -> bool {
        self.chunks.len() as u64 >= self.chunk_count
    }

    pub fn find_blob(&self, locator_hex: &str) -> Option<&Blob> {
        self.chunks.values().flat_map(|c| c.blobs.iter()).find(|b| b.locator == locator_hex)
    }

    /// When this rotation published: its earliest chunk.
    pub fn published_ms(&self) -> u64 {
        self.chunks.values().map(|c| c.ms).min().unwrap_or(0)
    }

    /// Continuity against the held key: `prevcommit` must commit to exactly it.
    pub fn continues_from(&self, held_epoch: u64, held_key: &Bytes32) -> Continuity {
        if self.prev_epoch == held_epoch {
            if to_hex(&epoch_key_commitment(held_epoch, held_key)) == self.prev_commit { Continuity::Ok } else { Continuity::Fork }
        } else if self.prev_epoch > held_epoch {
            Continuity::Gap
        } else {
            Continuity::Fork
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Continuity {
    Ok,
    Gap,
    Fork,
}

pub fn group_rotations(parsed: Vec<ParsedRekey>) -> Vec<Rotation> {
    let mut by_key: BTreeMap<(String, String, u64, String), Rotation> = BTreeMap::new();
    for p in parsed {
        let key = (p.rotator.clone(), p.scope_hex.clone(), p.new_epoch, p.prev_commit.clone());
        let set = by_key.entry(key).or_insert_with(|| Rotation {
            rotator: p.rotator.clone(),
            scope_hex: p.scope_hex.clone(),
            new_epoch: p.new_epoch,
            prev_epoch: p.prev_epoch,
            prev_commit: p.prev_commit.clone(),
            chunk_count: p.chunk_count,
            chunks: BTreeMap::new(),
            severed: false,
            authority: p.authority.clone(),
        });
        set.chunk_count = set.chunk_count.max(p.chunk_count);
        set.severed |= p.severed;
        match set.chunks.get_mut(&p.chunk_index) {
            // A rotation published when its earliest chunk did (Armada takes the
            // earliest of all, extensions included): keeping the first one met
            // could date it after a member joined, reading as a cut it isn't.
            Some(held) => {
                held.ms = held.ms.min(p.ms);
                held.blobs.extend(p.blobs);
            }
            None => {
                set.chunks.insert(p.chunk_index, p);
            }
        }
    }
    by_key.into_values().collect()
}

/// My blob's locator for a rotation.
pub fn my_locator(rotator: &str, me: &str, scope_hex: &str, new_epoch: u64) -> Option<String> {
    Some(to_hex(&recipient_locator(&hex32(rotator)?, &hex32(me)?, &hex32(scope_hex)?, new_epoch)))
}

/// Decrypt a blob under the rotator↔me pairwise key.
pub fn open_blob(blob: &Blob, my_sk: &nostr::prelude::SecretKey, rotator: &nostr::prelude::PublicKey) -> Result<Vec<u8>, RekeyError> {
    let conv = crate::derive::conversation_key(my_sk, rotator);
    let b64 = nip44::decrypt_str(&conv, &blob.wrapped).map_err(|_| RekeyError::Decrypt)?;
    STANDARD.decode(b64.trim()).map_err(|_| RekeyError::Decrypt)
}

fn read_epoch(plain: &[u8]) -> u64 {
    u64::from_be_bytes(plain[32..40].try_into().unwrap())
}

/// Parse a 72-byte channel blob, verifying its inner scope and epoch.
pub fn decode_channel_blob(plain: &[u8], channel_id: &Bytes32, epoch: u64) -> Result<Bytes32, RekeyError> {
    if plain.len() != 72 {
        return Err(RekeyError::Width(plain.len()));
    }
    if &plain[..32] != channel_id || read_epoch(plain) != epoch {
        return Err(RekeyError::Splice);
    }
    Ok(plain[40..72].try_into().unwrap())
}

#[derive(Clone, Debug)]
pub struct BaseBlob {
    pub new_root: Bytes32,
    /// Absent on a legacy 72-byte blob.
    pub control_pk: Option<String>,
    /// The staff write secret, already checked to derive to `control_pk`.
    pub control_root: Option<Bytes32>,
}

/// Parse a 72/104/136-byte base blob.
pub fn decode_base_blob(plain: &[u8], community_id: &Bytes32, epoch: u64) -> Result<BaseBlob, RekeyError> {
    if !matches!(plain.len(), 72 | 104 | 136) {
        return Err(RekeyError::Width(plain.len()));
    }
    if plain[..32] != [0u8; 32] || read_epoch(plain) != epoch {
        return Err(RekeyError::Splice);
    }
    let new_root: Bytes32 = plain[40..72].try_into().unwrap();
    if plain.len() == 72 {
        return Ok(BaseBlob { new_root, control_pk: None, control_root: None });
    }
    let control_pk = to_hex(&plain[72..104]);
    if plain.len() == 104 {
        return Ok(BaseBlob { new_root, control_pk: Some(control_pk), control_root: None });
    }
    let control_root: Bytes32 = plain[104..136].try_into().unwrap();
    if control_signer_group_key(&control_root, community_id, epoch).pk_hex() != control_pk {
        return Err(RekeyError::ControlMismatch);
    }
    Ok(BaseBlob { new_root, control_pk: Some(control_pk), control_root: Some(control_root) })
}

/// The Grant `control_wrap` plaintext: `epoch_be[8] ‖ control_root[32]`, the
/// epoch inside the ciphertext like every rekey blob (CORD-04 §3).
pub fn encode_control_wrap(epoch: u64, control_root: &Bytes32) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[..8].copy_from_slice(&epoch.to_be_bytes());
    out[8..].copy_from_slice(control_root);
    out
}

/// A Grant's `control_wrap` field: the plaintext, base64, NIP-44'd under the
/// granter↔member pairwise key (a bunker signer's APIs are string-only).
pub fn seal_control_wrap(epoch: u64, control_root: &Bytes32, granter: &nostr::prelude::SecretKey, member: &nostr::prelude::PublicKey) -> Result<String, nip44::Nip44Error> {
    let conv = crate::derive::conversation_key(granter, member);
    nip44::encrypt_str(&conv, &STANDARD.encode(encode_control_wrap(epoch, control_root)))
}

/// Parse a decrypted 40-byte Grant `control_wrap`: `epoch_be[8] ‖ control_root[32]`.
pub fn decode_control_wrap(plain: &[u8]) -> Option<(u64, Bytes32)> {
    (plain.len() == 40).then(|| (u64::from_be_bytes(plain[..8].try_into().unwrap()), plain[8..40].try_into().unwrap()))
}

/// Blobs per Channel-rotation event a writer sends (CORD-06 §1); readers accept 120.
pub const CHANNEL_BLOBS_PER_EVENT: usize = 80;

/// A Channel rotation's rumors (CORD-06 §1): `new_key` at `new_epoch` for each
/// recipient (the rotator always among them), committing to `(prev_epoch,
/// prev_key)` so a holder of the prior key can prove continuity. A Private
/// Channel's birth on the ranked Roster is one of these from `(0,
/// community_root)` to epoch 1 (CORD-03 §2). `authority` rides every chunk so
/// a partial holder can judge it; absent when the owner rotates.
#[allow(clippy::too_many_arguments)]
pub fn build_channel_rotation(
    rotator: &nostr::prelude::Keys,
    channel_id: &Bytes32,
    new_epoch: u64,
    prev_epoch: u64,
    prev_key: &Bytes32,
    new_key: &Bytes32,
    recipients: &[String],
    ms: u64,
    authority: Option<&Citation>,
) -> Result<Vec<crate::rumor::Rumor>, RekeyError> {
    let me = rotator.public_key().to_hex();
    let scope_hex = to_hex(channel_id);
    let mut plain = Vec::with_capacity(72);
    plain.extend_from_slice(channel_id);
    plain.extend_from_slice(&new_epoch.to_be_bytes());
    plain.extend_from_slice(new_key);
    let plain = STANDARD.encode(plain);
    let mut who: Vec<String> = vec![me.clone()];
    for r in recipients {
        let r = r.to_lowercase();
        if !who.contains(&r) {
            who.push(r);
        }
    }
    let mut blobs = Vec::new();
    for r in &who {
        let pk = hex32(r).and_then(|b| nostr::prelude::PublicKey::from_slice(&b).ok()).ok_or(RekeyError::Field("recipient"))?;
        let conv = crate::derive::conversation_key(rotator.secret_key(), &pk);
        let locator = my_locator(&me, r, &scope_hex, new_epoch).ok_or(RekeyError::Field("recipient"))?;
        let wrapped = nip44::encrypt_str(&conv, &plain).map_err(|_| RekeyError::Decrypt)?;
        blobs.push(serde_json::json!({ "locator": locator, "wrapped": wrapped }));
    }
    let prev_commit = to_hex(&epoch_key_commitment(prev_epoch, prev_key));
    let chunks: Vec<&[serde_json::Value]> = blobs.chunks(CHANNEL_BLOBS_PER_EVENT).collect();
    let n = chunks.len().to_string();
    Ok(chunks
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let mut tags = vec![
                vec!["scope".to_string(), scope_hex.clone()],
                vec!["newepoch".into(), new_epoch.to_string()],
                vec!["prevepoch".into(), prev_epoch.to_string()],
                vec!["prevcommit".into(), prev_commit.clone()],
                vec!["chunk".into(), (i + 1).to_string(), n.clone()],
            ];
            if let Some(a) = authority {
                tags.push(a.to_tag());
            }
            crate::rumor::Rumor::new(kinds::REKEY, serde_json::Value::Array(c.to_vec()).to_string(), tags, &me, Some(ms), None)
        })
        .collect())
}
