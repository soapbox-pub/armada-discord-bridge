//! NIP-92 `imeta` as Armada actually writes and reads it.
//!
//! Two facts about that dialect are not visible from NIP-92 alone, and both are
//! why bridged media arrived broken:
//!
//!  - **Every attachment sent from a Concord community is client-encrypted.**
//!    The blob at `url` is AES-256-GCM ciphertext with the GCM tag appended,
//!    and the key rides in the same tag under the Vector/0xChat field names
//!    (`encryption-algorithm` / `decryption-key` / `decryption-nonce`, plus
//!    `ox`, the SHA-256 of the *plaintext*). A bridge that reads only `url` and
//!    `size` downloads ciphertext and uploads it to Discord as an image.
//!
//!  - **Discord types an upload by its FILENAME, not by any metadata.** Blossom
//!    URLs are content-addressed, so the last path segment is frequently a bare
//!    hex hash; naming the file after it produces an unpreviewable attachment
//!    no matter how correct the `m` field is. The `m` field is the one that
//!    knows, because on an encrypted attachment the served content-type
//!    describes the ciphertext.
//!
//! The parse is deliberately more permissive than the write side (base64 key
//! material, absent `ox`) and the *validity* check is deliberately separate
//! from it — see [`is_supported_encryption`].

use std::collections::HashMap;
use std::sync::LazyLock;

use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use regex::Regex;
use url::Url;

/// AES-GCM blob-encryption parameters carried in an imeta tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImetaEncryption {
    /// Algorithm as sent, lowercased. Only `aes-gcm` can be applied.
    pub algorithm: String,
    /// AES-256 key, normalised to lowercase hex, or the raw value if undecodable.
    pub key: String,
    /// AES-GCM nonce/IV as lowercase hex. Armada and 0xChat use 16 bytes, not 12.
    pub nonce: String,
    /// SHA-256 (hex) of the PLAINTEXT. Absent on a forward whose sender lacked it.
    pub ox: Option<String>,
}

/// Bytes of GCM authentication tag WebCrypto appends to its ciphertext.
const GCM_TAG_BYTES: usize = 16;

/// Space-delimited imeta fields -> a map; a later duplicate field wins.
///
/// Split on the FIRST space only: `waveform` and `alt` carry multi-word values,
/// and a field with no space at all is not a field.
pub fn imeta_fields(tag: &[String]) -> HashMap<String, String> {
    tag.iter()
        .skip(1)
        .filter_map(|part| part.split_once(' '))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

/// Encryption parameters, or `None` when the attachment is plaintext.
///
/// A value comes back whenever `encryption-algorithm` is present at all — even
/// for an algorithm we cannot apply or key material that is malformed. Folding
/// "unreadable" back into `None` is what would make the caller treat the blob
/// as plaintext and hand ciphertext to Discord, which is the bug.
pub fn parse_imeta_encryption(fields: &HashMap<String, String>) -> Option<ImetaEncryption> {
    let algorithm = fields.get("encryption-algorithm").filter(|a| !a.is_empty())?;
    let field = |name: &str| fields.get(name).map_or("", String::as_str);
    Some(ImetaEncryption {
        algorithm: algorithm.to_lowercase(),
        key: decode_key_material(field("decryption-key")),
        nonce: decode_key_material(field("decryption-nonce")),
        ox: fields.get("ox").filter(|ox| is_hex(ox, Some(64))).map(|ox| ox.to_lowercase()),
    })
}

/// Whether [`decrypt_blob`] can actually apply these parameters.
///
/// The nonce must be 12 or 16 bytes, the two sizes `decrypt_blob` implements;
/// anything else fails closed here, before the blob is downloaded.
pub fn is_supported_encryption(enc: Option<&ImetaEncryption>) -> bool {
    let Some(enc) = enc else { return false };
    enc.algorithm == "aes-gcm" && is_hex(&enc.key, Some(64)) && (is_hex(&enc.nonce, Some(24)) || is_hex(&enc.nonce, Some(32)))
}

/// Ciphertext -> plaintext, verified against `ox`.
///
/// The layout is WebCrypto's own output uploaded verbatim: `ciphertext ‖ 16-byte
/// tag`. The nonce is 16 bytes rather than the usual 12 (0xChat
/// compatibility), so the IV length is taken from the tag rather than assumed.
///
/// Errors rather than returning the bytes on any failure. A blob whose `ox`
/// does not match has been swapped underneath the sender's key, and the bridge
/// would be re-publishing it into Discord under that sender's name.
pub fn decrypt_blob(data: &[u8], enc: &ImetaEncryption) -> Result<Vec<u8>> {
    if data.len() < GCM_TAG_BYTES {
        bail!("ciphertext is shorter than its GCM tag");
    }
    let nonce_len = hex::decode(&enc.nonce).map_err(|_| anyhow!("decryption nonce is not hex"))?.len();
    if nonce_len != 12 && nonce_len != 16 {
        bail!("unsupported AES-GCM nonce length {nonce_len}");
    }
    let plaintext = concord::media::decrypt_pointer(data, &enc.key, &enc.nonce)
        .ok_or_else(|| anyhow!("attachment failed AES-GCM decryption"))?;
    if let Some(ox) = &enc.ox
        && concord::media::sha256_hex(&plaintext) != *ox
    {
        bail!("decrypted attachment does not match its `ox` hash");
    }
    Ok(plaintext)
}

/// Extensions, by MIME. Only the types worth rendering inline are listed; the
/// fallback derives one from the subtype, which is right far more often than it
/// is wrong (`application/zip` -> `zip`) and harmless when it is.
const EXTENSION_BY_MIME: &[(&str, &str)] = &[
    ("image/jpeg", "jpg"),
    ("image/png", "png"),
    ("image/gif", "gif"),
    ("image/webp", "webp"),
    ("image/avif", "avif"),
    ("image/svg+xml", "svg"),
    ("video/mp4", "mp4"),
    ("video/webm", "webm"),
    ("video/quicktime", "mov"),
    ("audio/mpeg", "mp3"),
    ("audio/mp4", "m4a"),
    ("audio/ogg", "ogg"),
    ("audio/wav", "wav"),
    ("application/pdf", "pdf"),
];

/// The reverse, for URLs we can only type by looking at them.
const MIME_BY_EXTENSION: &[(&str, &str)] = &[
    ("jpg", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("png", "image/png"),
    ("gif", "image/gif"),
    ("webp", "image/webp"),
    ("avif", "image/avif"),
    ("mp4", "video/mp4"),
    ("webm", "video/webm"),
    ("mov", "video/quicktime"),
    ("mp3", "audio/mpeg"),
    ("m4a", "audio/mp4"),
    ("ogg", "audio/ogg"),
    ("wav", "audio/wav"),
];

/// Trailing `.ext` of a filename or path segment.
static EXTENSION_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.[A-Za-z0-9]{1,8}$").unwrap());

/// Longest filename handed to Discord's multipart upload.
const MAX_FILENAME_CHARS: usize = 96;

pub fn extension_for_mime(mime: &str) -> Option<String> {
    let ty = mime.split(';').next().unwrap_or("").trim().to_lowercase();
    if let Some((_, ext)) = EXTENSION_BY_MIME.iter().find(|(m, _)| *m == ty) {
        return Some((*ext).to_owned());
    }
    let subtype = ty.split('/').nth(1)?.split('+').next()?;
    let ok = (1..=8).contains(&subtype.len()) && subtype.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    ok.then(|| subtype.to_owned())
}

/// The MIME a URL's extension implies, for media types only.
pub fn mime_from_url(url: &str) -> Option<&'static str> {
    let parsed = Url::parse(url).ok()?;
    let last = parsed.path().rsplit('/').next().unwrap_or("");
    let ext = EXTENSION_RE.find(last)?.as_str()[1..].to_lowercase();
    MIME_BY_EXTENSION.iter().find(|(e, _)| *e == ext).map(|(_, m)| *m)
}

/// Append the extension a content-addressed blob URL is missing.
///
/// Blossom names blobs `/<sha256>`, and BUD-01 requires servers to serve the
/// same blob at `/<sha256>.<ext>` — so this costs nothing and buys the two
/// things that read the URL rather than the metadata: Discord's link unfurl and
/// Armada's extension sniffing, which is the only signal a bare URL in message
/// content carries.
pub fn with_extension(url: &str, mime: &str) -> String {
    let Some(ext) = extension_for_mime(mime) else { return url.to_owned() };
    let Ok(mut parsed) = Url::parse(url) else { return url.to_owned() };
    let last = parsed.path().rsplit('/').next().unwrap_or("");
    if last.is_empty() || EXTENSION_RE.is_match(last) {
        return url.to_owned();
    }
    let path = format!("{}.{ext}", parsed.path());
    parsed.set_path(&path);
    parsed.into()
}

/// A filename Discord will accept and can type, out of values the sender chose.
///
/// Both candidate sources — the imeta `name` field and the URL's last path
/// segment — are remote input that lands in a multipart `filename=` header, so
/// anything outside a conservative set is replaced: a quote or a newline there
/// rewrites the part header, and a `/` or a leading `..` is a path the far side
/// may honour. The extension is then supplied from the MIME if the name lacks
/// one, because that is what decides whether Discord previews the upload.
pub fn attachment_filename(url: &str, mime: &str, declared: Option<&str>) -> String {
    // ASCII `\w`, as in JS: a Unicode class would let lookalikes through.
    static UNSAFE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^A-Za-z0-9_.\- ]+").unwrap());
    static LEADING: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[.\s]+").unwrap());

    let declared = declared.map(str::trim).filter(|d| !d.is_empty());
    let segment = last_path_segment(url);
    let raw = declared.or((!segment.is_empty()).then_some(segment.as_str())).unwrap_or("file");
    let cleaned = UNSAFE.replace_all(raw, "_");
    let cleaned = LEADING.replace(&cleaned, "");
    let cleaned = cleaned.trim();
    let name = if cleaned.is_empty() { "file" } else { cleaned };
    // Everything left is ASCII, so byte slicing below is character slicing.
    let (stem, ext) = match EXTENSION_RE.find(name) {
        Some(found) => (&name[..found.start()], found.as_str().to_owned()),
        None => (name, format!(".{}", extension_for_mime(mime).as_deref().unwrap_or("bin"))),
    };
    let stem = &stem[..stem.len().min(MAX_FILENAME_CHARS - ext.len())];
    format!("{}{ext}", if stem.is_empty() { "file" } else { stem })
}

fn last_path_segment(url: &str) -> String {
    Url::parse(url).map(|u| u.path().rsplit('/').next().unwrap_or("").to_owned()).unwrap_or_default()
}

/// Hex validator (even length, hex digits only), optionally of a fixed length.
fn is_hex(value: &str, len: Option<usize>) -> bool {
    if value.is_empty() || len.is_some_and(|l| value.len() != l) {
        return false;
    }
    value.len().is_multiple_of(2) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Normalise key material to lowercase hex.
///
/// Neither NIP-17 nor the NIP-94 encryption extension pins an encoding, and
/// senders in the wild use both hex and base64 — Armada's own reader accepts
/// either, so a bridge that accepted only hex would refuse to decrypt an image
/// that every other member of the channel can see. Hex wins the ambiguity: a
/// base64 string that happens to be all-hex decodes to the wrong LENGTH, which
/// [`is_supported_encryption`] then rejects rather than silently mis-keying.
///
/// Returns the value unchanged when it is neither, so the caller can still tell
/// the attachment claims to be encrypted.
fn decode_key_material(value: &str) -> String {
    static B64: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/\-_]+={0,2}$").unwrap());
    // Lenient like Node's `Buffer.from(_, "base64")`: padding optional, stray
    // trailing bits ignored, URL-safe alphabet folded into the standard one.
    const LENIENT: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    );
    let trimmed = value.trim();
    if is_hex(trimmed, None) {
        return trimmed.to_lowercase();
    }
    if !B64.is_match(trimmed) {
        return value.to_owned();
    }
    let normalised = trimmed.trim_end_matches('=').replace('-', "+").replace('_', "/");
    match LENIENT.decode(normalised) {
        Ok(bytes) if !bytes.is_empty() => hex::encode(bytes),
        _ => value.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    fn fields(parts: &[&str]) -> HashMap<String, String> {
        let tag: Vec<String> = std::iter::once("imeta").chain(parts.iter().copied()).map(String::from).collect();
        imeta_fields(&tag)
    }

    #[test]
    fn fields_split_on_the_first_space_and_later_duplicates_win() {
        let f = fields(&["url https://x/a", "alt two words", "nospace", "m image/png", "m image/gif"]);
        assert_eq!(f["alt"], "two words");
        assert_eq!(f["m"], "image/gif");
        assert!(!f.contains_key("nospace"));
    }

    #[test]
    fn hex_and_base64_key_material_both_decode() {
        let key = [7u8; 32];
        let nonce = [9u8; 16];
        let hex_enc = parse_imeta_encryption(&fields(&[
            "encryption-algorithm AES-GCM",
            &format!("decryption-key {}", hex::encode(key).to_uppercase()),
            &format!("decryption-nonce {}", hex::encode(nonce)),
        ]))
        .unwrap();
        let b64_enc = parse_imeta_encryption(&fields(&[
            "encryption-algorithm aes-gcm",
            &format!("decryption-key {}", STANDARD.encode(key)),
            &format!("decryption-nonce {}", URL_SAFE_NO_PAD.encode(nonce)),
        ]))
        .unwrap();
        assert_eq!(hex_enc, b64_enc);
        assert_eq!(hex_enc.key, hex::encode(key));
        assert!(is_supported_encryption(Some(&hex_enc)));
    }

    #[test]
    fn absent_algorithm_is_plaintext_but_unreadable_is_not() {
        assert_eq!(parse_imeta_encryption(&fields(&["url https://x/a"])), None);
        let enc = parse_imeta_encryption(&fields(&["encryption-algorithm chacha", "decryption-key ???"])).unwrap();
        assert_eq!(enc.key, "???");
        assert!(!is_supported_encryption(Some(&enc)));
        assert!(!is_supported_encryption(None));
    }

    #[test]
    fn wrong_length_material_is_unsupported() {
        let enc = |key: &str, nonce: &str| ImetaEncryption {
            algorithm: "aes-gcm".into(),
            key: key.into(),
            nonce: nonce.into(),
            ox: None,
        };
        assert!(!is_supported_encryption(Some(&enc(&"ab".repeat(31), &"00".repeat(16)))));
        assert!(!is_supported_encryption(Some(&enc(&"ab".repeat(32), &"00".repeat(8)))));
        assert!(!is_supported_encryption(Some(&enc(&"ab".repeat(32), ""))));
        assert!(is_supported_encryption(Some(&enc(&"ab".repeat(32), &"00".repeat(12)))));
    }

    #[test]
    fn decrypts_armada_blobs_and_checks_ox() {
        let plain = b"hello attachment";
        let (blob, mk) = concord::media::encrypt(plain);
        let mut enc = ImetaEncryption {
            algorithm: "aes-gcm".into(),
            key: hex::encode(mk.key),
            nonce: hex::encode(mk.nonce),
            ox: Some(concord::media::sha256_hex(plain)),
        };
        assert_eq!(decrypt_blob(&blob, &enc).unwrap(), plain);

        enc.ox = Some("00".repeat(32));
        assert!(decrypt_blob(&blob, &enc).unwrap_err().to_string().contains("ox"));

        enc.ox = None;
        let mut tampered = blob.clone();
        tampered[0] ^= 1;
        assert!(decrypt_blob(&tampered, &enc).is_err());
        assert!(decrypt_blob(&blob[..8], &enc).is_err());
    }

    #[test]
    fn decrypts_twelve_byte_nonces() {
        use aes_gcm::aead::{Aead, KeyInit};
        let key = [3u8; 32];
        let nonce = [4u8; 12];
        let blob = aes_gcm::Aes256Gcm::new(&key.into()).encrypt(&nonce.into(), &b"twelve"[..]).unwrap();
        let enc = ImetaEncryption { algorithm: "aes-gcm".into(), key: hex::encode(key), nonce: hex::encode(nonce), ox: None };
        assert_eq!(decrypt_blob(&blob, &enc).unwrap(), b"twelve");
        let odd = ImetaEncryption { nonce: "00".repeat(8), ..enc };
        assert!(decrypt_blob(&blob, &odd).is_err());
    }

    #[test]
    fn extensions_and_mimes() {
        assert_eq!(extension_for_mime("image/jpeg; charset=x").as_deref(), Some("jpg"));
        assert_eq!(extension_for_mime("application/zip").as_deref(), Some("zip"));
        assert_eq!(extension_for_mime("application/ld+json").as_deref(), Some("ld"));
        assert_eq!(extension_for_mime("application/vnd.ms-excel"), None);
        assert_eq!(mime_from_url("https://b.example/abc.PNG?x=1"), Some("image/png"));
        assert_eq!(mime_from_url("https://b.example/abc"), None);
        assert_eq!(mime_from_url("not a url"), None);
    }

    #[test]
    fn with_extension_appends_only_when_the_last_segment_lacks_one() {
        let hash = "a".repeat(64);
        assert_eq!(
            with_extension(&format!("https://b.example/{hash}"), "image/png"),
            format!("https://b.example/{hash}.png")
        );
        assert_eq!(
            with_extension(&format!("https://b.example/{hash}?q=1"), "image/png"),
            format!("https://b.example/{hash}.png?q=1")
        );
        assert_eq!(with_extension("https://b.example/a.jpg", "image/png"), "https://b.example/a.jpg");
        assert_eq!(with_extension("https://b.example/dir/", "image/png"), "https://b.example/dir/");
        assert_eq!(with_extension("https://b.example/x", "application/vnd.ms-excel"), "https://b.example/x");
        assert_eq!(with_extension("nope", "image/png"), "nope");
    }

    #[test]
    fn filenames_are_sanitised() {
        let url = format!("https://b.example/{}", "a".repeat(64));
        // Quotes, newlines and slashes cannot reach the multipart header.
        assert_eq!(attachment_filename(&url, "image/png", Some("ev\"il\r\nname.png")), "ev_il_name.png");
        assert_eq!(attachment_filename(&url, "image/png", Some("../../etc/passwd")), "_.._etc_passwd.png");
        assert_eq!(attachment_filename(&url, "image/png", Some("..hidden.gif")), "hidden.gif");
        // No declared name: the URL segment, typed from the MIME.
        assert_eq!(attachment_filename(&url, "image/png", None), format!("{}.png", "a".repeat(64)));
        assert_eq!(attachment_filename(&url, "", Some("  ")), format!("{}.bin", "a".repeat(64)));
        assert_eq!(attachment_filename("bad", "image/gif", Some("...")), "file.gif");
        let long = attachment_filename(&url, "image/webp", Some(&"x".repeat(300)));
        assert_eq!(long.len(), MAX_FILENAME_CHARS);
        assert!(long.ends_with(".webp"));
    }
}
