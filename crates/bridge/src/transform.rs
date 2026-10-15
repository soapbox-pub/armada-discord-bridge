//! Content transforms between Discord and Concord message text (MVP cut:
//! plain text fidelity; attachments ride as URLs, custom emoji flatten to
//! shortcodes). Richer mapping (imeta uploads, NIP-30 emoji tags, real
//! mention p-tags) layers on top later without changing these seams.
//!
//! Lengths here are UTF-16 code units, the way Discord (and the TS bridge)
//! count them, but no cut ever lands inside a character.

use std::sync::LazyLock;

use regex::Regex;

use crate::types::DiscordInboundMessage;

/// Keep well under the 65,535-byte NIP-44 plaintext cap (multi-layer overhead).
pub const CONCORD_MAX_CHARS: usize = 60_000;

/// Discord hard limit for webhook/bot message content.
pub const DISCORD_MAX_CHARS: usize = 2_000;

/// The command a plain `/command` message names, lowercased; "/" alone is not one.
pub fn parse_bot_command(content: &str) -> Option<String> {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^/([a-z][a-z0-9-]*)\b").unwrap());
    RE.captures(content.trim()).map(|c| c[1].to_lowercase())
}

/// The embed media URL that will REPLACE the whole content, or `None` when
/// the text is left alone.
///
/// GIF-picker sends (Tenor, Klipy) put a provider PAGE url in the content and
/// hide the real media behind Discord's embed; Armada only inlines direct
/// media, so the substitution below swaps it in.
///
/// Public because the router has to attach an `imeta` tag naming EXACTLY the
/// URL that ends up in the content, and Armada keys its imeta map on the URL
/// string byte-for-byte. Two copies of this condition drift, and a drifted copy
/// is worse than none: the inline URL reads as untagged AND a duplicate embed
/// gets appended from the orphaned tag.
pub fn substituted_embed_media(msg: &DiscordInboundMessage) -> Option<&str> {
    static BARE_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^https?://\S+$").unwrap());
    let bare = msg.content.trim();
    if !BARE_URL.is_match(bare) {
        return None;
    }
    msg.embeds
        .iter()
        .find(|e| e.url.as_deref() == Some(bare) && e.media_url.as_deref().is_some_and(|m| !m.is_empty()))
        .and_then(|e| e.media_url.as_deref())
}

/// Discord markup -> Concord plain text.
pub fn discord_to_concord(msg: &DiscordInboundMessage) -> String {
    // ASCII classes throughout: JS `\d` and `\w` are ASCII-only, Rust's are not.
    static USER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<@!?([0-9]+)>").unwrap());
    static CHANNEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<#([0-9]+)>").unwrap());
    static EMOJI: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<a?:([A-Za-z0-9_]+):[0-9]+>").unwrap());

    let mut text = substituted_embed_media(msg).unwrap_or(&msg.content).to_owned();

    // <@id> and <@!id> user mentions -> @display
    text = USER
        .replace_all(&text, |c: &regex::Captures| match msg.mentions.iter().find(|m| m.id == c[1]) {
            Some(m) => format!("@{}", m.display),
            None => c[0].to_owned(),
        })
        .into_owned();

    // <#id> channel mentions -> #name
    text = CHANNEL
        .replace_all(&text, |c: &regex::Captures| match msg.channel_names.get(&c[1]).filter(|n| !n.is_empty()) {
            Some(name) => format!("#{name}"),
            None => c[0].to_owned(),
        })
        .into_owned();

    // <:name:id> and <a:name:id> custom emoji -> :name:
    text = EMOJI.replace_all(&text, ":${1}:").into_owned();

    // Attachments append as bare URLs, one per line.
    let urls: Vec<&str> = msg.attachments.iter().map(|a| a.url.as_str()).filter(|u| !u.is_empty()).collect();
    if !urls.is_empty() {
        text = std::iter::once(text.trim_end()).chain(urls).filter(|s| !s.is_empty()).collect::<Vec<_>>().join("\n");
    }

    if utf16_len(&text) > CONCORD_MAX_CHARS {
        text = format!("{}…", &text[..utf16_prefix(&text, CONCORD_MAX_CHARS - 1)]);
    }
    text
}

/// Concord plain text -> Discord: shorten bare nostr: identity URIs (Discord
/// renders them as dead links otherwise). Event/address URIs stay verbatim so
/// they remain copyable.
pub fn concord_to_discord(content: &str) -> String {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"nostr:(npub1|nprofile1)([02-9ac-hj-np-z]+)").unwrap());
    RE.replace_all(content, |c: &regex::Captures| format!("@{}{}…", &c[1], &c[2][..c[2].len().min(8)]))
        .into_owned()
}

/// Split for Discord's 2,000-char limit (pass [`DISCORD_MAX_CHARS`]),
/// preferring newline then space boundaries so words and code fences survive
/// where possible.
pub fn split_for_discord(content: &str, max: usize) -> Vec<String> {
    if utf16_len(content) <= max {
        return vec![content.to_owned()];
    }
    let mut parts = Vec::new();
    let mut rest = content;
    while utf16_len(rest) > max {
        let mut end = utf16_prefix(rest, max);
        if end == 0 {
            // A window narrower than the first character: take it whole rather
            // than loop forever.
            end = rest.chars().next().map_or(0, char::len_utf8);
        }
        let window = &rest[..end];
        // A boundary only counts past half the window (in UTF-16 units, as JS).
        let past_half = |b: usize| utf16_len(&window[..b]) as f64 >= max as f64 * 0.5;
        let cut = window
            .rfind('\n')
            .filter(|&b| past_half(b))
            .or_else(|| window.rfind(' ').filter(|&b| past_half(b)))
            .unwrap_or(end);
        parts.push(rest[..cut].to_owned());
        rest = &rest[cut..];
        rest = rest.strip_prefix(['\n', ' ']).unwrap_or(rest);
    }
    if !rest.is_empty() {
        parts.push(rest.to_owned());
    }
    parts
}

/// Discord rejects webhook usernames <2 or >80 chars or containing "discord"
/// or "clyde", and its filter normalizes lookalikes (leetspeak substitutions
/// still match), so a letter is dropped rather than swapped.
pub fn sanitize_username(name: &str) -> String {
    static DISCORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)discord").unwrap());
    static CLYDE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)clyde").unwrap());
    let cleaned = DISCORD.replace_all(name, "disc-rd");
    let cleaned = CLYDE.replace_all(&cleaned, "cly-e");
    let cleaned = cleaned.trim();
    if utf16_len(cleaned) < 2 {
        let padded = format!("nostr {cleaned}");
        let padded = padded.trim();
        return format!("{padded}{}", "_".repeat(2usize.saturating_sub(utf16_len(padded))));
    }
    cleaned[..utf16_prefix(cleaned, 80)].to_owned()
}

/// Length in UTF-16 code units, as JS `String.length` counts.
fn utf16_len(s: &str) -> usize {
    s.chars().map(char::len_utf16).sum()
}

/// Byte length of the longest prefix of `s` that is at most `max` UTF-16
/// units. A cut that would land inside a surrogate pair backs off one, where
/// JS `slice` would leave half a character.
fn utf16_prefix(s: &str, max: usize) -> usize {
    let mut units = 0;
    for (i, c) in s.char_indices() {
        units += c.len_utf16();
        if units > max {
            return i;
        }
    }
    s.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DiscordAttachmentIn, DiscordMentionIn, EmbedIn};

    fn msg(content: &str) -> DiscordInboundMessage {
        DiscordInboundMessage { content: content.to_owned(), ..Default::default() }
    }

    #[test]
    fn bot_commands() {
        assert_eq!(parse_bot_command("  /Claim now"), Some("claim".to_owned()));
        assert_eq!(parse_bot_command("/"), None);
        assert_eq!(parse_bot_command("hi /claim"), None);
    }

    #[test]
    fn mentions_channels_and_emoji_flatten() {
        let mut m = msg("hi <@1> and <@!2> in <#3> <#4> <:wave:55> <a:dance:66>");
        m.mentions = vec![DiscordMentionIn { id: "1".into(), display: "mk".into() }];
        m.channel_names.insert("3".into(), "general".into());
        assert_eq!(discord_to_concord(&m), "hi @mk and <@!2> in #general <#4> :wave: :dance:");
    }

    #[test]
    fn mention_display_is_not_a_replacement_template() {
        let mut m = msg("<@1>");
        m.mentions = vec![DiscordMentionIn { id: "1".into(), display: "$0 $1".into() }];
        assert_eq!(discord_to_concord(&m), "@$0 $1");
    }

    #[test]
    fn attachments_append_as_lines() {
        let mut m = msg("look  ");
        m.attachments = vec![
            DiscordAttachmentIn { url: "https://cdn/a.png".into(), filename: None },
            DiscordAttachmentIn { url: String::new(), filename: None },
        ];
        assert_eq!(discord_to_concord(&m), "look\nhttps://cdn/a.png");
        m.content = String::new();
        assert_eq!(discord_to_concord(&m), "https://cdn/a.png");
    }

    #[test]
    fn embed_media_substitutes_only_a_bare_matching_url() {
        let page = "https://tenor.com/view/x";
        let mut m = msg(&format!(" {page} "));
        m.embeds = vec![
            EmbedIn { url: Some(page.into()), media_url: None },
            EmbedIn { url: Some(page.into()), media_url: Some("https://media.tenor.com/x.gif".into()) },
        ];
        assert_eq!(substituted_embed_media(&m), Some("https://media.tenor.com/x.gif"));
        assert_eq!(discord_to_concord(&m), "https://media.tenor.com/x.gif");
        m.content = format!("{page} lol");
        assert_eq!(substituted_embed_media(&m), None);
    }

    #[test]
    fn concord_text_is_capped_without_splitting_a_character() {
        let long = "a".repeat(CONCORD_MAX_CHARS + 5);
        let out = discord_to_concord(&msg(&long));
        assert_eq!(utf16_len(&out), CONCORD_MAX_CHARS);
        assert!(out.ends_with('…'));

        // 59,998 units of ASCII, then an emoji straddling the cut at 59,999.
        let straddle = format!("{}😀😀", "a".repeat(CONCORD_MAX_CHARS - 2));
        let out = discord_to_concord(&msg(&straddle));
        assert_eq!(out, format!("{}…", "a".repeat(CONCORD_MAX_CHARS - 2)));
    }

    #[test]
    fn nostr_identities_shorten() {
        assert_eq!(
            concord_to_discord("hey nostr:npub1qqqqqqqqqqqqqqqqqqqq and nostr:nevent1abc"),
            "hey @npub1qqqqqqqq… and nostr:nevent1abc"
        );
    }

    #[test]
    fn split_short_is_one_part() {
        assert_eq!(split_for_discord("hi", DISCORD_MAX_CHARS), vec!["hi"]);
    }

    #[test]
    fn split_prefers_newline_then_space_past_half() {
        assert_eq!(split_for_discord("aaaaaa\nbbb ccc", 10), vec!["aaaaaa", "bbb ccc"]);
        assert_eq!(split_for_discord("aaaaaa bbbbbbb", 10), vec!["aaaaaa", "bbbbbbb"]);
        // A boundary before the halfway mark is ignored: hard cut.
        assert_eq!(split_for_discord("aa bbbbbbbbbbbb", 10), vec!["aa bbbbbbb", "bbbbb"]);
    }

    #[test]
    fn split_counts_utf16_and_never_splits_a_character() {
        let s = "😀".repeat(5); // 10 UTF-16 units
        let parts = split_for_discord(&s, 3);
        assert!(parts.iter().all(|p| utf16_len(p) <= 3));
        assert_eq!(parts.concat(), s);
    }

    #[test]
    fn sanitize_username_neutralizes_forbidden_substrings() {
        // Discord normalizes leetspeak, so the output must not contain the
        // forbidden words under any character-for-character substitution.
        assert_eq!(sanitize_username("Discord Fan"), "disc-rd Fan");
        assert_eq!(sanitize_username("dIsCoRdIsCoRd"), "disc-rdIsCoRd");
        assert_eq!(sanitize_username("clyde2"), "cly-e2");
        assert_eq!(sanitize_username("mk (via discord)"), "mk (via disc-rd)");
    }

    #[test]
    fn sanitize_username_enforces_the_length_window() {
        assert!(utf16_len(&sanitize_username("x")) >= 2);
        assert!(utf16_len(&sanitize_username("")) >= 2);
        assert_eq!(utf16_len(&sanitize_username(&"a".repeat(200))), 80);
    }

    #[test]
    fn sanitize_username_leaves_ordinary_names_alone() {
        assert_eq!(sanitize_username("mireille"), "mireille");
    }
}
