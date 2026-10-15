//! Pure text helpers the router applies at the boundary: emoji in both
//! directions, markdown escaping for bridge-authored chrome, and GIF-picker
//! media resolution. Every regex here spells `\w` and `\d` as ASCII classes,
//! because that is what they mean in the JavaScript these rules came from and
//! in Discord's own validation.

use std::sync::LazyLock;

use regex::Regex;
use url::Url;

use crate::klipy::is_klipy_media_host;
use crate::net::Prober;
use crate::types::{DiscordInboundMessage, EmbedIn};

/// Longest emoji we will hand to Discord's reaction API, in code points. Real
/// ZWJ sequences top out around ten; this leaves headroom without letting a
/// whole message through.
const MAX_REACTION_CODEPOINTS: usize = 16;

/// Longest display name we will place in an embed. Discord's description cap is
/// 4096; a name is not what should be allowed to approach it.
const MAX_EMBED_NAME_CHARS: usize = 80;

/// Discord's own rule for a custom-emoji name. Both directions validate against
/// it, because on the way back to Discord the shortcode goes into an API PATH:
/// a kind 7 whose emoji tag named itself with 60KB of text put all 60KB into
/// `PUT /channels/…/reactions/{emoji}/@me`.
static EMOJI_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_]{2,32}$").unwrap());

/// NIP-25 reaction content -> a Discord-reactable unicode emoji, or `None` for
/// content Discord would reject ("+"/"" mean like, "-" dislike; NIP-30
/// `:shortcode:` custom emoji have no Discord equivalent).
///
/// The test used to be "contains a pictograph" while the RETURN was the entire
/// trimmed content, so a kind 7 whose content was "👍" followed by 60KB of text
/// put all 60KB into an API path. Containing an emoji is not being one: the
/// whole string now has to be emoji scaffolding — pictographs, components (skin
/// tones, regional indicators), ZWJ and variation selectors — and short.
pub fn reaction_emoji(content: &str) -> Option<String> {
    static SHORTCODE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^:.+:$").unwrap());
    static PICTOGRAPH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\p{Extended_Pictographic}").unwrap());
    static ONLY_EMOJI: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^(?:\p{Extended_Pictographic}|\p{Emoji_Component}|\x{200D}|\x{FE0F})+$").unwrap());
    let c = content.trim();
    if c.is_empty() || c == "+" {
        return Some("👍".into());
    }
    if c == "-" {
        return Some("👎".into());
    }
    if SHORTCODE.is_match(c) {
        return None;
    }
    // A pictograph must be PRESENT — Emoji_Component alone admits bare digits,
    // which are keycap parts — and must be all there IS.
    if !PICTOGRAPH.is_match(c) || c.chars().count() > MAX_REACTION_CODEPOINTS || !ONLY_EMOJI.is_match(c) {
        return None;
    }
    Some(c.to_owned())
}

/// Neutralise Discord markdown in text somebody else wrote, for the one place
/// bridged text lands in bridge-authored chrome rather than in a puppet's own
/// message: the reply embed.
///
/// Backslash-escaping is what Discord itself honours. `[`/`]`/`(`/`)` are the
/// pair that matters (link syntax); the emphasis and spoiler marks are included
/// so a name cannot restyle the sentence around it, and `\` first so the
/// escapes we add are not themselves escaped away.
pub fn escape_markdown(text: &str) -> String {
    let mut clipped = String::new();
    let mut units = 0;
    let mut cut = false;
    for ch in text.chars() {
        units += ch.len_utf16();
        if units > MAX_EMBED_NAME_CHARS {
            cut = true;
            break;
        }
        clipped.push(ch);
    }
    if cut {
        clipped.push('…');
    }
    let mut out = String::with_capacity(clipped.len());
    for ch in clipped.chars() {
        if "\\`*_~|[]()>#-".contains(ch) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Stable, public CDN URL for a Discord custom emoji.
pub fn discord_emoji_url(id: &str, animated: bool) -> String {
    format!("https://cdn.discordapp.com/emojis/{id}.{}", if animated { "gif" } else { "png" })
}

/// The emoji id in a Discord CDN URL, or `None` if the URL is not one.
///
/// Parsed rather than substring-matched: the old test looked for
/// `cdn.discordapp.com/emojis/<digits>.` ANYWHERE in the string, so
/// `https://evil.example/?x=cdn.discordapp.com/emojis/1.` passed and a foreign
/// host got to name the emoji Discord would be asked about.
fn discord_emoji(raw: &str) -> Option<(String, bool)> {
    static PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^/emojis/([0-9]{1,25})\.([A-Za-z0-9_]+)$").unwrap());
    let url = Url::parse(raw).ok()?;
    if url.scheme() != "https" || url.host_str() != Some("cdn.discordapp.com") {
        return None;
    }
    let m = PATH.captures(url.path())?;
    Some((m[1].to_owned(), &m[2] == "gif"))
}

/// Custom emoji in raw Discord content (`<:name:id>` / `<a:name:id>`) -> NIP-30
/// `["emoji", shortcode, url]` tags, one per distinct shortcode. The transform
/// flattens the markup to `:name:`; these let Armada render the image.
pub fn custom_emoji_tags(content: &str) -> Vec<Vec<String>> {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<(a?):([A-Za-z0-9_]+):([0-9]+)>").unwrap());
    let mut tags = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for m in RE.captures_iter(content) {
        if !seen.insert(m[2].to_owned()) {
            continue;
        }
        tags.push(vec!["emoji".into(), m[2].to_owned(), discord_emoji_url(&m[3], &m[1] == "a")]);
    }
    tags
}

/// The reverse of [`custom_emoji_tags`]: an Armada `:shortcode:` whose emoji tag
/// points at Discord's emoji CDN becomes native Discord markup, so mirrors
/// render the image. Foreign emoji URLs stay as text.
pub fn apply_custom_emoji(content: &str, tags: &[Vec<String>]) -> String {
    let mut out = content.to_owned();
    for tag in tags {
        let (Some(name), Some(url)) = (tag.get(1), tag.get(2)) else { continue };
        if tag[0] != "emoji" || name.is_empty() || url.is_empty() || !EMOJI_NAME.is_match(name) {
            continue;
        }
        let Some((id, animated)) = discord_emoji(url) else { continue };
        out = out.replace(&format!(":{name}:"), &format!("<{}:{name}:{id}>", if animated { "a" } else { "" }));
    }
    out
}

/// An Armada custom-emoji reaction whose image lives on Discord's emoji CDN maps
/// back to the native emoji (`name:id`, reactable by the bot).
pub fn concord_custom_emoji_to_discord(tags: &[Vec<String>]) -> Option<String> {
    let tag = tags.iter().find(|t| t.first().is_some_and(|n| n == "emoji") && t.len() >= 3 && !t[1].is_empty() && !t[2].is_empty())?;
    let (id, _) = discord_emoji(&tag[2])?;
    EMOJI_NAME.is_match(&tag[1]).then(|| format!("{}:{id}", tag[1]))
}

/// URLs that ride as file uploads leave the content, or Discord renders the
/// media twice (link unfurl + attachment). Oversized or failed blobs never make
/// this list, so their links survive.
pub fn strip_attached_urls(content: &str, urls: &[String]) -> String {
    static TRAILING: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^\S\n]+\n").unwrap());
    static BLANKS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\n{3,}").unwrap());
    if urls.is_empty() {
        return content.to_owned();
    }
    let mut text = content.to_owned();
    for url in urls {
        text = text.replace(url.as_str(), "");
    }
    let text = TRAILING.replace_all(&text, "\n");
    BLANKS.replace_all(&text, "\n\n").trim().to_owned()
}

/// GIF pickers (Tenor, Klipy) expose only an mp4 in the Discord embed; the
/// provider almost always hosts a true .gif too. Probe the likely URLs
/// (extension swap, Tenor's page-url + .gif redirect) and keep the mp4 only when
/// no candidate actually serves an image.
pub async fn resolve_gif_variant(page_url: &str, media_url: &str, prober: &dyn Prober) -> String {
    static GIF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\.gif(\?|$)").unwrap());
    static MP4: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\.mp4(\?|$)").unwrap());
    static SLASHES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/+$").unwrap());
    if GIF.is_match(media_url) {
        return media_url.to_owned();
    }
    // Klipy answers every missing rendition with one placeholder image — 200,
    // `image/gif` — so the swap below "verifies" for every Klipy send and the
    // placeholder crosses instead of the GIF. Only the Items API (klipy.rs)
    // knows the real .gif; without it the mp4 goes to the transcode fallback.
    if is_klipy_media_host(media_url) || is_klipy_media_host(page_url) {
        return media_url.to_owned();
    }
    let candidates = [MP4.replace(media_url, ".gif$1").into_owned(), format!("{}.gif", SLASHES.replace(page_url, ""))];
    for url in candidates.iter().filter(|u| u.as_str() != media_url) {
        // Guarded, not a bare fetch: `media_url` is an OpenGraph value read off
        // whatever page the message linked, so its author picks the host.
        if let Some(res) = prober.probe(url).await
            && res.ok
            && res.mime.starts_with("image/")
        {
            return url.clone();
        }
    }
    media_url.to_owned()
}

/// When the message is only a GIF-picker page link, upgrade its embed media to
/// a true .gif.
pub async fn upgrade_gif_embed(msg: DiscordInboundMessage, prober: &dyn Prober) -> DiscordInboundMessage {
    static BARE_URL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^https?://\S+$").unwrap());
    let bare = msg.content.trim().to_owned();
    if !BARE_URL.is_match(&bare) {
        return msg;
    }
    let Some(media) = msg.embeds.iter().find(|e| e.url.as_deref() == Some(bare.as_str())).and_then(|e| e.media_url.clone()) else {
        return msg;
    };
    let media_url = resolve_gif_variant(&bare, &media, prober).await;
    DiscordInboundMessage { embeds: vec![EmbedIn { url: Some(bare), media_url: Some(media_url) }], ..msg }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reaction_emoji_passes_real_emoji_and_refuses_payloads() {
        for e in ["👍", "🔥", "👨‍👩‍👧‍👦", "👍🏽", "❤️"] {
            assert_eq!(reaction_emoji(e).as_deref(), Some(e), "{e}");
        }
        assert_eq!(reaction_emoji("+").as_deref(), Some("👍"));
        assert_eq!(reaction_emoji("").as_deref(), Some("👍"));
        assert_eq!(reaction_emoji("-").as_deref(), Some("👎"));
        assert_eq!(reaction_emoji(&format!("👍{}", "x".repeat(60_000))), None);
        assert_eq!(reaction_emoji("👍 nice"), None);
        assert_eq!(reaction_emoji(&"👍".repeat(17)), None);
        assert_eq!(reaction_emoji(":blob:"), None);
        assert_eq!(reaction_emoji("hello"), None);
        assert_eq!(reaction_emoji("123"), None);
        // Flags are regional indicators, not pictographs; the TS refuses them too.
        assert_eq!(reaction_emoji("🇺🇸"), None);
    }

    #[test]
    fn escape_markdown_defuses_links_and_clips() {
        assert_eq!(escape_markdown("[#general](https://phishing.example)"), r"\[\#general\]\(https://phishing.example\)");
        assert_eq!(escape_markdown("alice"), "alice");
        let long = escape_markdown(&"a".repeat(200));
        assert_eq!(long, format!("{}…", "a".repeat(80)));
    }

    #[test]
    fn custom_emoji_round_trip() {
        let tags = custom_emoji_tags("hi <:blob:123> <a:dance:456> <:blob:123>");
        assert_eq!(
            tags,
            vec![
                vec!["emoji".to_string(), "blob".into(), "https://cdn.discordapp.com/emojis/123.png".into()],
                vec!["emoji".to_string(), "dance".into(), "https://cdn.discordapp.com/emojis/456.gif".into()],
            ]
        );
        assert_eq!(apply_custom_emoji("hi :blob: :dance:", &tags), "hi <:blob:123> <a:dance:456>");
        assert_eq!(concord_custom_emoji_to_discord(&tags).as_deref(), Some("blob:123"));
    }

    #[test]
    fn refuses_emoji_urls_that_only_mention_the_cdn() {
        let tags = vec![vec!["emoji".to_string(), "blob".into(), "https://evil.example/?x=cdn.discordapp.com/emojis/1.png".into()]];
        assert_eq!(apply_custom_emoji(":blob:", &tags), ":blob:");
        assert_eq!(concord_custom_emoji_to_discord(&tags), None);
        let long = vec![vec!["emoji".to_string(), "x".repeat(60), "https://cdn.discordapp.com/emojis/1.png".into()]];
        assert_eq!(concord_custom_emoji_to_discord(&long), None);
    }

    #[test]
    fn strips_attached_urls() {
        let urls = vec!["https://b.example/x.png".to_string()];
        assert_eq!(strip_attached_urls("look \nhttps://b.example/x.png\n\n\nend", &urls), "look\n\nend");
        assert_eq!(strip_attached_urls("https://b.example/x.png", &urls), "");
    }
}
