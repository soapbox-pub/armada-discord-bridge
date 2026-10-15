//! KLIPY lookups for Discord's GIF picker.
//!
//! A Klipy send reaches the bridge as a page URL (`https://klipy.com/gifs/<slug>`)
//! whose Discord embed exposes only an mp4. Nothing keyless gets from there to
//! the real GIF:
//!
//!  - Rendition filenames are random per format (`…/5iZlPUTw.mp4` sits next to
//!    `…/NVSeglDC.gif`), so no URL rewrite finds the GIF.
//!  - Worse, static.klipy.com answers ANY missing rendition with the same
//!    placeholder image, 200 and `image/gif`. The `.mp4` -> `.gif` swap
//!    therefore "succeeded" for every Klipy send and Armada was handed the
//!    placeholder in place of the GIF.
//!  - klipy.com itself serves the bridge host a Cloudflare challenge, so the
//!    page's og:image is out of reach too.
//!
//! The Items API resolves a slug to its real renditions, and api.klipy.com is
//! not behind the challenge. The key is optional: without it the bridge falls
//! back to transcoding the mp4.

use std::sync::LazyLock;
use std::time::Duration;

use async_trait::async_trait;
use regex::Regex;
use serde_json::Value;
use url::Url;

const KLIPY_API: &str = "https://api.klipy.com/api/v1";

/// Klipy uses this for per-user "recent" lists; one bridge-wide id is enough.
const CUSTOMER_ID: &str = "armada-discord-bridge";

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest to smallest: the first one under the byte budget wins.
const SIZES: [&str; 4] = ["hd", "md", "sm", "xs"];

/// One real GIF rendition, as the Items API describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KlipyGif {
    pub url: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    /// Bytes, as Klipy reports them. Advisory: the download still enforces its own cap.
    pub size: Option<u64>,
}

/// The two item kinds that share the Items response shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KlipyKind {
    Gifs,
    Stickers,
}

impl KlipyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            KlipyKind::Gifs => "gifs",
            KlipyKind::Stickers => "stickers",
        }
    }
}

/// An item a Klipy page URL names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KlipyItemRef {
    pub kind: KlipyKind,
    pub slug: String,
}

/// Whether a URL is on Klipy's media CDN, where a missing file still answers 200.
pub fn is_klipy_media_host(url: &str) -> bool {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(^|\.)klipy\.com$").unwrap());
    Url::parse(url).ok().and_then(|u| u.host_str().map(|h| RE.is_match(h))).unwrap_or(false)
}

/// The item a Klipy page URL names, or `None` for anything else.
///
/// GIFs and stickers share the Items response shape; clips and memes do not,
/// and are left to the generic embed path.
pub fn klipy_item(page_url: &str) -> Option<KlipyItemRef> {
    static HOST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^(www\.)?klipy\.com$").unwrap());
    static PATH: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^/(gifs|stickers)/([A-Za-z0-9_-]{1,200})/?$").unwrap());
    let url = Url::parse(page_url).ok()?;
    if url.scheme() != "https" || !HOST.is_match(url.host_str()?) {
        return None;
    }
    let m = PATH.captures(url.path())?;
    let kind = if &m[1] == "gifs" { KlipyKind::Gifs } else { KlipyKind::Stickers };
    Some(KlipyItemRef { kind, slug: m[2].to_owned() })
}

/// The largest GIF rendition of an Items API item that fits `max_bytes`,
/// falling back to the smallest listed.
pub fn pick_gif(item: &Value, max_bytes: u64) -> Option<KlipyGif> {
    let gifs: Vec<&Value> = SIZES
        .iter()
        .filter_map(|size| item.get("file")?.get(size)?.get("gif"))
        .filter(|file| file.get("url").and_then(Value::as_str).is_some_and(|u| u.starts_with("https://")))
        .collect();
    let size_of = |file: &Value| file.get("size").and_then(Value::as_f64);
    // An absent `size` is not disqualifying; the download cap is the real bound.
    let fit = gifs.iter().find(|file| size_of(file).is_none_or(|s| s <= max_bytes as f64)).or(gifs.last())?;
    let dim = |name: &str| fit.get(name).and_then(Value::as_u64).and_then(|d| u32::try_from(d).ok());
    Some(KlipyGif {
        url: fit["url"].as_str()?.to_owned(),
        width: dim("width"),
        height: dim("height"),
        size: size_of(fit).filter(|s| *s >= 0.0).map(|s| s as u64),
    })
}

/// Resolves a GIF-picker page URL to the real GIF behind it.
#[async_trait]
pub trait GifResolver: Send + Sync {
    /// The real GIF behind a page URL, or `None` when the URL is not one this
    /// resolver knows or the lookup fails. Never errors: this is an upgrade,
    /// and the message still bridges without it.
    async fn resolve_gif(&self, page_url: &str, max_bytes: u64) -> Option<KlipyGif>;
}

pub struct KlipyClient {
    api_key: String,
    api_base: Url,
    http: reqwest::Client,
}

impl KlipyClient {
    pub fn new(api_key: impl Into<String>, http: reqwest::Client) -> Self {
        let api_base = Url::parse(KLIPY_API).expect("KLIPY_API is a valid URL");
        Self { api_key: api_key.into(), api_base, http }
    }

    /// Point the client at another Items API root (tests).
    pub fn with_api_base(mut self, api_base: Url) -> Self {
        self.api_base = api_base;
        self
    }

    fn endpoint(&self, item: &KlipyItemRef) -> Option<Url> {
        let mut endpoint = self.api_base.clone();
        endpoint.path_segments_mut().ok()?.pop_if_empty().push(&self.api_key).push(item.kind.as_str()).push("items");
        endpoint.query_pairs_mut().append_pair("slugs", &item.slug).append_pair("customer_id", CUSTOMER_ID);
        Some(endpoint)
    }

    async fn lookup(&self, endpoint: Url, item: &KlipyItemRef, max_bytes: u64) -> Result<Option<KlipyGif>, String> {
        // The key is in the path, so log the slug and never the URL — and
        // reqwest puts the URL in its errors' Display, hence `without_url`.
        let res = self.http.get(endpoint).timeout(LOOKUP_TIMEOUT).send().await.map_err(|e| e.without_url().to_string())?;
        if !res.status().is_success() {
            return Err(format!("HTTP {}", res.status().as_u16()));
        }
        let body: Value = res.json().await.map_err(|e| e.without_url().to_string())?;
        let items = match body.get("data") {
            Some(Value::Array(items)) => items.as_slice(),
            Some(data) => data.get("data").and_then(Value::as_array).map_or(&[][..], Vec::as_slice),
            None => &[],
        };
        let found = items.iter().find(|i| i.get("slug").and_then(Value::as_str) == Some(&item.slug)).or(items.first());
        Ok(found.and_then(|m| pick_gif(m, max_bytes)))
    }
}

#[async_trait]
impl GifResolver for KlipyClient {
    async fn resolve_gif(&self, page_url: &str, max_bytes: u64) -> Option<KlipyGif> {
        let item = klipy_item(page_url)?;
        let result = match self.endpoint(&item) {
            Some(endpoint) => self.lookup(endpoint, &item, max_bytes).await,
            None => Err("API base cannot take a path".to_owned()),
        };
        result
            .unwrap_or_else(|error| {
                tracing::warn!("bridge: klipy lookup failed for {}/{}: {error}", item.kind.as_str(), item.slug);
                None
            })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// The Items API response for one slug, trimmed to the fields the bridge reads.
    fn items_response(slug: &str, sizes: &[(&str, Option<u64>)]) -> Value {
        let mut file = serde_json::Map::new();
        for (name, size) in sizes {
            let mut gif = json!({ "url": format!("https://static.klipy.com/ii/x/{name}.gif"), "width": 300, "height": 300 });
            if let Some(size) = size {
                gif["size"] = json!(size);
            }
            file.insert((*name).to_owned(), json!({ "gif": gif }));
        }
        json!({ "result": true, "data": { "data": [{ "slug": slug, "file": file }] } })
    }

    /// A one-shot HTTP/1.1 responder; returns its base URL and the request
    /// target it was asked for.
    async fn serve(status: u16, body: String) -> (Url, Arc<Mutex<Option<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let asked = Arc::new(Mutex::new(None));
        let seen = asked.clone();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
            }
            let line = String::from_utf8_lossy(&req).lines().next().unwrap_or("").to_owned();
            *seen.lock().unwrap() = line.split(' ').nth(1).map(str::to_owned);
            let head = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            sock.write_all(head.as_bytes()).await.unwrap();
            sock.write_all(body.as_bytes()).await.unwrap();
            sock.shutdown().await.ok();
        });
        (Url::parse(&format!("http://{addr}/api/v1")).unwrap(), asked)
    }

    #[test]
    fn klipy_item_reads_kind_and_slug() {
        assert_eq!(
            klipy_item("https://klipy.com/gifs/monday-already-monday-again-1"),
            Some(KlipyItemRef { kind: KlipyKind::Gifs, slug: "monday-already-monday-again-1".into() })
        );
        assert_eq!(
            klipy_item("https://www.klipy.com/stickers/wave/"),
            Some(KlipyItemRef { kind: KlipyKind::Stickers, slug: "wave".into() })
        );
    }

    #[test]
    fn klipy_item_refuses_anything_else() {
        for url in [
            "https://klipy.com/clips/x",
            "https://klipy.com/gifs/x/y",
            "https://klipy.com.evil.example/gifs/x",
            "http://klipy.com/gifs/x",
            "https://static.klipy.com/gifs/x",
            "https://klipy.com/gifs/../api",
            "not a url",
        ] {
            assert_eq!(klipy_item(url), None, "{url}");
        }
    }

    #[test]
    fn media_host_matches_klipy_and_subdomains_only() {
        assert!(is_klipy_media_host("https://static.klipy.com/a.mp4"));
        assert!(is_klipy_media_host("https://static2.klipy.com/a.mp4"));
        assert!(!is_klipy_media_host("https://notklipy.com/a.mp4"));
        assert!(!is_klipy_media_host("https://klipy.com.evil.example/a.mp4"));
    }

    #[test]
    fn pick_gif_takes_the_largest_under_budget() {
        let body = items_response("x", &[("hd", Some(900)), ("md", Some(500)), ("sm", Some(200))]);
        assert_eq!(pick_gif(&body["data"]["data"][0], 600).unwrap().url, "https://static.klipy.com/ii/x/md.gif");
    }

    #[test]
    fn pick_gif_falls_back_to_the_smallest() {
        let body = items_response("x", &[("hd", Some(900)), ("md", Some(800))]);
        assert_eq!(pick_gif(&body["data"]["data"][0], 100).unwrap().url, "https://static.klipy.com/ii/x/md.gif");
    }

    #[test]
    fn pick_gif_ignores_non_https() {
        let item = json!({ "file": { "hd": { "gif": { "url": "http://static.klipy.com/a.gif" } } } });
        assert_eq!(pick_gif(&item, 1000), None);
    }

    #[tokio::test]
    async fn resolve_looks_the_slug_up() {
        let (base, asked) = serve(200, items_response("monday-1", &[("hd", Some(100))]).to_string()).await;
        let client = KlipyClient::new("KEY", reqwest::Client::new()).with_api_base(base);
        let gif = client.resolve_gif("https://klipy.com/gifs/monday-1", 1000).await;
        assert_eq!(
            gif,
            Some(KlipyGif {
                url: "https://static.klipy.com/ii/x/hd.gif".into(),
                width: Some(300),
                height: Some(300),
                size: Some(100)
            })
        );
        let target = asked.lock().unwrap().clone().unwrap();
        let target = Url::parse(&format!("http://h{target}")).unwrap();
        assert_eq!(target.path(), "/api/v1/KEY/gifs/items");
        let query: Vec<(String, String)> = target.query_pairs().into_owned().collect();
        assert!(query.contains(&("slugs".into(), "monday-1".into())));
        assert!(query.iter().any(|(k, v)| k == "customer_id" && !v.is_empty()));
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn api_errors_resolve_to_none_without_logging_the_key() {
        let logs = Captured::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt().with_writer(move || writer.clone()).with_ansi(false).finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (base, _) = serve(401, String::new()).await;
        let client = KlipyClient::new("SECRETKEY", reqwest::Client::new()).with_api_base(base);
        assert_eq!(client.resolve_gif("https://klipy.com/gifs/x", 1000).await, None);

        // A connection failure: reqwest's own error text names the URL.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_base = Url::parse(&format!("http://{}/api/v1", dead.local_addr().unwrap())).unwrap();
        drop(dead);
        let client = KlipyClient::new("SECRETKEY", reqwest::Client::new()).with_api_base(dead_base);
        assert_eq!(client.resolve_gif("https://klipy.com/gifs/y", 1000).await, None);

        let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("klipy lookup failed for gifs/x"), "{logged}");
        assert!(logged.contains("gifs/y"), "{logged}");
        assert!(!logged.contains("SECRETKEY"), "{logged}");
    }

    #[tokio::test]
    async fn never_calls_out_for_a_non_klipy_url() {
        let (base, asked) = serve(200, "{}".into()).await;
        let client = KlipyClient::new("KEY", reqwest::Client::new()).with_api_base(base);
        assert_eq!(client.resolve_gif("https://tenor.com/view/x", 1000).await, None);
        tokio::task::yield_now().await;
        assert_eq!(*asked.lock().unwrap(), None);
    }
}
