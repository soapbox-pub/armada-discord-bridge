//! Blossom blob rehosting (BUD-02): Discord CDN attachments are signed URLs
//! that expire in ~24 hours, so bridged media is uploaded to a Blossom server
//! and the durable URL rides in the rumor instead. Uploads are authorized by a
//! kind 24242 event signed by the sending puppet, so blobs are attributable to
//! the same identity as the message.

use std::time::Duration;

use anyhow::{Context, bail};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use nostr::prelude::*;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::net::{FetchOptions, safe_fetch};

const KIND_BLOSSOM_AUTH: u16 = 24242;

/// How long one server gets to accept an upload before the next is tried.
///
/// The upload used to be a bare fetch with no deadline, so a server that
/// accepted the connection and then stalled held the message — and every one
/// queued behind it — indefinitely.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Where an uploaded blob landed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uploaded {
    pub url: String,
    pub sha256: String,
}

/// Blob storage as the router sees it, behind a trait so its tests can fake it.
#[async_trait]
pub trait BlobPort: Send + Sync {
    /// Fetch a blob named by someone else: `(bytes, mime)`.
    async fn download(&self, url: &str, max_bytes: usize) -> anyhow::Result<(Vec<u8>, String)>;
    async fn upload(&self, data: &[u8], mime: &str, author: &Keys) -> anyhow::Result<Uploaded>;
}

/// Parse `BLOSSOM_SERVER`: one URL, or several comma-separated in preference
/// order. Blank entries and trailing slashes are dropped.
pub fn blossom_servers(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|s| s.trim().trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

#[derive(Default, Deserialize)]
struct Descriptor {
    #[serde(default)]
    url: Option<String>,
}

pub struct BlossomStore {
    servers: Vec<String>,
    /// Plain, unguarded client: uploads go only to servers the operator
    /// configured, never to a URL that arrived from outside.
    client: reqwest::Client,
}

impl BlossomStore {
    /// `servers` is tried in order on every upload. One host was the whole
    /// story before, and blossom.primal.net spent days answering 500 and 401 —
    /// hundreds of Discord attachments crossed as CDN links that expire in a
    /// day. A second host turns that outage into a slower upload instead.
    pub fn new(servers: Vec<String>) -> anyhow::Result<Self> {
        if servers.is_empty() {
            bail!("BlossomStore needs at least one server");
        }
        let client = reqwest::Client::builder()
            .build()
            .context("building Blossom HTTP client")?;
        Ok(Self { servers, client })
    }

    async fn upload_to(
        &self,
        base: &str,
        data: &[u8],
        mime: &str,
        authorization: &str,
    ) -> anyhow::Result<Option<String>> {
        let res = self
            .client
            .put(format!("{base}/upload"))
            .header(AUTHORIZATION, authorization)
            .header(CONTENT_TYPE, mime)
            .body(data.to_vec())
            .timeout(UPLOAD_TIMEOUT)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if !res.status().is_success() {
            bail!("HTTP {}", res.status().as_u16());
        }
        // A server that took the blob but answered with no usable descriptor
        // still has it; BUD-01 says where.
        let text = res.text().await.unwrap_or_default();
        let descriptor: Descriptor = serde_json::from_str(&text).unwrap_or_default();
        Ok(descriptor.url.filter(|u| !u.is_empty()))
    }
}

#[async_trait]
impl BlobPort for BlossomStore {
    /// Every caller of this passes a URL the bridge did not choose — an `imeta`
    /// tag on an inbound rumor, or a media URL off a Discord embed, which is an
    /// OpenGraph value from whatever page was linked. It therefore goes through
    /// [`safe_fetch`]: http(s) only, public hosts only (this process holds the
    /// seal key, and sits on the deployment's internal network), redirects
    /// re-checked, and the cap enforced by a running counter instead of a
    /// `content-length` the remote server chose.
    async fn download(&self, url: &str, max_bytes: usize) -> anyhow::Result<(Vec<u8>, String)> {
        let fetched = safe_fetch(url, max_bytes, FetchOptions::default()).await?;
        Ok((fetched.body, fetched.mime))
    }

    async fn upload(&self, data: &[u8], mime: &str, author: &Keys) -> anyhow::Result<Uploaded> {
        let hash = hex::encode(Sha256::digest(data));
        let now = Timestamp::now();
        // One auth event covers every server: BUD-02 scopes it by `x`, not by host
        // (a `server` tag is optional, and adding one would pin it to a single host).
        let auth = EventBuilder::new(
            Kind::Custom(KIND_BLOSSOM_AUTH),
            "Upload bridged Discord attachment",
        )
        .custom_created_at(now)
        .tags([
            Tag::custom("t", ["upload"]),
            Tag::custom("x", [hash.as_str()]),
            Tag::expiration(Timestamp::from_secs(now.as_secs() + 300)),
        ])
        .finalize(author)
        .context("signing Blossom upload authorization")?;
        let authorization = format!("Nostr {}", STANDARD.encode(auth.as_json()));

        let mut failures = Vec::new();
        for base in &self.servers {
            match self.upload_to(base, data, mime, &authorization).await {
                Ok(url) => {
                    let url = url.unwrap_or_else(|| format!("{base}/{hash}"));
                    return Ok(Uploaded { url, sha256: hash });
                }
                Err(error) => failures.push(format!("{base}: {error}")),
            }
        }
        bail!(
            "blossom upload failed on every server ({})",
            failures.join("; ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::test_server::{Reply, serve};

    const DATA: [u8; 3] = [1, 2, 3];

    fn store(servers: &[&str]) -> BlossomStore {
        BlossomStore::new(servers.iter().map(|s| (*s).to_owned()).collect()).unwrap()
    }

    #[test]
    fn splits_a_comma_separated_preference_list() {
        assert_eq!(
            blossom_servers(" https://a.example/ , ,https://b.example//"),
            vec!["https://a.example", "https://b.example"]
        );
    }

    #[test]
    fn refuses_to_be_built_with_no_server() {
        assert!(BlossomStore::new(blossom_servers(" , ")).is_err());
    }

    #[tokio::test]
    async fn uses_the_first_server_when_it_accepts() {
        let first = serve(|_| Reply::json(r#"{"url":"https://a.example/abc"}"#)).await;
        let second = serve(|_| Reply::json(r#"{"url":"https://b.example/abc"}"#)).await;
        let store = store(&[&first.url, &second.url]);
        let uploaded = store
            .upload(&DATA, "image/png", &Keys::generate())
            .await
            .unwrap();
        assert_eq!(uploaded.url, "https://a.example/abc");
        assert_eq!(second.hit_count(), 0);
    }

    #[tokio::test]
    async fn falls_through_to_the_next_server_on_an_error_status() {
        // The failure that motivated this: primal answering 500/401 for days.
        let first = serve(|_| Reply::Full {
            status: 500,
            headers: Vec::new(),
            body: b"nope".to_vec(),
        })
        .await;
        let second = serve(|_| Reply::json(r#"{"url":"https://b.example/abc"}"#)).await;
        let store = store(&[&first.url, &second.url]);
        let uploaded = store
            .upload(&DATA, "image/png", &Keys::generate())
            .await
            .unwrap();
        assert_eq!(uploaded.url, "https://b.example/abc");
        assert_eq!(first.hit_count(), 1);
    }

    #[tokio::test]
    async fn falls_through_when_a_server_is_unreachable() {
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_url = format!("http://{}", dead.local_addr().unwrap());
        drop(dead);
        let live = serve(|_| Reply::json("{}")).await;
        let store = store(&[&dead_url, &live.url]);
        let uploaded = store
            .upload(&DATA, "image/png", &Keys::generate())
            .await
            .unwrap();
        // No descriptor URL: fall back to BUD-01's /<sha256> on the server that took it.
        assert_eq!(uploaded.url, format!("{}/{}", live.url, uploaded.sha256));
        assert_eq!(uploaded.sha256, hex::encode(Sha256::digest(DATA)));
    }

    #[tokio::test]
    async fn reports_every_server_when_all_of_them_fail() {
        let a = serve(|_| Reply::status(401)).await;
        let b = serve(|_| Reply::status(500)).await;
        let store = store(&[&a.url, &b.url]);
        let error = store
            .upload(&DATA, "image/png", &Keys::generate())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(&format!("{}: HTTP 401", a.url)), "{error}");
        assert!(error.contains(&format!("{}: HTTP 500", b.url)), "{error}");
    }

    #[tokio::test]
    async fn sends_the_blob_with_a_bud02_authorization_signed_by_the_author() {
        let server = serve(|_| Reply::json("{}")).await;
        let author = Keys::generate();
        store(&[&server.url])
            .upload(&DATA, "image/png", &author)
            .await
            .unwrap();

        let hits = server.hits.lock().unwrap();
        let req = &hits[0];
        assert_eq!((req.method.as_str(), req.path.as_str()), ("PUT", "/upload"));
        assert_eq!(req.header("content-type"), Some("image/png"));
        assert_eq!(req.body, DATA);

        let token = req
            .header("authorization")
            .unwrap()
            .strip_prefix("Nostr ")
            .unwrap();
        let event = Event::from_json(STANDARD.decode(token).unwrap()).unwrap();
        event.verify().unwrap();
        assert_eq!(event.pubkey, author.public_key());
        assert_eq!(event.kind, Kind::Custom(24242));
        let tag = |name: &str| {
            event
                .tags
                .iter()
                .find(|t| t.as_slice()[0] == name)
                .map(|t| t.as_slice()[1].clone())
        };
        assert_eq!(tag("t").as_deref(), Some("upload"));
        assert_eq!(tag("x"), Some(hex::encode(Sha256::digest(DATA))));
        let expiration: u64 = tag("expiration").unwrap().parse().unwrap();
        assert_eq!(expiration, event.created_at.as_secs() + 300);
    }

    // Downloads take URLs from outside, so they go through the guard; a store
    // pointed at loopback for uploads does not make loopback fetchable.
    #[tokio::test]
    async fn downloads_go_through_the_outbound_guard() {
        let server = serve(|_| Reply::body("image/png", "png")).await;
        let store = store(&[&server.url]);
        let error = store
            .download(&format!("{}/a.png", server.url), 1024)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("non-public host"), "{error}");
        assert!(store.download("file:///etc/passwd", 1024).await.is_err());
        assert_eq!(server.hit_count(), 0);
    }
}
