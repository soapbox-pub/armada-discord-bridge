//! Outbound-fetch guard for URLs that arrive from outside the trust boundary.
//!
//! Everything here exists because the bridge fetches URLs it did not choose:
//! NIP-92 `imeta` tags on inbound rumors, media URLs off Discord embeds (which
//! are OpenGraph values from whatever page was linked), and relay lists inside
//! a pasted invite. The bridge runs in the same process as the portal — which
//! holds PORTAL_SEAL_KEY, the key that unseals every per-bridge secret in the
//! database. An unguarded fetch there is a request primitive into the
//! deployment's own network (the cloud metadata service, Postgres, the portal's
//! own admin surface), with the result posted into a Discord channel. (In the
//! Bun original, `fetch` also resolved `file:` and `data:`, making it a read
//! primitive over the process's filesystem and environment; reqwest does not,
//! but the scheme check stays so that never depends on the HTTP client.)
//!
//! Three separate things have to hold, and each was missing on its own:
//!   - the scheme must be http(s), so `file:`/`data:`/`blob:` never resolve;
//!   - the host must not be loopback, link-local, or RFC1918/ULA, checked
//!     against the RESOLVED addresses rather than the spelling, so a public
//!     name pointing at 127.0.0.1 is caught too;
//!   - the check must be re-run on every redirect hop, or the first Location
//!     header undoes it.
//!
//! The address that is CHECKED is also the address that is CONNECTED to: the
//! guard resolves once and pins the result, because handing the name back to
//! the HTTP client would resolve a second, independent time and a 0-TTL record
//! that alternates public -> 127.0.0.1 (DNS rebinding) passes a check it never
//! has to honor.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use async_trait::async_trait;
use reqwest::Method;
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, LOCATION};
use reqwest::redirect::Policy;
use url::{Host, Url};

/// Redirect hops honored before a fetch is abandoned.
const MAX_REDIRECTS: usize = 3;

/// Whole-operation budget for a guarded fetch: DNS, every redirect hop, and the
/// body read share it. Without one, a server that dribbles a byte a minute holds
/// the socket until the process dies — the byte counter bounds bytes, not time.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

/// Budget for a [`safe_probe`] issued by [`SafeProber`].
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Whether an IP literal is one we refuse to originate requests to: loopback,
/// link-local (including the cloud metadata service on 169.254.169.254),
/// private/CGNAT ranges, and their IPv6 equivalents.
///
/// Spelling is the whole point of classifying by parsed VALUE. A URL parser
/// re-serializes an IPv6 host into the canonical all-hex form, so the literal
/// `[::ffff:127.0.0.1]` arrives at the guard as `::ffff:7f00:1`. A check
/// written against the dotted-quad spelling matches the one form that never
/// actually shows up, which is how loopback and the cloud metadata service were
/// both reachable through a tag any channel member could publish.
pub fn is_private_address(ip: &str) -> bool {
    // Normalize before classifying, not after: a bracketed literal and a zone id
    // both fail to parse, so anything that reached the checks still wearing them
    // was silently answered "not private".
    let lower = ip.to_ascii_lowercase();
    let bare = lower.strip_prefix('[').unwrap_or(&lower);
    let bare = bare.strip_suffix(']').unwrap_or(bare);
    let bare = bare.split('%').next().unwrap_or_default();
    if let Ok(v4) = bare.parse::<Ipv4Addr>() {
        return is_private_v4(v4);
    }
    if bare.contains(':') {
        // Looks like v6 and does not parse as v6: refuse rather than guess.
        return match bare.parse::<Ipv6Addr>() {
            Ok(v6) => is_private_v6(v6),
            Err(_) => true,
        };
    }
    false
}

/// [`is_private_address`] for an address that is already parsed.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    if a == 0 || a == 10 || a == 127 {
        return true;
    }
    if a == 169 && b == 254 {
        return true; // link-local + metadata
    }
    if a == 172 && (16..=31).contains(&b) {
        return true;
    }
    if a == 192 && b == 168 {
        return true;
    }
    // 192.0.0.0/16, which is broader than the two reserved /24s inside it
    // (protocol assignments, and TEST-NET-1 at 192.0.2.0/24) but is not space
    // a media origin or relay is ever reachable on.
    if a == 192 && b == 0 {
        return true;
    }
    if a == 192 && b == 88 && c == 99 {
        return true; // 6to4 relay anycast
    }
    if a == 100 && (64..=127).contains(&b) {
        return true; // CGNAT
    }
    if a == 198 && (b == 18 || b == 19) {
        return true; // benchmarking
    }
    if a == 198 && b == 51 && c == 100 {
        return true; // TEST-NET-2
    }
    if a == 203 && b == 0 && c == 113 {
        return true; // TEST-NET-3
    }
    a >= 224 // multicast + reserved
}

fn is_private_v6(ip: Ipv6Addr) -> bool {
    let g = ip.segments();
    if let Some(embedded) = embedded_ipv4(&g) {
        return is_private_v4(embedded);
    }
    if ip.is_unspecified() || ip.is_loopback() {
        return true; // :: and ::1
    }
    if g[0] & 0xffc0 == 0xfe80 {
        return true; // fe80::/10 link-local
    }
    if g[0] & 0xfe00 == 0xfc00 {
        return true; // fc00::/7 ULA
    }
    g[0] & 0xff00 == 0xff00 // ff00::/8 multicast
}

/// The IPv4 address embedded in an IPv6 one, for every form that routes to a v4
/// destination. Each of these is a way to spell "connect to 127.0.0.1" without
/// writing an IPv4 address, so each has to defer to the v4 rules.
fn embedded_ipv4(g: &[u16; 8]) -> Option<Ipv4Addr> {
    let quad = |hi: u16, lo: u16| {
        let [a, b] = hi.to_be_bytes();
        let [c, d] = lo.to_be_bytes();
        Ipv4Addr::new(a, b, c, d)
    };
    let zero_through = |n: usize| g[..n].iter().all(|&x| x == 0);
    if zero_through(5) && g[5] == 0xffff {
        return Some(quad(g[6], g[7])); // ::ffff:0:0/96, v4-mapped
    }
    // ::a.b.c.d (v4-compatible, deprecated but still routed). `::` and `::1` are
    // not v4 addresses and are handled as themselves by the caller.
    if zero_through(6) && !(g[6] == 0 && g[7] <= 1) {
        return Some(quad(g[6], g[7]));
    }
    if g[0] == 0x0064 && g[1] == 0xff9b {
        return Some(quad(g[6], g[7])); // 64:ff9b::/96, NAT64
    }
    if g[0] == 0x2002 {
        return Some(quad(g[1], g[2])); // 2002::/16, 6to4
    }
    None
}

/// Which addresses a guarded request may reach.
///
/// Production has exactly one answer, [`Reach::Public`]. The loopback variant
/// only exists under `cfg(test)`, so no build that ships can name it: it is how
/// the tests aim the full guard — redirect re-vetting, the byte counter, the
/// content-length cap — at a server on 127.0.0.1 without the guard itself
/// growing an off switch.
#[derive(Clone, Copy, Debug)]
enum Reach {
    Public,
    /// Public addresses plus 127.0.0.1 exactly. Every other private range stays
    /// refused, so a test can still watch a redirect to the metadata service die.
    #[cfg(test)]
    Loopback,
}

impl Reach {
    fn admits(self, ip: IpAddr) -> bool {
        match self {
            Reach::Public => !is_private_ip(ip),
            #[cfg(test)]
            Reach::Loopback => ip == IpAddr::V4(Ipv4Addr::LOCALHOST) || !is_private_ip(ip),
        }
    }
}

/// Resolve `hostname`, vet every address it names, and return the one to
/// connect to — or `None` if any of them is private.
///
/// Returning the address rather than a flag is what closes DNS rebinding:
/// [`safe_fetch`] connects to this exact IP instead of handing the name back to
/// the HTTP client for a second, independent resolution that the attacker's
/// nameserver is free to answer differently.
///
/// A name that FAILS to resolve is refused. The previous default was to allow
/// it, reasoning that a name the resolver cannot answer reaches nothing anyway
/// — but that only holds if there is one resolution, and there were two. An
/// authoritative server that SERVFAILs the guard's query and answers 127.0.0.1
/// to the socket's got a bypass without needing rebinding at all. An
/// unresolvable media URL is not worth that; the relay path filters rather than
/// throws and has a fallback list, so a DNS hiccup degrades instead of breaking.
///
/// Dotless names are refused outright: "localhost", "postgres", "redis" and
/// friends resolve per-host, are exactly the container-network shape this
/// guards, and never legitimately name a media origin or a public relay.
pub async fn resolve_public_host(hostname: &str) -> Option<IpAddr> {
    resolve_host(hostname, Reach::Public).await
}

async fn resolve_host(hostname: &str, reach: Reach) -> Option<IpAddr> {
    let bare = hostname.strip_prefix('[').unwrap_or(hostname);
    let bare = bare.strip_suffix(']').unwrap_or(bare);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return reach.admits(ip).then_some(ip);
    }
    // Something v6-shaped that does not parse (a zone id, a malformed group) is
    // not a name either; refuse it rather than hand it to the resolver.
    if bare.contains(':') || !bare.contains('.') {
        return None;
    }
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((bare, 0)).await.ok()?.collect();
    let first = addresses.first()?.ip();
    if addresses.iter().any(|a| !reach.admits(a.ip())) {
        return None;
    }
    Some(first)
}

/// Whether every address `hostname` names is public.
///
/// Public because relay URLs need the same host test with a different scheme
/// allow-list (ws/wss rather than http/https) — see the portal's relay guard.
/// The relay pool takes a URL and does its own connecting, so that caller gets
/// the verdict rather than the pinned address.
pub async fn host_is_public(hostname: &str) -> bool {
    resolve_public_host(hostname).await.is_some()
}

/// Parse and vet a URL that came from untrusted input. Errors with a reason
/// rather than returning a flag: every caller here treats a rejected URL as a
/// hard skip, and a silent falsy return is how one of these gets forgotten.
pub async fn assert_safe_http_url(raw: &str) -> anyhow::Result<Url> {
    Ok(vet_http_url(raw, Reach::Public).await?.0)
}

/// [`assert_safe_http_url`], keeping the address the verdict was made about.
async fn vet_http_url(raw: &str, reach: Reach) -> anyhow::Result<(Url, IpAddr)> {
    let url = Url::parse(raw).map_err(|_| anyhow!("refusing to fetch malformed URL"))?;
    vet_url(url, reach).await
}

async fn vet_url(url: Url, reach: Reach) -> anyhow::Result<(Url, IpAddr)> {
    if !matches!(url.scheme(), "http" | "https") {
        bail!("refusing to fetch {}: URL", url.scheme());
    }
    // Classify the parsed host, not its spelling: the URL parser has already
    // turned `0x7f.1` and `[::ffff:127.0.0.1]` into the addresses they mean.
    let address = match url.host() {
        Some(Host::Ipv4(ip)) => reach.admits(ip.into()).then_some(ip.into()),
        Some(Host::Ipv6(ip)) => reach.admits(ip.into()).then_some(ip.into()),
        Some(Host::Domain(name)) => resolve_host(name, reach).await,
        None => None,
    };
    let Some(address) = address else {
        bail!(
            "refusing to fetch non-public host {}",
            url.host_str().unwrap_or_default()
        );
    };
    Ok((url, address))
}

/// The DNS override that aims a request for `url` at `address`, or `None` when
/// the URL's host is already that literal address.
///
/// The URL itself is not rewritten: the name stays in it, so `Host` still
/// carries the original authority for virtual hosting, and TLS keeps the NAME
/// as its server identity — SNI and certificate validation are about who we
/// meant to talk to, and pinning the address must not become a way to accept
/// the wrong certificate. Only the resolution is replaced. Pure so the test can
/// check it; everything interesting about pinning is in what this returns.
fn pinned_override(url: &Url, address: IpAddr) -> Option<(String, SocketAddr)> {
    match url.host()? {
        Host::Domain(name) => Some((
            name.to_owned(),
            SocketAddr::new(address, url.port_or_known_default()?),
        )),
        Host::Ipv4(_) | Host::Ipv6(_) => None,
    }
}

/// A resolver that answers nothing.
///
/// Installed under the pin so that a name the override does not cover fails
/// instead of quietly getting the second, independent resolution the pin exists
/// to prevent. The override map is consulted first, so the vetted name never
/// reaches this.
struct RefuseResolve;

impl reqwest::dns::Resolve for RefuseResolve {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let error: Box<dyn std::error::Error + Send + Sync> =
            format!("{} was not vetted by the outbound guard", name.as_str()).into();
        Box::pin(std::future::ready(Err::<reqwest::dns::Addrs, _>(error)))
    }
}

/// A client that can only reach `address`, for one hop to `url`.
fn pinned_client(url: &Url, address: IpAddr) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        // Redirects are walked by hand in `guarded_fetch` so each Location is
        // re-vetted; a client that followed them itself would undo the guard.
        .redirect(Policy::none())
        // A proxy from the environment would be handed the NAME and resolve it
        // itself, so the socket would land wherever the proxy decided, not on
        // the vetted address.
        .no_proxy()
        .dns_resolver(RefuseResolve);
    if let Some((name, socket)) = pinned_override(url, address) {
        builder = builder.resolve(&name, socket);
    }
    builder.build().context("building pinned HTTP client")
}

/// Walk an untrusted URL to its final response with the guard applied at every
/// hop, pinning each connection to the address the verdict was made about.
///
/// Shared by [`safe_fetch`] and [`safe_probe`] so there is exactly one place the
/// guard lives. That is not tidiness: the GIF-variant probe used to call a bare
/// fetch with redirects followed on an OpenGraph URL from a linked page, and a
/// second copy of this loop is how that happens again.
///
/// Carries no deadline of its own; callers wrap the whole operation in one.
async fn guarded_fetch(
    raw: &str,
    method: &Method,
    headers: &HeaderMap,
    reach: Reach,
) -> anyhow::Result<reqwest::Response> {
    let (mut target, mut address) = vet_http_url(raw, reach).await?;
    let mut hop = 0;
    loop {
        let res = pinned_client(&target, address)?
            .request(method.clone(), target.clone())
            .headers(headers.clone())
            .send()
            .await
            .with_context(|| format!("download {raw}"))?;
        let location = match res.headers().get(LOCATION) {
            Some(location) if res.status().is_redirection() && !location.is_empty() => location,
            _ => return Ok(res),
        };
        if hop >= MAX_REDIRECTS {
            bail!("download {raw}: too many redirects");
        }
        // Resolve relative Locations against the hop we are on, then re-vet: an
        // unchecked Location is how a public URL reaches a private host.
        let next = location
            .to_str()
            .ok()
            .and_then(|location| target.join(location).ok())
            .ok_or_else(|| anyhow!("refusing to fetch malformed URL"))?;
        (target, address) = vet_url(next, reach).await?;
        hop += 1;
    }
}

/// Request options for [`safe_fetch`]. The defaults are a GET with no extra
/// headers under [`DEFAULT_TIMEOUT`].
#[derive(Clone, Debug, Default)]
pub struct FetchOptions {
    pub method: Option<Method>,
    pub headers: HeaderMap,
    /// One budget for DNS, every hop, and the body together.
    pub timeout: Option<Duration>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeFetchResult {
    pub body: Vec<u8>,
    pub mime: String,
}

/// Fetch an untrusted URL with the guard applied at every hop, and read the
/// body through a running byte counter.
///
/// The counter is the point: `content-length` is supplied by the remote server
/// and is absent entirely for chunked responses, so checking it and then
/// buffering the body reads the whole thing before the cap is ever consulted —
/// the cap only bound servers that volunteered their size.
pub async fn safe_fetch(
    raw: &str,
    max_bytes: usize,
    opts: FetchOptions,
) -> anyhow::Result<SafeFetchResult> {
    fetch_with(raw, max_bytes, opts, Reach::Public).await
}

async fn fetch_with(
    raw: &str,
    max_bytes: usize,
    opts: FetchOptions,
    reach: Reach,
) -> anyhow::Result<SafeFetchResult> {
    // One budget for the whole operation, not one per hop: three redirects that
    // each get the full timeout is three times the stall a caller asked for.
    let budget = opts.timeout.unwrap_or(DEFAULT_TIMEOUT);
    let method = opts.method.unwrap_or(Method::GET);
    let fetch = async {
        let mut res = guarded_fetch(raw, &method, &opts.headers, reach).await?;
        if !res.status().is_success() {
            bail!("download {raw}: HTTP {}", res.status().as_u16());
        }
        let declared = res
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        if let Some(declared) = declared.filter(|&d| d > max_bytes as u64) {
            bail!("download {raw}: {declared} bytes exceeds cap");
        }
        let mime = mime_of(res.headers());
        let mime = if mime.is_empty() {
            "application/octet-stream".to_owned()
        } else {
            mime
        };
        let body = read_capped(&mut res, max_bytes, raw).await?;
        Ok(SafeFetchResult { body, mime })
    };
    tokio::time::timeout(budget, fetch)
        .await
        .map_err(|_| anyhow!("download {raw}: timed out"))?
}

/// Read a response body through a running byte counter, abandoning the stream
/// the moment it goes over.
///
/// This is the half that has to hold even for a host we already trust: the
/// previous implementation checked `content-length` and then buffered the
/// whole body before any check ran, so the cap bound only servers that
/// truthfully declared their size.
async fn read_capped(
    res: &mut reqwest::Response,
    max_bytes: usize,
    label: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = res
        .chunk()
        .await
        .with_context(|| format!("download {label}"))?
    {
        if body.len() + chunk.len() > max_bytes {
            bail!("download {label}: body exceeds cap");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The media type of a response: `content-type` up to any parameters, or "".
fn mime_of(headers: &HeaderMap) -> String {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(|v| v.trim().to_owned())
        .unwrap_or_default()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeResult {
    pub ok: bool,
    pub mime: String,
}

/// HEAD an untrusted URL under the full guard, for "does this variant exist,
/// and is it the type I wanted" probes.
///
/// Returns `None` for every kind of no — a non-public host, a rejected scheme,
/// too many hops, a transport error, the deadline — because every caller
/// treats those identically: give up on this candidate and try the next. A
/// probe is not a download, so there is no body and no byte cap; the point is
/// that the request is still aimed only at addresses the guard approved.
/// Without it the probe is a blind SSRF: the URL comes from an OpenGraph tag on
/// a page the message author chose, and `HEAD http://169.254.169.254/…` from
/// this process is a reachability oracle for anything on the deployment's
/// internal network.
pub async fn safe_probe(raw: &str, timeout: Duration) -> Option<ProbeResult> {
    probe_with(raw, timeout, Reach::Public).await
}

async fn probe_with(raw: &str, timeout: Duration, reach: Reach) -> Option<ProbeResult> {
    let res = tokio::time::timeout(
        timeout,
        guarded_fetch(raw, &Method::HEAD, &HeaderMap::new(), reach),
    )
    .await
    .ok()?
    .ok()?;
    Some(ProbeResult {
        ok: res.status().is_success(),
        mime: mime_of(res.headers()),
    })
}

/// The probe the router uses, behind a trait so its tests can fake the network.
#[async_trait]
pub trait Prober: Send + Sync {
    async fn probe(&self, url: &str) -> Option<ProbeResult>;
}

/// [`Prober`] over [`safe_probe`] with [`PROBE_TIMEOUT`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SafeProber;

#[async_trait]
impl Prober for SafeProber {
    async fn probe(&self, url: &str) -> Option<ProbeResult> {
        safe_probe(url, PROBE_TIMEOUT).await
    }
}

/// A minimal HTTP/1.1 responder on 127.0.0.1 for this crate's tests: one
/// request per connection, `connection: close`, and a record of every request
/// that reached it.
#[cfg(test)]
pub(crate) mod test_server {
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;

    pub(crate) struct Request {
        pub method: String,
        pub path: String,
        /// Names lowercased.
        pub headers: Vec<(String, String)>,
        pub body: Vec<u8>,
    }

    impl Request {
        pub fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    pub(crate) enum Reply {
        /// A `content-length` matching the body is added unless one is given.
        Full {
            status: u16,
            headers: Vec<(&'static str, String)>,
            body: Vec<u8>,
        },
        /// A 200 whose length is delimited only by the connection closing.
        Unsized(Vec<u8>),
        /// A 200 that streams 64 KiB chunks until the client goes away.
        Endless,
        /// A 200 that promises a body and never sends a byte of it.
        Stall,
    }

    impl Reply {
        pub fn status(status: u16) -> Self {
            Reply::Full {
                status,
                headers: Vec::new(),
                body: Vec::new(),
            }
        }

        pub fn body(content_type: &str, body: impl Into<Vec<u8>>) -> Self {
            Reply::Full {
                status: 200,
                headers: vec![("content-type", content_type.to_owned())],
                body: body.into(),
            }
        }

        pub fn json(body: &str) -> Self {
            Self::body("application/json", body)
        }

        pub fn redirect(location: &str) -> Self {
            Reply::Full {
                status: 302,
                headers: vec![("location", location.to_owned())],
                body: Vec::new(),
            }
        }
    }

    type Handler = dyn Fn(&Request) -> Reply + Send + Sync;

    pub(crate) struct Server {
        pub url: String,
        pub hits: Arc<Mutex<Vec<Request>>>,
        task: JoinHandle<()>,
    }

    impl Server {
        pub fn hit_count(&self) -> usize {
            self.hits.lock().unwrap().len()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    pub(crate) async fn serve(
        handler: impl Fn(&Request) -> Reply + Send + Sync + 'static,
    ) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<Handler> = Arc::new(handler);
        let task = tokio::spawn({
            let hits = hits.clone();
            async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let (hits, handler) = (hits.clone(), handler.clone());
                    tokio::spawn(async move {
                        let _ = respond(stream, &*handler, &hits).await;
                    });
                }
            }
        });
        Server { url, hits, task }
    }

    async fn respond(
        mut stream: TcpStream,
        handler: &Handler,
        hits: &Mutex<Vec<Request>>,
    ) -> std::io::Result<()> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let mut first = lines.next().unwrap_or_default().split(' ');
        let method = first.next().unwrap_or_default().to_owned();
        let path = first.next().unwrap_or_default().to_owned();
        let headers: Vec<(String, String)> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
            .collect();
        let length = headers
            .iter()
            .find(|(k, _)| k == "content-length")
            .and_then(|(_, v)| v.parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = buf[head_end..].to_vec();
        while body.len() < length {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }

        let request = Request {
            method,
            path,
            headers,
            body,
        };
        let reply = handler(&request);
        hits.lock().unwrap().push(request);

        match reply {
            Reply::Full {
                status,
                headers,
                body,
            } => {
                let mut out = format!("HTTP/1.1 {status} X\r\nconnection: close\r\n");
                if !headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                {
                    out.push_str(&format!("content-length: {}\r\n", body.len()));
                }
                for (k, v) in &headers {
                    out.push_str(&format!("{k}: {v}\r\n"));
                }
                out.push_str("\r\n");
                stream.write_all(out.as_bytes()).await?;
                stream.write_all(&body).await?;
            }
            Reply::Unsized(body) => {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n")
                    .await?;
                stream.write_all(&body).await?;
            }
            Reply::Endless => {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nconnection: close\r\ntransfer-encoding: chunked\r\n\r\n")
                    .await?;
                let block = vec![0u8; 64 * 1024];
                loop {
                    stream
                        .write_all(format!("{:x}\r\n", block.len()).as_bytes())
                        .await?;
                    stream.write_all(&block).await?;
                    stream.write_all(b"\r\n").await?;
                }
            }
            Reply::Stall => {
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n")
                    .await?;
                std::future::pending::<()>().await;
            }
        }
        stream.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::test_server::{Reply, serve};
    use super::*;

    fn assert_err_contains<T: std::fmt::Debug>(result: anyhow::Result<T>, needle: &str) {
        let error = format!("{:#}", result.expect_err("expected an error"));
        assert!(
            error.contains(needle),
            "{error:?} does not mention {needle:?}"
        );
    }

    #[test]
    fn names_the_ipv4_ranges_we_refuse_to_originate_to() {
        for ip in [
            "127.0.0.1",
            "0.0.0.0",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "224.0.0.1",
        ] {
            assert!(is_private_address(ip), "{ip}");
        }
    }

    #[test]
    fn lets_real_public_addresses_through() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "172.15.0.1",
            "172.32.0.1",
            "93.184.216.34",
        ] {
            assert!(!is_private_address(ip), "{ip}");
        }
    }

    #[test]
    fn names_the_reserved_ipv4_blocks_that_are_not_rfc1918() {
        for ip in [
            "192.0.0.1",
            "192.0.2.5",
            "198.18.0.1",
            "198.19.255.1",
            "198.51.100.7",
            "203.0.113.9",
            "192.88.99.1",
        ] {
            assert!(is_private_address(ip), "{ip}");
        }
    }

    #[test]
    fn covers_the_ipv6_equivalents_including_v4_mapped_forms() {
        for ip in [
            "::1",
            "::",
            "fe80::1",
            "febf::1",
            "fd00::1",
            "fc00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_private_address(ip), "{ip}");
        }
        assert!(!is_private_address("2606:4700:4700::1111"));
    }

    // The regression that mattered: a URL parser re-serializes an IPv6 host into
    // the canonical all-hex form, so `[::ffff:127.0.0.1]` reaches the guard
    // spelled `::ffff:7f00:1`. The old check demanded a dotted quad and matched
    // none of these, which made every one of them "public".
    #[test]
    fn classifies_embedded_ipv4_by_value_in_the_spelling_a_url_yields() {
        for ip in [
            "::ffff:7f00:1",         // 127.0.0.1
            "::ffff:a9fe:a9fe",      // 169.254.169.254, the metadata service
            "::ffff:a00:1",          // 10.0.0.1
            "0:0:0:0:0:ffff:7f00:1", // uncompressed spelling of the same
            "::7f00:1",              // v4-compatible
            "64:ff9b::7f00:1",       // NAT64
            "2002:7f00:1::",         // 6to4
        ] {
            assert!(is_private_address(ip), "{ip}");
        }
        // The same forms naming a public address stay usable.
        assert!(!is_private_address("::ffff:808:808"));
        assert!(!is_private_address("2002:808:808::"));
    }

    // Both spellings fail to parse as an address, so before normalization moved
    // ahead of parsing these fell through every check and were answered "public".
    #[test]
    fn classifies_a_bracketed_or_zone_suffixed_literal() {
        assert!(is_private_address("[::1]"));
        assert!(is_private_address("[::ffff:7f00:1]"));
        assert!(is_private_address("fe80::1%eth0"));
    }

    #[test]
    fn refuses_a_v6_shaped_literal_it_cannot_parse() {
        assert!(is_private_address("::ffff:7f00:1:2:3:4:5:6"));
        assert!(is_private_address("1::2::3"));
    }

    #[test]
    fn pins_a_name_to_the_address_keeping_the_url_and_port() {
        let url = Url::parse("https://cdn.example.com/a/b.png?x=1").unwrap();
        let (name, socket) = pinned_override(&url, "93.184.216.34".parse().unwrap()).unwrap();
        assert_eq!(name, "cdn.example.com");
        assert_eq!(socket, "93.184.216.34:443".parse().unwrap());

        let url = Url::parse("https://cdn.example.com:8443/a").unwrap();
        let (name, socket) = pinned_override(&url, "2606:4700::1111".parse().unwrap()).unwrap();
        assert_eq!(name, "cdn.example.com");
        assert_eq!(socket, "[2606:4700::1111]:8443".parse().unwrap());
    }

    #[test]
    fn leaves_an_ip_literal_url_unpinned_because_it_is_the_address() {
        let url = Url::parse("http://93.184.216.34/x").unwrap();
        assert_eq!(
            pinned_override(&url, "93.184.216.34".parse().unwrap()),
            None
        );
    }

    // The pin end to end: a name nobody can resolve still reaches the server,
    // because the socket goes to the vetted address and never asks DNS, and the
    // request still carries the name as its Host.
    #[tokio::test]
    async fn a_pinned_client_connects_to_the_address_and_sends_the_name() {
        let server = serve(|_| Reply::body("text/plain", "ok")).await;
        let port = Url::parse(&server.url).unwrap().port().unwrap();
        let url = Url::parse(&format!("http://pinned.example.invalid:{port}/x")).unwrap();
        let res = pinned_client(&url, IpAddr::V4(Ipv4Addr::LOCALHOST))
            .unwrap()
            .get(url.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(res.text().await.unwrap(), "ok");
        assert_eq!(
            server.hits.lock().unwrap()[0].header("host"),
            Some(format!("pinned.example.invalid:{port}").as_str())
        );
    }

    // And the other half: any name the pin does not cover gets no resolution at
    // all, rather than a second one the attacker's nameserver gets to answer.
    #[tokio::test]
    async fn a_pinned_client_refuses_a_name_it_was_not_pinned_to() {
        let pinned = Url::parse("http://media.example.com/").unwrap();
        let client = pinned_client(&pinned, "93.184.216.34".parse().unwrap()).unwrap();
        assert!(
            client
                .get("http://localhost.example.com/")
                .send()
                .await
                .is_err()
        );
    }

    // The one that mattered in the Bun original: its fetch resolved file:// and
    // data:, and this process holds the seal key that unseals every per-bridge
    // secret.
    #[tokio::test]
    async fn refuses_non_http_schemes() {
        for url in [
            "file:///proc/self/environ",
            "file:///etc/passwd",
            "data:text/plain,hello",
            "blob:https://example.com/x",
        ] {
            assert_err_contains(assert_safe_http_url(url).await, "refusing to fetch");
        }
    }

    #[tokio::test]
    async fn refuses_loopback_and_metadata_hosts_by_literal_ip() {
        for url in [
            "http://127.0.0.1/x",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5:9200/",
            "http://[::1]/x",
            "http://0x7f.1/x", // the URL parser reads this as 127.0.0.1
        ] {
            assert_err_contains(assert_safe_http_url(url).await, "non-public host");
        }
    }

    #[tokio::test]
    async fn refuses_loopback_and_metadata_spelled_as_an_ipv6_literal() {
        for url in [
            "http://[::ffff:127.0.0.1]/x",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://[64:ff9b::7f00:1]/x",
            "http://[::ffff:10.0.0.5]:9200/",
        ] {
            assert_err_contains(assert_safe_http_url(url).await, "non-public host");
        }
    }

    // Fail closed. Two resolutions would happen without the pin (ours, then the
    // socket's), so a name our resolver cannot answer is not a name the socket
    // cannot reach.
    #[tokio::test]
    async fn refuses_a_name_that_does_not_resolve() {
        assert_err_contains(
            assert_safe_http_url("http://nothing.here.invalid/x").await,
            "non-public host",
        );
    }

    #[tokio::test]
    async fn refuses_bare_intranet_names_that_never_name_a_real_media_origin() {
        assert_err_contains(
            assert_safe_http_url("http://localhost:8787/").await,
            "non-public host",
        );
        assert_err_contains(
            assert_safe_http_url("http://postgres/").await,
            "non-public host",
        );
        assert!(!host_is_public("localhost").await);
        assert!(!host_is_public("fe80::1%eth0").await);
    }

    #[tokio::test]
    async fn refuses_malformed_input_rather_than_passing_it_on() {
        assert_err_contains(assert_safe_http_url("not a url").await, "malformed");
    }

    #[tokio::test]
    async fn host_is_public_answers_for_literals() {
        assert!(host_is_public("1.1.1.1").await);
        assert!(host_is_public("[2606:4700:4700::1111]").await);
        assert!(!host_is_public("[::ffff:7f00:1]").await);
    }

    /// The GIF-variant probe used to issue a bare fetch with redirects
    /// followed, which is how a guard with this much care in it still issued
    /// `HEAD http://169.254.169.254/…` on behalf of whoever posted a link. A
    /// refusal must be a value the caller can act on, not an error.
    #[tokio::test]
    async fn probe_answers_none_for_hosts_the_guard_refuses_without_connecting() {
        let server = serve(|_| Reply::body("image/gif", "GIF89a")).await;
        for url in [
            format!("{}/x.gif", server.url),
            "http://127.0.0.1/x.gif".to_owned(),
            "http://169.254.169.254/latest/meta-data/x.gif".to_owned(),
            "http://[::ffff:127.0.0.1]/x.gif".to_owned(),
            "http://localhost:8787/x.gif".to_owned(),
            "file:///etc/passwd".to_owned(),
            "not a url".to_owned(),
        ] {
            assert_eq!(safe_probe(&url, PROBE_TIMEOUT).await, None, "{url}");
            assert_eq!(SafeProber.probe(&url).await, None, "{url}");
        }
        assert_eq!(server.hit_count(), 0);
    }

    #[tokio::test]
    async fn safe_fetch_refuses_a_loopback_server_without_connecting() {
        let server = serve(|_| Reply::body("image/png", "png")).await;
        assert_err_contains(
            safe_fetch(
                &format!("{}/a.png", server.url),
                1024,
                FetchOptions::default(),
            )
            .await,
            "non-public host",
        );
        assert_eq!(server.hit_count(), 0);
    }

    // Everything below runs the real guard against a loopback server through
    // `Reach::Loopback`, which admits 127.0.0.1 and nothing else private.

    #[tokio::test]
    async fn probe_reports_status_and_type() {
        let server = serve(|req| {
            assert_eq!(req.method, "HEAD");
            if req.path == "/x.gif" {
                Reply::body("image/gif; charset=binary", "")
            } else {
                Reply::status(404)
            }
        })
        .await;
        let found = probe_with(
            &format!("{}/x.gif", server.url),
            // Must succeed, so not the production 3 s: a loaded test box stalls.
            Duration::from_secs(30),
            Reach::Loopback,
        )
        .await;
        assert_eq!(
            found,
            Some(ProbeResult {
                ok: true,
                mime: "image/gif".into()
            })
        );
        let missing = probe_with(
            &format!("{}/y.gif", server.url),
            // Must succeed, so not the production 3 s: a loaded test box stalls.
            Duration::from_secs(30),
            Reach::Loopback,
        )
        .await;
        assert_eq!(
            missing,
            Some(ProbeResult {
                ok: false,
                mime: String::new()
            })
        );
    }

    #[tokio::test]
    async fn returns_a_body_that_fits_intact() {
        let server = serve(|_| Reply::body("image/png; x=y", vec![7u8; 1024])).await;
        let got = fetch_with(
            &format!("{}/a", server.url),
            64 * 1024,
            FetchOptions::default(),
            Reach::Loopback,
        )
        .await
        .unwrap();
        assert_eq!(got.body, vec![7u8; 1024]);
        assert_eq!(got.mime, "image/png");
    }

    #[tokio::test]
    async fn defaults_a_missing_type_to_octet_stream() {
        let server = serve(|_| Reply::status(200)).await;
        let got = fetch_with(&server.url, 1024, FetchOptions::default(), Reach::Loopback)
            .await
            .unwrap();
        assert_eq!(got.mime, "application/octet-stream");
    }

    #[tokio::test]
    async fn treats_a_non_2xx_status_as_an_error() {
        let server = serve(|_| Reply::status(404)).await;
        assert_err_contains(
            fetch_with(&server.url, 1024, FetchOptions::default(), Reach::Loopback).await,
            "HTTP 404",
        );
    }

    // The shape the old code could not bound: no content-length, so its check
    // compared nothing against the cap and then buffered the lot.
    #[tokio::test]
    async fn stops_an_endless_chunked_body_that_never_declares_a_length() {
        let server = serve(|_| Reply::Endless).await;
        assert_err_contains(
            fetch_with(
                &server.url,
                256 * 1024,
                FetchOptions::default(),
                Reach::Loopback,
            )
            .await,
            "body exceeds cap",
        );
    }

    #[tokio::test]
    async fn stops_a_close_delimited_body_over_the_cap() {
        let server = serve(|_| Reply::Unsized(vec![0u8; 200 * 1024])).await;
        assert_err_contains(
            fetch_with(
                &server.url,
                64 * 1024,
                FetchOptions::default(),
                Reach::Loopback,
            )
            .await,
            "body exceeds cap",
        );
    }

    #[tokio::test]
    async fn refuses_a_declared_length_over_the_cap_before_reading() {
        let server = serve(|_| Reply::Full {
            status: 200,
            headers: vec![("content-length", "10000000".into())],
            body: Vec::new(),
        })
        .await;
        assert_err_contains(
            fetch_with(
                &server.url,
                64 * 1024,
                FetchOptions::default(),
                Reach::Loopback,
            )
            .await,
            "10000000 bytes exceeds cap",
        );
    }

    #[tokio::test]
    async fn follows_a_relative_redirect_to_a_vetted_host() {
        let server = serve(|req| match req.path.as_str() {
            "/start" => Reply::redirect("/final"),
            _ => Reply::body("text/plain", "landed"),
        })
        .await;
        let got = fetch_with(
            &format!("{}/start", server.url),
            1024,
            FetchOptions::default(),
            Reach::Loopback,
        )
        .await
        .unwrap();
        assert_eq!(got.body, b"landed");
        assert_eq!(server.hit_count(), 2);
    }

    // An unchecked Location is how a public URL reaches a private host: every
    // hop is re-vetted, and a refused one is never connected to.
    #[tokio::test]
    async fn re_vets_every_redirect_hop() {
        for (location, needle) in [
            (
                "http://169.254.169.254/latest/meta-data/",
                "non-public host",
            ),
            ("http://[::ffff:10.0.0.5]:9200/", "non-public host"),
            ("http://postgres:5432/", "non-public host"),
            ("file:///proc/self/environ", "refusing to fetch file:"),
        ] {
            let server = serve(move |_| Reply::redirect(location)).await;
            assert_err_contains(
                fetch_with(&server.url, 1024, FetchOptions::default(), Reach::Loopback).await,
                needle,
            );
            assert_eq!(
                probe_with(&server.url, PROBE_TIMEOUT, Reach::Loopback).await,
                None
            );
        }
    }

    #[tokio::test]
    async fn gives_up_after_three_redirects() {
        let server = serve(|_| Reply::redirect("/again")).await;
        assert_err_contains(
            fetch_with(&server.url, 1024, FetchOptions::default(), Reach::Loopback).await,
            "too many redirects",
        );
        assert_eq!(server.hit_count(), MAX_REDIRECTS + 1);
    }

    // One budget for the whole operation: a body that stalls is abandoned even
    // though it never trips the byte cap.
    #[tokio::test]
    async fn abandons_a_fetch_that_outlives_its_budget() {
        let server = serve(|_| Reply::Stall).await;
        let opts = FetchOptions {
            timeout: Some(Duration::from_millis(200)),
            ..FetchOptions::default()
        };
        assert_err_contains(
            fetch_with(&server.url, 1024, opts, Reach::Loopback).await,
            "timed out",
        );
    }
}
