//! Security headers for every response the portal serves, and the origin
//! checks in front of the API.
//!
//! The Content Security Policy is written against what the SPA build actually
//! emits — external modules and one stylesheet, no inline script — so scripts
//! need no inline allowance at all. The single inline script in this codebase
//! is the OAuth popup's, which overrides this policy with a per-response nonce.
//!
//! Deliberately NOT set: Cross-Origin-Opener-Policy. `same-origin` would sever
//! `window.opener` on the callback page and break the popup token handoff --
//! that exact COOP behaviour on Discord's own pages is why the nonce poller
//! exists in the first place.

use std::sync::{Arc, LazyLock};

use anyhow::Context;
use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use url::Url;

/// Relays the SPA opens sockets to itself, for kind 0 profile lookups. Must
/// match PROFILE_RELAYS in web/src/nostrProfile.ts: connect-src pins the list,
/// so a relay added there and not here fails silently in the browser. There is
/// a test for exactly that.
pub const SPA_RELAYS: [&str; 3] = ["wss://purplepag.es", "wss://relay.damus.io", "wss://relay.ditto.pub"];

pub fn csp() -> String {
    [
        "default-src 'none'".to_owned(),
        // The extension schemes keep NIP-07 signers working: some inject their
        // provider as a script element into the page rather than the main world.
        "script-src 'self' chrome-extension: moz-extension:".to_owned(),
        // React writes style attributes; nothing injects stylesheets.
        "style-src 'self' 'unsafe-inline'".to_owned(),
        // Avatars: Discord's CDN, and whatever host a kind 0 profile names.
        "img-src 'self' data: https:".to_owned(),
        "font-src 'self'".to_owned(),
        // The interesting line: script injected into the portal has nowhere to
        // send what it steals.
        format!("connect-src 'self' {}", SPA_RELAYS.join(" ")),
        "form-action 'self'".to_owned(),
        "frame-ancestors 'none'".to_owned(),
        "base-uri 'none'".to_owned(),
        "object-src 'none'".to_owned(),
    ]
    .join("; ")
}

static CSP: LazyLock<HeaderValue> = LazyLock::new(|| HeaderValue::from_str(&csp()).expect("CSP is ASCII"));

/// Every header here yields to one the handler set itself: the OAuth popup page
/// swaps in a nonce policy of its own. (The TypeScript portal got that by
/// setting these before the handler ran and letting it overwrite; here the
/// headers are filled in afterwards, only where absent. Streamed responses —
/// the confirm screen's event stream — still get them, since a response's
/// headers are complete before its body is polled.)
pub async fn security_headers(State(over_https): State<bool>, req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    set_absent(headers, header::CONTENT_SECURITY_POLICY, CSP.clone());
    set_absent(headers, header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    set_absent(headers, header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    set_absent(headers, header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    if over_https {
        set_absent(
            headers,
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    res
}

fn set_absent(headers: &mut HeaderMap, name: HeaderName, value: HeaderValue) {
    headers.entry(name).or_insert(value);
}

/// The origins the API answers to: the portal's own, and the operator's
/// allow-list. Compared by exact string — an Origin header is a serialized
/// origin, and anything looser (prefix, substring) admits neighbours like
/// `https://armada.buzz.evil.example`.
#[derive(Clone, Debug)]
pub struct OriginPolicy {
    pub self_origin: String,
    pub allowed: Vec<String>,
}

impl OriginPolicy {
    pub fn new(base_url: &str, allowed: Vec<String>) -> anyhow::Result<Self> {
        let url = Url::parse(base_url).with_context(|| format!("base URL is not a URL: {base_url}"))?;
        Ok(OriginPolicy { self_origin: url.origin().ascii_serialization(), allowed })
    }

    fn is_allowed(&self, origin: &str) -> bool {
        self.allowed.iter().any(|a| a == origin)
    }
}

/// Refuse state-changing requests from an origin we do not recognise, so CSRF
/// defence does not rest on `SameSite=Lax` alone.
///
/// Lax is a real control and does block cross-site POST in current browsers.
/// But it is one layer, enforced entirely by the client, and it stops covering
/// anything that later becomes reachable by a top-level GET or a form post.
/// This is the server-side half of the same claim.
///
/// A request with NO `Origin` header passes. Browsers always send it on these
/// methods, so its absence means a non-browser caller — curl, or the popup
/// handoff's server-side poller — which could never have ridden a victim's
/// cookies to begin with. Refusing those would break real callers to defend
/// against a shape that cannot occur. `Origin` present but unrecognised is the
/// attack, and that is what this turns away. (Present but not even text is
/// unrecognised too.)
pub async fn origin_guard(State(policy): State<Arc<OriginPolicy>>, req: Request, next: Next) -> Response {
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(req).await;
    }
    if let Some(origin) = req.headers().get(header::ORIGIN) {
        let origin = origin.to_str().unwrap_or("");
        if origin != policy.self_origin && !policy.is_allowed(origin) {
            tracing::warn!("portal: refused {} {} from origin {origin:?}", req.method(), req.uri().path());
            return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "origin not allowed" }))).into_response();
        }
    }
    next.run(req).await
}

/// CORS for allow-listed origins (the Armada client driving the import wizard
/// in-app). Mount on `/api/*`, outside [`origin_guard`].
///
/// `Access-Control-Allow-Credentials` is deliberately absent: cookies must never
/// ride a cross-origin request. Those callers carry an `Authorization: Bearer`
/// token instead, which the browser does not attach on its own, so an allow-list
/// entry grants the ability to *ask* with a token the user's client was given —
/// never the ability to spend a session cookie a visitor already holds.
pub async fn api_cors(State(policy): State<Arc<OriginPolicy>>, req: Request, next: Next) -> Response {
    let allowed_origin = req
        .headers()
        .get(header::ORIGIN)
        .filter(|o| o.to_str().is_ok_and(|o| policy.is_allowed(o)))
        .cloned();
    let mut res = if req.method() == Method::OPTIONS {
        let status = if allowed_origin.is_some() { StatusCode::NO_CONTENT } else { StatusCode::FORBIDDEN };
        status.into_response()
    } else {
        next.run(req).await
    };
    let headers = res.headers_mut();
    if let Some(origin) = allowed_origin {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Content-Type, Authorization"));
        headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, OPTIONS"));
        headers.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
    }
    // Cached responses must not leak one origin's ACAO header to another.
    // Appended, not set: a Vary the handler (or compression) added still holds.
    let varies_by_origin = headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|v| v.trim().eq_ignore_ascii_case("origin"));
    if !varies_by_origin {
        headers.append(header::VARY, HeaderValue::from_static("Origin"));
    }
    // Every API response is session-scoped; none of it belongs in a shared cache.
    set_absent(headers, header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

#[cfg(test)]
mod tests {
    //! The CSP is only as good as its assumptions about the SPA, and those live
    //! in another package. These tests fail when the two drift apart, instead of
    //! letting the browser discover it.

    use std::path::PathBuf;

    use axum::Router;
    use axum::body::Body;
    use axum::middleware::from_fn_with_state;
    use axum::routing::{any, get};
    use tower::ServiceExt;

    use super::*;

    fn web() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packages/portal/web")
    }

    fn directive(name: &str) -> String {
        csp().split("; ").find(|d| d.starts_with(&format!("{name} "))).unwrap_or("").to_owned()
    }

    #[test]
    fn allows_no_inline_or_evald_script() {
        assert!(!directive("script-src").contains("unsafe-inline"));
        assert!(!csp().contains("unsafe-eval"));
        assert!(csp().contains("default-src 'none'"));
    }

    #[test]
    fn pins_where_the_browser_may_talk() {
        let connect = directive("connect-src");
        assert!(connect.contains("'self'"));
        // No blanket schemes: an injected script must have nowhere to exfiltrate.
        for source in connect.split_whitespace() {
            assert!(!matches!(source, "https:" | "http:" | "wss:" | "ws:" | "*"), "blanket source {source}");
        }
        assert!(csp().contains("frame-ancestors 'none'"));
        assert!(csp().contains("object-src 'none'"));
        assert!(csp().contains("base-uri 'none'"));
    }

    #[test]
    fn lists_exactly_the_relays_the_spa_dials() {
        let source = std::fs::read_to_string(web().join("src/nostrProfile.ts")).unwrap();
        let re = regex::Regex::new(r#""(wss://[^"]+)""#).unwrap();
        let mut declared: Vec<&str> = re.captures_iter(&source).map(|c| c.get(1).unwrap().as_str()).collect();
        assert!(!declared.is_empty());
        declared.sort();
        declared.dedup();
        let mut ours = SPA_RELAYS.to_vec();
        ours.sort();
        assert_eq!(ours, declared);
        for relay in declared {
            assert!(directive("connect-src").contains(relay));
        }
    }

    /// Skipped when the SPA hasn't been built; CI and deploys build it.
    fn built_spa() -> Option<String> {
        let html = std::fs::read_to_string(web().join("dist/index.html")).ok();
        if html.is_none() {
            eprintln!("skipping: SPA not built");
        }
        html
    }

    #[test]
    fn built_spa_carries_no_inline_script_which_is_what_script_src_self_assumes() {
        let Some(html) = built_spa() else { return };
        let scripts: Vec<&str> =
            regex::Regex::new(r"<script\b[^>]*>").unwrap().find_iter(&html).map(|m| m.as_str()).collect();
        assert!(!scripts.is_empty()); // the bundle is linked, not absent
        for tag in scripts {
            assert!(tag.contains(" src="), "inline script: {tag}");
        }
    }

    #[test]
    fn built_spa_carries_no_inline_stylesheet_or_event_handler_attribute() {
        let Some(html) = built_spa() else { return };
        assert!(!regex::Regex::new(r"<style\b").unwrap().is_match(&html));
        assert!(!regex::Regex::new(r"(?i)\son(click|load|error)=").unwrap().is_match(&html));
    }

    async fn send(app: &Router, method: Method, uri: &str, headers: &[(&str, &str)]) -> Response {
        let mut req = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap()
    }

    fn headers_app(over_https: bool) -> Router {
        Router::new()
            .route("/plain", get(|| async { "ok" }))
            .route(
                "/popup",
                get(|| async { ([(header::CONTENT_SECURITY_POLICY, "script-src 'nonce-abc'")], "popup") }),
            )
            .layer(from_fn_with_state(over_https, security_headers))
    }

    #[tokio::test]
    async fn sets_security_headers_on_every_response() {
        let res = send(&headers_app(true), Method::GET, "/plain", &[]).await;
        let h = res.headers();
        assert_eq!(h[header::CONTENT_SECURITY_POLICY], csp());
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(h[header::STRICT_TRANSPORT_SECURITY], "max-age=31536000; includeSubDomains");
        assert!(!h.contains_key("cross-origin-opener-policy"));
        // Unrouted paths too.
        let missing = send(&headers_app(true), Method::GET, "/nope", &[]).await;
        assert_eq!(missing.headers()[header::CONTENT_SECURITY_POLICY], csp());
    }

    #[tokio::test]
    async fn sends_hsts_only_over_https() {
        let res = send(&headers_app(false), Method::GET, "/plain", &[]).await;
        assert!(!res.headers().contains_key(header::STRICT_TRANSPORT_SECURITY));
    }

    #[tokio::test]
    async fn lets_a_handler_override_the_policy() {
        let res = send(&headers_app(true), Method::GET, "/popup", &[]).await;
        let policies: Vec<_> = res.headers().get_all(header::CONTENT_SECURITY_POLICY).iter().collect();
        // One policy, the handler's: browsers enforce every CSP header they get,
        // so appending ours would block the nonce'd script.
        assert_eq!(policies, vec!["script-src 'nonce-abc'"]);
        assert_eq!(res.headers()[header::X_FRAME_OPTIONS], "DENY");
    }

    fn policy() -> Arc<OriginPolicy> {
        Arc::new(OriginPolicy::new("https://bridge.armada.buzz/some/path", vec!["https://armada.buzz".into()]).unwrap())
    }

    // The server-side half of CSRF defence. `SameSite=Lax` blocks the same shape
    // in the browser, but that is one control enforced by the client; these are
    // the cases that must not depend on it.

    fn guard_app() -> Router {
        Router::new().route("/api/x", any(|| async { "ok" })).layer(from_fn_with_state(policy(), origin_guard))
    }

    #[tokio::test]
    async fn origin_guard_allows_same_origin_and_allow_listed_origins() {
        assert_eq!(policy().self_origin, "https://bridge.armada.buzz");
        for origin in ["https://bridge.armada.buzz", "https://armada.buzz"] {
            assert_eq!(send(&guard_app(), Method::POST, "/api/x", &[("origin", origin)]).await.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn origin_guard_refuses_a_state_changing_request_from_anywhere_else() {
        for origin in [
            "https://evil.example",
            // Neighbours of the real origins: substring matching would pass these.
            "https://armada.buzz.evil.example",
            "https://bridge.armada.buzz.evil.example",
            "http://bridge.armada.buzz",
            "null",
        ] {
            let res = send(&guard_app(), Method::POST, "/api/x", &[("origin", origin)]).await;
            assert_eq!(res.status(), StatusCode::FORBIDDEN, "{origin}");
            let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
            assert_eq!(&body[..], br#"{"error":"origin not allowed"}"#);
        }
    }

    #[tokio::test]
    async fn origin_guard_allows_a_caller_that_sends_no_origin_at_all() {
        // Browsers always send Origin on POST, so this is a non-browser client —
        // which never had a victim's cookies to ride in the first place.
        assert_eq!(send(&guard_app(), Method::POST, "/api/x", &[]).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn origin_guard_leaves_reads_alone() {
        let res = send(&guard_app(), Method::GET, "/api/x", &[("origin", "https://evil.example")]).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    fn cors_app() -> Router {
        Router::new()
            .route("/api/x", any(|| async { "ok" }))
            .route("/api/cached", get(|| async { ([(header::CACHE_CONTROL, "max-age=60"), (header::VARY, "Accept")], "ok") }))
            .layer(from_fn_with_state(policy(), origin_guard))
            .layer(from_fn_with_state(policy(), api_cors))
    }

    #[tokio::test]
    async fn cors_answers_allow_listed_origins_without_credentials() {
        let res = send(&cors_app(), Method::GET, "/api/x", &[("origin", "https://armada.buzz")]).await;
        let h = res.headers();
        assert_eq!(h[header::ACCESS_CONTROL_ALLOW_ORIGIN], "https://armada.buzz");
        assert_eq!(h[header::ACCESS_CONTROL_ALLOW_HEADERS], "Content-Type, Authorization");
        assert_eq!(h[header::ACCESS_CONTROL_ALLOW_METHODS], "GET, POST, OPTIONS");
        assert_eq!(h[header::ACCESS_CONTROL_MAX_AGE], "600");
        assert!(!h.contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS));
        assert_eq!(h[header::VARY], "Origin");
        assert_eq!(h[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn cors_gives_other_origins_nothing() {
        for origin in ["https://evil.example", "https://bridge.armada.buzz"] {
            let res = send(&cors_app(), Method::GET, "/api/x", &[("origin", origin)]).await;
            assert!(!res.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN), "{origin}");
            assert_eq!(res.headers()[header::VARY], "Origin");
            assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
        }
    }

    #[tokio::test]
    async fn cors_preflight_is_204_for_allowed_origins_and_403_otherwise() {
        let ok = send(&cors_app(), Method::OPTIONS, "/api/x", &[("origin", "https://armada.buzz")]).await;
        assert_eq!(ok.status(), StatusCode::NO_CONTENT);
        assert_eq!(ok.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "https://armada.buzz");
        let refused = send(&cors_app(), Method::OPTIONS, "/api/x", &[("origin", "https://evil.example")]).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert!(!refused.headers().contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
        assert_eq!(send(&cors_app(), Method::OPTIONS, "/api/x", &[]).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn cors_headers_reach_the_origin_guards_refusal() {
        let res = send(&cors_app(), Method::POST, "/api/x", &[("origin", "https://evil.example")]).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert_eq!(res.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn cors_keeps_a_handlers_vary_and_cache_control() {
        let res = send(&cors_app(), Method::GET, "/api/cached", &[]).await;
        let vary: Vec<_> = res.headers().get_all(header::VARY).iter().collect();
        assert_eq!(vary, vec!["Accept", "Origin"]);
        assert_eq!(res.headers()[header::CACHE_CONTROL], "max-age=60");
    }
}
