//! Cookie sessions backed by portal_sessions. The session carries the Discord
//! identity and the manageable-guild list captured at OAuth time; guild
//! authority is re-checked against this at mutation time and refreshed on
//! re-login.
//!
//! Nothing in the row is usable on its own. The session id is a bearer
//! credential — the cookie value and the API token are the same string — so
//! the table stores only its SHA-256, and the Discord OAuth bearer riding
//! along in `data` is sealed. A database-only compromise (backup, replica,
//! dump, an over-shared console) therefore yields no session to hijack and no
//! token to spend against Discord.
//!
//! The row's `data` is the jsonb the TypeScript portal wrote, field for field,
//! so sessions survive a switch between the two runtimes.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, HeaderValue, header};
use deadpool_postgres::Pool;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::seal::{seal, unseal};

pub const SESSION_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const COOKIE: &str = "portal_sid";

/// What the `sid` column holds for a given raw token.
pub fn hash_sid(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionUser {
    pub id: String,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionGuild {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    pub can_manage: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionData {
    #[serde(default)]
    pub user: SessionUser,
    #[serde(default)]
    pub guilds: Vec<SessionGuild>,
    /// When `guilds` was last read from Discord (epoch ms). Authority to act on
    /// a guild expires with it: the guild-authority check re-reads rather than
    /// trusting a snapshot indefinitely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guilds_fetched_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dev: Option<bool>,
    /// Set when the OAuth run was started from a popup opened by an allow-listed
    /// origin; the callback hands the session token back to that exact origin via
    /// postMessage instead of redirecting. Validated against the allowed origins
    /// at both ends, so it can never name a site the operator didn't approve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub popup_origin: Option<String>,
    /// Client-generated random nonce for the popup flow. Discord's pages carry
    /// `Cross-Origin-Opener-Policy: same-origin-allow-popups`, which severs the
    /// popup's `window.opener` the moment it navigates there — so the callback's
    /// postMessage handoff cannot be relied on. The opener instead polls
    /// `/api/auth/claim` with this nonce; the first claim after the callback
    /// completes returns the session token and spends the nonce.
    ///
    /// The nonce is chosen by whoever composed the auth-start URL, which is the
    /// reason for the two fields below. See `/api/auth/claim`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_nonce: Option<String>,
    /// SHA-256 of the one-time token embedded in the callback page, which the
    /// Connect button spends to make the handoff collectable. Present only
    /// between the callback and that click.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_approval: Option<String>,
    /// Set by that click. Until it is, `/api/auth/claim` reports pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_approved: Option<bool>,
    /// When the popup run started (epoch ms), so the handoff can go stale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_started_at: Option<i64>,
    /// OAuth bearer, kept so the guild-authority check can re-read the
    /// manageable-guild list from Discord rather than trusting the snapshot
    /// taken at login. Sealed on the way into the row; callers only ever see
    /// the plaintext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
}

/// A session located by something other than its token: all the table has is
/// the hash, which identifies the row for a later write but cannot be handed
/// to a browser. Use [`Sessions::rotate`] to mint a token for it.
#[derive(Clone, Debug)]
pub struct FoundSession {
    pub sid_hash: String,
    pub data: SessionData,
    pub expires: SystemTime,
}

pub struct Sessions {
    pool: Pool,
    seal_key_hex: String,
    /// Mark the cookie `Secure`, so it never rides a plaintext request. Driven
    /// by the deployment's own base URL rather than the request's scheme: the
    /// portal sits behind a TLS proxy and sees plain HTTP on loopback, so
    /// inferring it per-request would disable it exactly where it matters.
    secure_cookie: bool,
}

impl Sessions {
    pub fn new(pool: Pool, seal_key_hex: String, secure_cookie: bool) -> Self {
        Sessions { pool, seal_key_hex, secure_cookie }
    }

    fn cookie(&self, value: &str, expires: SystemTime) -> HeaderValue {
        let secure = if self.secure_cookie { "; Secure" } else { "" };
        let cookie = format!("{COOKIE}={value}; Path=/; Expires={}; HttpOnly{secure}; SameSite=Lax", http_date(expires));
        // Every part is hex, a fixed attribute, or a formatted date.
        HeaderValue::from_str(&cookie).expect("cookie header is ASCII")
    }

    fn clear_cookie(&self) -> HeaderValue {
        self.cookie("", UNIX_EPOCH)
    }

    /// Creates the row; returns the raw sid and the Set-Cookie header value.
    pub async fn create(&self, data: &SessionData) -> anyhow::Result<(String, HeaderValue)> {
        let sid = new_sid();
        let expires = SystemTime::now() + SESSION_TTL;
        self.pool
            .get()
            .await?
            .execute(
                "INSERT INTO portal_sessions (sid, data, expires_at) VALUES ($1, $2, $3)",
                &[&hash_sid(&sid), &self.write_stored(data)?, &expires],
            )
            .await?;
        let cookie = self.cookie(&sid, expires);
        Ok((sid, cookie))
    }

    /// Replace a session's id, returning the new raw token.
    ///
    /// Two jobs. It is the moment a pre-auth row becomes an authenticated
    /// session, where rotating is the textbook defence against session fixation.
    /// And because the table stores only hashes, rotation is the *only* way to
    /// obtain a usable token for a session found by state or nonce rather than
    /// by cookie — the callback has no other way to learn what to hand back.
    ///
    /// `handoff` additionally seals the new token into the row for the popup
    /// poller to collect (see [`Sessions::collect_handoff`]), so both legs of
    /// that flow hand out the same token instead of racing to invalidate each
    /// other.
    pub async fn rotate(&self, sid_hash: &str, data: &SessionData, handoff: bool) -> anyhow::Result<String> {
        let sid = new_sid();
        let stash = if handoff { Some(seal(&self.seal_key_hex, &sid)?) } else { None };
        self.pool
            .get()
            .await?
            .execute(
                "UPDATE portal_sessions SET sid = $1, data = $2, handoff_sealed = $3 WHERE sid = $4",
                &[&hash_sid(&sid), &self.write_stored(data)?, &stash, &sid_hash],
            )
            .await?;
        Ok(sid)
    }

    /// Take the sealed token stashed by [`Sessions::rotate`] for the nonce
    /// poller, and spend it: a second collection finds nothing. Uncollected
    /// stashes expire with their session.
    pub async fn collect_handoff(&self, sid_hash: &str, data: &SessionData) -> anyhow::Result<Option<String>> {
        // RETURNING reports post-update values, so the stash is read from the
        // pre-update snapshot the FROM clause supplies.
        let row = self
            .pool
            .get()
            .await?
            .query_opt(
                "UPDATE portal_sessions s
                 SET data = $1, handoff_sealed = NULL
                 FROM portal_sessions prev
                 WHERE s.sid = $2 AND prev.sid = s.sid
                 RETURNING prev.handoff_sealed",
                &[&self.write_stored(data)?, &sid_hash],
            )
            .await?;
        match row.and_then(|r| r.get::<_, Option<Vec<u8>>>(0)) {
            Some(sealed) => Ok(Some(unseal(&self.seal_key_hex, &sealed)?)),
            None => Ok(None),
        }
    }

    /// Row shape: everything as-is except the OAuth bearer, which is sealed
    /// (hex of the sealed bytes, as the TypeScript portal stored it).
    fn write_stored(&self, data: &SessionData) -> anyhow::Result<serde_json::Value> {
        let mut stored = data.clone();
        if let Some(token) = stored.access_token.as_deref().filter(|t| !t.is_empty()) {
            stored.access_token = Some(hex::encode(seal(&self.seal_key_hex, token)?));
        }
        Ok(serde_json::to_value(stored)?)
    }

    /// Inverse of [`Sessions::write_stored`]. An unreadable bearer (key rotated
    /// out from under the row) is dropped rather than fatal: the session
    /// survives, and the guild-authority check denies once the captured guild
    /// list goes stale, which is a re-login rather than a lost session.
    fn read_stored(&self, stored: serde_json::Value) -> anyhow::Result<SessionData> {
        let mut data: SessionData = serde_json::from_value(stored)?;
        if let Some(sealed) = data.access_token.take().filter(|t| !t.is_empty()) {
            data.access_token =
                hex::decode(&sealed).ok().and_then(|bytes| unseal(&self.seal_key_hex, &bytes).ok());
        }
        Ok(data)
    }

    /// The session id for this request: an `Authorization: Bearer` token, or
    /// the cookie.
    ///
    /// The bearer path exists for clients on another origin (Armada running the
    /// import wizard in-app), where the `SameSite=Lax` cookie is never sent and
    /// relaxing it to `None` would put the session at the mercy of third-party
    /// cookie blocking. A token is only ever handed to an origin the operator
    /// allow-listed, and unlike a cookie it is not attached automatically, so a
    /// hostile page cannot spend it just by making the browser issue a request.
    pub fn token(headers: &HeaderMap) -> Option<String> {
        bearer(headers).or_else(|| cookie_value(headers))
    }

    /// The hashed id of the session this request's COOKIE names, ignoring any
    /// bearer. The OAuth callback uses it to check that the browser finishing a
    /// redirect-flow login is the one that started it — see the callback for
    /// why that binding cannot simply replace the state lookup.
    pub fn cookie_sid_hash(headers: &HeaderMap) -> Option<String> {
        cookie_value(headers).map(|raw| hash_sid(&raw))
    }

    pub async fn get(&self, headers: &HeaderMap) -> anyhow::Result<Option<SessionData>> {
        let Some(sid) = Self::token(headers) else { return Ok(None) };
        let row = self
            .pool
            .get()
            .await?
            .query_opt("SELECT data FROM portal_sessions WHERE sid = $1 AND expires_at > now()", &[&hash_sid(&sid)])
            .await?;
        row.map(|r| self.read_stored(r.get(0))).transpose()
    }

    /// The session that started the OAuth run named by `state`, for the callback.
    ///
    /// The callback deliberately does NOT identify the session by cookie: the
    /// popup flow's cookie routinely fails to survive the round trip through
    /// Discord (privacy modes that scope a popup's cookies to its opener, logins
    /// that continue in a different window or the Discord app, a second click on
    /// Connect overwriting the first popup's cookie), and the 128-bit
    /// single-shot `oauthState` is the CSRF binding anyway. [`Sessions::rotate`]
    /// replaces the data without `oauthState`, so a state can never be spent
    /// twice.
    ///
    /// Returns the *hashed* id, which is all the table has: it identifies the
    /// row for a later write but cannot be handed to a browser. Use
    /// [`Sessions::rotate`] to mint a token for it.
    pub async fn find_by_oauth_state(&self, state: &str) -> anyhow::Result<Option<FoundSession>> {
        let rows = self
            .pool
            .get()
            .await?
            .query(
                "SELECT sid, data, expires_at FROM portal_sessions
                 WHERE data->>'oauthState' = $1 AND expires_at > now()",
                &[&state],
            )
            .await?;
        let Some(row) = rows.into_iter().next() else { return Ok(None) };
        Ok(Some(FoundSession { sid_hash: row.get(0), data: self.read_stored(row.get(1))?, expires: row.get(2) }))
    }

    /// Spend the callback page's one-time approval token, marking the popup
    /// handoff collectable. Returns false if the token names no run, or names
    /// one that was already approved — a single statement, so two clicks race
    /// in Postgres rather than in a read-modify-write.
    pub async fn approve_handoff(&self, approval_token: &str) -> anyhow::Result<bool> {
        let approved = self
            .pool
            .get()
            .await?
            .execute(
                "UPDATE portal_sessions
                 SET data = jsonb_set(data - 'claimApproval', '{claimApproved}', 'true')
                 WHERE data->>'claimApproval' = $1 AND expires_at > now()",
                &[&hash_sid(approval_token)],
            )
            .await?;
        Ok(approved > 0)
    }

    /// The completed-or-pending OAuth run named by a claim nonce, as
    /// `(sid_hash, data)`.
    pub async fn find_by_claim_nonce(&self, nonce: &str) -> anyhow::Result<Option<(String, SessionData)>> {
        let rows = self
            .pool
            .get()
            .await?
            .query(
                "SELECT sid, data FROM portal_sessions WHERE data->>'claimNonce' = $1 AND expires_at > now()",
                &[&nonce],
            )
            .await?;
        let Some(row) = rows.into_iter().next() else { return Ok(None) };
        Ok(Some((row.get(0), self.read_stored(row.get(1))?)))
    }

    /// (Re)issue the cookie for an existing session. The callback uses this so
    /// the redirect flow stays signed in even when the auth-start cookie was
    /// lost or overwritten between the two legs.
    pub fn adopt_cookie(&self, sid: &str, expires: SystemTime) -> HeaderValue {
        self.cookie(sid, expires)
    }

    pub async fn update(&self, headers: &HeaderMap, data: &SessionData) -> anyhow::Result<()> {
        let Some(sid) = Self::token(headers) else { return Ok(()) };
        self.pool
            .get()
            .await?
            .execute("UPDATE portal_sessions SET data = $1 WHERE sid = $2", &[&self.write_stored(data)?, &hash_sid(&sid)])
            .await?;
        Ok(())
    }

    /// Deletes the presenting session; returns the clearing Set-Cookie. The
    /// cookie is cleared even when the request named no session: it costs
    /// nothing and leaves the browser in a known state.
    pub async fn destroy(&self, headers: &HeaderMap) -> anyhow::Result<HeaderValue> {
        if let Some(sid) = Self::token(headers) {
            self.pool.get().await?.execute("DELETE FROM portal_sessions WHERE sid = $1", &[&hash_sid(&sid)]).await?;
        }
        Ok(self.clear_cookie())
    }

    /// Drop every session belonging to a Discord user, the caller's included.
    /// Returns how many went, and the clearing Set-Cookie.
    ///
    /// [`Sessions::destroy`] can only reach the session presenting the request,
    /// which leaves one case with no remedy at all: the popup handoff hands its
    /// token to whoever polls the nonce, and deliberately plants no cookie in
    /// the browser that ran the login (see the callback). A token collected by
    /// someone else therefore names a session its owner holds no reference to
    /// and cannot name — it would simply run its seven days out. This is the
    /// recovery path for that, and for the ordinary "signed in on a machine I no
    /// longer have" case.
    ///
    /// Deliberately unsparing: it takes the calling session too, so the answer
    /// to "did I get them all" is yes without the caller having to reason about
    /// which token they are holding. Re-login is one click.
    ///
    /// `user.id` is not indexed — this is a rare, deliberate action, and
    /// indexing it would put a write on the hot path of a table anyone can grow.
    pub async fn revoke_all_for_user(&self, discord_user_id: &str) -> anyhow::Result<(u64, HeaderValue)> {
        let revoked = self
            .pool
            .get()
            .await?
            .execute("DELETE FROM portal_sessions WHERE data->'user'->>'id' = $1", &[&discord_user_id])
            .await?;
        Ok((revoked, self.clear_cookie()))
    }

    pub async fn sweep(&self) -> anyhow::Result<()> {
        self.pool.get().await?.execute("DELETE FROM portal_sessions WHERE expires_at <= now()", &[]).await?;
        Ok(())
    }
}

/// An AUTHENTICATED session, or None (the caller answers 401).
///
/// The `user.id` test is not redundant. `/api/auth/discord` creates a real row
/// and sets the cookie *before* the user has been anywhere near Discord, so it
/// can remember `oauthState` across the round trip — that pre-auth session
/// carries `user: { id: "", username: "" }`. Anyone can mint one by fetching a
/// URL. Existence of a session therefore proves only that a request was made;
/// only a non-empty `user.id` means an OAuth callback completed and Discord
/// told us who this is. Most routes then scope their SQL by `user.id` and would
/// merely find nothing under `''`, but not all of them do — the bridge-create
/// path does real work before any ownership check — so the gate belongs here,
/// once, rather than in each handler's WHERE clause.
pub async fn require_session(sessions: &Sessions, headers: &HeaderMap) -> anyhow::Result<Option<SessionData>> {
    Ok(sessions.get(headers).await?.filter(|s| !s.user.id.is_empty()))
}

fn new_sid() -> String {
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// `Authorization: Bearer <48 hex>`, case-insensitive, normalised to lowercase.
/// Anything else is not a bearer, and the cookie gets its turn.
fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let scheme = value.get(..6)?;
    let rest = &value[6..];
    if !scheme.eq_ignore_ascii_case("bearer") || !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let token = rest.trim_start();
    (token.len() == 48 && token.bytes().all(|b| b.is_ascii_hexdigit())).then(|| token.to_ascii_lowercase())
}

/// The `portal_sid` cookie, first occurrence across every Cookie header.
fn cookie_value(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| name.trim() == COOKIE)
        .map(|(_, value)| value.trim().trim_matches('"').to_owned())
        .filter(|value| !value.is_empty())
}

/// IMF-fixdate (`Thu, 01 Jan 1970 00:00:00 GMT`), the form `Expires` takes.
fn http_date(at: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let secs = at.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil-from-days (Howard Hinnant), for days since 1970-01-01.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        MONTHS[(month - 1) as usize],
        rem / 3600,
        rem / 60 % 60,
        rem % 60,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEAL_KEY: &str = "abababababababababababababababababababababababababababababababab";
    const TOKEN: &str = "discord-oauth-bearer-value";

    #[test]
    fn hashes_like_the_typescript_portal() {
        // sha256("abc"), lowercase hex: what migration 013 and the TS portal wrote.
        assert_eq!(hash_sid("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn formats_cookie_dates() {
        assert_eq!(http_date(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(UNIX_EPOCH + Duration::from_secs(1_790_182_800)), "Wed, 23 Sep 2026 17:00:00 GMT");
        assert_eq!(http_date(UNIX_EPOCH + Duration::from_secs(951_782_400)), "Tue, 29 Feb 2000 00:00:00 GMT");
    }

    #[test]
    fn round_trips_the_typescript_jsonb() {
        let stored = serde_json::json!({
            "user": {"id": "1", "username": "u", "avatarUrl": "https://cdn/x.png"},
            "guilds": [{"id": "g", "name": "G", "canManage": true}],
            "guildsFetchedAt": 1_790_182_800_123_i64,
            "claimNonce": "ab",
            "claimApproved": true,
        });
        let data: SessionData = serde_json::from_value(stored.clone()).unwrap();
        assert_eq!(data.user.avatar_url.as_deref(), Some("https://cdn/x.png"));
        assert!(data.guilds[0].can_manage);
        assert_eq!(data.guilds_fetched_at, Some(1_790_182_800_123));
        // Absent options stay absent: `data ? 'claimApproval'` and friends key
        // partial indexes and lookups off presence.
        assert_eq!(serde_json::to_value(&data).unwrap(), stored);
        // The pre-auth row shape, and the column's '{}' default.
        let pre: SessionData = serde_json::from_value(serde_json::json!({"user": {"id": "", "username": ""}, "guilds": [], "oauthState": "s"})).unwrap();
        assert_eq!(pre.oauth_state.as_deref(), Some("s"));
        assert_eq!(serde_json::from_value::<SessionData>(serde_json::json!({})).unwrap(), SessionData::default());
    }

    fn headers(pairs: &[(header::HeaderName, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(name.clone(), HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn reads_the_token_from_a_bearer_or_the_cookie() {
        let raw = "ab".repeat(24);
        assert_eq!(Sessions::token(&headers(&[(header::AUTHORIZATION, &format!("Bearer {}", "AB".repeat(24)))])), Some(raw.clone()));
        assert_eq!(Sessions::token(&headers(&[(header::AUTHORIZATION, &format!("  bearer\t{raw} "))])), Some(raw.clone()));
        assert_eq!(Sessions::token(&headers(&[(header::COOKIE, &format!("a=1; portal_sid={raw}; b=2"))])), Some(raw.clone()));
        // A malformed bearer is not a bearer; the cookie still counts.
        let both = headers(&[(header::AUTHORIZATION, "Bearer short"), (header::COOKIE, "portal_sid=c")]);
        assert_eq!(Sessions::token(&both).as_deref(), Some("c"));
        assert_eq!(Sessions::token(&headers(&[(header::AUTHORIZATION, &format!("Bearer{raw}"))])), None);
        assert_eq!(Sessions::token(&HeaderMap::new()), None);
    }

    /// No database: `cookie_sid_hash` reads one header. It exists so the OAuth
    /// callback can tell "the browser that started this login" from "a browser
    /// handed the callback URL", so what matters is that a bearer cannot stand
    /// in for the cookie — otherwise the binding would be bypassable by a header
    /// the attacker sets themselves.
    #[test]
    fn cookie_sid_hash_hashes_the_cookie_the_request_carries() {
        let raw = "ab".repeat(24);
        assert_eq!(Sessions::cookie_sid_hash(&headers(&[(header::COOKIE, &format!("portal_sid={raw}"))])), Some(hash_sid(&raw)));
    }

    #[test]
    fn cookie_sid_hash_is_none_with_no_cookie_and_ignores_a_bearer() {
        assert_eq!(Sessions::cookie_sid_hash(&HeaderMap::new()), None);
        // The bearer is attacker-settable on a cross-site request in a way the
        // cookie is not, so it must never satisfy the callback's binding.
        let bearer = headers(&[(header::AUTHORIZATION, &format!("Bearer {}", "cd".repeat(24)))]);
        assert_eq!(Sessions::cookie_sid_hash(&bearer), None);
    }

    // --- Sessions at rest: the row must not contain anything a database reader
    // could spend — not the session token, not the Discord OAuth bearer. Runs
    // against DATABASE_URL (skipped when unreachable). Each test owns a unique
    // user id, so they run in parallel and clean up only their own rows.

    static MIGRATED: tokio::sync::Mutex<bool> = tokio::sync::Mutex::const_new(false);

    struct Db {
        pool: Pool,
        sessions: Sessions,
        user: String,
    }

    impl Db {
        async fn open(name: &str) -> Option<Db> {
            let url =
                std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://postgres:test@127.0.0.1:55432/bridge".into());
            let pool = bridge::db::connect(&url, 2).ok()?;
            match tokio::time::timeout(Duration::from_secs(3), pool.get()).await {
                Ok(Ok(_)) => {}
                _ => {
                    eprintln!("skipping {name}: no database at DATABASE_URL");
                    return None;
                }
            }
            let mut migrated = MIGRATED.lock().await;
            if !*migrated {
                bridge::db::migrate(&pool).await.unwrap();
                *migrated = true;
            }
            drop(migrated);
            let user = format!("test-sessions-{name}-{}", new_sid());
            let sessions = Sessions::new(pool.clone(), SEAL_KEY.into(), false);
            Some(Db { pool, sessions, user })
        }

        fn data(&self) -> SessionData {
            SessionData {
                user: SessionUser { id: self.user.clone(), username: "tester".into(), avatar_url: None },
                access_token: Some(TOKEN.into()),
                ..SessionData::default()
            }
        }

        fn with_username(&self, username: &str) -> SessionData {
            let mut data = self.data();
            data.user.username = username.into();
            data
        }

        async fn create(&self) -> String {
            self.sessions.create(&self.data()).await.unwrap().0
        }

        async fn me(&self, sid: &str) -> Option<SessionData> {
            self.sessions.get(&headers(&[(header::AUTHORIZATION, &format!("Bearer {sid}"))])).await.unwrap()
        }

        async fn me_by_cookie(&self, sid: &str) -> Option<SessionData> {
            self.sessions.get(&headers(&[(header::COOKIE, &format!("portal_sid={sid}"))])).await.unwrap()
        }

        /// The row as a database-only attacker would see it; keyed by the hash.
        async fn row_for(&self, raw: &str) -> Option<(String, serde_json::Value, Option<Vec<u8>>)> {
            let row = self
                .pool
                .get()
                .await
                .unwrap()
                .query_opt("SELECT sid, data, handoff_sealed FROM portal_sessions WHERE sid = $1", &[&hash_sid(raw)])
                .await
                .unwrap()?;
            Some((row.get(0), row.get(1), row.get(2)))
        }

        async fn clean(&self) {
            let db = self.pool.get().await.unwrap();
            db.execute("DELETE FROM portal_sessions WHERE data->'user'->>'id' = $1", &[&self.user]).await.unwrap();
        }
    }

    #[tokio::test]
    async fn stores_the_hash_of_the_token_never_the_token() {
        let Some(db) = Db::open("hash").await else { return };
        let (sid, cookie) = db.sessions.create(&db.data()).await.unwrap();
        assert_eq!(sid.len(), 48);
        assert!(sid.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        let cookie = cookie.to_str().unwrap();
        assert!(cookie.starts_with(&format!("portal_sid={sid}; Path=/; Expires=")));
        assert!(cookie.contains("; HttpOnly") && cookie.ends_with("; SameSite=Lax") && !cookie.contains("Secure"));
        // The row is found by the hash: that IS the stored form.
        assert_eq!(db.row_for(&sid).await.unwrap().0, hash_sid(&sid));
        assert!(db.me(&sid).await.is_some());
        assert!(db.me_by_cookie(&sid).await.is_some());
        db.clean().await;
    }

    #[tokio::test]
    async fn marks_the_cookie_secure_when_asked() {
        let Some(db) = Db::open("secure").await else { return };
        let secure = Sessions::new(db.pool.clone(), SEAL_KEY.into(), true);
        let (_, cookie) = secure.create(&db.data()).await.unwrap();
        assert!(cookie.to_str().unwrap().contains("; HttpOnly; Secure; SameSite=Lax"));
        assert!(secure.adopt_cookie("x", UNIX_EPOCH).to_str().unwrap().contains("; Secure"));
        db.clean().await;
    }

    #[tokio::test]
    async fn does_not_accept_the_stored_id_as_a_token() {
        let Some(db) = Db::open("stored-id").await else { return };
        let sid = db.create().await;
        assert!(db.me_by_cookie(&hash_sid(&sid)).await.is_none());
        db.clean().await;
    }

    #[tokio::test]
    async fn seals_the_discord_bearer_and_hands_it_back_in_plaintext() {
        let Some(db) = Db::open("seal").await else { return };
        let sid = db.create().await;
        let (_, data, _) = db.row_for(&sid).await.unwrap();
        assert_ne!(data["accessToken"], TOKEN);
        assert!(!data.to_string().contains(TOKEN));
        assert_eq!(db.me(&sid).await.unwrap().access_token.as_deref(), Some(TOKEN));
        db.clean().await;
    }

    #[tokio::test]
    async fn drops_an_unreadable_bearer_instead_of_failing_the_session() {
        let Some(db) = Db::open("unreadable").await else { return };
        let sid = db.create().await;
        let other_key = Sessions::new(db.pool.clone(), "cd".repeat(32), false);
        let s = other_key.get(&headers(&[(header::AUTHORIZATION, &format!("Bearer {sid}"))])).await.unwrap().unwrap();
        assert_eq!(s.user.id, db.user);
        assert_eq!(s.access_token, None);
        db.clean().await;
    }

    #[tokio::test]
    async fn rotate_mints_a_working_token_and_kills_the_old_one() {
        let Some(db) = Db::open("rotate").await else { return };
        let sid = db.create().await;
        let next = db.sessions.rotate(&hash_sid(&sid), &db.with_username("rotated"), false).await.unwrap();
        assert_ne!(next, sid);
        assert!(db.me(&sid).await.is_none());
        assert_eq!(db.me(&next).await.unwrap().user.username, "rotated");
        db.clean().await;
    }

    #[tokio::test]
    async fn hands_the_popup_poller_the_same_token_the_callback_minted_once() {
        let Some(db) = Db::open("handoff").await else { return };
        let nonce = new_sid();
        let sid = db.create().await;
        let pending = SessionData { claim_nonce: Some(nonce.clone()), ..db.with_username("pending") };
        let minted = db.sessions.rotate(&hash_sid(&sid), &pending, true).await.unwrap();

        let (sid_hash, found) = db.sessions.find_by_claim_nonce(&nonce).await.unwrap().unwrap();
        assert_eq!(sid_hash, hash_sid(&minted));
        // Stashed sealed: the portal can read it back, the row does not show it.
        let stash = db.row_for(&minted).await.unwrap().2.unwrap();
        assert!(!String::from_utf8_lossy(&stash).contains(&minted));

        let rest = SessionData { claim_nonce: None, ..found };
        assert_eq!(db.sessions.collect_handoff(&sid_hash, &rest).await.unwrap(), Some(minted.clone()));
        // Single-use, and the nonce goes with it.
        assert_eq!(db.sessions.collect_handoff(&sid_hash, &rest).await.unwrap(), None);
        assert!(db.sessions.find_by_claim_nonce(&nonce).await.unwrap().is_none());
        assert_eq!(db.me(&minted).await.unwrap().user.username, "pending");
        db.clean().await;
    }

    #[tokio::test]
    async fn approve_handoff_spends_the_callback_pages_token_once() {
        let Some(db) = Db::open("approve").await else { return };
        let nonce = new_sid();
        let approval = new_sid();
        let sid = db.create().await;
        let pending = SessionData {
            claim_nonce: Some(nonce.clone()),
            claim_approval: Some(hash_sid(&approval)),
            ..db.with_username("awaiting-click")
        };
        let minted = db.sessions.rotate(&hash_sid(&sid), &pending, true).await.unwrap();

        // Before the click there is nothing for the poller to act on.
        assert_eq!(db.sessions.find_by_claim_nonce(&nonce).await.unwrap().unwrap().1.claim_approved, None);
        // The raw token is never in the row — only its hash can be looked up.
        assert!(!db.row_for(&minted).await.unwrap().1.to_string().contains(&approval));

        assert!(db.sessions.approve_handoff(&approval).await.unwrap());
        let (_, found) = db.sessions.find_by_claim_nonce(&nonce).await.unwrap().unwrap();
        assert_eq!(found.claim_approved, Some(true));
        assert_eq!(found.claim_approval, None);
        // Single-use: a replayed click finds no run to approve.
        assert!(!db.sessions.approve_handoff(&approval).await.unwrap());
        // The rest of the session is untouched by the jsonb surgery.
        assert_eq!(found.user.username, "awaiting-click");
        assert_eq!(db.me(&minted).await.unwrap().access_token.as_deref(), Some(TOKEN));
        db.clean().await;
    }

    #[tokio::test]
    async fn approve_handoff_refuses_a_token_that_names_no_run() {
        let Some(db) = Db::open("approve-none").await else { return };
        assert!(!db.sessions.approve_handoff(&new_sid()).await.unwrap());
    }

    #[tokio::test]
    async fn finds_the_run_by_oauth_state() {
        let Some(db) = Db::open("state").await else { return };
        let state = new_sid();
        let pre = SessionData { oauth_state: Some(state.clone()), ..db.data() };
        let (sid, _) = db.sessions.create(&pre).await.unwrap();
        let found = db.sessions.find_by_oauth_state(&state).await.unwrap().unwrap();
        assert_eq!(found.sid_hash, hash_sid(&sid));
        assert_eq!(found.data.access_token.as_deref(), Some(TOKEN));
        assert!(found.expires > SystemTime::now() + SESSION_TTL - Duration::from_secs(60));
        // Rotating without the state spends it.
        db.sessions.rotate(&found.sid_hash, &db.data(), false).await.unwrap();
        assert!(db.sessions.find_by_oauth_state(&state).await.unwrap().is_none());
        db.clean().await;
    }

    #[tokio::test]
    async fn update_rewrites_the_presenting_session() {
        let Some(db) = Db::open("update").await else { return };
        let sid = db.create().await;
        let by_cookie = headers(&[(header::COOKIE, &format!("portal_sid={sid}"))]);
        db.sessions.update(&by_cookie, &db.with_username("updated")).await.unwrap();
        let me = db.me(&sid).await.unwrap();
        assert_eq!(me.user.username, "updated");
        assert_eq!(me.access_token.as_deref(), Some(TOKEN));
        db.clean().await;
    }

    #[tokio::test]
    async fn require_session_refuses_a_pre_auth_session() {
        let Some(db) = Db::open("require").await else { return };
        let (pre, _) = db.sessions.create(&SessionData { oauth_state: Some(db.user.clone()), ..SessionData::default() }).await.unwrap();
        let sid = db.create().await;
        let bearer = |s: &str| headers(&[(header::AUTHORIZATION, &format!("Bearer {s}"))]);
        assert!(db.sessions.get(&bearer(&pre)).await.unwrap().is_some());
        assert!(require_session(&db.sessions, &bearer(&pre)).await.unwrap().is_none());
        assert!(require_session(&db.sessions, &bearer(&sid)).await.unwrap().is_some());
        db.sessions.destroy(&bearer(&pre)).await.unwrap();
        db.clean().await;
    }

    #[tokio::test]
    async fn destroy_removes_the_row() {
        let Some(db) = Db::open("destroy").await else { return };
        let sid = db.create().await;
        let cookie = db.sessions.destroy(&headers(&[(header::AUTHORIZATION, &format!("Bearer {sid}"))])).await.unwrap();
        assert!(cookie.to_str().unwrap().starts_with("portal_sid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"));
        assert!(db.me(&sid).await.is_none());
        assert!(db.row_for(&sid).await.is_none());
    }

    #[tokio::test]
    async fn revoke_all_reaches_a_session_the_caller_holds_no_reference_to() {
        let Some(db) = Db::open("revoke").await else { return };
        let mine = db.create().await;
        // The popup-handoff shape: a token released to a poller, with no cookie
        // in the browser that ran the login. destroy cannot name it; this must.
        let elsewhere = db.create().await;
        assert!(db.me(&elsewhere).await.is_some());

        let (revoked, cookie) = db.sessions.revoke_all_for_user(&db.user).await.unwrap();
        assert!(revoked >= 2);
        assert!(cookie.to_str().unwrap().starts_with("portal_sid=;"));
        assert!(db.me(&elsewhere).await.is_none());
        // Unsparing: the calling session goes too, so "did I get them all" is yes.
        assert!(db.me(&mine).await.is_none());
    }

    #[tokio::test]
    async fn sweep_drops_expired_rows() {
        let Some(db) = Db::open("sweep").await else { return };
        let sid = db.create().await;
        let pool = db.pool.get().await.unwrap();
        pool.execute("UPDATE portal_sessions SET expires_at = now() - interval '1 second' WHERE sid = $1", &[&hash_sid(&sid)])
            .await
            .unwrap();
        // Expired rows are invisible before the sweep and gone after it.
        assert!(db.me(&sid).await.is_none());
        db.sessions.sweep().await.unwrap();
        assert!(db.row_for(&sid).await.is_none());
        db.clean().await;
    }
}
