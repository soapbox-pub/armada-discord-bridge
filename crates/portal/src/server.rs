//! The portal's HTTP surface: JSON API plus the static SPA. In dev, run the
//! Vite dev server alongside (`npm run --prefix web dev`),
//! which proxies /api here; in production this serves web/dist directly.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router, middleware};
use deadpool_postgres::Pool;
use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::auth::{SessionData, SessionGuild, SessionUser, Sessions, require_session};
use crate::discord_rest::{CannotCreateChannels, DiscordRest, OAuthGuild, bot_install_url, bot_install_url_create, can_manage, discord_channel_name, oauth_url};
use crate::env::PortalEnv;
use crate::importer::{ConfirmBody, Importer, PrepareBody, Preview};
use crate::manager::{BRIDGE_COLUMNS, BridgeManager, BridgeRow};
use crate::security::{OriginPolicy, api_cors, origin_guard, security_headers};
use crate::seal::{seal, unseal};

/// How long a captured guild list may keep authorising mutations before it
/// has to be re-read from Discord.
const GUILD_AUTHORITY_TTL_MS: i64 = 5 * 60_000;

/// Popup handoff nonce: client-generated, so hold it to 128 bits or better.
static CLAIM_NONCE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^[0-9a-f]{32,64}$").unwrap());
static APPROVAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-f]{48}$").unwrap());

/// How long a popup handoff stays collectable, measured from auth-start. The
/// opener polls in real time, so minutes is generous; a run never collected
/// would otherwise sit for the session's whole seven days, one leaked nonce
/// from being spent.
const CLAIM_WINDOW_MS: i64 = 10 * 60_000;

#[derive(Clone)]
pub struct AppState {
    pub pool: Pool,
    pub env: Arc<PortalEnv>,
    pub sessions: Arc<Sessions>,
    pub manager: Arc<BridgeManager>,
    pub importer: Arc<Importer>,
    pub rest: DiscordRest,
}

type Res = Result<Response, AppError>;

/// An unexpected failure: logged, and answered with a bare 500.
pub struct AppError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        AppError(e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!(error = %format!("{:#}", self.0), "request failed");
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "internal error" }))).into_response()
    }
}

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

fn unauthorized() -> Response {
    err(StatusCode::UNAUTHORIZED, "unauthorized")
}

fn now_ms() -> i64 {
    bridge::client::now_ms() as i64
}

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// For the one server-rendered page in the codebase (the popup callback).
fn escape_html(text: &str) -> String {
    text.chars().map(|c| if "&<>\"'".contains(c) { format!("&#{};", c as u32) } else { c.to_string() }).collect()
}

/// A JSON literal safe to embed inside an inline `<script>`: `<`, `>` and `&`
/// escaped so a value can never close the script element.
fn script_json(v: &impl serde::Serialize) -> String {
    serde_json::to_string(v).expect("strings serialize").replace('<', "\\u003c").replace('>', "\\u003e").replace('&', "\\u0026")
}

fn to_session_guilds(guilds: &[OAuthGuild]) -> Vec<SessionGuild> {
    guilds
        .iter()
        .map(|g| SessionGuild {
            id: g.id.clone(),
            name: g.name.clone(),
            icon: g.icon.as_ref().map(|i| format!("https://cdn.discordapp.com/icons/{}/{i}.png", g.id)),
            can_manage: can_manage(g),
        })
        .collect()
}

/// Whether this session may act on a guild — verified, not merely remembered.
///
/// The guild list is captured at OAuth time, so on its own it would keep
/// authorising someone for the session's whole 7-day life after they were
/// demoted or removed from the server. Past the TTL it is re-read from Discord
/// with the session's own bearer and written back, so the window is minutes.
///
/// Failing to verify denies rather than falls back: a session whose bearer is
/// gone cannot prove anything, and re-login is one click. Dev-login sessions
/// have no bearer by design and keep their fixture guilds.
async fn guild_authority(st: &AppState, headers: &HeaderMap, session: &SessionData, guild_id: &str) -> anyhow::Result<Result<SessionGuild, Response>> {
    let mut guilds = session.guilds.clone();
    if session.dev != Some(true) && now_ms() - session.guilds_fetched_at.unwrap_or(0) > GUILD_AUTHORITY_TTL_MS {
        let Some(token) = &session.access_token else {
            return Ok(Err(err(StatusCode::UNAUTHORIZED, "reconnect Discord so your server permissions can be checked")));
        };
        match st.rest.fetch_my_guilds(token).await {
            Ok(fresh) => {
                guilds = to_session_guilds(&fresh);
                let updated = SessionData { guilds: guilds.clone(), guilds_fetched_at: Some(now_ms()), ..session.clone() };
                st.sessions.update(headers, &updated).await?;
            }
            Err(error) => {
                tracing::warn!(user = %session.user.id, error = %format!("{error:#}"), "guild authority refresh failed");
                return Ok(Err(err(StatusCode::UNAUTHORIZED, "could not check your Discord permissions; sign in again")));
            }
        }
    }
    match guilds.into_iter().find(|g| g.id == guild_id) {
        Some(g) if g.can_manage => Ok(Ok(g)),
        _ => Ok(Err(err(StatusCode::FORBIDDEN, "you do not hold Manage Server in that guild"))),
    }
}

/// Whether this session may still act on an import: owner of the row, and
/// still holding Manage Server in the guild it draws from.
///
/// `POST /api/imports` establishes authority once. Every route below it used
/// to check ownership alone, which made that first check permanent — and these
/// are not read-only routes. `rerun-history` fetches LIVE Discord history with
/// the bot token at call time, so someone since demoted or removed from a
/// server could keep pumping its fresh messages into a community they control.
async fn import_authority(st: &AppState, headers: &HeaderMap, session: &SessionData, import_id: &str) -> anyhow::Result<Result<(), Response>> {
    let row = st
        .pool
        .get()
        .await?
        .query_opt(
            "SELECT discord_guild_id FROM imports WHERE import_id::text = $1 AND owner_discord_id = $2",
            &[&import_id, &session.user.id],
        )
        .await?;
    let Some(row) = row else { return Ok(Err(err(StatusCode::NOT_FOUND, "not found"))) };
    // No guild recorded cannot be re-checked; the owner test already passed.
    let Some(guild) = row.get::<_, Option<String>>(0).filter(|g| !g.is_empty()) else { return Ok(Ok(())) };
    Ok(guild_authority(st, headers, session, &guild).await?.map(drop))
}

macro_rules! session_or_401 {
    ($st:expr, $headers:expr) => {
        match require_session(&$st.sessions, &$headers).await? {
            Some(s) => s,
            None => return Ok(unauthorized()),
        }
    };
}

macro_rules! check {
    ($result:expr) => {
        if let Err(response) = $result {
            return Ok(response);
        }
    };
}

fn with_cookie(mut response: Response, cookie: HeaderValue) -> Response {
    response.headers_mut().append(header::SET_COOKIE, cookie);
    response
}

// ── Auth ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AuthStart {
    mode: Option<String>,
    origin: Option<String>,
    nonce: Option<String>,
}

async fn auth_start(State(st): State<AppState>, Query(q): Query<AuthStart>) -> Res {
    if st.env.discord_client_id.is_empty() {
        return Ok(err(StatusCode::NOT_IMPLEMENTED, "DISCORD_CLIENT_ID not configured"));
    }
    let state = random_hex(16);
    // Popup mode: an allow-listed origin opened this window and awaits the
    // token. An origin that isn't allow-listed silently falls back to the
    // redirect flow rather than being told it was rejected.
    let popup = q.mode.as_deref() == Some("popup");
    let popup_origin = q.origin.clone().filter(|o| popup && st.env.allowed_origins.contains(o));
    if popup && popup_origin.is_none() {
        tracing::warn!(origin = ?q.origin, "popup auth from non-allow-listed origin, falling back to redirect flow");
    }
    // 128 bits minimum: whoever knows the nonce collects the token, and the
    // poll that spends it is necessarily unauthenticated. Entropy is not the
    // property that matters, though — the nonce arrives in the URL, so its
    // author knows it without guessing. See the claim route.
    let claim_nonce = q.nonce.filter(|n| popup_origin.is_some() && CLAIM_NONCE.is_match(n)).map(|n| n.to_lowercase());
    let data = SessionData {
        oauth_state: Some(state.clone()),
        claim_started_at: claim_nonce.is_some().then(now_ms),
        popup_origin,
        claim_nonce,
        ..Default::default()
    };
    let (_, cookie) = st.sessions.create(&data).await?;
    let redirect_uri = format!("{}/api/auth/discord/callback", st.env.base_url);
    Ok(with_cookie(Redirect::to(&oauth_url(&st.env.discord_client_id, &redirect_uri, &state)).into_response(), cookie))
}

#[derive(Deserialize)]
struct Callback {
    state: Option<String>,
    code: Option<String>,
}

async fn auth_callback(State(st): State<AppState>, headers: HeaderMap, Query(q): Query<Callback>) -> Res {
    let bad = || (StatusCode::BAD_REQUEST, "bad oauth state").into_response();
    // The session is found by the state, not the cookie: the popup flow's
    // cookie routinely does not survive the trip through Discord.
    let (Some(state), Some(code)) = (&q.state, &q.code) else {
        tracing::warn!(code = q.code.is_some(), state = q.state.is_some(), "oauth callback with no matching session");
        return Ok(bad());
    };
    let Some(found) = st.sessions.find_by_oauth_state(state).await? else {
        tracing::warn!("oauth callback with no matching session");
        return Ok(bad());
    };
    let stored = &found.data;

    // Redirect flow: the browser finishing the login must be the one that
    // started it. Finding the session by `state` alone is what the popup flow
    // needs, but on its own it is a login-CSRF primitive: an attacker starts a
    // run, gets their own `code`, and makes a victim's browser follow the
    // callback — which plants a cookie and leaves the victim operating inside
    // the ATTACKER's Discord account. The redirect flow is exactly the case
    // where the cookie does survive (SameSite=Lax rides this top-level GET), so
    // require it here, and leave the state-only path to the popup flow, which
    // hands its token to an allow-listed origin instead of planting a cookie.
    //
    // The accepted cost: starting the login twice overwrites the first run's
    // cookie, so completing the OLDER tab is refused. One more click.
    if stored.popup_origin.is_none() && Sessions::cookie_sid_hash(&headers).as_deref() != Some(found.sid_hash.as_str()) {
        tracing::warn!("oauth callback whose cookie does not match the run it completes; refusing");
        return Ok(bad());
    }
    let redirect_uri = format!("{}/api/auth/discord/callback", st.env.base_url);
    let token = st.rest.exchange_code(&st.env.discord_client_id, &st.env.discord_client_secret, &redirect_uri, code).await?;
    let me = st.rest.fetch_me(&token).await?;
    let guilds = st.rest.fetch_my_guilds(&token).await?;
    let mut data = SessionData {
        user: SessionUser {
            id: me.id.clone(),
            username: me.global_name.clone().filter(|n| !n.is_empty()).unwrap_or(me.username.clone()),
            avatar_url: me.avatar.as_ref().map(|a| format!("https://cdn.discordapp.com/avatars/{}/{a}.png", me.id)),
        },
        guilds: to_session_guilds(&guilds),
        guilds_fetched_at: Some(now_ms()),
        access_token: Some(token),
        popup_origin: stored.popup_origin.clone(),
        claim_nonce: stored.claim_nonce.clone(),
        claim_started_at: stored.claim_started_at,
        ..Default::default()
    };
    // The nonce poll is a bearer channel whose bearer was chosen by whoever
    // composed the auth-start URL, so the callback alone must not make the
    // token collectable. This approval token exists only in the page below,
    // in the browser that ran the login, and the click that spends it is the
    // one step that browser's owner has to take deliberately.
    let approval = stored.claim_nonce.as_ref().map(|_| random_hex(24));
    if let Some(a) = &approval {
        data.claim_approval = Some(hex::encode(Sha256::digest(a.as_bytes())));
    }
    // Rotate: the pre-auth id becomes an authenticated session, and since the
    // table stores only hashes this is where the token to hand back is minted.
    let sid = st.sessions.rotate(&found.sid_hash, &data, stored.claim_nonce.is_some()).await?;
    tracing::info!(popup = stored.popup_origin.is_some(), nonce = stored.claim_nonce.is_some(), "oauth callback completed");

    let Some(popup_origin) = &stored.popup_origin else {
        // Re-issue the cookie: the redirect flow's SPA needs it. NOT in popup
        // mode — that leg is exempt from the cookie binding above, so planting
        // a cookie there would hand the exemption a way into a victim's browser.
        return Ok(with_cookie(Redirect::to("/").into_response(), st.sessions.adopt_cookie(&sid, found.expires)));
    };

    // Popup mode: hand the token to the opener and close. The page carries a
    // session token, so it must not be stored anywhere, and it is the only
    // inline script in the codebase, so it gets a fresh nonce and nothing else.
    let nonce = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, rand::random::<[u8; 16]>());
    // postMessage needs no confirmation: the browser checks targetOrigin
    // against the receiving window's ACTUAL origin, so a hostile opener is
    // handed nothing. It is the poll that cannot tell them apart.
    let handoff = format!(
        "try {{ window.opener && window.opener.postMessage({{ type: \"armada-bridge-session\", token: {} }}, {}); }} catch (e) {{}}",
        script_json(&sid),
        script_json(popup_origin)
    );
    let body = match &approval {
        None => format!(
            "<!doctype html><meta charset=\"utf-8\"><title>Discord connected</title>\n<body style=\"font:14px system-ui;padding:2rem;text-align:center\">Discord connected. You can close this window.\n<script nonce=\"{nonce}\">(function(){{\n  {handoff}\n  window.close();\n}})();</script>"
        ),
        Some(approval) => format!(
            "<!doctype html><meta charset=\"utf-8\"><title>Discord connected</title>\n<body style=\"font:14px system-ui;padding:2rem;text-align:center\">\n<p>Connect your Discord account to <b>{origin}</b>?</p>\n<p style=\"color:#666\">Only do this if you started this login from that site.</p>\n<button id=\"go\" style=\"font:inherit;padding:.6rem 1.2rem\">Connect</button>\n<p id=\"msg\"></p>\n<script nonce=\"{nonce}\">(function(){{\n  {handoff}\n  document.getElementById(\"go\").addEventListener(\"click\", function(){{\n    this.disabled = true;\n    fetch(\"/api/auth/popup-approve\", {{\n      method: \"POST\",\n      headers: {{ \"content-type\": \"application/json\" }},\n      body: JSON.stringify({{ approval: {approval} }})\n    }}).then(function(r){{\n      if (!r.ok) throw new Error(\"failed\");\n      document.getElementById(\"msg\").textContent = \"Connected. You can close this window.\";\n      window.close();\n    }}).catch(function(){{\n      document.getElementById(\"msg\").textContent = \"Could not complete the connection.\";\n    }});\n  }});\n}})();</script>",
            origin = escape_html(popup_origin),
            approval = script_json(approval),
        ),
    };
    let mut response = Html(body).into_response();
    let h = response.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    // `connect-src 'self'` is what lets the Connect button reach
    // /api/auth/popup-approve; under `default-src 'none'` it silently fails.
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&format!("default-src 'none'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline'; connect-src 'self'"))?,
    );
    Ok(response)
}

/// Approval side of the popup flow: the Connect button on the callback page.
/// Unauthenticated by necessity — popup mode plants no cookie — but not
/// unauthorized: the token it spends was written into that page and nowhere
/// else, so holding it means being the browser that just completed the login.
async fn popup_approve(State(st): State<AppState>, body: Option<Json<Value>>) -> Res {
    let approval = body.as_ref().and_then(|b| b.get("approval")).and_then(Value::as_str).unwrap_or("");
    if !APPROVAL.is_match(approval) {
        return Ok(err(StatusCode::BAD_REQUEST, "approval required"));
    }
    if !st.sessions.approve_handoff(approval).await? {
        return Ok(err(StatusCode::NOT_FOUND, "no pending connection"));
    }
    tracing::info!("popup handoff approved");
    Ok(Json(json!({ "ok": true })).into_response())
}

/// Poll side of the popup flow. The opener cannot count on the callback's
/// postMessage (Discord's COOP severs `window.opener`), so it polls here with
/// the nonce it minted. Pending until the callback lands AND the person in
/// front of the popup has confirmed; the first successful claim spends it.
///
/// The confirmation is what makes this safe. The nonce travels in the
/// auth-start URL, so its author knows it: a stranger picks a nonce, links a
/// victim to `/api/auth/discord?mode=popup&origin=<allow-listed>&nonce=…`, and
/// polls here for the session that victim's login produced. Minting the nonce
/// server-side fails (the attacker mints one too), binding to the auth-start
/// cookie fails (the lure sets that cookie in the VICTIM's browser), and an
/// `Origin` requirement fails (a non-browser poller sends whatever it likes).
/// What distinguishes the honest case is that the opener runs in the same
/// browser as the login; until a same-origin redirect handoff ships on both
/// sides, the deliberate click stands in for proving it.
async fn claim(State(st): State<AppState>, body: Option<Json<Value>>) -> Res {
    let nonce = body.as_ref().and_then(|b| b.get("nonce")).and_then(Value::as_str).unwrap_or("");
    if !CLAIM_NONCE.is_match(nonce) {
        return Ok(err(StatusCode::BAD_REQUEST, "nonce required"));
    }
    let short = &nonce[..8];
    let pending = || Json(json!({ "pending": true })).into_response();
    let found = st.sessions.find_by_claim_nonce(&nonce.to_lowercase()).await?;
    let Some((sid_hash, data)) = found.filter(|(_, d)| !d.user.id.is_empty()) else {
        tracing::info!("claim {short}…: pending (awaiting callback)");
        return Ok(pending());
    };
    if data.claim_approved != Some(true) {
        tracing::info!("claim {short}…: pending (awaiting confirmation in the popup)");
        return Ok(pending());
    }
    if now_ms() - data.claim_started_at.unwrap_or(0) > CLAIM_WINDOW_MS {
        tracing::warn!("claim {short}…: refused, handoff window expired");
        return Ok(err(StatusCode::GONE, "handoff expired"));
    }
    // Every field the handoff used goes with it: a spent run leaves no nonce
    // to look up and no approval to re-spend.
    let rest = SessionData { claim_nonce: None, claim_approved: None, claim_approval: None, claim_started_at: None, ..data };
    match st.sessions.collect_handoff(&sid_hash, &rest).await? {
        Some(token) => {
            tracing::info!("claim {short}…: token released");
            Ok(Json(json!({ "token": token })).into_response())
        }
        // Single-use: this is a second poll racing the first.
        None => {
            tracing::info!("claim {short}…: already collected");
            Ok(pending())
        }
    }
}

async fn dev_login(State(st): State<AppState>) -> Res {
    if !st.env.dev_login {
        return Ok(err(StatusCode::FORBIDDEN, "dev login disabled"));
    }
    // The token comes back too, so a cross-origin client (Armada's wizard in
    // dev) can authenticate without the cookie.
    let data = SessionData {
        user: SessionUser { id: "0".into(), username: "dev".into(), avatar_url: None },
        guilds: vec![SessionGuild { id: "0".into(), name: "Dev Guild".into(), icon: None, can_manage: true }],
        dev: Some(true),
        ..Default::default()
    };
    let (sid, cookie) = st.sessions.create(&data).await?;
    Ok(with_cookie(Json(json!({ "ok": true, "token": sid })).into_response(), cookie))
}

async fn logout(State(st): State<AppState>, headers: HeaderMap) -> Res {
    let cookie = st.sessions.destroy(&headers).await?;
    Ok(with_cookie(Json(json!({ "ok": true })).into_response(), cookie))
}

/// Sign out everywhere. The popup handoff releases a token to whoever polls
/// the nonce and plants no cookie in the browser that ran the login, so a token
/// collected by someone else names a session its owner cannot reach with
/// /logout. Without this there is no way to take it back before it expires.
async fn revoke_all(State(st): State<AppState>, headers: HeaderMap) -> Res {
    let session = session_or_401!(st, headers);
    let (revoked, cookie) = st.sessions.revoke_all_for_user(&session.user.id).await?;
    tracing::info!(revoked, "revoked every session for one account");
    Ok(with_cookie(Json(json!({ "ok": true, "revoked": revoked })).into_response(), cookie))
}

async fn me(State(st): State<AppState>, headers: HeaderMap) -> Res {
    let configured = !st.env.discord_client_id.is_empty() && !st.env.discord_client_secret.is_empty();
    let session = st.sessions.get(&headers).await?.filter(|s| !s.user.id.is_empty());
    let Some(s) = session else {
        return Ok(Json(json!({ "user": null, "devLogin": st.env.dev_login, "discordConfigured": configured })).into_response());
    };
    let guilds: Vec<&SessionGuild> = s.guilds.iter().filter(|g| g.can_manage).collect();
    Ok(Json(json!({ "user": s.user, "guilds": guilds, "devLogin": st.env.dev_login, "discordConfigured": configured })).into_response())
}

// ── Discord-side wizard data ────────────────────────────────────────────────

async fn guild_channels(State(st): State<AppState>, headers: HeaderMap, Path(guild_id): Path<String>) -> Res {
    let session = session_or_401!(st, headers);
    // This answers with the BOT's view of the guild, private channels
    // included, so it needs the same authority as acting on the guild: guild
    // ids are not secret, and any logged-in stranger could enumerate a server.
    check!(guild_authority(&st, &headers, &session, &guild_id).await?);
    if st.env.discord_bot_token.is_empty() {
        return Ok(err(StatusCode::NOT_IMPLEMENTED, "bot token not configured"));
    }
    let Some(all) = st.rest.bot_guild_channels(&st.env.discord_bot_token, &guild_id).await? else {
        return Ok(Json(json!({ "present": false, "installUrl": bot_install_url(&st.env.discord_client_id, &guild_id) })).into_response());
    };
    let mut text: Vec<_> = all.iter().filter(|c| c.kind == 0).collect();
    text.sort_by_key(|c| c.position);
    let ids: Vec<String> = text.iter().map(|c| c.id.clone()).collect();
    let bridged: Vec<String> = st
        .pool
        .get()
        .await?
        .query("SELECT discord_channel_id FROM bridges WHERE discord_channel_id = ANY($1) AND status IN ('pending_confirm', 'active')", &[&ids])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let category = |id: &Option<String>| id.as_ref().and_then(|id| all.iter().find(|c| &c.id == id && c.kind == 4)).map(|c| c.name.clone());
    let channels: Vec<Value> = text
        .iter()
        .map(|c| {
            json!({
                "id": c.id, "name": c.name, "position": c.position, "category": category(&c.parent_id),
                "empty": c.last_message_id.is_none(), "bridged": bridged.contains(&c.id),
            })
        })
        .collect();
    Ok(Json(json!({
        "present": true,
        "channels": channels,
        "createInstallUrl": bot_install_url_create(&st.env.discord_client_id, &guild_id),
    }))
    .into_response())
}

// ── Server import ────────────────────────────────────────────────────────────

async fn import_create(State(st): State<AppState>, headers: HeaderMap, body: Option<Json<Value>>) -> Res {
    let session = session_or_401!(st, headers);
    let Some(guild_id) = body.as_ref().and_then(|b| b.get("guildId")).and_then(Value::as_str).map(str::to_owned) else {
        return Ok(err(StatusCode::BAD_REQUEST, "guildId required"));
    };
    check!(guild_authority(&st, &headers, &session, &guild_id).await?);
    Ok(match st.importer.preview(&session.user.id, &guild_id).await {
        Ok(Preview::NotPresent { install_url }) => Json(json!({ "present": false, "installUrl": install_url })).into_response(),
        Ok(Preview::Ready { import_id, plan, default_relays }) => {
            Json(json!({ "present": true, "importId": import_id, "plan": plan, "defaultRelays": default_relays })).into_response()
        }
        Err(error) => err(StatusCode::BAD_GATEWAY, format!("{error:#}")),
    })
}

async fn import_get(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Res {
    let session = session_or_401!(st, headers);
    let Some((row, invite_url)) = st.importer.get(&id, &session.user.id).await.ok().flatten() else {
        return Ok(err(StatusCode::NOT_FOUND, "not found"));
    };
    Ok(Json(json!({
        "importId": row.import_id, "status": row.status, "statusDetail": row.status_detail,
        "plan": row.plan, "communityId": row.community_id, "inviteUrl": invite_url,
    }))
    .into_response())
}

/// Every import mutation: authenticate, re-check authority, then act. A
/// failure the caller can do something about comes back as a 400 with why.
async fn import_action(st: &AppState, headers: &HeaderMap, id: &str, act: impl AsyncFnOnce(&str) -> anyhow::Result<Value>) -> Res {
    let session = session_or_401!(st, headers);
    check!(import_authority(st, headers, &session, id).await?);
    Ok(match act(&session.user.id).await {
        Ok(v) => Json(v).into_response(),
        Err(error) => err(StatusCode::BAD_REQUEST, format!("{error:#}")),
    })
}

async fn import_prepare(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<PrepareBody>) -> Res {
    let importer = st.importer.clone();
    import_action(&st, &headers, &id, async |owner| {
        let (owner_pk, templates) = importer.prepare(&id, owner, body).await?;
        Ok(json!({ "ownerPk": owner_pk, "templates": templates }))
    })
    .await
}

async fn import_confirm(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<ConfirmBody>) -> Res {
    let importer = st.importer.clone();
    import_action(&st, &headers, &id, async |owner| {
        importer.confirm(&id, owner, body).await?;
        Ok(json!({ "ok": true, "status": "publishing" }))
    })
    .await
}

async fn import_retry(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Res {
    let importer = st.importer.clone();
    import_action(&st, &headers, &id, async |owner| {
        importer.retry(&id, owner).await?;
        Ok(json!({ "ok": true }))
    })
    .await
}

/// Re-run only the history backfill (recovery for the silent-skip bug).
async fn import_rerun_history(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Res {
    let importer = st.importer.clone();
    import_action(&st, &headers, &id, async |owner| {
        importer.rerun_history(&id, owner).await?;
        Ok(json!({ "ok": true }))
    })
    .await
}

/// The same re-run addressed by the minted community, so the dashboard (which
/// only knows bridges) can trigger it.
async fn community_rerun_history(State(st): State<AppState>, headers: HeaderMap, Path(community_id): Path<String>) -> Res {
    let session = session_or_401!(st, headers);
    let row = st
        .pool
        .get()
        .await?
        .query_opt(
            "SELECT import_id::text FROM imports WHERE owner_discord_id = $1 AND plan->'checkpoints'->>'communityIdHex' = $2
             ORDER BY updated_at DESC LIMIT 1",
            &[&session.user.id, &community_id],
        )
        .await?;
    let Some(row) = row else { return Ok(err(StatusCode::NOT_FOUND, "no import found for this community")) };
    let id: String = row.get(0);
    let importer = st.importer.clone();
    import_action(&st, &headers, &id, async |owner| {
        importer.rerun_history(&id, owner).await?;
        Ok(json!({ "ok": true }))
    })
    .await
}

// ── Bridges ──────────────────────────────────────────────────────────────────

async fn owned_bridge(st: &AppState, bridge_id: &str, owner: &str) -> anyhow::Result<Option<BridgeRow>> {
    let sql = format!("SELECT {BRIDGE_COLUMNS} FROM bridges WHERE bridge_id::text = $1 AND owner_discord_id = $2");
    Ok(st.pool.get().await?.query_opt(&sql, &[&bridge_id, &owner]).await?.as_ref().map(BridgeRow::from_row))
}

async fn bridge_create(State(st): State<AppState>, headers: HeaderMap, body: Option<Json<Value>>) -> Res {
    let session = session_or_401!(st, headers);
    let field = |k: &str| body.as_ref().and_then(|b| b.get(k)).and_then(Value::as_str).map(str::to_owned);
    // "Add channel": reuse the sealed invite from a bridge the user already
    // owns instead of demanding a fresh link for every channel.
    let mut invite = field("inviteUrl").filter(|s| !s.is_empty());
    if invite.is_none()
        && let Some(from) = field("fromBridgeId")
    {
        let Some(sealed) = owned_bridge(&st, &from, &session.user.id).await?.and_then(|b| b.invite_url_sealed) else {
            return Ok(err(StatusCode::NOT_FOUND, "source bridge not found"));
        };
        invite = Some(unseal(&st.env.seal_key_hex, &sealed)?);
    }
    let Some(invite) = invite else { return Ok(err(StatusCode::BAD_REQUEST, "inviteUrl required")) };
    let inspected = match st.manager.inspect_invite(&invite).await {
        Ok(i) => i,
        Err(error) => return Ok(err(StatusCode::UNPROCESSABLE_ENTITY, format!("{error:#}"))),
    };
    let row = st
        .pool
        .get()
        .await?
        .query_one(
            "INSERT INTO bridges (owner_discord_id, status, invite_url_sealed, community_id, community_name)
             VALUES ($1, 'draft', $2, $3, $4) RETURNING bridge_id::text",
            &[&session.user.id, &seal(&st.env.seal_key_hex, &invite)?, &inspected.community_id, &inspected.name],
        )
        .await?;
    let ids: Vec<String> = inspected.channels.iter().map(|c| c.id_hex.clone()).collect();
    let bridged: Vec<String> = st
        .pool
        .get()
        .await?
        .query(
            "SELECT concord_channel_id FROM bridges WHERE community_id = $1 AND concord_channel_id = ANY($2) AND status IN ('pending_confirm', 'active')",
            &[&inspected.community_id, &ids],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let channels: Vec<Value> = inspected
        .channels
        .iter()
        .map(|c| {
            json!({
                "idHex": c.id_hex, "name": c.name, "category": c.category, "private": c.private, "forum": c.forum,
                "position": c.position, "bridged": bridged.contains(&c.id_hex),
            })
        })
        .collect();
    let can_create = st.importer.import_for_community(&inspected.community_id, &session.user.id).await?.is_some();
    Ok(Json(json!({
        "bridgeId": row.get::<_, String>(0),
        "community": { "idHex": inspected.community_id, "name": inspected.name, "relays": inspected.relays },
        "channels": channels,
        "canCreateChannels": can_create,
        "approvalUrl": approval_url(&st, &row.get::<_, String>(0)),
    }))
    .into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinkBody {
    guild_id: Option<String>,
    channel_id: Option<String>,
    concord_channel_id: Option<String>,
    consent: Option<bool>,
}

async fn bridge_link(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<LinkBody>) -> Res {
    let session = session_or_401!(st, headers);
    let Some(row) = owned_bridge(&st, &id, &session.user.id).await? else { return Ok(err(StatusCode::NOT_FOUND, "not found")) };
    if row.status != "draft" {
        return Ok(err(StatusCode::CONFLICT, format!("bridge is {}, not draft", row.status)));
    }
    let (Some(guild_id), Some(channel_id), Some(concord_id)) = (body.guild_id, body.channel_id, body.concord_channel_id) else {
        return Ok(err(StatusCode::BAD_REQUEST, "guildId, channelId, concordChannelId required"));
    };
    if body.consent != Some(true) {
        return Ok(err(StatusCode::BAD_REQUEST, "the encryption disclosure must be explicitly accepted"));
    }
    check!(guild_authority(&st, &headers, &session, &guild_id).await?);

    // Authority over `guildId` says nothing about `channelId`: both arrive in
    // the same body and ids are not secret. Without tying them together,
    // someone links a bridge naming a throwaway guild they own and a channel id
    // lifted from a server they do not, then confirms from their own community.
    // One shared bot serves every tenant and the manager routes on the channel
    // id alone, so that mirrors a stranger's channel into their community and
    // lets them post into it through the webhook.
    if st.env.discord_bot_token.is_empty() {
        return Ok(err(StatusCode::NOT_IMPLEMENTED, "bot token not configured"));
    }
    let Some(channels) = st.rest.bot_guild_text_channels(&st.env.discord_bot_token, &guild_id).await? else {
        return Ok(err(StatusCode::CONFLICT, "the bot is not in that guild"));
    };
    if !channels.iter().any(|c| c.id == channel_id) {
        return Ok(err(StatusCode::FORBIDDEN, "that channel is not in that guild"));
    }
    // A second live bridge on one channel would steal it from the first. The
    // unique index (migration 017) is the backstop for the race between two of
    // these checks; this answers with a 409 rather than a constraint violation.
    let db = st.pool.get().await?;
    let taken = db
        .query_opt(
            "SELECT 1 FROM bridges WHERE discord_channel_id = $1 AND status IN ('pending_confirm', 'active') AND bridge_id::text <> $2",
            &[&channel_id, &row.bridge_id],
        )
        .await?;
    if taken.is_some() {
        return Ok(err(StatusCode::CONFLICT, "that channel is already bridged"));
    }
    // The same for the Armada side (migration 019).
    let taken = db
        .query_opt(
            "SELECT 1 FROM bridges WHERE community_id = $1 AND concord_channel_id = $2 AND status IN ('pending_confirm', 'active')
               AND bridge_id::text <> $3",
            &[&row.community_id, &concord_id, &row.bridge_id],
        )
        .await?;
    if taken.is_some() {
        return Ok(err(StatusCode::CONFLICT, "that Armada channel is already bridged"));
    }
    db.execute(
        "UPDATE bridges SET discord_guild_id = $2, discord_channel_id = $3, concord_channel_id = $4, updated_at = now()
         WHERE bridge_id::text = $1",
        &[&row.bridge_id, &guild_id, &channel_id, &concord_id],
    )
    .await?;
    drop(db);
    let fresh = crate::manager::bridge_by_id(&st.pool, &row.bridge_id).await?.ok_or_else(|| anyhow::anyhow!("bridge vanished"))?;
    st.manager.activate(&fresh).await?;
    Ok(Json(json!({ "ok": true, "status": "pending_confirm" })).into_response())
}

/// Most channels one request links.
const MAX_LINKED: usize = 100;

/// NIP-98 HTTP auth, the shape an approval is signed in.
const HTTP_AUTH_KIND: u16 = 27235;

/// How far an approval's `created_at` may sit from now. Replaying one inside
/// the window links nothing new: its channels are bridged by then.
const APPROVAL_WINDOW_SECS: u64 = 120;

/// One row of the channel map: a Discord side and an Armada side, each an
/// existing channel or one to create, and an optional history copy.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MapPair {
    discord_channel_id: Option<String>,
    create_discord: Option<String>,
    concord_channel_id: Option<String>,
    create_concord: Option<String>,
    /// The category a created channel goes under, on whichever side creates it.
    category: Option<String>,
    /// `discord` copies Discord's past messages into Armada, `armada` the reverse.
    history: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LinkMany {
    guild_id: String,
    consent: bool,
    pairs: Vec<MapPair>,
}

#[derive(Deserialize)]
struct LinkManyBody {
    /// The `LinkMany`, as the JSON string the browser sent: an approval signs
    /// its hash, so it is parsed from these exact bytes and never re-encoded.
    request: String,
    /// A NIP-98 event over `request`, by an Armada key that holds Manage
    /// Channels in the community. Present, it stands in for the in-channel
    /// confirm.
    approval: Option<Value>,
}

/// The URL an approval for this draft names.
fn approval_url(st: &AppState, draft_id: &str) -> String {
    format!("{}/api/bridges/{draft_id}/link-many", st.env.base_url.trim_end_matches('/'))
}

/// The key that signed `approval`, if it is a fresh NIP-98 authorization of
/// exactly this request at exactly this URL.
///
/// Every binding matters. Without the payload hash, an approval for two
/// channels would authorise any channels at all; without the URL, one for a
/// different community's draft; without the time window, one leaked from any
/// earlier session, forever.
fn approval_signer(approval: &Value, url: &str, request: &str) -> Result<String, &'static str> {
    use nostr::prelude::*;
    let event = Event::from_json(approval.to_string()).map_err(|_| "the approval is not a Nostr event")?;
    event.verify().map_err(|_| "the approval's signature does not verify")?;
    if event.kind != Kind::Custom(HTTP_AUTH_KIND) {
        return Err("the approval is not an HTTP authorization (kind 27235)");
    }
    let tag = |name: &str| event.tags.iter().find(|t| t.as_slice().first().is_some_and(|n| n == name)).and_then(|t| t.as_slice().get(1).cloned());
    if tag("u").as_deref() != Some(url) || !tag("method").is_some_and(|m| m.eq_ignore_ascii_case("POST")) {
        return Err("the approval is for a different request");
    }
    if tag("payload").as_deref() != Some(hex::encode(Sha256::digest(request.as_bytes())).as_str()) {
        return Err("the approval does not match these channels");
    }
    let now = (now_ms() / 1000) as u64;
    if event.created_at.as_secs().abs_diff(now) > APPROVAL_WINDOW_SECS {
        return Err("the approval has expired; sign it again");
    }
    Ok(event.pubkey.to_hex())
}

fn is_unique_violation(error: &anyhow::Error) -> bool {
    error.chain().any(|e| e.downcast_ref::<tokio_postgres::Error>().and_then(|e| e.code()) == Some(&tokio_postgres::error::SqlState::UNIQUE_VIOLATION))
}

/// The channel map: link many channels of one Discord server and one Armada
/// community at once, creating what is missing on either side, with history.
///
/// Everything is checked before anything is created, in the order a failure
/// is likeliest, and creation goes Discord first: a Discord channel the bot
/// made is one click to delete, while an Armada channel edition is permanent.
async fn bridge_link_many(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>, Json(body): Json<LinkManyBody>) -> Res {
    let session = session_or_401!(st, headers);
    let Some(draft) = owned_bridge(&st, &id, &session.user.id).await? else { return Ok(err(StatusCode::NOT_FOUND, "not found")) };
    if draft.status != "draft" {
        return Ok(err(StatusCode::CONFLICT, format!("bridge is {}, not draft", draft.status)));
    }
    let Ok(req) = serde_json::from_str::<LinkMany>(&body.request) else { return Ok(err(StatusCode::BAD_REQUEST, "the request does not parse")) };
    if !req.consent {
        return Ok(err(StatusCode::BAD_REQUEST, "the encryption disclosure must be explicitly accepted"));
    }
    if req.pairs.is_empty() || req.pairs.len() > MAX_LINKED {
        return Ok(err(StatusCode::BAD_REQUEST, format!("link between 1 and {MAX_LINKED} channels at a time")));
    }
    check!(guild_authority(&st, &headers, &session, &req.guild_id).await?);
    let token = st.env.discord_bot_token.clone();
    if token.is_empty() {
        return Ok(err(StatusCode::NOT_IMPLEMENTED, "bot token not configured"));
    }
    // The same tie as `bridge_link`: authority over the guild says nothing
    // about a channel id that merely arrived beside it.
    let Some(guild_channels) = st.rest.bot_guild_channels(&token, &req.guild_id).await? else {
        return Ok(err(StatusCode::CONFLICT, "the bot is not in that guild"));
    };
    let invite = unseal(&st.env.seal_key_hex, draft.invite_url_sealed.as_deref().ok_or_else(|| anyhow::anyhow!("draft has no invite"))?)?;
    let community_id = draft.community_id.clone().unwrap_or_default();
    let community = match st.manager.inspect_invite(&invite).await {
        Ok(c) if c.community_id == community_id => c,
        Ok(_) => return Ok(err(StatusCode::CONFLICT, "the invite now resolves to a different community; start over")),
        Err(error) => return Ok(err(StatusCode::BAD_GATEWAY, format!("could not read the community: {error:#}"))),
    };

    let mut discord_seen = std::collections::HashSet::new();
    let mut concord_seen = std::collections::HashSet::new();
    for (i, p) in req.pairs.iter().enumerate() {
        let row = i + 1;
        let blank = |s: &Option<String>| s.as_deref().is_none_or(|s| s.trim().is_empty());
        match (&p.discord_channel_id, blank(&p.create_discord)) {
            (Some(d), true) => {
                if !guild_channels.iter().any(|c| &c.id == d && c.kind == 0) {
                    return Ok(err(StatusCode::FORBIDDEN, format!("row {row}: that channel is not in that guild")));
                }
                if !discord_seen.insert(d.clone()) {
                    return Ok(err(StatusCode::BAD_REQUEST, format!("row {row}: a Discord channel can be linked only once")));
                }
            }
            (None, false) => {}
            _ => return Ok(err(StatusCode::BAD_REQUEST, format!("row {row}: pick one Discord channel, or one to create"))),
        }
        match (&p.concord_channel_id, blank(&p.create_concord)) {
            (Some(c), true) => {
                if !community.channels.iter().any(|x| &x.id_hex == c) {
                    return Ok(err(StatusCode::BAD_REQUEST, format!("row {row}: that channel is not in the community")));
                }
                if !concord_seen.insert(c.clone()) {
                    return Ok(err(StatusCode::BAD_REQUEST, format!("row {row}: an Armada channel can be linked only once")));
                }
            }
            (None, false) => {}
            _ => return Ok(err(StatusCode::BAD_REQUEST, format!("row {row}: pick one Armada channel, or one to create"))),
        }
        if p.discord_channel_id.is_none() && p.concord_channel_id.is_none() {
            return Ok(err(StatusCode::BAD_REQUEST, format!("row {row}: one side has to exist already")));
        }
        match p.history.as_deref() {
            None | Some("none") => {}
            Some("discord") if p.discord_channel_id.is_some() => {}
            Some("armada") if p.concord_channel_id.is_some() => {}
            _ => return Ok(err(StatusCode::BAD_REQUEST, format!("row {row}: history can only come from a channel that exists"))),
        }
    }

    let db = st.pool.get().await?;
    let discord_ids: Vec<String> = discord_seen.iter().cloned().collect();
    let concord_ids: Vec<String> = concord_seen.iter().cloned().collect();
    let taken = db
        .query_opt(
            "SELECT 1 FROM bridges WHERE status IN ('pending_confirm', 'active')
               AND (discord_channel_id = ANY($1) OR (community_id = $2 AND concord_channel_id = ANY($3))) LIMIT 1",
            &[&discord_ids, &community_id, &concord_ids],
        )
        .await?;
    drop(db);
    if taken.is_some() {
        return Ok(err(StatusCode::CONFLICT, "one of those channels is already bridged; reload the map"));
    }
    // Discord cannot place a message before ones already there, so Armada's
    // history goes only into an empty channel, or it would read as new.
    for p in req.pairs.iter().filter(|p| p.history.as_deref() == Some("armada")) {
        let Some(d) = &p.discord_channel_id else { continue };
        if st.rest.bot_channel_messages_before(&token, d, None, 1).await?.is_some_and(|page| !page.is_empty()) {
            let name = guild_channels.iter().find(|c| &c.id == d).map_or("", |c| c.name.as_str());
            return Ok(err(
                StatusCode::CONFLICT,
                format!("#{name} has messages, so Armada's history can't go into it: Discord would show it as newer than they are"),
            ));
        }
    }

    let approved = match &body.approval {
        None => false,
        Some(approval) => {
            let signer = match approval_signer(approval, &approval_url(&st, &id), &body.request) {
                Ok(pk) => pk,
                Err(why) => return Ok(err(StatusCode::BAD_REQUEST, why)),
            };
            match st.manager.authorizes(&invite, &signer, concord::roles::perm::MANAGE_CHANNELS).await {
                Ok(true) => true,
                Ok(false) => {
                    return Ok(err(StatusCode::FORBIDDEN, format!("that Armada key does not hold Manage Channels in {}", community.name)));
                }
                Err(error) => return Ok(err(StatusCode::BAD_GATEWAY, format!("could not check the key's roles: {error:#}"))),
            }
        }
    };
    let import_id = if req.pairs.iter().any(|p| p.create_concord.is_some()) {
        match st.importer.import_for_community(&community_id, &session.user.id).await? {
            Some(import_id) => Some(import_id),
            None => {
                return Ok(err(
                    StatusCode::BAD_REQUEST,
                    "the bridge can only create Armada channels in a community it imported for you; create them in Armada, then reload the map",
                ));
            }
        }
    } else {
        None
    };

    // Discord first (see above). A refusal partway leaves what was made: the
    // map shows them as existing channels on the next try.
    let mut categories: std::collections::HashMap<String, String> =
        guild_channels.iter().filter(|c| c.kind == 4).map(|c| (c.name.to_lowercase(), c.id.clone())).collect();
    let mut discord_side = Vec::with_capacity(req.pairs.len());
    for p in &req.pairs {
        let Some(name) = p.create_discord.as_deref().filter(|_| p.discord_channel_id.is_none()) else {
            discord_side.push(p.discord_channel_id.clone().unwrap_or_default());
            continue;
        };
        let created = async {
            let parent = match p.category.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
                Some(category) => match categories.get(&category.to_lowercase()) {
                    Some(id) => Some(id.clone()),
                    None => {
                        let label: String = category.chars().take(100).collect();
                        let made = st.rest.bot_create_channel(&token, &req.guild_id, &label, 4, None).await?;
                        categories.insert(category.to_lowercase(), made.id.clone());
                        Some(made.id)
                    }
                },
                None => None,
            };
            st.rest.bot_create_channel(&token, &req.guild_id, &discord_channel_name(name), 0, parent.as_deref()).await
        };
        match created.await {
            Ok(channel) => discord_side.push(channel.id),
            Err(error) if error.is::<CannotCreateChannels>() => {
                return Ok((
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "the bot needs Manage Channels to create Discord channels; re-authorize it, then try again",
                        "installUrl": bot_install_url_create(&st.env.discord_client_id, &req.guild_id),
                    })),
                )
                    .into_response());
            }
            Err(error) => return Ok(err(StatusCode::BAD_GATEWAY, format!("could not create #{name} on Discord: {error:#}"))),
        }
    }
    let wanted: Vec<(String, Option<String>)> = req
        .pairs
        .iter()
        .filter(|p| p.concord_channel_id.is_none())
        .filter_map(|p| Some((p.create_concord.as_deref()?.trim().to_owned(), p.category.clone().filter(|c| !c.trim().is_empty()))))
        .collect();
    let mut made = match &import_id {
        Some(import_id) => match st.importer.create_channels(import_id, &wanted).await {
            Ok(made) => made.into_iter(),
            Err(error) => return Ok(err(StatusCode::BAD_GATEWAY, format!("could not create the Armada channels: {error:#}"))),
        },
        None => Vec::new().into_iter(),
    };

    let code = random_hex(4);
    let mut db = st.pool.get().await?;
    let tx = db.transaction().await?;
    let group: String = tx.query_one("SELECT gen_random_uuid()::text", &[]).await?.get(0);
    let mut rows = Vec::with_capacity(req.pairs.len());
    for (i, p) in req.pairs.iter().enumerate() {
        let concord = match &p.concord_channel_id {
            Some(c) => c.clone(),
            None => made.next().ok_or_else(|| anyhow::anyhow!("created fewer Armada channels than asked"))?,
        };
        let history = match p.history.as_deref() {
            Some(direction @ ("discord" | "armada")) => json!({ "direction": direction, "state": "pending", "imported": 0 }),
            _ => json!({}),
        };
        // The draft carries the sealed invite; it becomes the first row.
        let sql = if i == 0 {
            format!(
                "UPDATE bridges SET discord_guild_id = $2, discord_channel_id = $3, concord_channel_id = $4, link_group = ($5::text)::uuid,
                   history = $6, updated_at = now() WHERE bridge_id = ($1::text)::uuid RETURNING {BRIDGE_COLUMNS}"
            )
        } else {
            format!(
                "INSERT INTO bridges (owner_discord_id, status, invite_url_sealed, community_id, community_name,
                   discord_guild_id, discord_channel_id, concord_channel_id, link_group, history)
                 SELECT owner_discord_id, 'draft', invite_url_sealed, community_id, community_name, $2, $3, $4, ($5::text)::uuid, $6
                   FROM bridges WHERE bridge_id = ($1::text)::uuid
                 RETURNING {BRIDGE_COLUMNS}"
            )
        };
        let row = tx.query_one(&sql, &[&draft.bridge_id, &req.guild_id, &discord_side[i], &concord, &group, &history]).await?;
        rows.push(BridgeRow::from_row(&row));
    }
    tx.commit().await?;
    drop(db);

    if let Err(error) = st.manager.activate_group(&rows, (!approved).then_some(code.as_str())).await {
        // A race with another link for one of these channels: the unique
        // indexes refused the provision. Nothing has started yet (the group
        // starts only once all of it is provisioned), so unlink all of it
        // rather than leave part of a map to come up on the next boot.
        let ids: Vec<String> = rows.iter().map(|r| r.bridge_id.clone()).collect();
        st.pool
            .get()
            .await?
            .execute(
                "UPDATE bridges SET status = 'unlinked', status_detail = 'link interrupted', invite_url_sealed = NULL,
                   master_secret_sealed = NULL, primary_sk_sealed = NULL, updated_at = now()
                 WHERE bridge_id::text = ANY($1)",
                &[&ids],
            )
            .await?;
        if is_unique_violation(&error) {
            return Ok(err(StatusCode::CONFLICT, "one of those channels was bridged meanwhile; reload the map"));
        }
        return Err(error.into());
    }
    tracing::info!(group = %group, channels = rows.len(), approved, "linked a channel map");
    Ok(Json(json!({
        "ok": true,
        "status": if approved { "active" } else { "pending_confirm" },
        "bridgeIds": rows.iter().map(|r| r.bridge_id.clone()).collect::<Vec<_>>(),
        "confirmCode": (!approved).then_some(code),
    }))
    .into_response())
}

async fn bridges_list(State(st): State<AppState>, headers: HeaderMap) -> Res {
    let session = session_or_401!(st, headers);
    // Shaped in SQL to match what the dashboard has always been sent: the
    // uuid and timestamp as strings, and the count as a decimal string.
    // `tenant_id` leads every index on messages. Without it the count below
    // was a sequential scan of the whole table per bridge listed (2026-10-16).
    let rows = st
        .pool
        .get()
        .await?
        .query(
            "SELECT row_to_json(x) FROM (
               SELECT b.bridge_id, b.status, b.status_detail, b.community_name, b.community_id, b.history, b.link_group,
                      b.discord_guild_id, b.discord_channel_id, b.concord_channel_id, b.confirm_code,
                      b.discord_channel_name, b.concord_channel_name, b.discord_guild_name, b.primary_pk,
                      to_char(b.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS created_at,
                      (SELECT count(*) FROM messages m
                        WHERE m.tenant_id = 'default' AND m.discord_channel_id = b.discord_channel_id
                          AND m.concord_channel_id = b.concord_channel_id)::text AS bridged_count
               FROM bridges b
               WHERE b.owner_discord_id = $1 AND b.status <> 'unlinked'
               ORDER BY b.created_at DESC) x",
            &[&session.user.id],
        )
        .await?;
    let bridges: Vec<Value> = rows.iter().map(|r| r.get(0)).collect();
    let live: Vec<bool> = bridges.iter().map(|b| b["bridge_id"].as_str().is_some_and(|id| st.manager.is_live(id))).collect();
    Ok(Json(json!({ "bridges": bridges, "live": live })).into_response())
}

async fn bridge_lifecycle(st: AppState, headers: HeaderMap, id: String, act: &str) -> Res {
    let session = session_or_401!(st, headers);
    let Some(row) = owned_bridge(&st, &id, &session.user.id).await? else { return Ok(err(StatusCode::NOT_FOUND, "not found")) };
    match act {
        "pause" => st.manager.stop(&row.bridge_id, "paused", None).await?,
        "unlink" => st.manager.stop(&row.bridge_id, "unlinked", Some("unlinked from the portal")).await?,
        _ => st.manager.resume(&row.bridge_id).await?,
    }
    Ok(Json(json!({ "ok": true })).into_response())
}

async fn bridge_pause(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Res {
    bridge_lifecycle(st, headers, id, "pause").await
}
async fn bridge_resume(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Res {
    bridge_lifecycle(st, headers, id, "resume").await
}
async fn bridge_unlink(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Res {
    bridge_lifecycle(st, headers, id, "unlink").await
}

/// Poll-based status stream for the confirm screen.
async fn bridge_events(State(st): State<AppState>, headers: HeaderMap, Path(id): Path<String>) -> Res {
    let session = session_or_401!(st, headers);
    let Some(row) = owned_bridge(&st, &id, &session.user.id).await? else { return Ok(err(StatusCode::NOT_FOUND, "not found")) };
    let pool = st.pool.clone();
    let stream = futures_util::stream::unfold((0u32, String::new(), false), move |(i, last, done)| {
        let (pool, id) = (pool.clone(), row.bridge_id.clone());
        async move {
            let mut last = last;
            let mut i = i;
            if done {
                return None;
            }
            loop {
                if i >= 300 {
                    return None;
                }
                if i > 0 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                i += 1;
                let row = pool
                    .get()
                    .await
                    .ok()?
                    .query_opt("SELECT status, status_detail FROM bridges WHERE bridge_id::text = $1", &[&id])
                    .await
                    .ok()?;
                let (payload, finished) = match &row {
                    Some(r) => {
                        let status: String = r.get(0);
                        let detail: Option<String> = r.get(1);
                        (json!({ "status": status, "status_detail": detail }).to_string(), status != "pending_confirm")
                    }
                    None => (json!({ "status": "gone" }).to_string(), true),
                };
                if payload != last {
                    let chunk = axum::body::Bytes::from(format!("data: {payload}\n\n"));
                    return Some((Ok::<_, std::convert::Infallible>(chunk), (i, payload, finished)));
                }
                if finished {
                    return None;
                }
                last = payload;
            }
        }
    });
    let mut response = axum::body::Body::from_stream(stream).into_response();
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    Ok(response)
}

/// The whole application. `web_dir` holds the built SPA.
pub fn app(st: AppState, web_dir: &str) -> anyhow::Result<Router> {
    let policy = Arc::new(OriginPolicy::new(&st.env.base_url, st.env.allowed_origins.clone())?);
    let over_https = st.env.base_url.starts_with("https:");
    let api = Router::new()
        .route("/auth/discord", get(auth_start))
        .route("/auth/discord/callback", get(auth_callback))
        .route("/auth/popup-approve", post(popup_approve))
        .route("/auth/claim", post(claim))
        .route("/auth/dev", post(dev_login))
        .route("/auth/logout", post(logout))
        .route("/auth/revoke-all", post(revoke_all))
        .route("/me", get(me))
        .route("/guilds/{id}/channels", get(guild_channels))
        .route("/imports", post(import_create))
        .route("/imports/{id}", get(import_get))
        .route("/imports/{id}/prepare", post(import_prepare))
        .route("/imports/{id}/confirm", post(import_confirm))
        .route("/imports/{id}/retry", post(import_retry))
        .route("/imports/{id}/rerun-history", post(import_rerun_history))
        .route("/communities/{community_id}/rerun-history", post(community_rerun_history))
        .route("/bridges", post(bridge_create).get(bridges_list))
        .route("/bridges/{id}/link", post(bridge_link))
        .route("/bridges/{id}/link-many", post(bridge_link_many))
        .route("/bridges/{id}/pause", post(bridge_pause))
        .route("/bridges/{id}/resume", post(bridge_resume))
        .route("/bridges/{id}/unlink", post(bridge_unlink))
        .route("/bridges/{id}/events", get(bridge_events))
        // Innermost first: the origin guard's 403 still gets CORS's no-store and Vary.
        .layer(middleware::from_fn_with_state(policy.clone(), origin_guard))
        .layer(middleware::from_fn_with_state(policy, api_cors))
        .with_state(st);
    let index = format!("{}/index.html", web_dir.trim_end_matches('/'));
    let spa = tower_http::services::ServeDir::new(web_dir).fallback(tower_http::services::ServeFile::new(index));
    Ok(Router::new()
        .nest("/api", api)
        .fallback_service(spa)
        .layer(middleware::from_fn_with_state(over_https, security_headers)))
}

#[cfg(test)]
mod tests {
    use nostr::prelude::*;

    use super::*;

    const URL: &str = "https://portal.example/api/bridges/x/link-many";

    fn approval(keys: &Keys, kind: u16, url: &str, request: &str, at: u64) -> Value {
        let tags = [
            Tag::parse(["u", url]).unwrap(),
            Tag::parse(["method", "POST"]).unwrap(),
            Tag::parse(["payload".to_string(), hex::encode(Sha256::digest(request.as_bytes()))]).unwrap(),
        ];
        let event = EventBuilder::new(Kind::Custom(kind), "").tags(tags).custom_created_at(Timestamp::from(at)).finalize(keys).unwrap();
        serde_json::from_str(&event.as_json()).unwrap()
    }

    #[test]
    fn an_approval_binds_the_signer_to_exactly_this_request() {
        let keys = Keys::generate();
        let now = (now_ms() / 1000) as u64;
        let request = r#"{"guildId":"1","consent":true,"pairs":[]}"#;
        let good = approval(&keys, HTTP_AUTH_KIND, URL, request, now);
        assert_eq!(approval_signer(&good, URL, request), Ok(keys.public_key().to_hex()));

        assert!(approval_signer(&good, URL, r#"{"guildId":"2","consent":true,"pairs":[]}"#).is_err(), "other channels");
        assert!(approval_signer(&good, "https://portal.example/api/bridges/y/link-many", request).is_err(), "another draft");
        assert!(approval_signer(&approval(&keys, 1, URL, request, now), URL, request).is_err(), "not NIP-98");
        assert!(approval_signer(&approval(&keys, HTTP_AUTH_KIND, URL, request, now - 600), URL, request).is_err(), "stale");

        let mut forged = good.clone();
        forged["pubkey"] = json!(Keys::generate().public_key().to_hex());
        assert!(approval_signer(&forged, URL, request).is_err(), "someone else's name on it");
    }
}
