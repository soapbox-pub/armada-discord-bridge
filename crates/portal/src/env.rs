//! Portal environment. Discord OAuth vars are optional in dev (dev login).

use anyhow::{Context, anyhow, bail};

use crate::discord_rest::parse_timestamp_ms;

#[derive(Clone, PartialEq, Eq)]
pub struct PortalEnv {
    pub database_url: String,
    pub port: u16,
    /// Interface to bind. Loopback by default: the production deployment sits
    /// behind a TLS proxy on the same host, and binding every interface quietly
    /// published the whole API to the local network in plaintext, around
    /// whatever the proxy enforces. Container deployments, where the boundary is
    /// the container itself, set PORTAL_HOST=0.0.0.0 explicitly.
    pub host: String,
    pub base_url: String,
    pub seal_key_hex: String,
    pub discord_client_id: String,
    pub discord_client_secret: String,
    pub discord_bot_token: String,
    /// Blossom server URL(s) for attachment rehosting, comma-separated in preference order; empty leaves CDN links.
    pub blossom_server: String,
    /// KLIPY API key; resolves Klipy GIF-picker sends to their real GIF. Empty transcodes the mp4 instead.
    pub klipy_api_key: String,
    /// When "1", /api/auth/dev issues a fake session for UI development.
    pub dev_login: bool,
    /// Cosmetic base for minted invite URLs (any deeplink domain parses).
    pub invite_base_url: String,
    /// Default relay set for imported communities; empty falls back to stock.
    pub import_relays: Vec<String>,
    /// Origins allowed to drive the API cross-origin (the Armada client running
    /// the import wizard in-app). Empty = same-origin only, i.e. the portal's own
    /// SPA and nothing else.
    ///
    /// Credentials are NOT sent cross-origin; those callers authenticate with a
    /// bearer token instead of the session cookie, so a permissive entry here
    /// cannot be used to ride a visitor's existing portal session.
    pub allowed_origins: Vec<String>,
    /// Recovery knob for the Discord catch-up (epoch ms; unset in normal
    /// operation). Anchors each channel's replay on the newest message mirrored
    /// BEFORE this moment instead of the newest overall, so one boot can walk a
    /// gap that later traffic has already papered over — a restart on code that
    /// had no catch-up leaves exactly that. Already-mirrored messages are
    /// skipped, so starting early costs reads, not duplicates. Set for one boot,
    /// then remove.
    pub catch_up_since_ms: Option<i64>,
}

impl PortalEnv {
    /// Read the process environment.
    pub fn load() -> anyhow::Result<PortalEnv> {
        PortalEnv::from_env(|name| std::env::var(name).ok())
    }

    /// Build from any variable lookup, so tests need not touch process env.
    pub fn from_env(lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<PortalEnv> {
        let trimmed = |name: &str| lookup(name).map(|v| v.trim().to_owned()).unwrap_or_default();
        let required = |name: &str| {
            let value = trimmed(name);
            if value.is_empty() { Err(anyhow!("Missing required env var {name}")) } else { Ok(value) }
        };
        let list = |name: &str| -> Vec<String> {
            trimmed(name)
                .split(',')
                .map(|s| s.trim().trim_end_matches('/').to_owned())
                .filter(|s| !s.is_empty())
                .collect()
        };

        let seal_key_hex = required("PORTAL_SEAL_KEY")?;
        if seal_key_hex.len() != 64 || !seal_key_hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            bail!("PORTAL_SEAL_KEY must be 64 lowercase hex chars");
        }
        let port = match trimmed("PORTAL_PORT") {
            p if p.is_empty() => 8787,
            p => p.parse::<u16>().with_context(|| format!("PORTAL_PORT is not a port: {p}"))?,
        };
        let base_url = non_empty(trimmed("PORTAL_BASE_URL")).unwrap_or_else(|| format!("http://localhost:{port}"));
        let dev_login = lookup("PORTAL_DEV_LOGIN").as_deref() == Some("1");
        // Refuse to boot rather than serve the backdoor. `/api/auth/dev` hands any
        // unauthenticated caller a session whose fixture guild carries canManage and
        // which is permanently exempt from the fresh-Discord permission re-check —
        // and every dev session shares one owner id, so they own each other's
        // bridges. "Never set in production" was a line in the README with nothing
        // enforcing it, and the compose file passes the variable straight through.
        if dev_login && (lookup("NODE_ENV").as_deref() == Some("production") || base_url.starts_with("https:")) {
            bail!("PORTAL_DEV_LOGIN=1 refused: it grants any anonymous caller a session, and this looks like a production deployment");
        }

        // IMPORT_DEFAULT_RELAYS entries are kept verbatim apart from whitespace;
        // only origins lose trailing slashes (an Origin header never has one).
        let import_relays = trimmed("IMPORT_DEFAULT_RELAYS")
            .split(',')
            .map(|r| r.trim().to_owned())
            .filter(|r| !r.is_empty())
            .collect();

        Ok(PortalEnv {
            database_url: required("DATABASE_URL")?,
            port,
            host: non_empty(trimmed("PORTAL_HOST")).unwrap_or_else(|| "127.0.0.1".into()),
            base_url,
            seal_key_hex,
            discord_client_id: trimmed("DISCORD_CLIENT_ID"),
            discord_client_secret: trimmed("DISCORD_CLIENT_SECRET"),
            discord_bot_token: trimmed("DISCORD_TOKEN"),
            blossom_server: trimmed("BLOSSOM_SERVER"),
            klipy_api_key: trimmed("KLIPY_API_KEY"),
            dev_login,
            invite_base_url: non_empty(trimmed("INVITE_BASE_URL")).unwrap_or_else(|| "https://armada.buzz".into()),
            import_relays,
            allowed_origins: list("PORTAL_ALLOWED_ORIGINS"),
            catch_up_since_ms: parse_catch_up_since(&trimmed("DISCORD_CATCHUP_SINCE"))?,
        })
    }
}

fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

fn parse_catch_up_since(value: &str) -> anyhow::Result<Option<i64>> {
    if value.is_empty() {
        return Ok(None);
    }
    // Refuse rather than ignore: a typo here would silently skip the recovery
    // the operator set it for.
    match parse_timestamp_ms(value) {
        Some(ms) => Ok(Some(ms)),
        None => bail!("DISCORD_CATCHUP_SINCE is not a date: {value}"),
    }
}

/// Written by hand so the secrets never reach a log line: a derived `Debug`
/// would print PORTAL_SEAL_KEY, which unseals every per-bridge secret in the
/// database, the moment anything formatted the env with `{:?}`.
impl std::fmt::Debug for PortalEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted = |s: &str| if s.is_empty() { "" } else { "<redacted>" };
        f.debug_struct("PortalEnv")
            .field("database_url", &redacted(&self.database_url))
            .field("port", &self.port)
            .field("host", &self.host)
            .field("base_url", &self.base_url)
            .field("seal_key_hex", &redacted(&self.seal_key_hex))
            .field("discord_client_id", &self.discord_client_id)
            .field("discord_client_secret", &redacted(&self.discord_client_secret))
            .field("discord_bot_token", &redacted(&self.discord_bot_token))
            .field("blossom_server", &self.blossom_server)
            .field("klipy_api_key", &redacted(&self.klipy_api_key))
            .field("dev_login", &self.dev_login)
            .field("invite_base_url", &self.invite_base_url)
            .field("import_relays", &self.import_relays)
            .field("allowed_origins", &self.allowed_origins)
            .field("catch_up_since_ms", &self.catch_up_since_ms)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const KEY: &str = "abababababababababababababababababababababababababababababababab";

    fn env(pairs: &[(&str, &str)]) -> anyhow::Result<PortalEnv> {
        let mut map: HashMap<String, String> =
            [("PORTAL_SEAL_KEY", KEY), ("DATABASE_URL", "postgres://x")].iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        for (k, v) in pairs {
            map.insert(k.to_string(), v.to_string());
        }
        PortalEnv::from_env(|name| map.get(name).cloned())
    }

    #[test]
    fn applies_defaults() {
        let e = env(&[]).unwrap();
        assert_eq!(e.port, 8787);
        assert_eq!(e.host, "127.0.0.1");
        assert_eq!(e.base_url, "http://localhost:8787");
        assert_eq!(e.invite_base_url, "https://armada.buzz");
        assert_eq!(e.discord_bot_token, "");
        assert_eq!(e.blossom_server, "");
        assert!(!e.dev_login);
        assert!(e.import_relays.is_empty());
        assert!(e.allowed_origins.is_empty());
        assert_eq!(e.catch_up_since_ms, None);
    }

    #[test]
    fn requires_the_seal_key_and_database() {
        assert!(PortalEnv::from_env(|_| None).unwrap_err().to_string().contains("PORTAL_SEAL_KEY"));
        assert!(env(&[("PORTAL_SEAL_KEY", "short")]).unwrap_err().to_string().contains("64 lowercase hex"));
        assert!(env(&[("PORTAL_SEAL_KEY", &"AB".repeat(32))]).is_err());
        assert!(env(&[("DATABASE_URL", "  ")]).unwrap_err().to_string().contains("DATABASE_URL"));
    }

    #[test]
    fn reads_and_trims_values() {
        let e = env(&[
            ("PORTAL_PORT", "9000"),
            ("PORTAL_HOST", " 0.0.0.0 "),
            ("DISCORD_TOKEN", " tok "),
            ("BLOSSOM_SERVER", "https://a.example, https://b.example"),
            ("IMPORT_DEFAULT_RELAYS", " wss://r1.example ,, wss://r2.example/ "),
            ("PORTAL_ALLOWED_ORIGINS", "https://armada.buzz/, ,https://x.example//"),
        ])
        .unwrap();
        assert_eq!(e.port, 9000);
        assert_eq!(e.base_url, "http://localhost:9000");
        assert_eq!(e.host, "0.0.0.0");
        assert_eq!(e.discord_bot_token, "tok");
        assert_eq!(e.blossom_server, "https://a.example, https://b.example");
        assert_eq!(e.import_relays, vec!["wss://r1.example", "wss://r2.example/"]);
        assert_eq!(e.allowed_origins, vec!["https://armada.buzz", "https://x.example"]);
        assert!(env(&[("PORTAL_PORT", "eighty")]).is_err());
    }

    #[test]
    fn refuses_dev_login_in_production() {
        assert!(env(&[("PORTAL_DEV_LOGIN", "1")]).unwrap().dev_login);
        assert!(!env(&[("PORTAL_DEV_LOGIN", "true")]).unwrap().dev_login);
        let prod = env(&[("PORTAL_DEV_LOGIN", "1"), ("NODE_ENV", "production")]).unwrap_err();
        assert!(prod.to_string().contains("PORTAL_DEV_LOGIN=1 refused"));
        assert!(env(&[("PORTAL_DEV_LOGIN", "1"), ("PORTAL_BASE_URL", "https://bridge.example")]).is_err());
        // Production without the backdoor boots fine.
        assert!(env(&[("NODE_ENV", "production"), ("PORTAL_BASE_URL", "https://bridge.example")]).is_ok());
    }

    #[test]
    fn parses_the_catch_up_moment() {
        let at = |v: &str| env(&[("DISCORD_CATCHUP_SINCE", v)]).map(|e| e.catch_up_since_ms);
        assert_eq!(at("2026-09-23").unwrap(), Some(1_790_121_600_000));
        assert_eq!(at("2026-09-23T00:00:00Z").unwrap(), Some(1_790_121_600_000));
        assert_eq!(at("2026-09-23T19:00:00.123+02:00").unwrap(), Some(1_790_182_800_123));
        assert_eq!(at("  ").unwrap(), None);
        assert!(at("yesterday").unwrap_err().to_string().contains("DISCORD_CATCHUP_SINCE"));
        assert!(at("2026-02-30").is_err());
    }
}
