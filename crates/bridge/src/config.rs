//! Bridge configuration, read once from the environment at startup.
//!
//! Secrets policy: the puppet master secret and primary nsec are scoped per
//! bridge. In the single-tenant deployment they arrive via env; the
//! multi-tenant portal stores them sealed in Postgres and injects them per
//! worker.

use std::fmt;

use anyhow::{Result, anyhow, bail};

#[derive(Clone)]
pub struct BridgeConfig {
    /// Postgres connection string.
    pub database_url: String,
    /// Discord bot token (empty allowed until the Discord adapter lands).
    pub discord_token: String,
    /// 32-byte hex master secret; every Discord user's puppet keypair derives
    /// from it (HKDF). Rotating it rotates every puppet npub.
    pub master_secret_hex: String,
    /// The bridge's own member identity (hex or nsec), the invited npub.
    pub primary_secret_key: String,
    /// Log verbosity: debug | info | warn | error.
    pub log_level: String,
    /// Bridge message edits (kind 3302; payload not frozen in the CORDs).
    pub bridge_edits: bool,
    /// Blossom server URL(s) for attachment rehosting, comma-separated in preference order; empty leaves CDN links.
    pub blossom_server: String,
    /// KLIPY API key; resolves Klipy GIF-picker sends to their real GIF. Empty transcodes the mp4 instead.
    pub klipy_api_key: String,
}

impl BridgeConfig {
    /// Read the config through `lookup` (an env var getter), so tests need not
    /// touch the process environment.
    pub fn from_env(lookup: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let optional = |name: &str| lookup(name).map(|v| v.trim().to_owned()).unwrap_or_default();
        let required = |name: &str| {
            Some(optional(name)).filter(|v| !v.is_empty()).ok_or_else(|| anyhow!("Missing required env var {name}"))
        };
        let master_secret_hex = required("BRIDGE_MASTER_SECRET")?;
        if master_secret_hex.len() != 64 || !master_secret_hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            bail!("BRIDGE_MASTER_SECRET must be 64 lowercase hex chars (32 bytes)");
        }
        let log_level = optional("LOG_LEVEL");
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            discord_token: optional("DISCORD_TOKEN"),
            master_secret_hex,
            primary_secret_key: required("BRIDGE_PRIMARY_KEY")?,
            log_level: if log_level.is_empty() { "info".to_owned() } else { log_level },
            bridge_edits: lookup("BRIDGE_EDITS").as_deref() == Some("1"),
            blossom_server: optional("BLOSSOM_SERVER"),
            klipy_api_key: optional("KLIPY_API_KEY"),
        })
    }

    /// [`Self::from_env`] over the process environment.
    pub fn from_process_env() -> Result<Self> {
        Self::from_env(|name| std::env::var(name).ok())
    }
}

/// Redacts every secret, so a config in a log line or panic leaks nothing.
impl fmt::Debug for BridgeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BridgeConfig")
            .field("database_url", &"<redacted>")
            .field("discord_token", &"<redacted>")
            .field("master_secret_hex", &"<redacted>")
            .field("primary_secret_key", &"<redacted>")
            .field("log_level", &self.log_level)
            .field("bridge_edits", &self.bridge_edits)
            .field("blossom_server", &self.blossom_server)
            .field("klipy_api_key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn valid() -> HashMap<&'static str, String> {
        HashMap::from([
            ("DATABASE_URL", "postgres://localhost/bridge".to_owned()),
            ("BRIDGE_MASTER_SECRET", "ab".repeat(32)),
            ("BRIDGE_PRIMARY_KEY", "cd".repeat(32)),
        ])
    }

    fn load(env: &HashMap<&'static str, String>) -> Result<BridgeConfig> {
        BridgeConfig::from_env(|name| env.get(name).cloned())
    }

    #[test]
    fn loads_a_valid_config_with_defaults() {
        let config = load(&valid()).unwrap();
        assert_eq!(config.database_url, "postgres://localhost/bridge");
        assert_eq!(config.discord_token, "");
        assert_eq!(config.log_level, "info");
        assert!(!config.bridge_edits);
    }

    #[test]
    fn rejects_a_malformed_master_secret() {
        let mut env = valid();
        env.insert("BRIDGE_MASTER_SECRET", "not-hex".into());
        assert!(load(&env).unwrap_err().to_string().contains("BRIDGE_MASTER_SECRET"));
        env.insert("BRIDGE_MASTER_SECRET", "AB".repeat(32));
        assert!(load(&env).is_err());
    }

    #[test]
    fn rejects_missing_required_vars() {
        let mut env = valid();
        env.remove("DATABASE_URL");
        assert!(load(&env).unwrap_err().to_string().contains("DATABASE_URL"));
        env = valid();
        env.insert("BRIDGE_PRIMARY_KEY", "   ".into());
        assert!(load(&env).unwrap_err().to_string().contains("BRIDGE_PRIMARY_KEY"));
    }

    #[test]
    fn debug_redacts_secrets() {
        let shown = format!("{:?}", load(&valid()).unwrap());
        assert!(!shown.contains(&"ab".repeat(32)) && !shown.contains(&"cd".repeat(32)), "{shown}");
    }
}
