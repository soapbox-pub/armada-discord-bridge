//! Host vetting for relay URLs the portal is asked to connect to.
//!
//! Relay lists reach the server from two untrusted places: the list a user
//! types into the import wizard, and the `bootstrapRelays` embedded in a pasted
//! invite link (plus `community.relays` on the event that link resolves to — a
//! second hop the pasting user still indirectly controls). All three end up in
//! a relay pool, which opens a WebSocket: an HTTP GET to a host, port and path
//! of the submitter's choosing. `ws://127.0.0.1:6379/` was accepted.
//!
//! The scheme check that existed (`/^wss?:\/\//`) is not a host check. This is
//! the host check, sharing [`host_is_public`] with the bridge's fetch guard so
//! the two cannot drift on what counts as private.
//!
//! `ws://` to a PUBLIC host is still allowed. Concord payloads are NIP-44
//! sealed, so a plaintext relay hop leaks metadata rather than content, and
//! refusing it outright would be a behaviour change rather than a fix.

use anyhow::bail;
use bridge::net::host_is_public;
use url::Url;

async fn relay_is_safe(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw) else { return false };
    if !matches!(url.scheme(), "ws" | "wss") {
        return false;
    }
    match url.host_str() {
        Some(host) => host_is_public(host).await,
        None => false,
    }
}

/// Vet a user-submitted relay list, rejecting the whole request on the first
/// bad entry. Used where the list is typed by the caller and a silent drop
/// would leave them wondering why their relay never appeared.
pub async fn assert_public_relays(relays: &[String]) -> anyhow::Result<()> {
    for relay in relays {
        if !relay_is_safe(relay).await {
            bail!("not a usable relay URL: {relay}");
        }
    }
    Ok(())
}

/// Keep only the relays we are willing to dial, for lists that arrive inside an
/// invite bundle rather than from a form. Filtering beats failing here: one bad
/// entry in a community's published relay list should not take a working bridge
/// offline. Returns `fallback` when nothing survives, so the caller always has
/// somewhere to connect.
pub async fn filter_public_relays(relays: &[String], fallback: &[String]) -> Vec<String> {
    let mut safe = Vec::new();
    for relay in relays {
        if relay_is_safe(relay).await {
            safe.push(relay.clone());
        } else {
            tracing::warn!("portal: refusing to dial non-public relay {relay}");
        }
    }
    if safe.is_empty() { fallback.to_vec() } else { safe }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn refuses_private_hosts_and_foreign_schemes() {
        // The reported shape: a WebSocket "relay" that is really the local Redis.
        assert!(assert_public_relays(&list(&["ws://127.0.0.1:6379/"])).await.is_err());
        assert!(assert_public_relays(&list(&["ws://[::1]:8080/"])).await.is_err());
        assert!(assert_public_relays(&list(&["http://1.1.1.1/"])).await.is_err());
        assert!(assert_public_relays(&list(&["not a url"])).await.is_err());
        // One bad entry fails the whole list.
        let err = assert_public_relays(&list(&["wss://1.1.1.1/", "wss://10.0.0.1/"])).await.unwrap_err();
        assert!(err.to_string().contains("wss://10.0.0.1/"));
        // Public hosts pass, plaintext ws:// included.
        assert!(assert_public_relays(&list(&["wss://1.1.1.1/", "ws://8.8.8.8/"])).await.is_ok());
    }

    #[tokio::test]
    async fn filters_rather_than_fails_and_falls_back_when_nothing_survives() {
        let fallback = list(&["wss://9.9.9.9/"]);
        assert_eq!(
            filter_public_relays(&list(&["ws://127.0.0.1:6379/", "wss://1.1.1.1/"]), &fallback).await,
            list(&["wss://1.1.1.1/"]),
        );
        assert_eq!(
            filter_public_relays(&list(&["ws://127.0.0.1:6379/", "http://1.1.1.1/"]), &fallback).await,
            fallback,
        );
        assert_eq!(filter_public_relays(&[], &fallback).await, fallback);
    }
}
