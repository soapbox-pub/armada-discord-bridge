//! The process-wide rustls crypto provider.
//!
//! Two backends are compiled in — reqwest brings aws-lc-rs, relay-pool brings
//! ring — and with both present rustls refuses to guess a default. Anything
//! that builds a TLS config without naming a provider (twilight's gateway
//! does) then panics on first connect. That panic shipped once: the portal
//! came up, bound its port, and started no bridges (2026-10-15). Every binary
//! calls [`install`] before doing anything else.

/// Install aws-lc-rs, reqwest's choice, as the default. Idempotent.
pub fn install() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_config_can_be_built_without_naming_a_provider() {
        super::install();
        // Exactly what panicked in production when no default was installed.
        let _ = rustls::ClientConfig::builder();
    }
}
