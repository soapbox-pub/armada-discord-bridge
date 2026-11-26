//! Giving every Discord member a Role on Armada, as a verification bot does on
//! Discord itself. A Community that requires approval to post (or opens
//! Channels to a Role) lets bridged members in the way it lets anyone in: a
//! Grant of that Role (CORD-04 §3). A bridge's own npub signs it, so it may
//! only do what readers let any member do; `concord::grant` judges it as they
//! will.
//!
//! Which Role: one set with `/bridge role <name>`, else a Role named "Discord",
//! else one named "Bridged". It is chosen per (community, Discord server), the
//! pairing a puppet's identity belongs to. Only a plain Role (no power over
//! anyone) is ever handed out, so a misconfigured one can't make every
//! Discord member staff.

use async_trait::async_trait;
use concord::control::FoldedControl;
use concord::grant::{GrantBlocked, live_roles, plain_role_named};
use concord::roles::Role;

use crate::types::ChannelLink;

/// Role names taken when none is set, in order.
pub const FALLBACK_NAMES: [&str; 2] = ["Discord", "Bridged"];

/// What a (community, Discord server) pairing chose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoleSetting {
    /// A plain Role named after the bridge ([`FALLBACK_NAMES`]), if there is one.
    Auto,
    Off,
    Role(String),
}

impl RoleSetting {
    /// Stored as NULL (auto), '' (off) or a role id.
    pub fn from_column(v: Option<String>) -> RoleSetting {
        match v {
            None => RoleSetting::Auto,
            Some(s) if s.is_empty() => RoleSetting::Off,
            Some(id) => RoleSetting::Role(id),
        }
    }

    pub fn to_column(&self) -> Option<&str> {
        match self {
            RoleSetting::Auto => None,
            RoleSetting::Off => Some(""),
            RoleSetting::Role(id) => Some(id),
        }
    }
}

/// The Role Discord members are given under `setting`, if any: the one set
/// while it stands, else the first plain Role named after the bridge.
pub fn bridged_role_in(f: &FoldedControl, setting: &RoleSetting) -> Option<Role> {
    match setting {
        RoleSetting::Off => None,
        RoleSetting::Role(id) => live_roles(f).find(|r| r.role_id.eq_ignore_ascii_case(id)).cloned(),
        RoleSetting::Auto => plain_role_named(f, &FALLBACK_NAMES),
    }
}

/// Why no bridge can grant a Role, for an Armada admin. `npub` is the bridge
/// identity in the channel asking.
pub fn explain(blocked: GrantBlocked, npub: &str) -> String {
    match blocked {
        GrantBlocked::NotPlain => "it carries moderation or management permissions, and the bridge only hands out plain Roles".into(),
        GrantBlocked::NoManageRoles => format!("the bridge needs a Role with Manage roles: give one to its npub here, nostr:{npub}"),
        GrantBlocked::NotBeneath => format!("the bridge's own Role (nostr:{npub}) must be ranked above it"),
        GrantBlocked::NoStaffKey => "the bridge doesn't hold this community's staff write key yet; it arrives with the Grant that gave it Manage roles".into(),
        GrantBlocked::OpensPrivate => "it opens a private channel the bridge can't read, so Discord members would be let in with no way to read it".into(),
    }
}

/// Gives a puppet the bridged Role. The portal implements it: the setting is
/// per (community, server), and any of that community's bridge npubs holding
/// Manage roles may sign the Grant.
#[async_trait]
pub trait Admit: Send + Sync {
    /// The Role's name when the puppet holds it now or was just granted it.
    async fn admit(&self, link: &ChannelLink, puppet_pk: &str) -> Option<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use concord::roles::{RoleScope, perm};

    fn folded() -> FoldedControl {
        let mut f = FoldedControl { owner: "aa".repeat(32), ranked: true, ..Default::default() };
        for (id, name, rank, permissions) in [("11", "Bridge", "a", perm::MANAGE_ROLES), ("22", "Bridged", "b", perm::SEND_MESSAGES), ("33", "discord", "c", perm::SEND_MESSAGES)] {
            let mut r = Role::new(&id.repeat(32), name, 1, permissions, RoleScope::Server);
            r.rank = Some(rank.into());
            f.roster.roles.push(r);
        }
        f
    }

    #[test]
    fn the_setting_picks_the_role() {
        let f = folded();
        assert_eq!(bridged_role_in(&f, &RoleSetting::Auto).map(|r| r.name), Some("discord".into()), "Discord before Bridged, case aside");
        assert_eq!(bridged_role_in(&f, &RoleSetting::Off), None);
        assert_eq!(bridged_role_in(&f, &RoleSetting::Role("11".repeat(32))).map(|r| r.name), Some("Bridge".into()));
        assert_eq!(bridged_role_in(&f, &RoleSetting::Role("ff".repeat(32))), None, "a deleted Role gives nothing");
        for s in [RoleSetting::Auto, RoleSetting::Off, RoleSetting::Role("ab".into())] {
            assert_eq!(RoleSetting::from_column(s.to_column().map(str::to_owned)), s);
        }
    }
}
