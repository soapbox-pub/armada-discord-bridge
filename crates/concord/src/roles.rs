//! Roles and permissions — CORD-04. Read access is key possession; write
//! authority is rank in the owner-rooted Roster. Bit positions are frozen.
//!
//! Two Rosters exist. The legacy one (vsk 1) ranks Roles by integer `position`
//! and holds no channel permissions. Once the owner publishes `@everyone` (vsk
//! 13) the Community is on the ranked Roster for good: Roles are ordered by rank
//! keys (mapped here to dense positions, so every comparison below serves
//! both), `@everyone` lends its bits to every member, and per-Channel
//! overwrites decide what a member may do in each Channel (CORD-04 §8).

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::strict;

pub mod perm {
    pub const MANAGE_ROLES: u64 = 1 << 0;
    pub const MANAGE_CHANNELS: u64 = 1 << 1;
    pub const MANAGE_METADATA: u64 = 1 << 2;
    pub const KICK: u64 = 1 << 3;
    pub const BAN: u64 = 1 << 4;
    pub const MANAGE_MESSAGES: u64 = 1 << 5;
    pub const CREATE_INVITE: u64 = 1 << 6;
    // 1<<7 retired (was MANAGE_INVITES).
    pub const VIEW_AUDIT_LOG: u64 = 1 << 8;
    pub const MENTION_EVERYONE: u64 = 1 << 9;
    // Reserved: MANAGE_EMOJI = 1<<10, MANAGE_EVENTS = 1<<12.
    pub const PIN_MESSAGES: u64 = 1 << 11;
    // Channel permissions (CORD-04 §3, §8): what a member may do IN a Channel.
    pub const VIEW_CHANNEL: u64 = 1 << 13;
    pub const SEND_MESSAGES: u64 = 1 << 14;
    pub const SEND_IN_THREADS: u64 = 1 << 15;
    pub const ATTACH_FILES: u64 = 1 << 16;
    pub const ADD_REACTIONS: u64 = 1 << 17;
    pub const READ_MESSAGE_HISTORY: u64 = 1 << 18;
    pub const CONNECT: u64 = 1 << 19;
    pub const SPEAK: u64 = 1 << 20;
    pub const VIDEO: u64 = 1 << 21;
    pub const PRIORITY_SPEAKER: u64 = 1 << 22;
    pub const MUTE_MEMBERS: u64 = 1 << 23;
    pub const DEAFEN_MEMBERS: u64 = 1 << 24;
    pub const MOVE_MEMBERS: u64 = 1 << 25;
    pub const MODERATE_MEMBERS: u64 = 1 << 26;
    // Reserved: BYPASS_SLOWMODE = 1<<27, CREATE_PRIVATE_THREADS = 1<<30, MANAGE_THREADS = 1<<31.
    pub const MANAGE_NICKNAMES: u64 = 1 << 28;
    pub const CHANGE_NICKNAME: u64 = 1 << 29;

    /// Bits whose actions are Control editions; holders are staff (CORD-04 §3).
    pub const STAFF: u64 = MANAGE_ROLES | MANAGE_CHANNELS | MANAGE_METADATA | BAN | CREATE_INVITE | PIN_MESSAGES;

    /// Every management bit a stock Admin holds. There is no all-powerful bit,
    /// so an Admin does not inherit a permission added later.
    pub const ADMIN_ALL: u64 =
        MANAGE_ROLES | MANAGE_CHANNELS | MANAGE_METADATA | KICK | BAN | MANAGE_MESSAGES | CREATE_INVITE | VIEW_AUDIT_LOG | MENTION_EVERYONE | PIN_MESSAGES;

    /// The bits an overwrite may touch (CORD-04 §8): MANAGE_MESSAGES and bits 13
    /// to 26. Everything else, staff bits above all, means the same in every
    /// Channel, so the staff set is the same with or without overwrites.
    pub const OVERWRITABLE: u64 = MANAGE_MESSAGES
        | VIEW_CHANNEL
        | SEND_MESSAGES
        | SEND_IN_THREADS
        | ATTACH_FILES
        | ADD_REACTIONS
        | READ_MESSAGE_HISTORY
        | CONNECT
        | SPEAK
        | VIDEO
        | PRIORITY_SPEAKER
        | MUTE_MEMBERS
        | DEAFEN_MEMBERS
        | MOVE_MEMBERS
        | MODERATE_MEMBERS;

    /// What the switching `@everyone` holds (CORD-04 §3), as Armada writes it:
    /// the chat and voice basics, and the member's own Nickname.
    pub const EVERYONE_DEFAULT: u64 =
        VIEW_CHANNEL | SEND_MESSAGES | SEND_IN_THREADS | ATTACH_FILES | ADD_REACTIONS | READ_MESSAGE_HISTORY | CONNECT | SPEAK | VIDEO | CHANGE_NICKNAME;
}

pub const NAME_MAX_BYTES: usize = 64;
pub const MAX_ROLES_PER_MEMBER: usize = 64;
pub const MAX_ROLES_PER_COMMUNITY: usize = 100;
/// Beneath every Role: `@everyone`'s place, and a roleless member's.
pub const BENEATH_EVERY_ROLE: u32 = u32::MAX;
/// Sanity bound on a carried `control_wrap` (a NIP-44 wrap of 40 bytes is ~130 chars).
const MAX_CONTROL_WRAP_CHARS: usize = 1024;

/// Cut a name past 64 bytes to the last whole character within it (CORD-03 §2, CORD-04 §2).
pub fn cut_name(name: &str) -> String {
    if name.len() <= NAME_MAX_BYTES {
        return name.to_owned();
    }
    let mut end = NAME_MAX_BYTES;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].to_owned()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoleScope {
    Server,
    Channel(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Role {
    pub role_id: String,
    pub name: String,
    /// Lower is higher authority. Position 0 is the owner's alone, never a Role.
    /// On the ranked Roster it is the dense rank of `rank` among the keys in
    /// play, assigned at fold time.
    pub position: u32,
    /// The vsk-13 rank key (CORD-04 §3); `None` on a legacy Role.
    pub rank: Option<String>,
    pub permissions: u64,
    /// Legacy only: a Role scoped to one Channel. Ranked Roles are server-wide.
    pub scope: RoleScope,
    pub color: u32,
    /// Hoisted into its own member-list section.
    pub display: bool,
    /// Any member may @mention it (CORD-03 §3, vsk 13).
    pub mentionable: bool,
    /// Unknown fields, round-tripped by an editor (vsk 13).
    pub extra: Map<String, Value>,
}

/// The legacy (vsk 1) wire form, field order matching Armada's `roleToJSON`.
#[derive(serde::Serialize)]
struct RoleWire<'a> {
    role_id: &'a str,
    name: &'a str,
    position: u32,
    permissions: String,
    scope: ScopeWire<'a>,
    color: u32,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    display: bool,
}

#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum ScopeWire<'a> {
    Server,
    Channel { channel_id: &'a str },
}

#[derive(serde::Serialize)]
struct GrantWire<'a> {
    member: &'a str,
    role_ids: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    control_wrap: Option<&'a str>,
}

/// A stock server-scope Admin: every management bit, at position 1.
pub fn admin_role(role_id: &str) -> Role {
    Role::new(role_id, "Admin", 1, perm::ADMIN_ALL, RoleScope::Server)
}

impl Role {
    /// A plain Role: uncoloured, unhoisted, no rank key (a legacy Role until one is set).
    pub fn new(role_id: &str, name: &str, position: u32, permissions: u64, scope: RoleScope) -> Role {
        Role {
            role_id: role_id.to_owned(),
            name: name.to_owned(),
            position,
            rank: None,
            permissions,
            scope,
            color: 0,
            display: false,
            mentionable: false,
            extra: Map::new(),
        }
    }

    /// The legacy (vsk 1) content. `permissions` is always a decimal string.
    pub fn to_json(&self) -> String {
        let scope = match &self.scope {
            RoleScope::Server => ScopeWire::Server,
            RoleScope::Channel(id) => ScopeWire::Channel { channel_id: id },
        };
        let wire = RoleWire {
            role_id: &self.role_id,
            name: &self.name,
            position: self.position,
            permissions: self.permissions.to_string(),
            scope,
            color: self.color,
            display: self.display,
        };
        serde_json::to_string(&wire).expect("roles always serialize")
    }

    /// A legacy vsk-1 Role, read as serde reads Vector's `RoleContent`: `name`,
    /// `position`, `permissions` and `scope` required, a name past 64 bytes cut.
    pub fn from_json(json: &str) -> Option<Role> {
        let w = strict::parse_object(json)?;
        let role_id = w.get("role_id")?.as_str().filter(|s| crate::is_hex64(s))?.to_lowercase();
        let name = w.get("name")?.as_str()?;
        let permissions = strict::permission_bits(w.get("permissions")?)?;
        // Position 0 is the owner's alone (CORD-04 §3).
        let position = strict::uint(w.get("position")?, u32::MAX as u64).filter(|p| *p >= 1)? as u32;
        let color = match w.get("color") {
            None => 0,
            Some(c) => strict::uint(c, u32::MAX as u64)? as u32,
        };
        let sc = w.get("scope")?.as_object()?;
        let scope = match sc.get("kind").and_then(Value::as_str) {
            Some("server") => RoleScope::Server,
            Some("channel") => RoleScope::Channel(sc.get("channel_id")?.as_str()?.to_owned()),
            _ => return None,
        };
        Some(Role {
            role_id,
            name: cut_name(name),
            position,
            rank: None,
            permissions,
            scope,
            color,
            display: w.get("display") == Some(&Value::Bool(true)),
            mentionable: false,
            extra: Map::new(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberGrant {
    pub member: String,
    pub role_ids: Vec<String>,
    /// The staff write key riding a staff-making Grant (CORD-04 §3), base64.
    pub control_wrap: Option<String>,
}

impl MemberGrant {
    pub fn to_json(&self) -> String {
        let wire = GrantWire { member: &self.member, role_ids: &self.role_ids, control_wrap: self.control_wrap.as_deref() };
        serde_json::to_string(&wire).expect("grants always serialize")
    }

    /// A Grant, read as Vector's `GrantRead`: `member` required, `role_ids`
    /// absent or an array of strings, `control_wrap` absent, null or a string,
    /// no field repeated. A wrap out of bounds is dropped, never carried.
    pub fn from_json(json: &str) -> Option<MemberGrant> {
        let w = strict::parse_object(json)?;
        let member = w.get("member")?.as_str().filter(|s| crate::is_hex64(s))?.to_lowercase();
        let role_ids = match w.get("role_ids") {
            None => Vec::new(),
            Some(Value::Array(a)) => {
                let ids: Option<Vec<String>> = a.iter().map(|r| r.as_str().map(str::to_owned)).collect();
                let mut ids = ids?;
                ids.truncate(MAX_ROLES_PER_MEMBER);
                ids
            }
            Some(_) => return None,
        };
        let control_wrap = match w.get("control_wrap") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()).filter(|s| !s.is_empty() && s.len() <= MAX_CONTROL_WRAP_CHARS),
            Some(_) => return None,
        };
        Some(MemberGrant { member, role_ids, control_wrap })
    }
}

/// Who an overwrite applies to (CORD-04 §8). Ids are lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum OverwriteTarget {
    Everyone,
    Role(String),
    Member(String),
}

/// One overwrite in one Channel or Category, bits masked to [`perm::OVERWRITABLE`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Overwrite {
    /// The Channel or Category id, lowercase hex.
    pub scope: String,
    pub target: OverwriteTarget,
    pub allow: u64,
    pub deny: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Roster {
    pub roles: Vec<Role>,
    pub grants: Vec<MemberGrant>,
    /// What every member holds before any Role; `Some` once the Community is on
    /// the ranked Roster (CORD-04 §2).
    pub everyone: Option<u64>,
    /// Channel and Category overwrites (CORD-04 §8), ranked Roster only.
    pub overwrites: Vec<Overwrite>,
    /// Channel id → the Category whose overwrites it takes.
    pub syncs: HashMap<String, String>,
    /// The Channels that stood before the switch: the only ones an unmarked
    /// Channel edition still describes (CORD-04 §2).
    pub legacy_channels: Option<Vec<String>>,
    /// Private Channel → its sealed `creator` (CORD-03 §2), for key holders.
    pub creators: HashMap<String, String>,
}

impl Roster {
    /// Whether this is the ranked (vsk-13) Roster: `@everyone` stands.
    pub fn is_ranked(&self) -> bool {
        self.everyone.is_some()
    }

    pub fn role(&self, role_id: &str) -> Option<&Role> {
        self.roles.iter().find(|r| r.role_id == role_id)
    }

    pub fn roles_of<'a>(&'a self, member: &'a str) -> impl Iterator<Item = &'a Role> + 'a {
        self.grants.iter().filter(move |g| g.member == member).flat_map(move |g| g.role_ids.iter().filter_map(move |id| self.role(id)))
    }

    /// `@everyone`'s bits and every granted Role's (CORD-04 §3).
    pub fn permissions(&self, member: &str) -> u64 {
        self.roles_of(member).fold(self.everyone.unwrap_or(0), |acc, r| acc | r.permissions)
    }

    /// The bits a member holds through Roles positioned strictly above `bound`:
    /// the only standing an action on something at `bound` may draw on
    /// (downward support, CORD-04 §3). `@everyone` lends nothing.
    pub fn permissions_above(&self, member: &str, bound: u32) -> u64 {
        self.roles_of(member).filter(|r| r.position < bound).fold(0, |acc, r| acc | r.permissions)
    }

    pub fn has(&self, member: &str, bits: u64) -> bool {
        self.permissions(member) & bits == bits
    }

    /// The member's rank: the lowest position among their Roles.
    pub fn highest_position(&self, member: &str) -> Option<u32> {
        self.roles_of(member).map(|r| r.position).min()
    }

    pub fn is_staff(&self, member: &str, owner: &str) -> bool {
        member == owner || self.permissions(member) & perm::STAFF != 0
    }

    /// Owner is supreme; otherwise the actor must hold `bits`.
    pub fn is_authorized(&self, actor: &str, owner: &str, bits: u64) -> bool {
        actor == owner || self.has(actor, bits)
    }

    /// Does the actor strictly outrank `target_position`?
    pub fn outranks(&self, actor: &str, owner: &str, target_position: u32) -> bool {
        actor == owner || self.highest_position(actor).is_some_and(|p| p < target_position)
    }

    pub fn outranks_member(&self, actor: &str, owner: &str, member: &str) -> bool {
        if actor == owner {
            return true;
        }
        if member == owner {
            return false;
        }
        let target = self.highest_position(member).unwrap_or(BENEATH_EVERY_ROLE);
        self.outranks(actor, owner, target)
    }

    pub fn can_act_on_position(&self, actor: &str, owner: &str, position: u32, bits: u64) -> bool {
        actor == owner || (self.has(actor, bits) && self.outranks(actor, owner, position))
    }

    /// The actor holds the bit AND strictly outranks the target; the owner is never a target.
    pub fn can_act_on_member(&self, actor: &str, owner: &str, target: &str, bits: u64) -> bool {
        if target == owner {
            return false;
        }
        let position = self.highest_position(target).unwrap_or(BENEATH_EVERY_ROLE);
        self.can_act_on_position(actor, owner, position, bits)
    }

    /// A member's permissions in one Channel (CORD-04 §8), resolved Discord's
    /// way: server bits, the `@everyone` overwrite, a Private Channel closed to
    /// `@everyone`, the Roles' denies then allows, the sealed creator let in,
    /// the member's own overwrite last, and nothing at all without
    /// VIEW_CHANNEL. The owner holds everything. On the legacy Roster there are
    /// no overwrites, so this is the server bits — except that a legacy Private
    /// Channel's access is key possession, which the caller decides.
    pub fn channel_permissions(&self, owner: &str, member: &str, channel_id_hex: &str, is_private: bool) -> u64 {
        if member == owner {
            return u64::MAX;
        }
        if !self.is_ranked() {
            return self.permissions(member);
        }
        let held: Vec<&Role> = self.roles_of(member).collect();
        let mut p = held.iter().fold(self.everyone.unwrap_or(0), |acc, r| acc | r.permissions);
        let channel = channel_id_hex.to_lowercase();
        let created = p & perm::MANAGE_CHANNELS != 0 && self.creators.get(&channel).is_some_and(|c| c == member);
        let scope = self.syncs.get(&channel).cloned().unwrap_or(channel);
        let here: Vec<&Overwrite> = self.overwrites.iter().filter(|o| o.scope == scope).collect();
        if let Some(e) = here.iter().find(|o| o.target == OverwriteTarget::Everyone) {
            p = (p & !e.deny) | e.allow;
        }
        if is_private {
            p &= !perm::VIEW_CHANNEL;
        }
        let (mut deny, mut allow) = (0u64, 0u64);
        for o in &here {
            if let OverwriteTarget::Role(id) = &o.target
                && held.iter().any(|r| &r.role_id == id) {
                    deny |= o.deny;
                    allow |= o.allow;
                }
        }
        p = (p & !deny) | allow;
        if created {
            p |= perm::VIEW_CHANNEL;
        }
        if let Some(mine) = here.iter().find(|o| matches!(&o.target, OverwriteTarget::Member(id) if id == member)) {
            p = (p & !mine.deny) | mine.allow;
        }
        if p & perm::VIEW_CHANNEL == 0 { 0 } else { p }
    }

    /// Whether `@everyone`, resolved up to the View Channel step, may post in a
    /// Channel: one where it can't is restricted (CORD-03 §1). A legacy Roster
    /// restricts nothing.
    pub fn everyone_sends(&self, channel_id_hex: &str) -> bool {
        let Some(everyone) = self.everyone else { return true };
        let channel = channel_id_hex.to_lowercase();
        let scope = self.syncs.get(&channel).cloned().unwrap_or(channel);
        let row = self.overwrites.iter().find(|o| o.scope == scope && o.target == OverwriteTarget::Everyone);
        let p = row.map_or(everyone, |o| (everyone & !o.deny) | o.allow);
        p & perm::SEND_MESSAGES != 0
    }

    /// Whether a member is entitled to a legacy private Channel's key: the owner
    /// always, otherwise via a Role scoped to that Channel. On the ranked Roster
    /// entitlement is VIEW_CHANNEL through [`Roster::channel_permissions`].
    pub fn entitled_to_channel(&self, member: &str, owner: &str, channel_id_hex: &str) -> bool {
        if self.is_ranked() {
            return self.channel_permissions(owner, member, channel_id_hex, true) & perm::VIEW_CHANNEL != 0;
        }
        member == owner
            || self.roles_of(member).any(|r| matches!(&r.scope, RoleScope::Channel(id) if id.eq_ignore_ascii_case(channel_id_hex)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "00000000000000000000000000000000000000000000000000000000000000aa";
    const ALICE: &str = "00000000000000000000000000000000000000000000000000000000000000a1";
    const CHAN: &str = "00000000000000000000000000000000000000000000000000000000000000c1";
    const CAT: &str = "00000000000000000000000000000000000000000000000000000000000000ca";
    const MOD: &str = "00000000000000000000000000000000000000000000000000000000000000d1";

    fn ranked() -> Roster {
        let mut m = admin_role(MOD);
        m.permissions = perm::MANAGE_MESSAGES;
        Roster {
            roles: vec![m],
            grants: vec![MemberGrant { member: ALICE.into(), role_ids: vec![MOD.into()], control_wrap: None }],
            everyone: Some(perm::EVERYONE_DEFAULT),
            ..Default::default()
        }
    }

    #[test]
    fn everyone_lends_its_bits() {
        let r = ranked();
        assert!(r.has("ff".repeat(32).as_str(), perm::SEND_MESSAGES));
        assert!(r.everyone_sends(CHAN));
    }

    #[test]
    fn an_everyone_deny_restricts_and_a_role_allow_reopens() {
        let mut r = ranked();
        r.overwrites.push(Overwrite { scope: CHAN.into(), target: OverwriteTarget::Everyone, allow: 0, deny: perm::SEND_MESSAGES });
        assert!(!r.everyone_sends(CHAN));
        let nobody = "ee".repeat(32);
        assert_eq!(r.channel_permissions(OWNER, &nobody, CHAN, false) & perm::SEND_MESSAGES, 0);
        r.overwrites.push(Overwrite { scope: CHAN.into(), target: OverwriteTarget::Role(MOD.into()), allow: perm::SEND_MESSAGES, deny: 0 });
        assert_ne!(r.channel_permissions(OWNER, ALICE, CHAN, false) & perm::SEND_MESSAGES, 0);
    }

    #[test]
    fn a_private_channel_needs_an_allow_and_a_synced_one_reads_its_category() {
        let mut r = ranked();
        assert_eq!(r.channel_permissions(OWNER, ALICE, CHAN, true), 0);
        r.syncs.insert(CHAN.into(), CAT.into());
        r.overwrites.push(Overwrite { scope: CAT.into(), target: OverwriteTarget::Member(ALICE.into()), allow: perm::VIEW_CHANNEL, deny: 0 });
        assert_ne!(r.channel_permissions(OWNER, ALICE, CHAN, true) & perm::VIEW_CHANNEL, 0);
        assert_eq!(r.channel_permissions(OWNER, OWNER, CHAN, true), u64::MAX);
    }

    #[test]
    fn legacy_role_reading_is_strict() {
        let ok = r#"{"role_id":"00000000000000000000000000000000000000000000000000000000000000d1","name":"Mods","position":2,"permissions":"32","scope":{"kind":"server"},"color":0}"#;
        assert!(Role::from_json(ok).is_some());
        assert!(Role::from_json(&ok.replace(r#","scope":{"kind":"server"}"#, "")).is_none(), "scope is required");
        assert!(Role::from_json(&ok.replace(r#""position":2"#, r#""position":2.0"#)).is_none(), "an integer literal");
        assert!(Role::from_json(&ok.replace(r#""name":"Mods","#, r#""name":"Mods","name":"Admins","#)).is_none(), "a repeated key");
    }
}
