//! A member (a bridge's bot, say) granting a plain Role, as readers will judge
//! the Grant (CORD-04 §3): Manage Roles through a Role ranked above the Role
//! and above the member, the staff write key to write the Control Plane with,
//! and never a Role that opens a Private Channel the granter can't read. The
//! additive half of Armada's `planMemberRoles`, plus `useStaffKeyWatch`'s
//! taking of the staff key a Grant carries. Changes no fold rule.

use base64::Engine;

use crate::control::{BuildError, FoldedControl, build_grant_edition, grant_citation};
use crate::derive::{control_signer_group_key, conversation_key, edition_binding, grant_locator};
use crate::edition::EditionMeta;
use crate::rekey::decode_control_wrap;
use crate::roles::{BENEATH_EVERY_ROLE, MAX_ROLES_PER_MEMBER, MemberGrant, Role, perm};
use crate::rumor::Rumor;
use crate::{Bytes32, hex32, to_hex};
use nostr::prelude::{Keys, PublicKey};

/// Powers over other members or the Community: a Role holding any is staff's,
/// not the way a member is let in (Armada `isPlainRole`).
pub const MANAGEMENT_BITS: u64 =
    perm::STAFF | perm::KICK | perm::MANAGE_MESSAGES | perm::MUTE_MEMBERS | perm::DEAFEN_MEMBERS | perm::MOVE_MEMBERS | perm::MODERATE_MEMBERS | perm::MANAGE_NICKNAMES;

/// A Role that only lets its holders take part.
pub fn is_plain(role: &Role) -> bool {
    role.permissions & MANAGEMENT_BITS == 0
}

/// The live Roles: on the ranked Roster only those with a rank key stand.
pub fn live_roles(f: &FoldedControl) -> impl Iterator<Item = &Role> {
    f.roster.roles.iter().filter(|r| !f.ranked || r.rank.is_some())
}

/// A live Role by name, case and surrounding space aside.
pub fn role_named(f: &FoldedControl, name: &str) -> Option<Role> {
    live_roles(f).find(|r| r.name.trim().eq_ignore_ascii_case(name.trim())).cloned()
}

/// The first plain live Role carrying one of `names`, in their order.
pub fn plain_role_named(f: &FoldedControl, names: &[&str]) -> Option<Role> {
    names.iter().find_map(|n| live_roles(f).find(|r| r.name.trim().eq_ignore_ascii_case(n.trim()) && is_plain(r))).cloned()
}

/// Whether `actor` could grant `role` to a member holding nothing above it.
pub fn may_grant(f: &FoldedControl, actor: &str, role: &Role) -> bool {
    if actor == f.owner {
        return true;
    }
    if f.banned.contains(actor) {
        return false;
    }
    if f.ranked { f.roster.permissions_above(actor, role.position) & perm::MANAGE_ROLES != 0 } else { f.roster.can_act_on_position(actor, &f.owner, role.position, perm::MANAGE_ROLES) }
}

/// Why a member can't grant a Role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantBlocked {
    /// It carries moderation or management permissions.
    NotPlain,
    NoManageRoles,
    /// The granter's own Role isn't ranked above it.
    NotBeneath,
    /// The epoch is split and the granter doesn't hold the staff write key.
    NoStaffKey,
    /// It opens a Private Channel the granter can't read.
    OpensPrivate,
}

/// Why `actor` can't grant `role`, judged as readers will judge the Grant.
/// `held_private` names the Private Channels whose keys `actor` holds.
pub fn grant_blocked(f: &FoldedControl, actor: &str, role: &Role, staff_key: bool, held_private: &[String]) -> Option<GrantBlocked> {
    if !is_plain(role) {
        return Some(GrantBlocked::NotPlain);
    }
    if !f.roster.is_authorized(actor, &f.owner, perm::MANAGE_ROLES) {
        return Some(GrantBlocked::NoManageRoles);
    }
    if !may_grant(f, actor, role) {
        return Some(GrantBlocked::NotBeneath);
    }
    if !staff_key {
        return Some(GrantBlocked::NoStaffKey);
    }
    if opens_unkeyed(f, role, held_private) {
        return Some(GrantBlocked::OpensPrivate);
    }
    None
}

/// Whether holding `role` lets a member into a Private Channel whose key the
/// granter doesn't hold: Armada refuses such a Grant, since the member would
/// be left at its door (CORD-03 §5).
fn opens_unkeyed(f: &FoldedControl, role: &Role, held_private: &[String]) -> bool {
    // Nobody: a member holding only `role`, so only it can let them in.
    let nobody = "0000000000000000000000000000000000000000000000000000000000000000";
    let mut with = f.roster.clone();
    with.grants.retain(|g| g.member != nobody);
    with.grants.push(MemberGrant { member: nobody.into(), role_ids: vec![role.role_id.clone()], control_wrap: None });
    f.channels.values().filter(|c| c.private && !c.deleted).any(|c| {
        let held = held_private.iter().any(|h| h.eq_ignore_ascii_case(&c.channel_id_hex));
        !held && !f.roster.entitled_to_channel(nobody, &f.owner, &c.channel_id_hex) && with.entitled_to_channel(nobody, &f.owner, &c.channel_id_hex)
    })
}

/// The staff write key `me`'s own Grant carries, as hex: opened under the
/// pairwise key with the Grant's author, and taken only for the current epoch
/// and only if it derives to the Control Plane's write address.
pub fn staff_key_from_grant(f: &FoldedControl, community_id: &Bytes32, me: &Keys, root_epoch: u64, control_pk: &str) -> Option<String> {
    let pk = me.public_key();
    let grant = f.roster.grants.iter().find(|g| g.member == pk.to_hex())?;
    let wrap = grant.control_wrap.as_deref()?;
    let head = f.head_editions.get(&to_hex(&grant_locator(community_id, &pk.to_bytes())))?;
    let granter = PublicKey::from_hex(&head.author).ok()?;
    let conv = conversation_key(me.secret_key(), &granter);
    let plain = base64::engine::general_purpose::STANDARD.decode(crate::nip44::decrypt_str(&conv, wrap).ok()?).ok()?;
    let (epoch, control_root) = decode_control_wrap(&plain)?;
    (epoch == root_epoch && control_signer_group_key(&control_root, community_id, epoch).pk_hex() == control_pk).then(|| to_hex(&control_root))
}

/// Why a Grant to one member wasn't planned.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GrantRefused {
    #[error("the member's Grant isn't fully read")]
    Incomplete,
    #[error("the member holds a Role at or above the granter's")]
    MemberAbove,
    #[error("the member is staff")]
    Staff,
    #[error("the Role isn't beneath the granter's")]
    RoleAbove,
    #[error("the member holds as many Roles as one may")]
    TooMany,
    #[error(transparent)]
    Build(#[from] BuildError),
}

/// The Grant edition adding `role` to what `member` holds, by `actor`: chained
/// on the member's Grant head, citing the actor's own, marked on the ranked
/// Roster. Never makes the member staff, so it carries no `control_wrap`.
pub fn plan_grant(f: &FoldedControl, community_id: &Bytes32, actor: &str, member: &str, role: &Role) -> Result<Rumor, GrantRefused> {
    let member_bytes = hex32(member).ok_or(BuildError::BadId("member"))?;
    let eid = to_hex(&grant_locator(community_id, &member_bytes));
    // Grants are whole: an entity the fold couldn't account for would be
    // overwritten blind.
    if f.incomplete.contains(&eid) {
        return Err(GrantRefused::Incomplete);
    }
    let rank = f.roster.highest_position(member).unwrap_or(BENEATH_EVERY_ROLE);
    let outranks = if f.ranked { f.roster.permissions_above(actor, rank) & perm::MANAGE_ROLES != 0 } else { f.roster.can_act_on_member(actor, &f.owner, member, perm::MANAGE_ROLES) };
    if member == actor || member == f.owner || !(actor == f.owner || outranks) {
        return Err(GrantRefused::MemberAbove);
    }
    if f.roster.is_staff(member, &f.owner) {
        return Err(GrantRefused::Staff);
    }
    if !may_grant(f, actor, role) {
        return Err(GrantRefused::RoleAbove);
    }
    let mut role_ids = f.roster.grants.iter().find(|g| g.member == member).map(|g| g.role_ids.clone()).unwrap_or_default();
    if role_ids.len() >= MAX_ROLES_PER_MEMBER {
        return Err(GrantRefused::TooMany);
    }
    role_ids.push(role.role_id.to_lowercase());

    let head = f.heads.get(&eid).copied();
    let me = hex32(actor).ok_or(BuildError::BadId("actor"))?;
    let authority = (actor != f.owner).then(|| f.heads.get(&to_hex(&grant_locator(community_id, &me))).map(|h| grant_citation(community_id, &me, h.version, h.hash))).flatten();
    let binding = edition_binding(community_id);
    let mut meta = EditionMeta { actor, version: head.map_or(1, |h| h.version + 1), prev: head.as_ref().map(|h| &h.hash), authority: authority.as_ref(), created_at: None, binding: None };
    if f.ranked {
        meta = meta.marked(&binding);
    }
    let grant = MemberGrant { member: member.to_owned(), role_ids, control_wrap: None };
    Ok(build_grant_edition(community_id, &grant, &meta)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::community::Membership;
    use crate::control::{fold_control, seal_edition};
    use crate::derive::everyone_locator;
    use crate::edition::{Edition, build_edition_rumor, parse_edition};
    use crate::kinds::Plane;
    use crate::rekey::seal_control_wrap;
    use crate::roles::RoleScope;
    use crate::roster::{VSK_RANKED_ROLE, everyone_to_json, ranked_role_to_json};
    use crate::stream::open_plane_wrap;

    /// A ranked Community: `@everyone` can't post (approval to post), a Bridge
    /// Role with Manage Roles held by the bot, and a plain Matrix Role under it.
    struct World {
        m: Membership,
        owner: Keys,
        bot: Keys,
        editions: Vec<Edition>,
        bridge: Role,
        matrix: Role,
    }

    impl World {
        fn new(bot_perms: u64) -> World {
            let owner = Keys::generate();
            let m = Membership::mint("t", &owner.public_key().to_hex(), vec![], 0);
            let mut w = World {
                m,
                owner,
                bot: Keys::generate(),
                editions: vec![],
                bridge: ranked("Bridge", "a", bot_perms),
                matrix: ranked("Matrix", "b", perm::SEND_MESSAGES | perm::ADD_REACTIONS),
            };
            let cid = w.m.id();
            let owner_hex = w.owner.public_key().to_hex();
            let binding = edition_binding(&cid);
            let meta = EditionMeta { created_at: Some(1_700_000_000), ..EditionMeta::first(&owner_hex, None) }.marked(&binding);
            let everyone = everyone_to_json(perm::EVERYONE_DEFAULT & !(perm::SEND_MESSAGES | perm::ADD_REACTIONS), Some(&[]));
            w.put(&build_edition_rumor(VSK_RANKED_ROLE, &everyone_locator(&cid), everyone, &meta), &w.owner.clone());
            for role in [w.bridge.clone(), w.matrix.clone()] {
                w.put(&build_edition_rumor(VSK_RANKED_ROLE, &hex32(&role.role_id).unwrap(), ranked_role_to_json(&role).unwrap(), &meta), &w.owner.clone());
            }
            // The owner's Grant of a staff Role carries the staff write key (CORD-04 §3).
            let control_root = hex32(w.m.control_root.as_deref().unwrap()).unwrap();
            let wrap = seal_control_wrap(w.m.root_epoch, &control_root, w.owner.secret_key(), &w.bot.public_key()).unwrap();
            let grant = MemberGrant { member: w.bot.public_key().to_hex(), role_ids: vec![w.bridge.role_id.clone()], control_wrap: Some(wrap) };
            w.put(&build_grant_edition(&cid, &grant, &meta).unwrap(), &w.owner.clone());
            w
        }

        fn put(&mut self, rumor: &Rumor, by: &Keys) {
            let control = self.m.control_write_stream().unwrap();
            let wrap = seal_edition(rumor, &control, by).unwrap();
            self.editions.push(parse_edition(open_plane_wrap(&wrap, &self.m.current_control_stream(), Plane::Control).unwrap()).unwrap());
        }

        fn fold(&self) -> FoldedControl {
            fold_control(&self.editions, &self.m.id(), &self.m.owner, None, None)
        }

        fn bot_hex(&self) -> String {
            self.bot.public_key().to_hex()
        }
    }

    fn ranked(name: &str, rank: &str, permissions: u64) -> Role {
        let mut r = Role::new(&hex::encode(rand::random::<[u8; 32]>()), name, 0, permissions, RoleScope::Server);
        r.rank = Some(rank.into());
        r
    }

    #[test]
    fn the_fold_takes_the_bridges_grant_of_the_matrix_role() {
        let mut w = World::new(perm::MANAGE_ROLES);
        let f = w.fold();
        assert!(f.ranked);
        let role = plain_role_named(&f, &["Matrix", "Bridged"]).expect("a plain Role named Matrix");
        assert_eq!(role.name, "Matrix");
        assert_eq!(grant_blocked(&f, &w.bot_hex(), &role, true, &[]), None);

        let puppet = Keys::generate().public_key().to_hex();
        let rumor = plan_grant(&f, &w.m.id(), &w.bot_hex(), &puppet, &role).unwrap();
        assert!(rumor.tags.iter().any(|t| t[0] == "eb"), "marked on the ranked Roster");
        w.put(&rumor, &w.bot.clone());
        let f = w.fold();
        assert!(f.roster.roles_of(&puppet).any(|r| r.role_id == role.role_id), "readers take the bot's Grant");
        assert_ne!(f.roster.permissions(&puppet) & perm::SEND_MESSAGES, 0, "the Role lets them post");
    }

    #[test]
    fn a_later_grant_keeps_what_the_member_already_holds() {
        let mut w = World::new(perm::MANAGE_ROLES);
        let f = w.fold();
        let puppet = Keys::generate().public_key().to_hex();
        let other = ranked("Verified", "c", perm::SEND_MESSAGES);
        let matrix = f.roster.role(&w.matrix.role_id).cloned().unwrap();
        let rumor = plan_grant(&f, &w.m.id(), &w.bot_hex(), &puppet, &matrix).unwrap();
        w.put(&rumor, &w.bot.clone());
        let owner_hex = w.owner.public_key().to_hex();
        let binding = edition_binding(&w.m.id());
        let meta = EditionMeta { created_at: Some(1_700_000_001), ..EditionMeta::first(&owner_hex, None) }.marked(&binding);
        w.put(&build_edition_rumor(VSK_RANKED_ROLE, &hex32(&other.role_id).unwrap(), ranked_role_to_json(&other).unwrap(), &meta), &w.owner.clone());
        let f = w.fold();
        let other = f.roster.role(&other.role_id).cloned().unwrap();
        let rumor = plan_grant(&f, &w.m.id(), &w.bot_hex(), &puppet, &other).unwrap();
        w.put(&rumor, &w.bot.clone());
        let f = w.fold();
        let held: Vec<&str> = f.roster.roles_of(&puppet).map(|r| r.name.as_str()).collect();
        assert!(held.contains(&"Matrix") && held.contains(&"Verified"), "{held:?}");
    }

    #[test]
    fn without_manage_roles_the_bridge_grants_nothing() {
        let w = World::new(perm::SEND_MESSAGES);
        let f = w.fold();
        let role = plain_role_named(&f, &["Matrix"]).unwrap();
        assert_eq!(grant_blocked(&f, &w.bot_hex(), &role, true, &[]), Some(GrantBlocked::NoManageRoles));
    }

    #[test]
    fn a_role_ranked_above_the_bridges_is_out_of_reach() {
        let w = World::new(perm::MANAGE_ROLES);
        let f = w.fold();
        let above = Role { position: 0, ..w.matrix.clone() };
        assert_eq!(grant_blocked(&f, &w.bot_hex(), &above, true, &[]), Some(GrantBlocked::NotBeneath));
    }

    #[test]
    fn only_plain_roles_are_handed_out() {
        let w = World::new(perm::MANAGE_ROLES | perm::KICK);
        let f = w.fold();
        let moderator = Role { permissions: perm::KICK, ..w.matrix.clone() };
        assert_eq!(grant_blocked(&f, &w.bot_hex(), &moderator, true, &[]), Some(GrantBlocked::NotPlain));
        let mut named = f.clone();
        named.roster.roles.iter_mut().filter(|r| r.name == "Matrix").for_each(|r| r.permissions |= perm::KICK);
        assert_eq!(plain_role_named(&named, &["Matrix"]), None, "a Role named Matrix that isn't plain isn't taken by name");
        assert!(role_named(&named, "matrix ").is_some(), "but can be named outright");
    }

    #[test]
    fn a_grant_to_someone_the_granter_doesnt_outrank_is_refused() {
        let w = World::new(perm::MANAGE_ROLES);
        let f = w.fold();
        let matrix = f.roster.role(&w.matrix.role_id).cloned().unwrap();
        let owner = w.owner.public_key().to_hex();
        assert_eq!(plan_grant(&f, &w.m.id(), &w.bot_hex(), &owner, &matrix), Err(GrantRefused::MemberAbove));
        assert_eq!(plan_grant(&f, &w.m.id(), &w.bot_hex(), &w.bot_hex(), &matrix), Err(GrantRefused::MemberAbove));
    }

    #[test]
    fn the_bridge_takes_the_staff_key_its_grant_carries() {
        let mut w = World::new(perm::MANAGE_ROLES);
        let f = w.fold();
        let root = w.m.control_root.clone().unwrap();
        let control_pk = w.m.control_pk.clone().unwrap();
        assert_eq!(staff_key_from_grant(&f, &w.m.id(), &w.bot, w.m.root_epoch, &control_pk), Some(root));
        assert_eq!(staff_key_from_grant(&f, &w.m.id(), &w.bot, w.m.root_epoch + 1, &control_pk), None, "only for the current epoch");
        let stranger = Keys::generate();
        assert_eq!(staff_key_from_grant(&f, &w.m.id(), &stranger, w.m.root_epoch, &control_pk), None);
        w.m.control_root = None;
        assert!(w.m.control_write_stream().is_none());
    }
}
