//! Byte-compatibility with Armada: every expectation here was produced by
//! Armada's own TypeScript (`tools/vectors/gen.ts`).

use std::collections::HashSet;

use concord::community::{Membership, RekeyOutcome};
use concord::control::fold_control;
use concord::derive::*;
use concord::edition::{edition_hash, parse_edition};
use concord::invite::{decode_fragment, encode_fragment, parse_bundle_event, parse_invite_link, stock_relays};
use concord::kinds::Plane;
use concord::nostr::prelude::{Event, Keys, SecretKey};
use concord::rekey::{group_rotations, parse_rekey};
use concord::stream::{StreamKey, check_channel_binding, open_plane_wrap, open_wrap};
use concord::{hex32, to_hex};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/armada.json")).unwrap()
}

fn h(v: &Value) -> [u8; 32] {
    hex32(v.as_str().unwrap()).unwrap()
}

fn event(v: &Value) -> Event {
    Event::from_json(v.to_string()).unwrap()
}

fn keys(v: &Value) -> Keys {
    Keys::new(SecretKey::from_hex(v.as_str().unwrap()).unwrap())
}

#[test]
fn derivations_match() {
    let v = vectors();
    let k = &v["keys"];
    let d = &v["derive"];
    let (root, cid, chan) = (h(&k["community_root"]), h(&k["community_id"]), h(&k["channel_id"]));
    assert_eq!(to_hex(&community_id_of(&h(&k["owner"]), &h(&k["owner_salt"]))), k["community_id"].as_str().unwrap());

    let check = |g: GroupKey, want: &Value| {
        assert_eq!(g.pk_hex(), want["pk"].as_str().unwrap());
        assert_eq!(to_hex(&g.keys.secret_key().to_secret_bytes()), want["sk"].as_str().unwrap());
        assert_eq!(to_hex(&g.conv_key), want["conv_key"].as_str().unwrap());
    };
    check(channel_group_key(&root, &chan, 0), &d["channel_public_e0"]);
    check(channel_group_key(&h(&k["private_channel_key"]), &chan, 3), &d["channel_private_e3"]);
    check(control_group_key(&root, &cid, 0), &d["control_e0"]);
    check(control_signer_group_key(&h(&k["control_root"]), &cid, 0), &d["control_signer_e0"]);
    check(guestbook_group_key(&root, &cid, 2), &d["guestbook_e2"]);
    check(dissolved_group_key(&cid), &d["dissolved"]);
    check(channel_rekey_group_key(&root, &chan, 4), &d["channel_rekey_e4"]);
    check(base_rekey_group_key(&root, &cid, 1), &d["base_rekey_e1"]);

    let s = |v: &Value| v.as_str().unwrap().to_owned();
    assert_eq!(to_hex(&grant_locator(&cid, &h(&k["alice"]))), s(&d["grant_locator_alice"]));
    assert_eq!(to_hex(&pins_locator(&cid, &chan)), s(&d["pins_locator"]));
    assert_eq!(to_hex(&banlist_locator(&cid)), s(&d["banlist_locator"]));
    assert_eq!(to_hex(&invite_links_locator(&cid, &h(&k["owner"]))), s(&d["invite_links_locator_owner"]));
    assert_eq!(to_hex(&signal_locator(&cid, "pause")), s(&d["signal_locator_pause"]));
    assert_eq!(to_hex(&recipient_locator(&h(&k["owner"]), &h(&k["alice"]), &[0; 32], 1)), s(&d["recipient_locator"]));
    assert_eq!(to_hex(&invite_bundle_key(&[0x99; 16])), s(&d["invite_bundle_key"]));
    assert_eq!(to_hex(&epoch_key_commitment(7, &root)), s(&d["epoch_key_commitment"]));
}

#[test]
fn edition_hash_matches() {
    let e = &vectors()["edition_hash"];
    let got = edition_hash(&h(&e["entity_id"]), 2, Some(&h(&e["prev"])), e["content"].as_str().unwrap().as_bytes());
    assert_eq!(to_hex(&got), e["hash"].as_str().unwrap());
    let got = edition_hash(&h(&e["entity_id"]), 1, None, b"{}");
    assert_eq!(to_hex(&got), e["hash_no_prev"].as_str().unwrap());
}

#[test]
fn opens_armada_chat_wrap() {
    let v = vectors();
    let k = &v["keys"];
    let stream: StreamKey = channel_group_key(&h(&k["community_root"]), &h(&k["channel_id"]), 0).into();
    let opened = open_plane_wrap(&event(&v["chat_wrap"]["wrap"]), &stream, Plane::Chat).unwrap();
    let want = &v["chat_wrap"]["rumor"];
    assert_eq!(opened.rumor.id, want["id"].as_str().unwrap());
    assert_eq!(opened.rumor.content, want["content"].as_str().unwrap());
    assert_eq!(opened.author(), k["alice"].as_str().unwrap());
    assert_eq!(opened.ms, 1_700_000_000_417);
    check_channel_binding(&opened.rumor, k["channel_id"].as_str().unwrap(), 0).unwrap();
    assert!(check_channel_binding(&opened.rumor, k["channel_id"].as_str().unwrap(), 1).is_err());
    // The wrong stream refuses it.
    let other: StreamKey = channel_group_key(&h(&k["community_root"]), &h(&k["channel_id"]), 1).into();
    assert!(open_wrap(&event(&v["chat_wrap"]["wrap"]), &other).is_err());
}

#[test]
fn rust_wraps_round_trip() {
    let v = vectors();
    let k = &v["keys"];
    let stream: StreamKey = channel_group_key(&h(&k["community_root"]), &h(&k["channel_id"]), 0).into();
    let alice = keys(&k["alice_sk"]);
    let b = concord::chat::Binding { channel_id_hex: k["channel_id"].as_str().unwrap(), epoch: 0 };
    let rumor = concord::chat::message(&b, &alice.public_key().to_hex(), "héllo \u{1F389}".into(), None, None, vec![], 1_700_000_123_456, Some(60));
    let wrap = concord::stream::seal_and_wrap(&rumor, Plane::Chat, &stream, &alice, Default::default()).unwrap();
    let opened = open_plane_wrap(&wrap, &stream, Plane::Chat).unwrap();
    assert_eq!(opened.rumor, rumor);
    assert_eq!(opened.rumor.tag_value("expiration"), Some("1700000183"));
}

fn membership(v: &Value) -> Membership {
    let k = &v["keys"];
    let bundle = serde_json::json!({
        "community_id": k["community_id"], "owner": k["owner"], "owner_salt": k["owner_salt"],
        "community_root": k["community_root"], "root_epoch": 0, "control_pk": v["control"]["control_pk"],
        "channels": [], "relays": [], "name": "x",
    });
    Membership::from_bundle(&serde_json::from_value::<concord::invite::InviteBundle>(bundle).unwrap().validate().unwrap(), 0)
}

#[test]
fn control_fold_matches_armada() {
    let v = vectors();
    let m = membership(&v);
    let streams = m.control_streams();
    let editions: Vec<_> = v["control"]["wraps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| parse_edition(open_plane_wrap(&event(w), &streams[0], Plane::Control).unwrap()).unwrap())
        .collect();
    let folded = fold_control(&editions, &m.id(), &m.owner, None, None);
    let want = &v["control"]["expect"];
    assert_eq!(folded.metadata.as_ref().unwrap().name, want["name"].as_str().unwrap());
    let want_channels = want["channels"].as_object().unwrap();
    assert_eq!(folded.channels.len(), want_channels.len());
    for (id, c) in want_channels {
        let got = &folded.channels[id];
        assert_eq!(got.name, c["name"].as_str().unwrap());
        assert_eq!(got.private, c["private"].as_bool().unwrap());
    }
    let banned: HashSet<String> = want["banned"].as_array().unwrap().iter().map(|b| b.as_str().unwrap().to_owned()).collect();
    assert_eq!(folded.banned, banned);
    assert_eq!(folded.roster.roles.len(), 1);
    assert_eq!(folded.roster.grants.len(), 1);
    assert_eq!(folded.channels["0202020202020202020202020202020202020202020202020202020202020202"].position, Some(1.0));

    // Without the control_pk's signature, a forged wrap must be refused.
    let read = control_group_key(&m.root_key(), &m.id(), 0);
    let mut forged_stream: StreamKey = (&read).into();
    forged_stream.pk = streams[0].pk;
    forged_stream.restricted = false;
    let forged = concord::stream::seal_and_wrap(&editions[0].opened.rumor, Plane::Control, &(&read).into(), &keys(&v["keys"]["owner_sk"]), Default::default()).unwrap();
    assert!(open_wrap(&forged, &streams[0]).is_err());

    let views = m.channels(Some(&folded));
    assert_eq!(views.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["random", "lobby"]);
}

#[test]
fn v2_derivations_match() {
    let v = vectors();
    let k = &v["keys"];
    let d = &v["derive_v2"];
    let (root, cid, chan, alice, owner) = (h(&k["community_root"]), h(&k["community_id"]), h(&k["channel_id"]), h(&k["alice"]), h(&k["owner"]));
    let s = |v: &Value| v.as_str().unwrap().to_owned();
    assert_eq!(to_hex(&everyone_locator(&cid)), s(&d["everyone_locator"]));
    assert_eq!(to_hex(&edition_binding(&cid)), s(&d["edition_binding"]));
    assert_eq!(to_hex(&tenure_locator(&cid, &alice, &owner)), s(&d["tenure_locator"]));
    let acl = |kind, id: Option<&[u8; 32]>| to_hex(&acl_locator(&cid, &chan, &overwrite_target_bytes(&cid, kind, id)));
    assert_eq!(acl(OverwriteTargetKind::Everyone, None), s(&d["acl_everyone"]));
    assert_eq!(acl(OverwriteTargetKind::Role, Some(&[0x03; 32])), s(&d["acl_role"]));
    assert_eq!(acl(OverwriteTargetKind::Member, Some(&alice)), s(&d["acl_member"]));
    assert_eq!(to_hex(&sync_locator(&cid, &chan)), s(&d["sync_locator"]));
    assert_eq!(to_hex(&writers_locator(&cid, &chan)), s(&d["writers_locator"]));
    assert_eq!(to_hex(&writer_scope(&chan)), s(&d["writer_scope"]));
    assert_eq!(to_hex(&certifier_scope(&chan)), s(&d["certifier_scope"]));
    assert_eq!(to_hex(&history_scope(&chan)), s(&d["history_scope"]));
    let check = |g: GroupKey, want: &Value| {
        assert_eq!(g.pk_hex(), want["pk"].as_str().unwrap());
        assert_eq!(to_hex(&g.conv_key), want["conv_key"].as_str().unwrap());
    };
    check(channel_writer_group_key(&[0x71; 32], &chan, 1), &d["channel_writer_e1"]);
    check(channel_access_group_key(&root, &chan, 0), &d["channel_access_e0"]);
    let address = channel_group_key(&root, &chan, 0).pubkey().to_bytes();
    assert_eq!(wrap_owner_key(keys(&k["alice_sk"]).secret_key(), &address, &[0x09; 32]).public_key().to_hex(), s(&d["wrap_owner"]));
    let marked = concord::edition::marked_edition_hash(&[0x11; 32], 2, Some(&[0x22; 32]), br#"{"name":"Mods"}"#, &[0x33; 32]);
    assert_eq!(to_hex(&marked), s(&d["marked_hash"]));
    // The spec's own vector (CORD-04 §1).
    assert!(to_hex(&marked).starts_with("462cc8"));
}

#[test]
fn ranked_fold_matches_armada() {
    use concord::roles::OverwriteTarget;
    let v = vectors();
    let r = &v["ranked"];
    let k = &v["keys"];
    let cid = h(&r["community_id"]);
    let owner = k["owner"].as_str().unwrap();
    let read = control_group_key(&h(&k["community_root"]), &cid, 0);
    let stream = StreamKey { pk: concord::nostr::prelude::PublicKey::from_hex(r["control_pk"].as_str().unwrap()).unwrap(), conv_key: read.conv_key, sk: None, restricted: true };
    let editions: Vec<_> = r["wraps"].as_array().unwrap().iter().map(|w| parse_edition(open_plane_wrap(&event(w), &stream, Plane::Control).unwrap()).unwrap()).collect();
    let folded = fold_control(&editions, &cid, owner, None, None);
    let want = &r["expect"];

    assert_eq!(folded.ranked, want["ranked"].as_bool().unwrap());
    assert_eq!(folded.roster.everyone.map(|e| e.to_string()), want["everyone"].as_str().map(str::to_owned));
    let legacy: Vec<String> = want["legacy"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_owned()).collect();
    assert_eq!(folded.roster.legacy_channels.as_ref(), Some(&legacy));

    let mut got_roles: Vec<Value> = folded
        .roster
        .roles
        .iter()
        .map(|x| serde_json::json!({ "id": x.role_id, "name": x.name, "rank": x.rank, "position": x.position, "permissions": x.permissions.to_string(), "mentionable": x.mentionable, "display": x.display }))
        .collect();
    let mut want_roles = want["roles"].as_array().unwrap().clone();
    let by_id = |a: &Value, b: &Value| a["id"].as_str().cmp(&b["id"].as_str());
    got_roles.sort_by(by_id);
    want_roles.sort_by(by_id);
    assert_eq!(got_roles, want_roles);

    let mut got_grants: Vec<(String, Vec<String>)> = folded.roster.grants.iter().map(|g| (g.member.clone(), g.role_ids.clone())).collect();
    let mut want_grants: Vec<(String, Vec<String>)> = serde_json::from_value(want["grants"].clone()).unwrap();
    got_grants.sort();
    want_grants.sort();
    assert_eq!(got_grants, want_grants);

    let mut got_ow: Vec<Value> = folded
        .roster
        .overwrites
        .iter()
        .map(|o| {
            let (kind, id) = match &o.target {
                OverwriteTarget::Everyone => ("everyone", None),
                OverwriteTarget::Role(i) => ("role", Some(i.clone())),
                OverwriteTarget::Member(i) => ("member", Some(i.clone())),
            };
            serde_json::json!([o.scope, kind, id, o.allow.to_string(), o.deny.to_string()])
        })
        .collect();
    let mut want_ow = want["overwrites"].as_array().unwrap().clone();
    let key = |a: &Value| a.to_string();
    got_ow.sort_by_key(key);
    want_ow.sort_by_key(key);
    assert_eq!(got_ow, want_ow);

    let want_syncs: std::collections::HashMap<String, String> = serde_json::from_value(want["syncs"].clone()).unwrap();
    assert_eq!(folded.roster.syncs, want_syncs);
    let got_cats: Vec<Value> = folded.categories.values().map(|c| serde_json::json!([c.id_hex, c.name, c.position, c.deleted])).collect();
    assert_eq!(Value::Array(got_cats), want["categories"]);

    for (id, c) in want["channels"].as_object().unwrap() {
        let got = &folded.channels[id];
        assert_eq!(got.name, c["name"].as_str().unwrap(), "{id}");
        assert_eq!(got.private, c["private"].as_bool().unwrap());
        assert_eq!(got.deleted, c["deleted"].as_bool().unwrap());
        assert_eq!(got.category_id.as_deref(), c["category"].as_str());
        assert_eq!(got.rank.as_deref(), c["position"].as_str());
        assert_eq!(got.sealed.is_some(), c["sealed"].as_bool().unwrap());
    }
    assert_eq!(folded.channels.len(), want["channels"].as_object().unwrap().len());
    let got_writers: HashSet<String> = folded.writers.keys().cloned().collect();
    let want_writers: HashSet<String> = serde_json::from_value(want["writers"].clone()).unwrap();
    assert_eq!(got_writers, want_writers);

    for (cn, id) in r["channels"].as_object().unwrap() {
        let id = id.as_str().unwrap();
        assert_eq!(folded.roster.everyone_sends(id), want["everyone_sends"][cn].as_bool().unwrap(), "everyone_sends {cn}");
        for (mn, pk) in r["members"].as_object().unwrap() {
            assert_eq!(folded.channel_permissions(pk.as_str().unwrap(), id).to_string(), want["permissions"][mn][cn].as_str().unwrap(), "{mn} in {cn}");
        }
    }

    // The sealed Private Channel opens with its key and names its creator.
    let secret = r["channels"]["secret"].as_str().unwrap();
    let sealed = folded.channels[secret].sealed.as_ref().unwrap();
    let opened = concord::channel_seal::open_channel_seal(sealed, &h(&r["secret_key"]), &hex32(secret).unwrap()).unwrap();
    assert_eq!(opened.metadata["name"], "secret-plans");
    assert_eq!(opened.creator.as_deref(), Some(owner));

    // A post at the writer address opens under the read key and stands on its
    // certificate; a roleless member's post at the read address doesn't.
    let ann = r["channels"]["announcements"].as_str().unwrap();
    let ledger = folded.restricting_ledger(ann).unwrap();
    let read_key = channel_group_key(&h(&k["community_root"]), &hex32(ann).unwrap(), 0);
    let writer = StreamKey { pk: concord::nostr::prelude::PublicKey::from_hex(r["writer_pk"].as_str().unwrap()).unwrap(), conv_key: read_key.conv_key, sk: None, restricted: false };
    let post = open_plane_wrap(&event(&r["post_wrap"]), &writer, Plane::Chat).unwrap();
    check_channel_binding(&post.rumor, ann, 0).unwrap();
    let stands = concord::writers::post_stands(ledger, &cid, post.author(), post.ms, &post.rumor.tags);
    assert_eq!(stands, want["post_stands"].as_bool().unwrap());
    assert!(stands);
    let stray = open_plane_wrap(&event(&r["stray_wrap"]), &(&read_key).into(), Plane::Chat).unwrap();
    let stray_stands = concord::writers::post_stands(ledger, &cid, stray.author(), stray.ms, &stray.rumor.tags);
    assert_eq!(stray_stands, want["stray_stands"].as_bool().unwrap());
    assert!(!stray_stands);
}

#[test]
fn invites_match() {
    let v = vectors();
    let i = &v["invite"];
    let token: [u8; 16] = [0x99; 16];
    assert_eq!(encode_fragment(&token, &stock_relays()).unwrap(), i["fragment_stock"].as_str().unwrap());
    let custom: Vec<String> = ["wss://relay.ditto.pub", "wss://relay.example.com", "ws://localhost:7777"].map(String::from).to_vec();
    assert_eq!(encode_fragment(&token, &custom).unwrap(), i["fragment_custom"].as_str().unwrap());
    assert_eq!(decode_fragment(i["fragment_custom"].as_str().unwrap()).unwrap(), (token, custom));

    let link = parse_invite_link(i["url"].as_str().unwrap()).unwrap();
    assert_eq!(link.link_signer, i["link_signer"].as_str().unwrap());
    assert_eq!(link.token, token);
    assert_eq!(link.bootstrap_relays, ["wss://relay.ditto.pub", "wss://relay.example.com"]);

    let bundle = parse_bundle_event(&event(&i["bundle_event"]), &link, 0).unwrap();
    assert_eq!(bundle.name, "Test Community");
    assert_eq!(bundle.channels[0].epoch, 3);
    assert_eq!(bundle.label.as_deref(), Some("Reddit"));
    assert!(parse_invite_link("https://example.com/not-an-invite#abc").is_err());
}

#[test]
fn adopts_armada_refounding() {
    let v = vectors();
    let mut m = membership(&v);
    let address = m.next_base_rekey_address();
    let stream: StreamKey = (&address).into();
    let parsed: Vec<_> = v["rekey"]["wraps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| parse_rekey(&open_plane_wrap(&event(w), &stream, Plane::Rekey).unwrap()).unwrap())
        .collect();
    let rotations = group_rotations(parsed);
    let folded = concord::control::FoldedControl { owner: m.owner.clone(), ..Default::default() };

    // Alice is a member: she gets the root and control_pk, not the control_root.
    let alice = keys(&v["keys"]["alice_sk"]);
    let mut am = m.clone();
    assert_eq!(am.apply_base_rotations(&rotations, &folded, &alice), RekeyOutcome::AdoptedRoot(1));
    assert_eq!(am.root, v["rekey"]["new_root"].as_str().unwrap());
    assert_eq!(am.control_pk.as_deref(), v["rekey"]["new_control_pk"].as_str());
    assert!(am.control_root.is_none());
    assert_eq!(am.held_roots.len(), 2);
    assert_eq!(am.held_roots[1].retired_at, Some(1_700_000_100));

    // The owner (staff) also gets the control_root, and can then write Control.
    let owner = keys(&v["keys"]["owner_sk"]);
    assert_eq!(m.apply_base_rotations(&rotations, &folded, &owner), RekeyOutcome::AdoptedRoot(1));
    assert_eq!(m.control_root.as_deref(), v["rekey"]["new_control_root"].as_str());
    assert!(m.current_control_stream().sk.is_some());

    // Bob joined before the rotation and got no blob; the owner outranks him.
    let bob = keys(&v["keys"]["bob_sk"]);
    let mut bm = membership(&v);
    assert_eq!(bm.apply_base_rotations(&rotations, &folded, &bob), RekeyOutcome::Excluded(1));
}

/// The owner-side builders produce Armada's exact rumors, ids included.
#[test]
fn builders_match_armada() {
    use concord::control::*;
    use concord::edition::{Citation, EditionMeta};
    use concord::roles::{MemberGrant, Role, RoleScope, admin_role};

    let v = vectors();
    let k = &v["keys"];
    let b = &v["builders"];
    let s = |v: &Value| v.as_str().unwrap().to_owned();
    let (cid, owner, op) = (h(&k["community_id"]), s(&k["owner"]), s(&k["alice"]));
    let role_id = to_hex(&[0x03; 32]);
    let at = Some(1_700_000_300);
    let check = |got: concord::rumor::Rumor, want: &Value| {
        assert_eq!(got.content, s(&want["content"]));
        assert_eq!(serde_json::to_value(&got.tags).unwrap(), want["tags"]);
        assert_eq!(got.id, s(&want["id"]));
    };

    // The vac every op-key action carries cites the owner's grant to op.
    let grant = MemberGrant { member: op.clone(), role_ids: vec![role_id.clone()], control_wrap: None };
    let grant_rumor = build_grant_edition(&cid, &grant, &EditionMeta { created_at: at, ..EditionMeta::first(&owner, None) }).unwrap();
    let grant_hash = edition_hash(&grant_locator(&cid, &hex32(&op).unwrap()), 1, None, grant_rumor.content.as_bytes());
    let vac = Citation { entity_id: grant_locator(&cid, &hex32(&op).unwrap()), version: 1, edition_hash: grant_hash };
    let owner_meta = EditionMeta { created_at: at, ..EditionMeta::first(&owner, None) };
    let op_meta = EditionMeta { created_at: at, ..EditionMeta::first(&op, Some(&vac)) };
    check(grant_rumor, &b["grant"]);

    check(build_role_edition(&admin_role(&role_id), &owner_meta).unwrap(), &b["admin_role"]);
    let access = Role::new(&to_hex(&[0x04; 32]), "mods", 7, 0, RoleScope::Channel(s(&k["channel_id"])));
    check(build_role_edition(&access, &op_meta).unwrap(), &b["access_role"]);
    assert!(build_role_edition(&Role { position: 0, ..access }, &op_meta).is_err());

    let owner_key = MemberGrant { member: owner.clone(), role_ids: vec![], control_wrap: Some("AbC=".into()) };
    check(build_grant_edition(&cid, &owner_key, &op_meta).unwrap(), &b["owner_key_grant"]);

    let link_signer = s(&v["invite"]["link_signer"]);
    check(build_registry_edition(&cid, &owner, &[link_signer], &owner_meta).unwrap(), &b["registry"]);

    let mut meta = serde_json::json!({ "name": "voice-chat", "private": true });
    with_channel_position(&mut meta, Some(4));
    with_channel_category(&mut meta, Some("  Hangouts "));
    meta["custom"]["discord.import"] = serde_json::json!({ "topic": "t", "type": "voice" });
    check(build_channel_edition(&h(&k["channel_id"]), &meta, &op_meta).unwrap(), &b["channel"]);

    use base64::Engine;
    let plain = concord::rekey::encode_control_wrap(3, &h(&k["control_root"]));
    assert_eq!(base64::engine::general_purpose::STANDARD.encode(plain), s(&b["control_wrap"]));
}

#[test]
fn minted_community_can_write_its_control_plane() {
    let owner = Keys::generate();
    let m = Membership::mint("x", &owner.public_key().to_hex(), vec!["wss://a".into(); 7], 0);
    assert_eq!(m.relays, ["wss://a"]);
    let control = m.control_write_stream().expect("the minter holds the staff key");
    assert_eq!(Some(control.pk_hex()), m.control_pk);
    // A member who joined by bundle reads the same plane but cannot write it.
    let bundle = serde_json::json!({
        "community_id": m.community_id, "owner": m.owner, "owner_salt": m.owner_salt,
        "community_root": m.root, "root_epoch": 0, "control_pk": m.control_pk, "name": "x",
    });
    let member = Membership::from_bundle(&serde_json::from_value::<concord::invite::InviteBundle>(bundle).unwrap().validate().unwrap(), 0);
    assert_eq!(member.current_control_stream().pk, control.pk);
    assert!(member.control_write_stream().is_none());
}

#[test]
fn inbox_prefers_dm_relays_then_nip65_reads() {
    use concord::nostr::prelude::*;
    let alice = Keys::generate();
    let ev = |kind: u16, tags: Vec<Vec<&str>>| {
        EventBuilder::new(Kind::Custom(kind), "").tags(tags.into_iter().map(|t| Tag::parse(t).unwrap())).finalize(&alice).unwrap()
    };
    let nip65 = ev(10002, vec![vec!["r", "wss://read.example"], vec!["r", "wss://write.example", "write"]]);
    assert_eq!(concord::invite::inbox_relays_from(std::slice::from_ref(&nip65), &alice.public_key()), ["wss://read.example"]);
    let dm = ev(10050, vec![vec!["relay", "inbox.example/"], vec!["relay", "wss://inbox.example"]]);
    assert_eq!(concord::invite::inbox_relays_from(&[nip65, dm], &alice.public_key()), ["wss://inbox.example"]);
    assert_eq!(concord::invite::invite_delivery_relays(&[]), stock_relays());
}

#[test]
fn invite_url_matches_armada() {
    let v = vectors();
    let i = &v["invite"];
    let signer = concord::nostr::prelude::PublicKey::from_hex(i["link_signer"].as_str().unwrap()).unwrap();
    let relays: Vec<String> = ["wss://relay.ditto.pub", "wss://relay.example.com"].map(String::from).to_vec();
    let url = concord::invite::build_invite_url("https://armada.buzz/", &signer, &[0x99; 16], &relays).unwrap();
    assert_eq!(url, i["url"].as_str().unwrap());
}

#[test]
fn opens_armada_direct_invite() {
    let v = vectors();
    let bob = keys(&v["keys"]["bob_sk"]);
    let opened = concord::direct_invite::unwrap(&event(&v["direct_invite"]["wrap"]), &bob).expect("Bob opens Armada's invite");
    assert_eq!(opened.inviter, v["keys"]["owner"].as_str().unwrap());
    assert_eq!(opened.bundle.channels[0].key, v["keys"]["private_channel_key"].as_str().unwrap());
    assert!(concord::direct_invite::unwrap(&event(&v["direct_invite"]["wrap"]), &keys(&v["keys"]["alice_sk"])).is_none());
}

#[test]
fn guestbook_and_comment_tags_match() {
    let v = vectors();
    let m = membership(&v);
    let opened = open_plane_wrap(&event(&v["guestbook"]["wrap"]), &m.current_guestbook_stream(), Plane::Guestbook).unwrap();
    let rebuilt = concord::guestbook::join(opened.author(), opened.ms, Some((v["keys"]["owner"].as_str().unwrap(), "Reddit")));
    assert_eq!(rebuilt.id, opened.rumor.id);

    let r = &v["chat_wrap"]["rumor"];
    let tags: Vec<Vec<String>> = serde_json::from_value(r["tags"].clone()).unwrap();
    let parent = concord::chat::Target { id: r["id"].as_str().unwrap(), kind: 9, author: r["pubkey"].as_str().unwrap(), tags: &tags };
    let want: Vec<Vec<String>> = serde_json::from_value(v["comment_tags"].clone()).unwrap();
    assert_eq!(concord::chat::comment_tags(&parent), want);
}
