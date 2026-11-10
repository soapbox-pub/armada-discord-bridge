//! Conformance against Vector, the other Concord client: Communities and random
//! Control Planes Vector built and folded itself (copied from the fixtures
//! Armada carries, by `tools/vectors/vector.ts`). The bridge must fold every one
//! to Vector's answer, or it disagrees with a client about who may do what.

use std::collections::{BTreeMap, HashMap, HashSet};

use concord::control::{FoldedControl, fold_control};
use concord::derive::control_group_key;
use concord::edition::{Edition, parse_edition};
use concord::kinds::Plane;
use concord::nostr::prelude::{Event, PublicKey};
use concord::roles::OverwriteTarget;
use concord::roster::AUTHORITY_VSKS;
use concord::stream::{StreamKey, open_plane_wrap};
use concord::{hex32, to_hex};
use serde_json::{Value, json};

fn fixture(name: &str) -> Value {
    let path = format!("{}/tests/vectors/vector/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

/// Every Control edition the fixture's events open to.
fn editions(community: &Value, events: &Value) -> Vec<Edition> {
    let (root, id) = (hex32(s(&community["root"])).unwrap(), hex32(s(&community["id"])).unwrap());
    let read = control_group_key(&root, &id, community["root_epoch"].as_u64().unwrap());
    let stream = match community["control_pk"].as_str() {
        Some(pk) => StreamKey { pk: PublicKey::from_hex(pk).unwrap(), conv_key: read.conv_key, sk: None, restricted: true },
        None => (&read).into(),
    };
    events
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| {
            let event: Event = serde_json::from_value(e.clone()).ok()?;
            parse_edition(open_plane_wrap(&event, &stream, Plane::Control).ok()?).ok()
        })
        .collect()
}

fn target(t: &OverwriteTarget) -> String {
    match t {
        OverwriteTarget::Everyone => "Everyone".into(),
        OverwriteTarget::Role(id) => format!("Role(\"{id}\")"),
        OverwriteTarget::Member(id) => format!("Member(\"{id}\")"),
    }
}

/// The fold in the shape Vector's generator writes (Armada's `roster.fuzz.test.ts`).
fn reading(c: &Value, editions: &[Edition], f: &FoldedControl) -> Value {
    let owner = s(&c["community"]["owner"]);
    let mut overwrites: Vec<String> = f.roster.overwrites.iter().map(|o| format!("{}|{}|{}|{}", o.scope, target(&o.target), o.allow, o.deny)).collect();
    overwrites.sort();
    let perms: BTreeMap<String, Vec<String>> = c["actors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            let row = c["scopes"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|ch| [false, true].map(|p| f.roster.channel_permissions(owner, s(a), s(ch), p).to_string()))
                .collect();
            (s(a).to_owned(), row)
        })
        .collect();
    let mut roles: Vec<Value> = f.roster.roles.iter().map(|r| json!({ "id": r.role_id, "rank": r.rank, "permissions": r.permissions.to_string(), "name": r.name })).collect();
    roles.sort_by(|a, b| s(&a["id"]).cmp(s(&b["id"])));
    let mut grants: Vec<String> = f
        .roster
        .grants
        .iter()
        .map(|g| {
            let mut ids = g.role_ids.clone();
            ids.sort();
            format!("{}:{}", g.member, ids.join(","))
        })
        .collect();
    grants.sort();
    let mut banned: Vec<&String> = f.banned.iter().collect();
    banned.sort();
    let banned_at: BTreeMap<&String, u64> = f.banned_at.iter().map(|(k, v)| (k, *v)).collect();
    // The Roster's heads: a Channel squatting a Roster coordinate heads the Control fold there, not this one.
    let roster_eids: HashSet<String> = editions.iter().filter(|e| AUTHORITY_VSKS.contains(&e.vsk.as_str())).map(|e| e.eid_hex()).collect();
    let mut heads: Vec<Value> = f
        .head_editions
        .iter()
        .filter(|(eid, e)| roster_eids.contains(*eid) && AUTHORITY_VSKS.contains(&e.vsk.as_str()))
        .map(|(eid, e)| json!({ "eid": eid, "version": e.version, "hash": to_hex(&e.self_hash), "id": to_hex(&e.rumor_id) }))
        .collect();
    heads.sort_by(|a, b| s(&a["eid"]).cmp(s(&b["eid"])));
    json!({
        "everyone": f.roster.everyone.map(|e| e.to_string()),
        "legacy": f.roster.legacy_channels,
        "overwrites": overwrites,
        "syncs": f.roster.syncs.iter().collect::<BTreeMap<_, _>>(),
        "perms": perms,
        "roles": roles,
        "grants": grants,
        "banned": banned,
        "banned_at": banned_at,
        "heads": heads,
    })
}

/// Vector's answer, normalized to [`reading`]'s shape.
fn theirs(v: &Value) -> Value {
    let mut roles = v["roles"].as_array().unwrap().clone();
    roles.sort_by(|a, b| s(&a["id"]).cmp(s(&b["id"])));
    let mut banned: Vec<&str> = v["banned"].as_array().unwrap().iter().map(s).collect();
    banned.sort();
    let mut heads: Vec<Value> = v["heads"].as_array().unwrap().iter().map(|h| json!({ "eid": h["eid"], "version": h["version"], "hash": h["hash"], "id": h["id"] })).collect();
    heads.sort_by(|a, b| s(&a["eid"]).cmp(s(&b["eid"])));
    json!({
        "everyone": v["everyone"],
        "legacy": v["legacy"],
        "overwrites": v["overwrites"],
        "syncs": v["syncs"],
        "perms": v["perms"],
        "roles": roles,
        "grants": v["grants"],
        "banned": banned,
        "banned_at": v["banned_at"],
        "heads": heads,
    })
}

#[test]
fn every_fuzzed_roster_folds_as_vector_folds_it() {
    let cases = fixture("roster_fuzz");
    let mut failures = Vec::new();
    for c in cases.as_array().unwrap() {
        let all = editions(&c["community"], &c["events"]);
        let served: HashSet<&str> = c["served"].as_array().unwrap().iter().map(s).collect();
        let slice: Vec<Edition> = all.into_iter().filter(|e| served.contains(to_hex(&e.rumor_id).as_str())).collect();
        assert_eq!(slice.len(), served.len(), "case {}: every served edition opens", c["seed"]);
        let cid = hex32(s(&c["community"]["id"])).unwrap();
        let f = fold_control(&slice, &cid, s(&c["community"]["owner"]), None, None);
        let (mine, want) = (reading(c, &slice, &f), theirs(&c["vector"]));
        for key in want.as_object().unwrap().keys() {
            if mine[key] != want[key] {
                failures.push(format!("case {} {key}:\n  bridge {}\n  vector {}", c["seed"], mine[key], want[key]));
            }
        }
    }
    assert!(failures.is_empty(), "{} divergences from Vector:\n{}", failures.len(), failures.join("\n"));
}

/// guild.json and switched.json: whole Communities, one of them switched to
/// ranked roles after it had Channels and Roles.
#[test]
fn vectors_communities_fold_to_the_same_roles_permissions_and_channels() {
    for name in ["guild", "switched"] {
        let f = fixture(name);
        let editions = editions(&f["community"], &f["events"]);
        assert!(!editions.is_empty(), "{name}: the Control Plane opens");
        let owner = s(&f["community"]["owner"]);
        let cid = hex32(s(&f["community"]["id"])).unwrap();
        let folded = fold_control(&editions, &cid, owner, None, None);
        let v = &f["vector"];
        assert_eq!(folded.ranked, v["activated"].as_bool().unwrap(), "{name}: on ranked roles");

        let num = |x: &Value| x.as_str().map(str::to_owned).unwrap_or_else(|| x.to_string());
        assert_eq!(folded.roster.everyone.map(|e| e.to_string()), v["roles"].get("everyone").map(num), "{name}: @everyone");
        let mut mine: Vec<(String, String, Option<String>, String)> =
            folded.roster.roles.iter().map(|r| (r.role_id.clone(), r.name.clone(), r.rank.clone(), r.permissions.to_string())).collect();
        let mut want: Vec<(String, String, Option<String>, String)> = v["roles"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (s(&r["role_id"]).to_owned(), s(&r["name"]).to_owned(), r["rank"].as_str().map(str::to_owned), num(&r["permissions"])))
            .collect();
        mine.sort();
        want.sort();
        assert_eq!(mine, want, "{name}: roles");
        let grants = |gs: Vec<(String, Vec<String>)>| {
            let mut out: Vec<String> = gs
                .into_iter()
                .map(|(m, mut ids)| {
                    ids.sort();
                    format!("{m}:{}", ids.join(","))
                })
                .collect();
            out.sort();
            out
        };
        let want_grants = v["roles"]["grants"].as_array().unwrap().iter().map(|g| (s(&g["member"]).to_owned(), g["role_ids"].as_array().unwrap().iter().map(|r| s(r).to_owned()).collect())).collect();
        assert_eq!(grants(folded.roster.grants.iter().map(|g| (g.member.clone(), g.role_ids.clone())).collect()), grants(want_grants), "{name}: grants");
        let legacy: Option<Vec<String>> = v["roles"].get("legacy_channels").and_then(|l| serde_json::from_value(l.clone()).ok());
        assert_eq!(folded.roster.legacy_channels, legacy, "{name}: legacy channels");

        for (label, m) in v["members"].as_object().unwrap() {
            let pk = s(&m["pubkey"]);
            assert_eq!(folded.roster.permissions(pk).to_string(), s(&m["server"]), "{name}: {label}'s server permissions");
            for ch in v["channels"].as_array().unwrap() {
                let (id, private) = (s(&ch["id"]), ch["private"].as_bool().unwrap());
                let got = folded.roster.channel_permissions(owner, pk, id, private).to_string();
                assert_eq!(got, s(&m["channels"][id]), "{name}: {label} in #{}", s(&ch["name"]));
            }
        }

        let mut cats: Vec<Value> =
            folded.categories.values().filter(|c| !c.deleted).map(|c| json!({ "id": c.id_hex, "name": c.name, "position": c.position })).collect();
        cats.sort_by(|a, b| s(&a["id"]).cmp(s(&b["id"])));
        let mut want_cats: Vec<Value> = v["categories"].as_array().unwrap().iter().map(|c| json!({ "id": c["id"], "name": c["name"], "position": c.get("position") })).collect();
        want_cats.sort_by(|a, b| s(&a["id"]).cmp(s(&b["id"])));
        assert_eq!(cats, want_cats, "{name}: categories");

        let legacy_ids: HashSet<String> = folded.roster.legacy_channels.clone().unwrap_or_default().into_iter().collect();
        for ch in v["channels"].as_array().unwrap() {
            let id = s(&ch["id"]);
            let mine = folded.channels.get(id).unwrap_or_else(|| panic!("{name}: #{} folds", s(&ch["name"])));
            assert_eq!(mine.private, ch["private"].as_bool().unwrap(), "{name}: #{} privacy", s(&ch["name"]));
            if mine.private {
                // One made on ranked roles is sealed; one the switch carried across keeps its plaintext head.
                if !legacy_ids.contains(id) {
                    let sealed = mine.sealed.as_ref().expect("a Private Channel's details are sealed");
                    // Vector's owner holds the key, and it opens the seal.
                    if let (Some(key), Some(cid)) = (ch["key"].as_str().and_then(hex32), hex32(id)) {
                        let opened = concord::channel_seal::open_channel_seal(sealed, &key, &cid).expect("the held key opens the seal");
                        assert_eq!(opened.metadata["name"], ch["name"], "{name}: sealed name");
                    }
                }
                continue;
            }
            assert_eq!(mine.name, s(&ch["name"]));
            let extra: HashMap<String, Value> = serde_json::from_value(ch["extra"].clone()).unwrap_or_default();
            for k in ["category", "position", "topic", "view"] {
                assert_eq!(mine.raw.get(k), extra.get(k), "{name}: #{}.{k}", s(&ch["name"]));
            }
        }
    }
}
