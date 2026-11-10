// Generates cross-implementation test vectors from Armada's own Concord code, so
// the Rust crate is checked against the implementation it must interoperate with.
//
//   (cd tools/vectors && bun install)
//   bun tools/vectors/gen.ts > crates/concord/tests/vectors/armada.json
//
// ARMADA points at a checkout of the Armada client (default ~/Projects/armada).

import { finalizeEvent, getPublicKey } from "nostr-tools/pure";
import { encrypt as nip44Encrypt, getConversationKey } from "nostr-tools/nip44";
import { homedir } from "node:os";

const ARMADA = process.env.ARMADA ?? `${homedir()}/Projects/armada`;
// Vite injects this at build time; some transitive imports read it.
(globalThis as any).__ARMADA_BUILD_CONFIG__ = {};
const lib = (m: string) => import(`${ARMADA}/src/concord/lib/${m}.ts`);

const derive = await lib("derive");
const stream = await lib("stream");
const version = await lib("version");
const edition = await lib("edition");
const control = await lib("control");
const invite = await lib("invite");
const rekey = await lib("rekey");
const guestbook = await lib("guestbook");
const chat = await lib("chat");

const { bytesToHex, hexToBytes } = derive;
const h = (s: string) => hexToBytes(s);
const fill = (b: number) => new Uint8Array(32).fill(b);

const signer = (sk: Uint8Array) => ({ signEvent: async (t: any) => finalizeEvent(t, sk) });
const gk = (k: any) => ({ sk: bytesToHex(k.sk), pk: k.pk, conv_key: bytesToHex(k.convKey) });

const ownerSk = fill(0x11);
const owner = getPublicKey(ownerSk);
const aliceSk = fill(0x22);
const alice = getPublicKey(aliceSk);
const bobSk = fill(0x33);
const bob = getPublicKey(bobSk);
const ownerSalt = fill(0x44);
const communityId = derive.communityIdOf(h(owner), ownerSalt);
const root = fill(0x55);
const controlRoot = fill(0x66);
const channelId = fill(0x77);
const privateKey = fill(0x88);

const out: Record<string, unknown> = {};

out.keys = {
  owner_sk: bytesToHex(ownerSk), owner,
  alice_sk: bytesToHex(aliceSk), alice,
  bob_sk: bytesToHex(bobSk), bob,
  owner_salt: bytesToHex(ownerSalt),
  community_id: bytesToHex(communityId),
  community_root: bytesToHex(root),
  control_root: bytesToHex(controlRoot),
  channel_id: bytesToHex(channelId),
  private_channel_key: bytesToHex(privateKey),
};

out.derive = {
  channel_public_e0: gk(derive.channelGroupKey(root, channelId, 0)),
  channel_private_e3: gk(derive.channelGroupKey(privateKey, channelId, 3)),
  control_e0: gk(derive.controlGroupKey(root, communityId, 0)),
  control_signer_e0: gk(derive.controlSignerGroupKey(controlRoot, communityId, 0)),
  guestbook_e2: gk(derive.guestbookGroupKey(root, communityId, 2)),
  dissolved: gk(derive.dissolvedGroupKey(communityId)),
  channel_rekey_e4: gk(derive.channelRekeyGroupKey(root, channelId, 4)),
  base_rekey_e1: gk(derive.baseRekeyGroupKey(root, communityId, 1)),
  grant_locator_alice: bytesToHex(derive.grantLocator(communityId, h(alice))),
  pins_locator: bytesToHex(derive.pinsLocator(communityId, channelId)),
  banlist_locator: bytesToHex(derive.banlistLocator(communityId)),
  invite_links_locator_owner: bytesToHex(derive.inviteLinksLocator(communityId, h(owner))),
  signal_locator_pause: bytesToHex(derive.signalLocator(communityId, "pause")),
  recipient_locator: bytesToHex(derive.recipientLocator(h(owner), h(alice), new Uint8Array(32), 1)),
  invite_bundle_key: bytesToHex(derive.inviteBundleKey(new Uint8Array(16).fill(0x99))),
  epoch_key_commitment: bytesToHex(derive.epochKeyCommitment(7, root)),
};

out.edition_hash = {
  entity_id: bytesToHex(channelId),
  version: "2",
  prev: bytesToHex(fill(0xab)),
  content: '{"name":"général","private":false}',
  hash: bytesToHex(version.editionHash(channelId, 2n, fill(0xab), new TextEncoder().encode('{"name":"général","private":false}'))),
  hash_no_prev: bytesToHex(version.editionHash(channelId, 1n, undefined, new TextEncoder().encode("{}"))),
};

// A chat message wrapped by Armada, for the Rust side to open.
const chan = derive.channelGroupKey(root, channelId, 0);
const msgRumor = stream.buildRumor({
  kind: 9,
  content: "Hey chat! \"quoted\" \n émoji 🎉 </script>",
  tags: [...stream.channelBindingTags(bytesToHex(channelId), 0n), ["q", "ab".repeat(32), "", owner]],
  pubkey: alice,
  ms: 1_700_000_000_417,
});
const msgSeal = await stream.sealRumor(msgRumor, 20013, chan, signer(aliceSk));
const msgWrap = await stream.wrapSeal(msgSeal, chan);
out.chat_wrap = { wrap: msgWrap, rumor: msgRumor };

// The Control Plane: owner genesis (metadata + #general), a role, a grant to Alice,
// a channel added by Alice under that grant, and a banlist naming Bob.
const controlRead = derive.controlGroupKey(root, communityId, 0);
const controlSigner = derive.controlSignerGroupKey(controlRoot, communityId, 0);
const controlWrite = { sk: controlSigner.sk, pk: controlSigner.pk, get convKey() { return controlRead.convKey; } };
const editions: any[] = [];
const publish = async (rumor: any, sk: Uint8Array) => {
  const wrap = await control.sealEdition(rumor, controlWrite, signer(sk));
  editions.push(wrap);
  return rumor;
};
const general = fill(0x01);
const random = fill(0x02);
const roleId = bytesToHex(fill(0x03));
await publish(control.buildMetadataEdition(communityId, { name: "Test Community", description: "desc", relays: ["wss://relay.example"] }, { actorPubkey: owner, version: 1n, createdAtSecs: 1_700_000_000 }), ownerSk);
const generalRumor = await publish(control.buildChannelEdition(general, { name: "general", private: false }, { actorPubkey: owner, version: 1n, createdAtSecs: 1_700_000_001 }), ownerSk);
await publish(control.buildRoleEdition({ roleId, name: "Admin", position: 1, permissions: (1n << 1n) | (1n << 0n), scope: { kind: "server" }, color: 0 }, { actorPubkey: owner, version: 1n, createdAtSecs: 1_700_000_002 }), ownerSk);
const grantRumor = control.buildGrantEdition(communityId, { member: alice, roleIds: [roleId] }, { actorPubkey: owner, version: 1n, createdAtSecs: 1_700_000_003 });
await publish(grantRumor, ownerSk);
const grantEid = derive.grantLocator(communityId, h(alice));
const grantHash = version.editionHash(grantEid, 1n, undefined, new TextEncoder().encode(grantRumor.content));
const authority = { entityId: grantEid, version: 1n, editionHash: grantHash };
await publish(control.buildChannelEdition(random, { name: "random", private: false, custom: { "armada.order": { position: 1 } } }, { actorPubkey: alice, version: 1n, createdAtSecs: 1_700_000_004, authority }), aliceSk);
// Alice renames #general (v2) — authorized by MANAGE_CHANNELS.
const generalHash = version.editionHash(general, 1n, undefined, new TextEncoder().encode(generalRumor.content));
await publish(control.buildChannelEdition(general, { name: "lobby", private: false }, { actorPubkey: alice, version: 2n, prevHash: generalHash, createdAtSecs: 1_700_000_005, authority }), aliceSk);
// Bob (no roles) tries to rename #random: must be dropped.
await publish(control.buildChannelEdition(random, { name: "pwned", private: false }, { actorPubkey: bob, version: 2n, prevHash: version.editionHash(random, 1n, undefined, new TextEncoder().encode('{"name":"random","private":false,"custom":{"armada.order":{"position":1}}}')), createdAtSecs: 1_700_000_006 }), bobSk);
await publish(control.buildBanlistEdition(communityId, [bob], { actorPubkey: owner, version: 1n, createdAtSecs: 1_700_000_007 }), ownerSk);

const community = {
  id: communityId, idHex: bytesToHex(communityId), owner, ownerSalt, root, rootEpoch: 0n,
  controlPk: controlSigner.pk, heldRoots: [{ epoch: 0n, key: root, controlPk: controlSigner.pk }],
  privateChannels: [], relays: [], name: "x",
};
const parsed = control.openControlWraps(editions, control.controlGroups(community));
const folded = control.foldControlState(parsed, communityId, owner);
out.control = {
  control_pk: controlSigner.pk,
  wraps: editions,
  expect: {
    name: folded.metadata?.name,
    channels: Object.fromEntries([...folded.channels].map(([id, c]: any) => [id, { name: c.name, private: c.isPrivate, deleted: c.deleted }])),
    banned: [...folded.banned],
    roles: folded.roster.roles.map((r: any) => r.roleId),
    grants: folded.roster.grants.map((g: any) => [g.member, g.roleIds]),
  },
};

// Invite links.
const token = new Uint8Array(16).fill(0x99);
const linkSignerSk = fill(0xaa);
const linkSigner = getPublicKey(linkSignerSk);
const bundle = {
  community_id: bytesToHex(communityId), owner, owner_salt: bytesToHex(ownerSalt),
  community_root: bytesToHex(root), root_epoch: 0, control_pk: controlSigner.pk,
  channels: [{ id: bytesToHex(channelId), key: bytesToHex(privateKey), epoch: 3, name: "secret" }],
  relays: ["wss://relay.example"], name: "Test Community", creator_npub: owner, label: "Reddit",
};
out.invite = {
  fragment_stock: invite.encodeFragment(token, invite.STOCK_RELAYS),
  fragment_custom: invite.encodeFragment(token, ["wss://relay.ditto.pub", "wss://relay.example.com", "ws://localhost:7777"]),
  url: invite.buildInviteUrl("https://armada.buzz", linkSigner, token, ["wss://relay.ditto.pub", "wss://relay.example.com"]),
  link_signer: linkSigner,
  token: bytesToHex(token),
  bundle_event: await invite.buildBundleEvent(bundle, token, linkSignerSk),
  bundle,
};

// A base rekey (Refounding to epoch 1) by the owner, carrying blobs for Alice (member) and the owner (staff).
const newRoot = fill(0xbb);
const newControlRoot = fill(0xcc);
const newControlPk = derive.controlSignerGroupKey(newControlRoot, communityId, 1).pk;
const prevCommit = bytesToHex(derive.epochKeyCommitment(0, root));
const memberPlain = rekey.bytesToBase64(rekey.encodeWrappedBaseKey(1n, newRoot, h(newControlPk)));
const staffPlain = rekey.bytesToBase64(rekey.encodeWrappedBaseKey(1n, newRoot, h(newControlPk), newControlRoot));
const blobs = [
  { locator: rekey.myLocator(owner, alice, "0".repeat(64), 1n), wrapped: nip44Encrypt(memberPlain, getConversationKey(ownerSk, alice)) },
  { locator: rekey.myLocator(owner, owner, "0".repeat(64), 1n), wrapped: nip44Encrypt(staffPlain, getConversationKey(ownerSk, owner)) },
];
const rekeyRumors = rekey.buildRekeyRumors(owner, { scope: { kind: "root" }, newEpoch: 1n, prevEpoch: 0n, prevCommit }, blobs, 1_700_000_100_000);
const baseAddress = derive.baseRekeyGroupKey(root, communityId, 1);
out.rekey = {
  new_root: bytesToHex(newRoot),
  new_control_root: bytesToHex(newControlRoot),
  new_control_pk: newControlPk,
  prev_commit: prevCommit,
  wraps: await Promise.all(rekeyRumors.map(async (r: any) => stream.wrapSeal(await stream.sealRumor(r, 20013, baseAddress, signer(ownerSk)), baseAddress))),
};

// A Guestbook join by Alice and a thread reply.
const gb = derive.guestbookGroupKey(root, communityId, 0);
out.guestbook = {
  wrap: await guestbook.sealGuestbook(guestbook.buildJoinRumor(alice, 1_700_000_200_000, { creator: owner, label: "Reddit" }), gb, signer(aliceSk)),
};
out.comment_tags = chat.buildConcordCommentTags({ id: msgRumor.id, kind: 9, pubkey: alice, tags: msgRumor.tags });

// The owner-side builders a custodial importer publishes with: whole rumors
// (ids included), so field order and number formatting are pinned too.
const roles = await lib("roles");
const channelCategory = await lib("channelCategory");
const channelOrder = await lib("channelOrder");
const directInvite = await lib("directInvite");
const at = { createdAtSecs: 1_700_000_300 };
const opPk = alice;
const vac = { entityId: grantEid, version: 1n, editionHash: grantHash };
let channelMeta = { name: "voice-chat", private: true };
channelMeta = channelOrder.withChannelPosition(channelMeta, 4);
channelMeta = channelCategory.withChannelCategory(channelMeta, "  Hangouts ");
channelMeta = { ...channelMeta, custom: { ...channelMeta.custom, "discord.import": { topic: "t", type: "voice" } } };
out.builders = {
  admin_role: control.buildRoleEdition(roles.adminRole(roleId), { actorPubkey: owner, version: 1n, ...at }),
  access_role: control.buildRoleEdition(
    { roleId: bytesToHex(fill(0x04)), name: "mods", position: 7, permissions: 0n, scope: { kind: "channel", channelId: bytesToHex(channelId) }, color: 0 },
    { actorPubkey: opPk, version: 1n, authority: vac, ...at },
  ),
  grant: control.buildGrantEdition(communityId, { member: opPk, roleIds: [roleId] }, { actorPubkey: owner, version: 1n, ...at }),
  owner_key_grant: control.buildGrantEdition(communityId, { member: owner, roleIds: [], controlWrap: "AbC=" }, { actorPubkey: opPk, version: 1n, authority: vac, ...at }),
  registry: control.buildRegistryEdition(communityId, owner, [linkSigner], { actorPubkey: owner, version: 1n, ...at }),
  channel: control.buildChannelEdition(channelId, channelMeta, { actorPubkey: opPk, version: 1n, authority: vac, ...at }),
  control_wrap: rekey.bytesToBase64(rekey.encodeControlWrap(3n, controlRoot)),
};

// A Direct Invite sealed by Armada to Bob, carrying a private channel key.
out.direct_invite = {
  wrap: await directInvite.wrapDirectInvite(
    await directInvite.sealDirectInvite(directInvite.buildDirectInviteRumor(bundle, owner), bob, {
      ...signer(ownerSk),
      nip44: { encrypt: async (pk: string, text: string) => nip44Encrypt(text, getConversationKey(ownerSk, pk)) },
    }),
    bob,
  ),
};

// ── Roles v2 (CORD-04 §2-§9, CORD-03 §1-§4) ──────────────────────────────────
// A second Community, switched to the vsk-13 Roster at genesis as Armada does,
// with every entity kind the switch brought: ranked Roles and `@everyone`,
// Grants under downward support, a Category, overwrites, a sync, a restricted
// Channel's Writers ledger and a sealed Private Channel — plus editions the
// fold must refuse. The Rust fold is checked against Armada's on all of it.
const roster = await lib("roster");
const writers = await lib("writers");
const channelSeal = await lib("channelSeal");
const P = roles.Permissions;
const enc = (s: string) => new TextEncoder().encode(s);

out.derive_v2 = {
  everyone_locator: bytesToHex(derive.everyoneLocator(communityId)),
  edition_binding: bytesToHex(derive.editionBinding(communityId)),
  tenure_locator: bytesToHex(derive.tenureLocator(communityId, h(alice), h(owner))),
  acl_everyone: bytesToHex(derive.aclLocator(communityId, channelId, derive.overwriteTargetBytes(communityId, "everyone"))),
  acl_role: bytesToHex(derive.aclLocator(communityId, channelId, derive.overwriteTargetBytes(communityId, "role", fill(0x03)))),
  acl_member: bytesToHex(derive.aclLocator(communityId, channelId, derive.overwriteTargetBytes(communityId, "member", h(alice)))),
  sync_locator: bytesToHex(derive.syncLocator(communityId, channelId)),
  writers_locator: bytesToHex(derive.writersLocator(communityId, channelId)),
  writer_scope: bytesToHex(derive.writerScope(channelId)),
  certifier_scope: bytesToHex(derive.certifierScope(channelId)),
  history_scope: bytesToHex(derive.historyScope(channelId)),
  channel_writer_e1: gk(derive.channelWriterGroupKey(fill(0x71), channelId, 1)),
  channel_access_e0: gk(derive.channelAccessGroupKey(root, channelId, 0)),
  wrap_owner: derive.wrapOwnerKey(aliceSk, derive.channelGroupKey(root, channelId, 0).pk, fill(0x09)).pk,
  marked_hash: bytesToHex(version.markedEditionHash(fill(0x11), 2n, fill(0x22), enc('{"name":"Mods"}'), fill(0x33))),
};

{
  const salt2 = fill(0x45);
  const cid = derive.communityIdOf(h(owner), salt2);
  const binding = derive.editionBinding(cid);
  const cRead = derive.controlGroupKey(root, cid, 0);
  const cSigner = derive.controlSignerGroupKey(controlRoot, cid, 0);
  const cWrite = { sk: cSigner.sk, pk: cSigner.pk, get convKey() { return cRead.convKey; } };
  const wraps: any[] = [];
  let t = 1_700_000_500;
  const put = async (o: { vsk: string; entityId: Uint8Array; content: string; sk: Uint8Array; version?: bigint; prevHash?: Uint8Array; authority?: any; marked?: boolean }) => {
    const actorPubkey = getPublicKey(o.sk);
    const rumor = edition.buildEditionRumor({
      vsk: o.vsk, entityId: o.entityId, version: o.version ?? 1n, prevHash: o.prevHash, content: o.content,
      actorPubkey, createdAtSecs: t++, authority: o.authority, ...(o.marked === false ? {} : { binding }),
    });
    wraps.push(await control.sealEdition(rumor, cWrite, signer(o.sk)));
    return rumor;
  };
  const cite = (member: string, content: string, signerPk: string) => {
    const entityId = derive.grantLocator(cid, h(member));
    return { entityId, version: 1n, editionHash: version.markedEditionHash(entityId, 1n, undefined, enc(content), h(signerPk)) };
  };
  const general = fill(0xa1), ann = fill(0xa2), rules = fill(0xa3), secret = fill(0xa4), cat = fill(0xc1);
  const admin = bytesToHex(fill(0xd1)), mod = bytesToHex(fill(0xd2));
  const [genHex, annHex, rulesHex, secretHex, catHex] = [general, ann, rules, secret, cat].map(bytesToHex);
  const everyoneId = derive.everyoneLocator(cid);
  const role = (roleId: string, name: string, rank: string, permissions: bigint, extra: object = {}) =>
    roster.rankedRoleToJSON({ roleId, name, rank, permissions, position: 0, scope: { kind: "server" }, color: 0, ...extra });

  // Genesis, unmarked as every client writes it, then the switch.
  await put({ vsk: "0", entityId: cid, content: JSON.stringify({ name: "Ranked" }), sk: ownerSk, marked: false });
  const genRumor = await put({ vsk: "2", entityId: general, content: JSON.stringify({ name: "general", private: false }), sk: ownerSk, marked: false });
  await put({ vsk: "13", entityId: everyoneId, content: roster.everyoneToJSON(roles.EVERYONE_DEFAULT, [genHex]), sk: ownerSk });
  await put({ vsk: "13", entityId: h(admin), content: role(admin, "Admin", "V", P.MANAGE_ROLES | P.MANAGE_CHANNELS | P.BAN | P.MANAGE_MESSAGES | P.VIEW_CHANNEL | P.SEND_MESSAGES | P.ADD_REACTIONS), sk: ownerSk });
  await put({ vsk: "13", entityId: h(mod), content: role(mod, "Mod", "W", P.MANAGE_MESSAGES | P.KICK, { mentionable: true, display: true }), sk: ownerSk });
  const aliceGrant = grantFromAlice();
  function grantFromAlice() {
    return roles.grantToJSON({ member: alice, roleIds: [admin] });
  }
  await put({ vsk: "3", entityId: derive.grantLocator(cid, h(alice)), content: aliceGrant, sk: ownerSk });
  const vacA = cite(alice, aliceGrant, owner);
  await put({ vsk: "3", entityId: derive.grantLocator(cid, h(bob)), content: roles.grantToJSON({ member: bob, roleIds: [mod] }), sk: aliceSk, authority: vacA });
  // Refused: Bob holds no Manage Roles; Alice can't mint above herself, nor hand out a bit she lacks.
  await put({ vsk: "13", entityId: fill(0xe1), content: role(bytesToHex(fill(0xe1)), "Evil", "X", P.BAN), sk: bobSk });
  await put({ vsk: "13", entityId: fill(0xe2), content: role(bytesToHex(fill(0xe2)), "Super", "U", P.KICK), sk: aliceSk, authority: vacA });
  await put({ vsk: "13", entityId: fill(0xe3), content: role(bytesToHex(fill(0xe3)), "Pinner", "Y", P.PIN_MESSAGES), sk: aliceSk, authority: vacA });
  // Alice files a Category and two Channels, renames #general, and restricts #announcements.
  await put({ vsk: "15", entityId: cat, content: JSON.stringify({ name: "Info", position: "V" }), sk: aliceSk, authority: vacA });
  await put({ vsk: "2", entityId: ann, content: JSON.stringify({ name: "announcements", private: false, category: catHex, position: "W", topic: "news" }), sk: aliceSk, authority: vacA });
  await put({ vsk: "2", entityId: rules, content: JSON.stringify({ name: "rules", private: false, category: catHex, position: "X", view: "forum" }), sk: aliceSk, authority: vacA });
  await put({ vsk: "2", entityId: general, version: 2n, prevHash: version.editionHash(general, 1n, undefined, enc(genRumor.content)), content: JSON.stringify({ name: "lobby", private: false }), sk: aliceSk, authority: vacA });
  const ow = (scope: string, target: any, allow: bigint, deny: bigint) => ({ scope, target, allow, deny });
  for (const [o, sk] of [
    [ow(annHex, { kind: "everyone" }, 0n, P.SEND_MESSAGES), aliceSk],
    [ow(annHex, { kind: "role", id: mod }, P.SEND_MESSAGES, 0n), aliceSk],
    [ow(catHex, { kind: "everyone" }, 0n, P.ADD_REACTIONS), aliceSk],
    [ow(secretHex, { kind: "member", id: bob }, P.VIEW_CHANNEL | P.SEND_MESSAGES, 0n), ownerSk],
    // Refused: Bob can't write overwrites; Alice can't touch a bit her Roles lack.
    [ow(rulesHex, { kind: "everyone" }, 0n, P.VIEW_CHANNEL), bobSk],
    [ow(rulesHex, { kind: "everyone" }, 0n, P.CONNECT), aliceSk],
  ] as const) {
    await put({ vsk: "14", entityId: roster.overwriteLocator(cid, o), content: roster.overwriteToJSON(o), sk: sk as Uint8Array, ...(sk === aliceSk ? { authority: vacA } : {}) });
  }
  await put({ vsk: "17", entityId: derive.syncLocator(cid, rules), content: roster.syncToJSON(rulesHex, catHex), sk: aliceSk, authority: vacA });
  // The restricted Channel's ledger: writer epoch 1, minted by Alice, with a certifier.
  const writerSecret = fill(0x71);
  const certifierSk = fill(0x72);
  const writerPk = derive.channelWriterGroupKey(writerSecret, ann, 1).pk;
  const ledger = writers.ledgerAppended(writers.emptyLedger(annHex), t * 1000, { kind: "writer", epoch: 1, pk: writerPk, root: 0, by: alice, certifier: getPublicKey(certifierSk) });
  await put({ vsk: "18", entityId: derive.writersLocator(cid, ann), content: writers.ledgerToJson(ledger), sk: aliceSk, authority: vacA });
  // A sealed Private Channel, born at epoch 1.
  const secretKey = fill(0x88);
  await put({ vsk: "2", entityId: secret, content: channelSeal.sealChannelMetadata({ name: "secret-plans", private: true, topic: "shh" }, secretKey, secret, 1n, undefined, { creator: owner }), sk: ownerSk });

  const comm = {
    id: cid, idHex: bytesToHex(cid), owner, ownerSalt: salt2, root, rootEpoch: 0n,
    controlPk: cSigner.pk, heldRoots: [{ epoch: 0n, key: root, controlPk: cSigner.pk }], privateChannels: [], relays: [], name: "x",
  };
  const folded = control.foldControlState(control.openControlWraps(wraps, control.controlGroups(comm)), cid, owner);
  const nobody = getPublicKey(fill(0x5e));
  const members: Record<string, string> = { owner, alice, bob, nobody };
  const chans: Record<string, string> = { general: genHex, announcements: annHex, rules: rulesHex, secret: secretHex };
  const perms: Record<string, Record<string, string>> = {};
  for (const [mn, pk] of Object.entries(members)) {
    perms[mn] = {};
    for (const [cn, id] of Object.entries(chans)) {
      perms[mn][cn] = roles.channelPermissions(folded.roster, owner, pk, id, folded.channels.get(id)?.isPrivate ?? false).toString();
    }
  }

  // Bob posts at the writer address, certified; a roleless member posts at the read address.
  const cert = writers.signWriterCert(certifierSk, writers.certDigest(cid, ann, 1, h(bob)));
  const read = derive.channelGroupKey(root, ann, 0);
  const wgroup = derive.channelWriterGroupKey(writerSecret, ann, 1);
  const post = stream.buildRumor({
    kind: 9, content: "an announcement", pubkey: bob, ms: (t + 5) * 1000,
    tags: [...stream.channelBindingTags(annHex, 0n), ["wepoch", "1"], ["wcert", cert]],
  });
  const postWrap = await stream.wrapSeal(await stream.sealRumor(post, 20013, read, signer(bobSk)), { sk: wgroup.sk, pk: wgroup.pk, get convKey() { return read.convKey; } });
  const stray = stream.buildRumor({ kind: 9, content: "can I post?", pubkey: nobody, ms: (t + 6) * 1000, tags: stream.channelBindingTags(annHex, 0n) });
  const strayWrap = await stream.wrapSeal(await stream.sealRumor(stray, 20013, read, signer(fill(0x5e))), read);
  const l = folded.writers.get(annHex);

  // The owner hands Bob, whom an overwrite let into the sealed channel, its key
  // on the channel's access plane (CORD-03 §5).
  const delivery = await (await lib("delivery")).buildAccessDeliveries(
    owner,
    async (pk: string, text: string) => nip44Encrypt(text, getConversationKey(ownerSk, pk)),
    { scopeIdHex: secretHex, epoch: 1n, key: secretKey, recipients: [bob], atSecs: t + 7 },
  );
  const access = derive.channelAccessGroupKey(root, secret, 0);
  const deliveryWraps = await Promise.all(delivery.map(async (r: any) => stream.wrapSeal(await stream.sealRumor(r, 20013, access, signer(ownerSk)), access)));

  out.ranked = {
    owner_salt: bytesToHex(salt2),
    community_id: bytesToHex(cid),
    control_pk: cSigner.pk,
    wraps,
    secret_key: bytesToHex(secretKey),
    members,
    channels: chans,
    expect: {
      ranked: folded.rankedRoster === true,
      everyone: folded.roster.everyone?.toString(),
      legacy: folded.roster.legacyChannels,
      roles: folded.roster.roles.map((r: any) => ({ id: r.roleId, name: r.name, rank: r.rank, position: r.position, permissions: r.permissions.toString(), mentionable: r.mentionable === true, display: r.display === true })),
      grants: folded.roster.grants.map((g: any) => [g.member, g.roleIds]),
      overwrites: folded.roster.overwrites.map((o: any) => [o.scope, o.target.kind, o.target.id ?? null, o.allow.toString(), o.deny.toString()]),
      syncs: folded.roster.syncs,
      categories: [...folded.categories.values()].map((c: any) => [c.idHex, c.name, c.position ?? null, c.deleted]),
      channels: Object.fromEntries([...folded.channels].map(([id, c]: any) => [id, { name: c.name, private: c.isPrivate, deleted: c.deleted, category: c.metadata.category ?? null, position: c.metadata.position ?? null, sealed: c.sealed !== undefined }])),
      writers: [...folded.writers.keys()],
      everyone_sends: Object.fromEntries(Object.entries(chans).map(([cn, id]) => [cn, roles.everyoneSends(folded.roster, id)])),
      permissions: perms,
      post_stands: writers.postStands(l, cid, { author: bob, ms: post.created_at * 1000 + 0, tags: post.tags }),
      stray_stands: writers.postStands(l, cid, { author: nobody, ms: stray.created_at * 1000, tags: stray.tags }),
    },
    writer_pk: writerPk,
    post_wrap: postWrap,
    stray_wrap: strayWrap,
    delivery_wraps: deliveryWraps,
  };
}

console.log(JSON.stringify(out, null, 2));
