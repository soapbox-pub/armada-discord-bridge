// Folds what a server import published with Armada's own code, and checks it
// reads the community as the importer meant: ranked roles, the op's Admin, no
// staff bit on @everyone, the synced Category, the read-only channel's ledger,
// and the owner's key to the private channel admitted and authenticated.
//
//   DUMP_IMPORT=/tmp/import.json DATABASE_URL=… cargo test -p portal imports_a_guild
//   bun tools/vectors/check-import.ts /tmp/import.json
//
// ARMADA points at a checkout of the Armada client (default ~/Projects/armada).

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { getPublicKey } from "nostr-tools/pure";
import { decrypt as nip44Decrypt, getConversationKey } from "nostr-tools/nip44";

const ARMADA = process.env.ARMADA ?? `${homedir()}/Projects/armada`;
(globalThis as any).__ARMADA_BUILD_CONFIG__ = {};
const lib = (m: string) => import(`${ARMADA}/src/concord/lib/${m}.ts`);
const [derive, control, roles, stream, delivery, rekey, writers] = await Promise.all(
  ["derive", "control", "roles", "stream", "delivery", "rekey", "writers"].map(lib),
);

const { membership: m, events, owner_sk, op } = JSON.parse(readFileSync(process.argv[2], "utf8"));
const h = derive.hex32;
const cid = h(m.community_id);
const community = {
  id: cid, idHex: m.community_id, owner: m.owner, ownerSalt: h(m.owner_salt), root: h(m.root), rootEpoch: BigInt(m.root_epoch),
  controlPk: m.control_pk, heldRoots: [{ epoch: 0n, key: h(m.root), controlPk: m.control_pk }], privateChannels: [], relays: [], name: m.name,
};
const folded = control.foldControlState(control.openControlWraps(events, control.controlGroups(community)), cid, m.owner);
const failures: string[] = [];
const check = (ok: boolean, what: string) => { if (!ok) failures.push(what); };

check(folded.rankedRoster === true, "the community is on ranked roles");
check(roles.hasPermission(folded.roster, op, roles.Permissions.MANAGE_ROLES), "the op holds the owner-granted Admin");
check(!roles.isStaff(folded.roster, getPublicKey(new Uint8Array(32).fill(0x5e)), m.owner), "@everyone holds no staff bit: a stranger isn't staff");
check(folded.incomplete.length === 0, "nothing in the plane is incomplete");
check(Object.keys(folded.roster.syncs ?? {}).length >= 1, "a channel is synced to its Category");
const channels = [...folded.channels.values()] as any[];
const news = channels.find((c) => c.metadata.name === "news");
check(news && !roles.everyoneSends(folded.roster, news.channelIdHex), "#news is closed to @everyone");
const ledger = news && folded.writers?.get(news.channelIdHex);
check(ledger && writers.ledgerRestricted(ledger) && Boolean(writers.certifierOf(ledger, 1)), "#news has a certified Writers ledger");

const ownerSk = h(owner_sk);
const me = getPublicKey(ownerSk);
for (const ch of channels.filter((c) => c.isPrivate)) {
  const plane = delivery.accessPlane(community, h(ch.channelIdHex));
  let taken = false;
  for (const e of events.filter((e: any) => e.pubkey === plane.pk)) {
    const d = delivery.parseDelivery(stream.openWrap(e, plane));
    if (!d || d.form !== "access" || d.scopeIdHex !== ch.channelIdHex) continue;
    const blob = d.blobs.find((b: any) => b.locator === rekey.myLocator(d.deliverer, me, d.scopeIdHex, d.newEpoch));
    if (!blob) continue;
    const key = rekey.decodeWrappedKey(rekey.base64ToBytes(nip44Decrypt(blob.wrapped, getConversationKey(ownerSk, d.deliverer))), h(ch.channelIdHex), d.newEpoch);
    taken ||= delivery.accessDeliveryAdmits(folded, ch.sealed, ch.channelIdHex, me, d.deliverer, d.newEpoch) && !delivery.accessKeyRefuted(ch.sealed, ch.channelIdHex, d.newEpoch, key);
  }
  check(taken, `the owner takes the key to private channel ${ch.channelIdHex.slice(0, 8)}`);
}

if (failures.length) {
  console.error(`Armada disagrees with the import:\n- ${failures.join("\n- ")}`);
  process.exit(1);
}
console.log(`Armada reads the import as planned (${channels.length} channels, ${folded.roster.roles.length} roles).`);
