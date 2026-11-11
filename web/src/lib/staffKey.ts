import { api } from "@/api";
import type { EventTemplate } from "nostr-tools/pure";
import type { useNostrLogin } from "@/useNostrLogin";

/**
 * Hand the owner of an imported community its staff write key: without it
 * Armada won't let them change a single setting.
 *
 * The portal holds the key and can't deliver it itself: on Roles v2 only the
 * owner may sign a Grant naming the owner, and Armada opens that Grant's wrap
 * with the owner↔owner key, which needs the owner's secret. So the portal
 * sends the key wrapped op→owner, the owner's signer opens it and wraps it to
 * themselves, and the owner signs the Grant the portal builds around it.
 */
export async function deliverStaffKey(importId: string, login: ReturnType<typeof useNostrLogin>): Promise<void> {
  const base = `/api/imports/${importId}/staff-key`;
  const offer = await api<{ ownerPk: string; opPk: string; wrap: string }>(base);
  if (offer.ownerPk !== login.pk) throw new Error("Log in with the key that owns this community.");
  const signer = login.nip44Signer();
  const controlWrap = await signer.encrypt(offer.ownerPk, await signer.decrypt(offer.opPk, offer.wrap));
  const { template } = await api<{ template: EventTemplate }>(base, { method: "POST", body: JSON.stringify({ controlWrap }) });
  const signed = await login.signTemplate(template);
  await api(base, { method: "POST", body: JSON.stringify({ controlWrap, signed }) });
}
