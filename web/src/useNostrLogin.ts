import { useEffect, useState } from "react";
import * as nip19 from "nostr-tools/nip19";
import { finalizeEvent, getPublicKey } from "nostr-tools/pure";
import type { EventTemplate, NostrEvent } from "nostr-tools/pure";

import { fetchNostrProfile } from "./nostrProfile";
import type { NostrProfile } from "./nostrProfile";

/** NIP-07 browser extension surface, if one is installed. */
interface Nip07 {
  getPublicKey(): Promise<string>;
  signEvent(template: EventTemplate): Promise<NostrEvent>;
}
declare global {
  interface Window { nostr?: Nip07 }
}

const LOGIN_STORE = "portal:nostr-login";

/**
 * Armada-style key login, used by the import wizard: nsec paste or NIP-07
 * extension, local signing only.
 *
 * A pasted key lives in memory for as long as the tab does and is never
 * written to storage. It used to be persisted so the login survived reloads,
 * which sounds like the ordinary Nostr-client trade until you follow what this
 * particular key is and how long it is needed: it is the community OWNER's
 * identity — the position-0 authority that `community_id` commits to, and that
 * no rotation can revoke — and the wizard signs with it exactly once, in the
 * burst between `/prepare` and `/confirm`. Nothing after `confirm` signs.
 *
 * The persistence did not even buy a resumable wizard: `step`, `importId` and
 * `plan` are component state, so a reload restarts the import from the top
 * regardless. What it bought was an owner key sitting on disk indefinitely,
 * readable by any script on an origin that also serves the Discord session.
 *
 * The extension path is unchanged: it stores only which method was used and
 * re-asks the signer, which is what persistence is supposed to look like.
 */
export function useNostrLogin(defaultRelays: string[]) {
  const [pk, setPk] = useState("");
  const [method, setMethod] = useState<"extension" | "nsec" | null>(null);
  const [nsec, setNsec] = useState("");
  const [profile, setProfile] = useState<NostrProfile>({});
  const [loginError, setLoginError] = useState("");
  const [loggingIn, setLoggingIn] = useState(false);

  // Restore a previous login on mount.
  useEffect(() => {
    const raw = localStorage.getItem(LOGIN_STORE);
    if (!raw) return;
    try {
      const stored = JSON.parse(raw) as { method: "extension" | "nsec"; nsec?: string };
      if (stored.method === "nsec") {
        // Written by an earlier build. Not restored — deleted: leaving it
        // would mean the fix only protects keys pasted from here on, while the
        // ones already on disk stay there until someone logs out.
        localStorage.removeItem(LOGIN_STORE);
      } else if (stored.method === "extension" && window.nostr) {
        void window.nostr.getPublicKey()
          .then((k) => {
            setPk(k);
            setMethod("extension");
          })
          .catch(() => localStorage.removeItem(LOGIN_STORE));
      }
    } catch {
      localStorage.removeItem(LOGIN_STORE);
    }
  }, []);

  // Look up the owner's kind 0 (avatar + name) once they log in.
  useEffect(() => {
    if (!pk) {
      setProfile({});
      return;
    }
    let stale = false;
    void fetchNostrProfile(pk, defaultRelays).then((p) => {
      if (!stale) setProfile(p);
    });
    return () => {
      stale = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pk]);

  async function connectExtension() {
    setLoginError("");
    setLoggingIn(true);
    try {
      const k = await window.nostr!.getPublicKey();
      setPk(k);
      setMethod("extension");
      localStorage.setItem(LOGIN_STORE, JSON.stringify({ method: "extension" }));
    } catch (e) {
      setLoginError(String((e as Error).message));
    } finally {
      setLoggingIn(false);
    }
  }

  function nsecKey(): Uint8Array | null {
    try {
      const decoded = nip19.decode(nsec.trim());
      return decoded.type === "nsec" ? (decoded.data as Uint8Array) : null;
    } catch {
      return null;
    }
  }

  function unlockNsec() {
    setLoginError("");
    const sk = nsecKey();
    if (!sk) {
      setLoginError("Enter a secret key starting with nsec1.");
      return;
    }
    setPk(getPublicKey(sk));
    setMethod("nsec");
  }

  function disconnect() {
    setPk("");
    setMethod(null);
    setNsec("");
    localStorage.removeItem(LOGIN_STORE);
  }

  async function signTemplate(template: EventTemplate): Promise<NostrEvent> {
    if (method === "extension") return window.nostr!.signEvent(template);
    const sk = nsecKey();
    if (!sk) throw new Error("your key is no longer available; unlock again");
    return finalizeEvent(template, sk);
  }

  return {
    pk,
    npub: pk ? nip19.npubEncode(pk) : "",
    method,
    nsec,
    setNsec,
    profile,
    loginError,
    setLoginError,
    loggingIn,
    connectExtension,
    unlockNsec,
    disconnect,
    signTemplate,
  };
}
