/**
 * Minimal browser-side kind 0 lookup: race a REQ across a few relays, keep
 * the newest profile, give up quietly after the timeout. Just enough for an
 * avatar + name in the login chip; no subscriptions kept open.
 */

export interface NostrProfile {
  name?: string;
  picture?: string;
}

/** Aggregators most profiles land on, merged with the community relay set. */
const PROFILE_RELAYS = ["wss://purplepag.es", "wss://relay.damus.io", "wss://relay.ditto.pub"];

/**
 * An avatar URL we are willing to put in an `img src`, or undefined.
 *
 * `picture` is whatever a relay served: it reaches us unvalidated and is
 * rendered by the login chip. `javascript:` does not execute from an `img`
 * in any current browser and the CSP's `img-src` would refuse most of the
 * rest, so this is defence in depth rather than a live hole — but the check
 * belongs at the point the value enters the app, not at each render site,
 * and https-only also stops a mixed-content or `data:` surprise later.
 */
function safePictureUrl(raw: unknown): string | undefined {
  if (typeof raw !== "string" || raw === "") return undefined;
  try {
    return new URL(raw).protocol === "https:" ? raw : undefined;
  } catch {
    // not a URL at all (relative paths included: there is no base to resolve
    // an avatar against that would mean anything).
    return undefined;
  }
}

export function fetchNostrProfile(pkHex: string, relays: string[], timeoutMs = 4000): Promise<NostrProfile> {
  const urls = [...new Set([...relays, ...PROFILE_RELAYS])];
  return new Promise((resolve) => {
    let best: { created_at: number; profile: NostrProfile } | null = null;
    const sockets: WebSocket[] = [];
    let settled = false;
    let closed = 0;

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      for (const ws of sockets) {
        try {
          ws.close();
        } catch {
          // already closed
        }
      }
      resolve(best?.profile ?? {});
    };
    const timer = setTimeout(finish, timeoutMs);
    const oneDone = () => {
      closed++;
      if (closed >= urls.length) finish();
    };

    for (const url of urls) {
      try {
        const ws = new WebSocket(url);
        sockets.push(ws);
        ws.onopen = () => ws.send(JSON.stringify(["REQ", "p", { kinds: [0], authors: [pkHex], limit: 1 }]));
        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data as string) as [string, ...unknown[]];
            if (msg[0] === "EVENT") {
              const e = msg[2] as { kind: number; pubkey: string; created_at: number; content: string };
              if (e.kind !== 0 || e.pubkey !== pkHex) return;
              if (!best || e.created_at > best.created_at) {
                const c = JSON.parse(e.content) as { name?: string; display_name?: string; picture?: string };
                best = {
                  created_at: e.created_at,
                  profile: { name: c.display_name || c.name, picture: safePictureUrl(c.picture) },
                };
              }
            }
            if (msg[0] === "EOSE") ws.close();
          } catch {
            // malformed relay message; ignore
          }
        };
        ws.onerror = () => ws.close();
        ws.onclose = oneDone;
      } catch {
        oneDone();
      }
    }
    if (urls.length === 0) finish();
  });
}
