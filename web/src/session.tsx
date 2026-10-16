import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import { api, UNAUTHORIZED_EVENT } from "@/api";
import type { Me } from "@/api";

/**
 * Where a deep link's destination is parked while the visitor signs in.
 * Discord's OAuth callback always redirects to `/`, so a signed-out visitor
 * who arrived at, say, /import from Armada's "Import from Discord" button
 * would otherwise land on the dashboard having forgotten why they came.
 */
const PENDING_PATH_KEY = "portal:pending-view";

/**
 * Only same-app paths: the value is replayed into navigate(), and something
 * like `//evil.example` is a path to a router but a host to a browser.
 * Older builds parked the bare word `import` (and, before that, a retired
 * `claim:<id>`); the first still means /import, the second matches nothing
 * and clears itself.
 */
function parkedPath(raw: string | null): string | null {
  if (raw === "import") return "/import";
  if (!raw || !raw.startsWith("/") || raw.startsWith("//")) return null;
  return raw;
}

interface Session {
  me: Me | null;
  refresh: () => Promise<void>;
  signOut: () => Promise<void>;
  signOutEverywhere: () => Promise<number>;
}

const SessionContext = createContext<Session | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const location = useLocation();
  const navigate = useNavigate();

  const refresh = useCallback(async () => {
    try {
      setMe(await api<Me>("/api/me"));
    } catch {
      setMe({ user: null, devLogin: false, discordConfigured: false });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // A session can expire under an open tab; re-read it rather than leave
  // every page showing "unauthorized" errors.
  useEffect(() => {
    const onUnauthorized = () => void refresh();
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, [refresh]);

  // Signed out on a deep link: park it for after the OAuth round trip.
  // Browsing back to the front page abandons it.
  const signedOut = me !== null && !me.user;
  useEffect(() => {
    if (!signedOut) return;
    if (location.pathname === "/") sessionStorage.removeItem(PENDING_PATH_KEY);
    else sessionStorage.setItem(PENDING_PATH_KEY, location.pathname + location.search);
  }, [signedOut, location.pathname, location.search]);

  // Signed in with something parked: go there, once.
  const signedIn = Boolean(me?.user);
  useEffect(() => {
    if (!signedIn) return;
    const pending = parkedPath(sessionStorage.getItem(PENDING_PATH_KEY));
    sessionStorage.removeItem(PENDING_PATH_KEY);
    if (pending && pending !== location.pathname + location.search) navigate(pending, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signedIn]);

  const signOut = useCallback(async () => {
    await api("/api/auth/logout", { method: "POST" });
    navigate("/", { replace: true });
    await refresh();
  }, [navigate, refresh]);

  const signOutEverywhere = useCallback(async () => {
    const res = await api<{ revoked: number }>("/api/auth/revoke-all", { method: "POST" });
    navigate("/", { replace: true });
    await refresh();
    return res.revoked;
  }, [navigate, refresh]);

  return <SessionContext.Provider value={{ me, refresh, signOut, signOutEverywhere }}>{children}</SessionContext.Provider>;
}

export function useSession(): Session {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error("useSession outside SessionProvider");
  return ctx;
}

/** For pages behind the signed-in gate, where `me.user` is known non-null. */
export function useMe() {
  const { me } = useSession();
  return { user: me!.user!, guilds: me?.guilds ?? [] };
}
