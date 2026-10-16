import { useCallback, useEffect, useState } from "react";

import { api } from "./api";
import type { BridgeSummary, Me } from "./api";
import { ImportWizard } from "./ImportWizard";
import { Wizard } from "./Wizard";

/**
 * Where a deep link's intent is parked while the visitor signs in. Discord's
 * OAuth callback always redirects to `/`, so reading the path straight into
 * state only works for someone who already has a session; anyone arriving cold
 * would land on the dashboard having forgotten why they came.
 */
const PENDING_VIEW_KEY = "portal:pending-view";

export function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [view, setView] = useState<"dashboard" | "wizard" | "import">("dashboard");
  const [wizardFrom, setWizardFrom] = useState<BridgeSummary | undefined>();

  // Deep link: /import, from Armada's "Import from Discord" buttons. Park the
  // intent, then clean the URL so a refresh mid-wizard doesn't restart it.
  useEffect(() => {
    if (window.location.pathname !== "/import") return;
    sessionStorage.setItem(PENDING_VIEW_KEY, "import");
    window.history.replaceState(null, "", "/");
  }, []);

  // Consume it once there's a session to act on.
  useEffect(() => {
    if (!me?.user) return;
    const pending = sessionStorage.getItem(PENDING_VIEW_KEY);
    if (!pending) return;
    sessionStorage.removeItem(PENDING_VIEW_KEY);
    // A retired `claim:<id>` parked by an older build lands here too. It is
    // already out of sessionStorage by now, and matches nothing, so it clears
    // itself rather than needing a migration.
    if (pending === "import") setView("import");
  }, [me]);

  const refresh = useCallback(() => {
    void api<Me>("/api/me").then(setMe).catch(() => setMe({ user: null, devLogin: false, discordConfigured: false }));
  }, []);
  useEffect(refresh, [refresh]);

  return (
    <>
      {me?.user && (
        <header className="masthead">
          <div className="brand">
            <LogoMark />
            <h1>Armada &#8646; Discord Bridge</h1>
          </div>
          <div className="row">
            {me.user.avatarUrl && (
              <img className="session-avatar" src={me.user.avatarUrl} alt="" referrerPolicy="no-referrer" />
            )}
            <span className="muted">{me.user.username}</span>
            <button className="ghost" onClick={() => void api("/api/auth/logout", { method: "POST" }).then(refresh)}>
              Sign out
            </button>
            <button
              className="ghost"
              title="Ends every session for this account, on every device — including this one."
              onClick={() => {
                if (!confirm("Sign out of every session for this account, on all devices?")) return;
                void api<{ revoked: number }>("/api/auth/revoke-all", { method: "POST" }).then(refresh);
              }}
            >
              Sign out everywhere
            </button>
          </div>
        </header>
      )}

      {!me && <p className="muted">Loading…</p>}
      {me && !me.user && <SignIn devLogin={me.devLogin} discordConfigured={me.discordConfigured} onSignedIn={refresh} />}
      {me?.user && view === "dashboard" && (
        <Dashboard
          onNew={(from) => { setWizardFrom(from); setView("wizard"); }}
          onImport={() => setView("import")}
        />
      )}
      {me?.user && view === "wizard" && (
        <Wizard
          guilds={me.guilds ?? []}
          from={wizardFrom}
          onDone={() => setView("dashboard")}
          onCancel={() => setView("dashboard")}
        />
      )}
      {me?.user && view === "import" && (
        <ImportWizard
          guilds={me.guilds ?? []}
          onDone={() => setView("dashboard")}
          onCancel={() => setView("dashboard")}
        />
      )}
      <Footer />
    </>
  );
}

function Footer() {
  return (
    <footer className="footer">
      <div className="footer-brand">
        <LogoMark />
        <span>Armada &#8646; Discord Bridge</span>
      </div>
      <nav className="footer-links">
        <a href="https://gitworkshop.dev/npub1jvnpg4c6ljadf5t6ry0w9q0rnm4mksde87kglkrc993z46c39axsgq89sc/armada-discord-bridge" target="_blank" rel="noreferrer">
          Source code
        </a>
        <a href="https://soapbox.pub/armada" target="_blank" rel="noreferrer">About Armada</a>
        <a href="https://armada.buzz" target="_blank" rel="noreferrer">armada.buzz</a>
        <a href="https://soapbox.pub" target="_blank" rel="noreferrer">Soapbox</a>
      </nav>
    </footer>
  );
}

function SignIn(props: { devLogin: boolean; discordConfigured: boolean; onSignedIn: () => void }) {
  return (
    <>
      <section className="hero-title">
        <LogoMark />
        <div>
          <h2>
            Armada <span className="swap">&#8646;</span> Discord Bridge
          </h2>
          <p>Mirror a channel from your Discord server into your Armada community, and back.</p>
        </div>
      </section>

      <section className="hero">
        <div className="hero-copy">
          <p>
            Each Discord user posts in Armada under their own bridged identity; each
            Armada member shows up in Discord with their own name and avatar. Replies,
            reactions, deletes, and attachments follow the messages across.
          </p>
          <p className="disclosure">
            Bridged messages leave Armada's end-to-end encryption and land on Discord's
            servers in plaintext, under Discord's terms and retention.
          </p>
          <div className="row" style={{ marginTop: "1rem" }}>
            {props.discordConfigured ? (
              <a className="btn big" href="/api/auth/discord">Sign in with Discord to get started</a>
            ) : (
              <span className="muted">
                Discord OAuth is not configured on this server (set DISCORD_CLIENT_ID and
                DISCORD_CLIENT_SECRET, restart the API).
              </span>
            )}
            {props.devLogin && (
              <button className="ghost" onClick={() => void api("/api/auth/dev", { method: "POST" }).then(props.onSignedIn)}>
                Dev login
              </button>
            )}
          </div>
        </div>
        <BridgeDemo />
      </section>

      <section className="panel landing">
        <h2>FAQ</h2>
        <div className="faq">
          <details>
            <summary>How do I set up a bridge?</summary>
            <ol>
              <li>Sign in with Discord.</li>
              <li>Pick a server and channel you manage.</li>
              <li>Paste an Armada invite link and pair the channels.</li>
              <li>An Armada moderator runs <span className="mono">/bridge confirm</span> in the channel.</li>
            </ol>
          </details>
          <details>
            <summary>Who can set one up?</summary>
            <p>
              You need Manage Server on the Discord side, and a member with Manage
              Channels on the Armada side has to confirm in the channel. Both communities
              agree before anything is mirrored.
            </p>
          </details>
          <details>
            <summary>Are bridged messages still end-to-end encrypted?</summary>
            <p>
              No. Everything posted in the paired channel, in either direction, is
              mirrored to Discord's servers in plaintext, under Discord's terms and
              retention. The wizard asks for explicit consent to this, and the bridge
              announces itself in the Armada channel.
            </p>
          </details>
          <details>
            <summary>What carries across?</summary>
            <p>
              Messages, replies, reactions, deletes, and attachments, in both directions.
              Each Discord user posts in Armada under their own bridged identity, and each
              Armada member appears in Discord with their own name and avatar.
            </p>
          </details>
          <details>
            <summary>How do we undo it?</summary>
            <p>
              Either side can pause or unlink the bridge at any time. Unlinking destroys
              the bridge's keys, and its bridged identities are unrecoverable.
            </p>
          </details>
        </div>
      </section>
    </>
  );
}

/* A bridged channel pair, each pane mocked in its platform's own chrome, with
   the real attribution the bridge produces (webhook APP badge on Discord,
   via-Discord tag on Armada). */
function BridgeDemo() {
  return (
    <div className="demo" aria-hidden="true">
      <div className="demo-pane discord">
        <div className="demo-head">
          <span className="demo-chan"><b>#</b> releases</span>
          <span className="demo-net"><DiscordMark /> Discord</span>
        </div>
        <div className="demo-msg">
          <AvatarKira id="dk" />
          <div>
            <span className="demo-name">kira <span className="demo-time">Today at 21:04</span></span>
            <p>v2 ships tonight, patch notes incoming</p>
          </div>
        </div>
        <div className="demo-msg">
          <AvatarMireille id="dm" />
          <div>
            <span className="demo-name">
              mireille <span className="demo-app">APP</span> <span className="demo-time">Today at 21:05</span>
            </span>
            <p>flagship is ready when you are ⚓</p>
          </div>
        </div>
      </div>
      <div className="demo-link">
        <span className="status active">bridged</span>
      </div>
      <div className="demo-pane armada">
        <div className="demo-head">
          <span className="demo-chan"><b>#</b> flagship</span>
          <span className="demo-net"><span className="demo-brandmark"><LogoMark /></span> Armada</span>
        </div>
        <div className="demo-msg">
          <AvatarKira id="ak" />
          <div>
            <span className="demo-name">
              kira <span className="demo-bridge-tag">via Discord</span> <span className="demo-time">21:04</span>
            </span>
            <p>v2 ships tonight, patch notes incoming</p>
          </div>
        </div>
        <div className="demo-msg">
          <AvatarMireille id="am" />
          <div>
            <span className="demo-name">mireille <span className="demo-time">21:05</span></span>
            <p>flagship is ready when you are ⚓</p>
          </div>
        </div>
      </div>
    </div>
  );
}

/* Discord's Clyde mark (simple-icons path), for the mock pane only. */
function DiscordMark() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M20.317 4.3698a19.7913 19.7913 0 00-4.8851-1.5152.0741.0741 0 00-.0785.0371c-.211.3753-.4447.8648-.6083 1.2495-1.8447-.2762-3.68-.2762-5.4868 0-.1636-.3933-.4058-.8742-.6177-1.2495a.077.077 0 00-.0785-.037 19.7363 19.7363 0 00-4.8852 1.515.0699.0699 0 00-.0321.0277C.5334 9.0458-.319 13.5799.0992 18.0578a.0824.0824 0 00.0312.0561c2.0528 1.5076 4.0413 2.4228 5.9929 3.0294a.0777.0777 0 00.0842-.0276c.4616-.6304.8731-1.2952 1.226-1.9942a.076.076 0 00-.0416-.1057c-.6528-.2476-1.2743-.5495-1.8722-.8923a.077.077 0 01-.0076-.1277c.1258-.0943.2517-.1923.3718-.2914a.0743.0743 0 01.0776-.0105c3.9278 1.7933 8.18 1.7933 12.0614 0a.0739.0739 0 01.0785.0095c.1202.099.246.1981.3728.2924a.077.077 0 01-.0066.1276 12.2986 12.2986 0 01-1.873.8914.0766.0766 0 00-.0407.1067c.3604.698.7719 1.3628 1.225 1.9932a.076.076 0 00.0842.0286c1.961-.6067 3.9495-1.5219 6.0023-3.0294a.077.077 0 00.0313-.0552c.5004-5.177-.8382-9.6739-3.5485-13.6604a.061.061 0 00-.0312-.0286zM8.02 15.3312c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9555-2.4189 2.157-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.9555 2.4189-2.1569 2.4189zm7.9748 0c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9554-2.4189 2.1569-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.946 2.4189-2.1568 2.4189Z" />
    </svg>
  );
}

/* Flat mock profile pictures; clip ids are namespaced per instance since each
   avatar renders once in each pane. */
function AvatarKira({ id }: { id: string }) {
  return (
    <svg viewBox="0 0 40 40" className="demo-avatar" aria-hidden="true">
      <defs><clipPath id={id}><circle cx="20" cy="20" r="20" /></clipPath></defs>
      <g clipPath={`url(#${id})`}>
        <rect width="40" height="40" fill="#31427c" />
        <ellipse cx="20" cy="42" rx="15" ry="12" fill="#2ec4b6" />
        <circle cx="20" cy="17.5" r="9" fill="#eab68f" />
        <path d="M11 18a9 9 0 0 1 18 0h-2.3a6.7 6.7 0 0 0-13.4 0Z" fill="#2b2118" />
        <circle cx="16.8" cy="18.5" r="1" fill="#2b2118" />
        <circle cx="23.2" cy="18.5" r="1" fill="#2b2118" />
      </g>
    </svg>
  );
}

function AvatarMireille({ id }: { id: string }) {
  return (
    <svg viewBox="0 0 40 40" className="demo-avatar" aria-hidden="true">
      <defs><clipPath id={id}><circle cx="20" cy="20" r="20" /></clipPath></defs>
      <g clipPath={`url(#${id})`}>
        <rect width="40" height="40" fill="#8f2d63" />
        <circle cx="20" cy="18" r="11.5" fill="#241b33" />
        <rect x="8.5" y="18" width="23" height="18" fill="#241b33" />
        <ellipse cx="20" cy="43" rx="11" ry="10" fill="#e84f9b" />
        <circle cx="20" cy="17.5" r="8.3" fill="#c98e63" />
        <path d="M11.7 18a8.3 8.3 0 0 1 16.6 0h-2.2a6.1 6.1 0 0 0-12.2 0Z" fill="#241b33" />
        <circle cx="17" cy="18.5" r="1" fill="#241b33" />
        <circle cx="23" cy="18.5" r="1" fill="#241b33" />
      </g>
    </svg>
  );
}

function Dashboard(props: { onNew: (from?: BridgeSummary) => void; onImport: () => void }) {
  const [bridges, setBridges] = useState<BridgeSummary[] | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    void api<{ bridges: BridgeSummary[] }>("/api/bridges")
      .then((r) => setBridges(r.bridges))
      .catch((e) => setError(String((e as Error).message)));
  }, []);
  useEffect(load, [load]);

  const [notice, setNotice] = useState("");
  async function rerunHistory(communityId: string) {
    setError("");
    setNotice("");
    try {
      await api(`/api/communities/${communityId}/rerun-history`, { method: "POST" });
      setNotice("History re-import started; messages appear in Armada as they publish.");
    } catch (e) {
      setError(String((e as Error).message));
    }
  }

  async function act(id: string, action: "pause" | "resume" | "unlink") {
    if (action === "unlink" && !confirm("Unlink this bridge? Its keys are destroyed; the puppet identities are unrecoverable.")) return;
    try {
      await api(`/api/bridges/${id}/${action}`, { method: "POST" });
      load();
    } catch (e) {
      setError(String((e as Error).message));
    }
  }

  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between" }}>
        <h2>Your bridges</h2>
        <div className="row">
          <button className="ghost" onClick={props.onImport}>Import a server</button>
          <button onClick={() => props.onNew()}>Create a bridge</button>
        </div>
      </div>
      {error && <p className="error">{error}</p>}
      {notice && <p className="muted">{notice}</p>}
      {bridges === null && <p className="muted">Loading…</p>}
      {bridges !== null && (
      <div className="frame">
      {bridges.length === 0 && (
        <p className="muted">No bridges yet. Create one to link a Discord channel with an Armada channel.</p>
      )}
      {bridges.map((b) => (
        <div className="panel" key={b.bridge_id}>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <strong>
              {b.discord_channel_name && b.concord_channel_name ? (
                <>
                  #{b.discord_channel_name} <span className="swap">&#8646;</span> #{b.concord_channel_name}
                </>
              ) : (
                b.community_name ?? "(unnamed community)"
              )}
            </strong>
            <span className={`status ${b.status}`}>{b.status}</span>
          </div>
          {b.discord_channel_name && b.concord_channel_name && (
            <div className="muted linkmeta">
              {b.discord_guild_name ?? "Discord"} (Discord) &middot; {b.community_name ?? "community"} (Armada)
            </div>
          )}
          <table>
            <tbody>
              <tr>
                <td className="muted">discord channel</td>
                <td>
                  {b.discord_channel_name ? `#${b.discord_channel_name} ` : ""}
                  <span className="mono muted">{b.discord_channel_id ?? "—"}</span>
                </td>
              </tr>
              <tr>
                <td className="muted">armada channel</td>
                <td>
                  {b.concord_channel_name ? `#${b.concord_channel_name} ` : ""}
                  <span className="mono muted">{b.concord_channel_id ? `${b.concord_channel_id.slice(0, 16)}…` : "—"}</span>
                </td>
              </tr>
              <tr>
                <td className="muted">bridge npub (for mods)</td>
                <td className="mono">{b.primary_pk ? `${b.primary_pk.slice(0, 16)}…` : "—"}</td>
              </tr>
              <tr>
                <td className="muted">messages bridged</td>
                <td className="mono">{b.bridged_count}</td>
              </tr>
              {b.status_detail && (
                <tr>
                  <td className="muted">detail</td>
                  <td>{b.status_detail}</td>
                </tr>
              )}
            </tbody>
          </table>
          <div className="row" style={{ marginTop: "0.6rem" }}>
            {b.community_id && b.discord_guild_id && (
              <button className="ghost" onClick={() => props.onNew(b)}>Add channel</button>
            )}
            {b.community_id && (
              <button className="ghost" onClick={() => void rerunHistory(b.community_id!)}>
                Re-run history import
              </button>
            )}
            {b.status === "active" && <button className="ghost" onClick={() => void act(b.bridge_id, "pause")}>Pause</button>}
            {(b.status === "paused" || b.status === "severed") && (
              <button className="ghost" onClick={() => void act(b.bridge_id, "resume")}>Resume</button>
            )}
            <button className="danger" onClick={() => void act(b.bridge_id, "unlink")}>Unlink</button>
          </div>
        </div>
      ))}
      </div>
      )}
    </div>
  );
}

/* Armada crest (public/logo-mark.svg inlined so currentColor takes the theme). */
function LogoMark() {
  return (
    <svg viewBox="0 0 256 256" fill="none" aria-hidden="true" className="logo-mark">
      <path
        d="M64 16 H232 a8 8 0 0 1 8 8 V192 L192 240 H24 a8 8 0 0 1 -8 -8 V64 Z"
        fill="none" stroke="currentColor" strokeWidth="10"
      />
      <path d="M128 56 L180 162 H158 L128 100 L98 162 H76 Z" fill="currentColor" />
      <path d="M106 134 H150 L158 150 H98 Z" fill="var(--logo-bg, #0e0a12)" />
      <g stroke="currentColor" strokeLinecap="round" opacity="0.55">
        <path d="M88 184 H168" strokeWidth="6" />
        <path d="M104 200 H152" strokeWidth="4" opacity="0.7" />
      </g>
    </svg>
  );
}
