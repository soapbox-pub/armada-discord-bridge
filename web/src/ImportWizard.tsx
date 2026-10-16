import { useEffect, useRef, useState } from "react";
import * as nip19 from "nostr-tools/nip19";
import type { NostrEvent } from "nostr-tools/pure";

import { api } from "./api";
import type { ImportPlanView, ImportStatus, OwnerSignTemplate } from "./api";
import { NostrLogin } from "./NostrLogin";
import { useNostrLogin } from "./useNostrLogin";

interface GuildOpt { id: string; name: string }

const STEPS = ["server", "review", "import", "done"] as const;

export function ImportWizard(props: { guilds: GuildOpt[]; onDone: () => void; onCancel: () => void }) {
  const [step, setStep] = useState(0);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const [guildId, setGuildId] = useState("");
  const [installUrl, setInstallUrl] = useState("");
  const [importId, setImportId] = useState("");
  const [plan, setPlan] = useState<ImportPlanView | null>(null);

  // The user's Armada account (shared login hook; key never leaves the browser).
  const login = useNostrLogin([]);
  const [signingStep, setSigningStep] = useState("");

  const [defaultRelays, setDefaultRelays] = useState<string[]>([]);
  const [relayList, setRelayList] = useState<string[]>([]);
  const [editRelays, setEditRelays] = useState(false);
  const [newRelay, setNewRelay] = useState("");
  const [consent, setConsent] = useState(false);
  const [status, setStatus] = useState<ImportStatus | null>(null);

  async function preview(gid: string) {
    setBusy(true);
    setError("");
    setInstallUrl("");
    try {
      const res = await api<
        | { present: false; installUrl: string }
        | { present: true; importId: string; plan: ImportPlanView; defaultRelays: string[] }
      >("/api/imports", { method: "POST", body: JSON.stringify({ guildId: gid }) });
      if (!res.present) {
        setInstallUrl(res.installUrl);
        setStep(1);
        return;
      }
      setImportId(res.importId);
      setPlan(res.plan);
      setDefaultRelays(res.defaultRelays);
      setRelayList(res.defaultRelays);
      setStep(1);
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  }

  function toggleChannel(discordId: string, field: "selected" | "bridge" | "history") {
    if (!plan) return;
    setPlan({
      ...plan,
      channels: plan.channels.map((c) => {
        if (c.discordId !== discordId) return c;
        if (field === "selected") {
          const selected = !c.selected;
          return { ...c, selected, bridge: selected && c.bridge, history: selected && c.history };
        }
        if (field === "bridge") {
          const bridge = !c.bridge;
          return { ...c, bridge, history: bridge && c.history };
        }
        return { ...c, history: !c.history };
      }),
    });
  }

  // ── Prepare → sign → confirm ───────────────────────────────────────────────

  async function startImport() {
    if (!plan || !login.pk) return;
    setBusy(true);
    setError("");
    try {
      setSigningStep("preparing the community…");
      const prep = await api<{ ownerPk: string; templates: OwnerSignTemplate[] }>(
        `/api/imports/${importId}/prepare`,
        {
          method: "POST",
          body: JSON.stringify({
            ownerNpub: login.pk,
            relays: editRelays ? relayList : undefined,
            channels: plan.channels.map((c) => ({
            discordId: c.discordId,
            selected: c.selected,
            bridge: c.bridge,
            history: c.history,
          })),
          }),
        },
      );
      const signedEvents: NostrEvent[] = [];
      for (let i = 0; i < prep.templates.length; i++) {
        setSigningStep(`signing as owner (${i + 1} / ${prep.templates.length})…`);
        signedEvents.push(await login.signTemplate(prep.templates[i].template));
      }
      setSigningStep("");
      await api(`/api/imports/${importId}/confirm`, {
        method: "POST",
        body: JSON.stringify({ signedEvents }),
      });
      setStep(2);
    } catch (e) {
      setSigningStep("");
      setError(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  }

  // Poll import progress while the pipeline runs.
  const polling = step === 2;
  const importIdRef = useRef(importId);
  importIdRef.current = importId;
  useEffect(() => {
    if (!polling) return;
    let stop = false;
    const tick = async () => {
      try {
        const res = await api<ImportStatus>(`/api/imports/${importIdRef.current}`);
        if (stop) return;
        setStatus(res);
        setPlan(res.plan);
        if (res.status === "done") {
          setStep(3);
          return;
        }
      } catch {
        // transient; keep polling
      }
      if (!stop) setTimeout(() => void tick(), 2000);
    };
    void tick();
    return () => {
      stop = true;
    };
  }, [polling]);

  // The community is ready: open it in Armada in a new tab (once). A popup
  // blocker may eat this; the button below covers that case.
  const openedRef = useRef(false);
  useEffect(() => {
    if (step !== 3 || !status?.inviteUrl || openedRef.current) return;
    openedRef.current = true;
    window.open(status.inviteUrl, "_blank", "noopener");
  }, [step, status?.inviteUrl]);

  async function retry() {
    setError("");
    try {
      await api(`/api/imports/${importId}/retry`, { method: "POST" });
      setStatus(null);
    } catch (e) {
      setError(String((e as Error).message));
    }
  }

  async function rerunHistory() {
    setError("");
    try {
      await api(`/api/imports/${importId}/rerun-history`, { method: "POST" });
      setStatus(null);
      setStep(2); // back to the progress screen; polling picks it up
    } catch (e) {
      setError(String((e as Error).message));
    }
  }

  const newRelayValid = /^wss?:\/\/\S+$/.test(newRelay.trim()) && !relayList.includes(newRelay.trim());

  function addRelay() {
    const relay = newRelay.trim();
    if (!newRelayValid) return;
    setRelayList([...relayList, relay]);
    setNewRelay("");
  }

  const selectedCount = plan?.channels.filter((c) => c.selected).length ?? 0;
  const bridgeCount = plan?.channels.filter((c) => c.selected && c.bridge).length ?? 0;
  const publishedCount = plan?.channels.filter((c) => c.selected && c.publishedAt).length ?? 0;
  const wiredCount = plan?.channels.filter((c) => c.bridgeId).length ?? 0;
  const npub = login.npub;

  return (
    <div>
      <div className="steps">
        {STEPS.map((name, i) => (
          <span key={name} className={i === step ? "on" : i < step ? "done" : ""}>
            {i + 1} {name}
          </span>
        ))}
      </div>
      {error && <p className="error">{error}</p>}

      {step === 0 && (
        <div className="panel">
          <h2>Pick the Discord server to import</h2>
          <p className="muted">
            The whole server becomes a brand-new Armada community that you own: channels,
            roles, and settings. Only servers where you hold Manage Server are listed.
          </p>
          {props.guilds.map((g) => (
            <button key={g.id} className={`pick ${guildId === g.id ? "on" : ""}`} onClick={() => setGuildId(g.id)}>
              {g.name} <span className="mono muted">{g.id}</span>
            </button>
          ))}
          <div className="row" style={{ marginTop: "0.75rem" }}>
            <button disabled={!guildId || busy} onClick={() => void preview(guildId)}>
              {busy ? "Reading the server…" : "Continue"}
            </button>
            <button className="ghost" onClick={props.onCancel}>Cancel</button>
          </div>
        </div>
      )}

      {step === 1 && installUrl && (
        <div className="panel">
          <h2>Install the bot</h2>
          <p>The bridge bot is not in this server yet; it does the reading and the mirroring.</p>
          <a className="btn" href={installUrl} target="_blank" rel="noreferrer">Install the bot</a>
          <button className="ghost" style={{ marginLeft: "0.6rem" }} onClick={() => void preview(guildId)}>
            I installed it, re-check
          </button>
        </div>
      )}

      {step === 1 && plan && (
        <div className="panel">
          <h2>Review the import: {plan.communityName}</h2>
          <p className="muted">
            {selectedCount} channels will be created, {bridgeCount} of them live-bridged;{" "}
            {plan.roles.length} roles come across.
          </p>

          <h3>Your Armada account</h3>
          <p className="muted">
            The new community is owned by your key, like any community you create in
            Armada. Your key signs the founding events here in your browser and never
            reaches our server.
          </p>
          <NostrLogin login={login} />

          <h3>Channels</h3>
          {plan.channels.map((c) => (
            <div className="row" key={c.discordId} style={{ gap: "0.6rem" }}>
              <label className="consent" style={{ flex: 1 }}>
                <input type="checkbox" checked={c.selected} onChange={() => toggleChannel(c.discordId, "selected")} />
                <span>
                  #{c.name}
                  {c.category && <span className="muted"> · {c.category}</span>}
                  {c.kind === "voice" && <span className="muted"> · voice room</span>}
                </span>
              </label>
              {c.bridgeable && (
                <label className="consent">
                  <input
                    type="checkbox"
                    checked={c.bridge}
                    disabled={!c.selected}
                    onChange={() => toggleChannel(c.discordId, "bridge")}
                  />
                  <span className="muted">bridge live</span>
                </label>
              )}
              {c.bridgeable && plan.historyAllowed && (
                <label className="consent">
                  <input
                    type="checkbox"
                    checked={c.history}
                    disabled={!c.selected || !c.bridge}
                    onChange={() => toggleChannel(c.discordId, "history")}
                  />
                  <span className="muted">history</span>
                </label>
              )}
            </div>
          ))}
          {!plan.historyAllowed && (
            <p className="muted">
              Message history is not currently available for servers with more than 100
              members{plan.memberCount ? ` (this server has ~${plan.memberCount})` : ""}.
            </p>
          )}
          {plan.historyAllowed && (
            <p className="muted">
              History imports the newest 10,000 messages per channel with their original
              times and authors.
            </p>
          )}
          {plan.emojis.length > 0 && (
            <p className="muted">
              {plan.emojis.length} custom emoji will be published as an Armada emoji pack.
            </p>
          )}

          {plan.roles.length > 0 && (
            <>
              <h3>Roles</h3>
              {plan.roles.map((r) => (
                <p key={r.discordId} style={{ margin: "0.15rem 0" }}>
                  {r.name}
                  {r.dropped.length > 0 && (
                    <span className="muted"> · loses {r.dropped.join(", ")}</span>
                  )}
                </p>
              ))}
            </>
          )}

          <h3>Not imported</h3>
          {plan.skipped.map((s, i) => (
            <p key={i} className="muted" style={{ margin: "0.15rem 0" }}>
              {s.name} — {s.reason}
            </p>
          ))}

          <h3>Relays</h3>
          {relayList.map((r) => (
            <div className="row" key={r} style={{ gap: "0.6rem" }}>
              <span className="mono muted" style={{ flex: 1 }}>{r}</span>
              {editRelays && (
                <button className="ghost" onClick={() => setRelayList(relayList.filter((x) => x !== r))}>
                  Remove
                </button>
              )}
            </div>
          ))}
          {!editRelays && (
            <p className="muted">
              The standard Armada relay set.{" "}
              <button className="ghost" onClick={() => setEditRelays(true)}>Change relays</button>
            </p>
          )}
          {editRelays && (
            <>
              <div className="row" style={{ gap: "0.6rem" }}>
                <input
                  type="text"
                  placeholder="wss://relay.example.com"
                  value={newRelay}
                  style={{ flex: 1 }}
                  onChange={(e) => setNewRelay(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") addRelay();
                  }}
                />
                <button className="ghost" disabled={!newRelayValid} onClick={addRelay}>
                  Add relay
                </button>
              </div>
              <p className="muted">
                <button
                  className="ghost"
                  onClick={() => {
                    setRelayList(defaultRelays);
                    setEditRelays(false);
                    setNewRelay("");
                  }}
                >
                  Reset to the standard set
                </button>
              </p>
            </>
          )}

          <div className="disclosure">
            You will sign {""}four founding events as the community owner. The bridge
            keeps an Admin role for running the import and the live bridges; you can
            revoke it from Armada at any time. Bridged channels leave end-to-end
            encryption: their messages are mirrored to Discord in plaintext. The import
            runs once and cannot be undone from here.
          </div>
          <label className="consent">
            <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
            <span>I understand the ownership model and that bridged channels are not end-to-end encrypted.</span>
          </label>
          <div className="row" style={{ marginTop: "0.6rem" }}>
            <button
              disabled={!consent || !login.pk || selectedCount === 0 || relayList.length === 0 || busy}
              onClick={() => void startImport()}
            >
              {signingStep || "Import the server"}
            </button>
            <button className="ghost" onClick={props.onCancel}>Cancel</button>
          </div>
        </div>
      )}

      {step === 2 && (
        <div className="panel">
          <h2>Importing…</h2>
          <p className="status active" style={{ display: "inline-block" }}>
            {status?.status ?? "starting"}
          </p>
          <table>
            <tbody>
              <tr>
                <td className="muted">community</td>
                <td>{plan?.checkpoints?.communityIdHex ? "minted, owned by your key" : "minting…"}</td>
              </tr>
              <tr>
                <td className="muted">channels published</td>
                <td className="mono">{publishedCount} / {selectedCount}</td>
              </tr>
              <tr>
                <td className="muted">roles published</td>
                <td className="mono">
                  {plan?.roles.filter((r) => r.publishedAt).length ?? 0} / {plan?.roles.length ?? 0}
                </td>
              </tr>
              <tr>
                <td className="muted">bridges wired</td>
                <td className="mono">{wiredCount} / {bridgeCount}</td>
              </tr>
              {plan?.historyAllowed && plan.channels.some((c) => c.history) && (
                <tr>
                  <td className="muted">history messages</td>
                  <td className="mono">
                    {plan.channels.reduce((n, c) => n + (c.historyImported ?? 0), 0)}
                    {status?.status === "history" ? " (importing…)" : ""}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
          {status?.status === "failed" && (
            <>
              <p className="error">{status.statusDetail ?? "import failed"}</p>
              <button onClick={() => void retry()}>Retry from where it stopped</button>
            </>
          )}
        </div>
      )}

      {step === 3 && (
        <div className="panel">
          <h2>{plan?.communityName} is live on Armada</h2>
          <p>
            {publishedCount} channels created, {wiredCount} live bridges running
            {plan && plan.channels.some((c) => c.historyImported) && (
              <>, {plan.channels.reduce((n, c) => n + (c.historyImported ?? 0), 0)} history messages imported</>
            )}
            {plan && plan.emojis.length > 0 && <>, {plan.emojis.length} custom emoji packed</>}
            , owned by <span className="mono">{npub ? `${npub.slice(0, 16)}…` : "your key"}</span>.
            Your community should have opened in a new tab; if it did not:
          </p>
          {status?.inviteUrl && (
            <p>
              <a className="btn" href={status.inviteUrl} target="_blank" rel="noreferrer">
                Open your community in Armada
              </a>
            </p>
          )}
          {status?.inviteUrl && (
            <p>
              <input type="text" readOnly value={status.inviteUrl} onFocus={(e) => e.currentTarget.select()} />
              <button
                className="ghost"
                style={{ marginTop: "0.4rem" }}
                onClick={() => void navigator.clipboard.writeText(status.inviteUrl!)}
              >
                Copy invite link
              </button>
            </p>
          )}
          {plan && plan.skipped.length > 0 && (
            <>
              <h3>Not imported</h3>
              {plan.skipped.map((s, i) => (
                <p key={i} className="muted" style={{ margin: "0.15rem 0" }}>
                  {s.name} — {s.reason}
                </p>
              ))}
            </>
          )}
          {plan?.historyAllowed && plan.channels.some((c) => c.selected && c.bridge && c.history) && (
            <button className="ghost" onClick={() => void rerunHistory()}>
              Re-run history import
            </button>
          )}
          <button onClick={props.onDone}>Go to dashboard</button>
        </div>
      )}
    </div>
  );
}
