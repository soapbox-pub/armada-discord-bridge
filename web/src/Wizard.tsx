import { useEffect, useState } from "react";

import { api } from "./api";
import type { BridgeSummary } from "./api";

interface GuildOpt { id: string; name: string }
interface ChannelOpt { id: string; name: string }
interface ConcordChannel { idHex: string; name: string }

const STEPS = ["guild", "channel", "armada", "pair", "confirm"] as const;

export function Wizard(props: {
  guilds: GuildOpt[];
  /** Add-channel mode: reuse this bridge's community; no invite link asked. */
  from?: BridgeSummary;
  onDone: () => void;
  onCancel: () => void;
}) {
  const [step, setStep] = useState(0);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const [guildId, setGuildId] = useState("");
  const [botPresent, setBotPresent] = useState<boolean | null>(null);
  const [installUrl, setInstallUrl] = useState("");
  const [channels, setChannels] = useState<ChannelOpt[]>([]);
  const [channelId, setChannelId] = useState("");
  const [inviteUrl, setInviteUrl] = useState("");
  const [bridgeId, setBridgeId] = useState("");
  const [communityName, setCommunityName] = useState("");
  const [concordChannels, setConcordChannels] = useState<ConcordChannel[]>([]);
  const [concordChannelId, setConcordChannelId] = useState("");
  const [consent, setConsent] = useState(false);
  const [status, setStatus] = useState("pending_confirm");

  async function checkBot(gid: string) {
    setBusy(true);
    setError("");
    try {
      const res = await api<{ present: boolean; channels?: ChannelOpt[]; installUrl?: string }>(
        `/api/guilds/${gid}/channels`,
      );
      setBotPresent(res.present);
      if (res.present) setChannels(res.channels ?? []);
      else setInstallUrl(res.installUrl ?? "");
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  }

  async function submitInvite(body: { inviteUrl: string } | { fromBridgeId: string }, advance: boolean) {
    setBusy(true);
    setError("");
    try {
      const res = await api<{ bridgeId: string; community: { name: string }; channels: ConcordChannel[] }>(
        "/api/bridges",
        { method: "POST", body: JSON.stringify(body) },
      );
      setBridgeId(res.bridgeId);
      setCommunityName(res.community.name);
      setConcordChannels(res.channels);
      if (advance) setStep(3);
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  }

  // Add-channel mode: the community is known, so mint the draft from the
  // stored invite right away and start at the Discord channel pick.
  useEffect(() => {
    if (!props.from?.discord_guild_id) return;
    setGuildId(props.from.discord_guild_id);
    setStep(1);
    void checkBot(props.from.discord_guild_id);
    void submitInvite({ fromBridgeId: props.from.bridge_id }, false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function submitLink() {
    setBusy(true);
    setError("");
    try {
      await api(`/api/bridges/${bridgeId}/link`, {
        method: "POST",
        body: JSON.stringify({ guildId, channelId, concordChannelId, consent }),
      });
      setStep(4);
    } catch (e) {
      setError(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (step !== 4 || !bridgeId) return;
    const source = new EventSource(`/api/bridges/${bridgeId}/events`);
    source.onmessage = (event) => {
      const data = JSON.parse(event.data) as { status: string };
      setStatus(data.status);
      if (data.status === "active") source.close();
    };
    return () => source.close();
  }, [step, bridgeId]);

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
          <h2>Pick the Discord server</h2>
          <p className="muted">Only servers where you hold Manage Server are listed.</p>
          {props.guilds.map((g) => (
            <button key={g.id} className={`pick ${guildId === g.id ? "on" : ""}`} onClick={() => setGuildId(g.id)}>
              {g.name} <span className="mono muted">{g.id}</span>
            </button>
          ))}
          <div className="row" style={{ marginTop: "0.75rem" }}>
            <button disabled={!guildId || busy} onClick={() => { setStep(1); void checkBot(guildId); }}>
              Continue
            </button>
            <button className="ghost" onClick={props.onCancel}>Cancel</button>
          </div>
        </div>
      )}

      {step === 1 && (
        <div className="panel">
          <h2>Install the bot, pick the channel</h2>
          {props.from && (
            <p className="muted">
              Adding a channel to {props.from.community_name ?? "the community"}; the stored
              invite is reused, no new link needed.
            </p>
          )}
          {botPresent === null && <p className="muted">Checking…</p>}
          {botPresent === false && (
            <>
              <p>The bridge bot is not in this server yet.</p>
              <a className="btn" href={installUrl} target="_blank" rel="noreferrer">Install the bot</a>
              <button className="ghost" style={{ marginLeft: "0.6rem" }} onClick={() => void checkBot(guildId)}>
                I installed it, re-check
              </button>
            </>
          )}
          {botPresent && (
            <>
              {channels.map((ch) => (
                <button key={ch.id} className={`pick ${channelId === ch.id ? "on" : ""}`} onClick={() => setChannelId(ch.id)}>
                  #{ch.name}
                </button>
              ))}
              <div className="row" style={{ marginTop: "0.75rem" }}>
                <button
                  disabled={!channelId || (props.from && !bridgeId) || busy}
                  onClick={() => setStep(props.from ? 3 : 2)}
                >
                  Continue
                </button>
              </div>
            </>
          )}
        </div>
      )}

      {step === 2 && (
        <div className="panel">
          <h2>Connect Armada</h2>
          <p className="muted">
            Paste an Armada invite link. Mint a dedicated invite for the bridge so the
            community can revoke it independently later.
          </p>
          <input
            type="url"
            placeholder="https://armada.buzz/invite/naddr1…#…"
            value={inviteUrl}
            onChange={(e) => setInviteUrl(e.target.value)}
          />
          <div className="row" style={{ marginTop: "0.75rem" }}>
            <button disabled={!inviteUrl || busy} onClick={() => void submitInvite({ inviteUrl }, true)}>
              {busy ? "Resolving…" : "Resolve invite"}
            </button>
          </div>
        </div>
      )}

      {step === 3 && (
        <div className="panel">
          <h2>Pair channels in {communityName}</h2>
          {concordChannels.map((ch) => (
            <button
              key={ch.idHex}
              className={`pick ${concordChannelId === ch.idHex ? "on" : ""}`}
              onClick={() => setConcordChannelId(ch.idHex)}
            >
              #{ch.name} <span className="mono muted">{ch.idHex.slice(0, 12)}…</span>
            </button>
          ))}
          <div className="disclosure">
            Bridged messages leave Concord's end-to-end encryption. Everything posted in
            the paired channel, in either direction, is mirrored to Discord's servers in
            plaintext, under Discord's terms and retention.
          </div>
          <label className="consent">
            <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
            <span>I understand the paired channel's messages will no longer be end-to-end encrypted.</span>
          </label>
          <button disabled={!concordChannelId || !consent || busy} onClick={() => void submitLink()}>
            Request the bridge
          </button>
        </div>
      )}

      {step === 4 && (
        <div className="panel">
          <h2>Waiting for Armada-side confirmation</h2>
          <p>
            The bridge posted a confirmation request into the Armada channel. Any member
            holding <span className="mono">Manage Channels</span> can enable it by replying there:
          </p>
          <p className="mono muted">/bridge confirm &lt;code shown in the channel&gt;</p>
          {status === "pending_confirm" && <p className="status pending_confirm">waiting for confirmation…</p>}
          {status === "active" && (
            <>
              <p className="status active">bridge active</p>
              <p>Messages now flow both ways.</p>
              <button onClick={props.onDone}>Go to dashboard</button>
            </>
          )}
          {status !== "pending_confirm" && status !== "active" && (
            <p className="error">bridge state: {status}</p>
          )}
        </div>
      )}
    </div>
  );
}
