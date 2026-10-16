import { ArrowLeftRight, Check, ExternalLink, Hash, Link2, Loader2, RefreshCw, ShieldAlert } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { Navigate, Route, Routes, useLocation, useNavigate, useSearchParams } from "react-router-dom";

import { api, listBridges } from "@/api";
import { GuildIcon } from "@/components/common";
import { Crest, DiscordMark } from "@/components/brand/marks";
import { PickRow, WizardShell, WizardStepBody, useFlowNav } from "@/components/WizardShell";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { toast } from "@/components/ui/toaster";
import { errText } from "@/lib/utils";
import { useMe } from "@/session";

interface ConcordChannel { idHex: string; name: string }

/**
 * What the wizard has gathered so far, mirrored to sessionStorage so a reload
 * resumes the step instead of starting over. Not the invite link: it carries
 * the community's invite secret, and once it resolves the server holds it,
 * sealed, on the draft (`bridgeId`), so there is no reason to keep a copy here.
 */
interface Draft {
  /** Add-channel mode: the bridge whose community (and sealed invite) is reused. */
  from?: string;
  guildId?: string;
  channelId?: string;
  channelName?: string;
  bridgeId?: string;
  communityName?: string;
  concordChannels?: ConcordChannel[];
  concordChannelId?: string;
}

const DRAFT_KEY = "portal:new-bridge";

function loadDraft(): Draft {
  try {
    return JSON.parse(sessionStorage.getItem(DRAFT_KEY) ?? "{}") as Draft;
  } catch {
    return {};
  }
}

interface Flow {
  draft: Draft;
  update: (patch: Partial<Draft>) => void;
  reset: (to?: Draft) => void;
  steps: string[];
  close: () => void;
}

const FlowContext = createContext<Flow | null>(null);
const useFlow = () => useContext(FlowContext)!;

const STEPS = ["/new", "/new/channel", "/new/armada", "/new/pair"];
const FROM_STEPS = ["/new/channel", "/new/pair"];

export function NewBridge() {
  const [draft, setDraft] = useState<Draft>(loadDraft);
  const [params] = useSearchParams();
  const from = params.get("from");
  const navigate = useNavigate();

  useEffect(() => {
    sessionStorage.setItem(DRAFT_KEY, JSON.stringify(draft));
  }, [draft]);

  const update = useCallback((patch: Partial<Draft>) => setDraft((d) => ({ ...d, ...patch })), []);
  const reset = useCallback((to: Draft = {}) => setDraft(to), []);
  const close = useCallback(() => {
    sessionStorage.removeItem(DRAFT_KEY);
    navigate("/", { replace: true });
  }, [navigate]);

  const steps = draft.from ? FROM_STEPS : STEPS;
  const flow: Flow = { draft, update, reset, steps, close };

  // `?from=<bridge>` starts add-channel mode: same community, same guild, the
  // stored invite reused. Resolved once, then the URL drops the parameter.
  if (from && draft.from !== from) {
    return (
      <FlowContext.Provider value={flow}>
        <StartFromBridge from={from} />
      </FlowContext.Provider>
    );
  }

  return (
    <FlowContext.Provider value={flow}>
      <Routes>
        <Route index element={<ServerStep />} />
        <Route path="channel" element={<ChannelStep />} />
        <Route path="armada" element={<ArmadaStep />} />
        <Route path="pair" element={<PairStep />} />
        <Route path="*" element={<Navigate to="/new" replace />} />
      </Routes>
    </FlowContext.Provider>
  );
}

function Shell({ path, onBack, children, wide }: { path: string; onBack?: () => void; children: ReactNode; wide?: boolean }) {
  const { steps, close } = useFlow();
  return (
    <WizardShell
      index={Math.max(0, steps.indexOf(path))}
      total={steps.length}
      stepKey={path}
      maxWidth={wide ? "max-w-xl" : "max-w-md"}
      onBack={onBack}
      onClose={close}
    >
      {children}
    </WizardShell>
  );
}

function ErrorLine({ error }: { error: string }) {
  if (!error) return null;
  return (
    <Alert variant="destructive">
      <AlertDescription>{error}</AlertDescription>
    </Alert>
  );
}

const discordGlyph = <DiscordMark className="size-14 text-discord" />;

function StartFromBridge({ from }: { from: string }) {
  const { reset, close } = useFlow();
  const navigate = useNavigate();
  const [error, setError] = useState("");

  useEffect(() => {
    let stale = false;
    void (async () => {
      try {
        const source = (await listBridges()).find((b) => b.bridge_id === from);
        if (!source?.discord_guild_id) throw new Error("That bridge isn't available to copy from.");
        const res = await api<{ bridgeId: string; community: { name: string }; channels: ConcordChannel[] }>("/api/bridges", {
          method: "POST",
          body: JSON.stringify({ fromBridgeId: from }),
        });
        if (stale) return;
        reset({
          from,
          guildId: source.discord_guild_id,
          bridgeId: res.bridgeId,
          communityName: res.community.name,
          concordChannels: res.channels,
        });
        navigate("/new/channel", { replace: true });
      } catch (e) {
        if (!stale) setError(errText(e));
      }
    })();
    return () => {
      stale = true;
    };
  }, [from, reset, navigate]);

  return (
    <WizardShell index={0} total={0} stepKey="from" onClose={close}>
      <WizardStepBody
        glyph={<Crest className="size-14" />}
        title={error ? "can't add a channel" : "opening the community…"}
        description={error || "Reusing the invite this community was bridged with."}
      >
        {!error && <Loader2 className="mx-auto size-5 animate-spin text-muted-foreground" />}
      </WizardStepBody>
    </WizardShell>
  );
}

// ── 1. Server ────────────────────────────────────────────────────────────────

function ServerStep() {
  const { guilds } = useMe();
  const { draft, update, reset } = useFlow();
  const { next } = useFlowNav();

  // Arriving here plainly after an add-channel run: that run's state is stale.
  useEffect(() => {
    if (draft.from) reset();
  }, [draft.from, reset]);

  return (
    <Shell path="/new">
      <WizardStepBody
        glyph={discordGlyph}
        title="pick a server"
        description="Choose the Discord server whose channel you want to bridge. Only servers where you hold Manage Server are listed."
      >
        <div className="space-y-3">
          {guilds.length === 0 && (
            <p className="text-sm text-muted-foreground">No servers found where you hold Manage Server.</p>
          )}
          <div className="space-y-1.5">
            {guilds.map((g) => (
              <PickRow
                key={g.id}
                selected={draft.guildId === g.id}
                onClick={() => {
                  if (draft.guildId !== g.id) update({ guildId: g.id, channelId: undefined, channelName: undefined });
                }}
              >
                <GuildIcon name={g.name} icon={g.icon} />
                <span className="min-w-0 flex-1 truncate text-sm font-medium">{g.name}</span>
                {draft.guildId === g.id && <Check className="size-4 shrink-0 text-primary" />}
              </PickRow>
            ))}
          </div>
          <Button size="lg" className="w-full clip-corner-lg" disabled={!draft.guildId} onClick={() => next("/new/channel")}>
            Continue
          </Button>
        </div>
      </WizardStepBody>
    </Shell>
  );
}

// ── 2. Channel (and the bot install, if it's missing) ────────────────────────

function ChannelStep() {
  const { guilds } = useMe();
  const { draft, update } = useFlow();
  const { next, back } = useFlowNav();
  const [state, setState] = useState<
    { kind: "loading" } | { kind: "missing"; installUrl: string } | { kind: "ready"; channels: Array<{ id: string; name: string }> }
  >({ kind: "loading" });
  const [error, setError] = useState("");
  const [checking, setChecking] = useState(false);

  const check = useCallback(async () => {
    if (!draft.guildId) return;
    setChecking(true);
    setError("");
    try {
      const res = await api<{ present: boolean; channels?: Array<{ id: string; name: string }>; installUrl?: string }>(
        `/api/guilds/${draft.guildId}/channels`,
      );
      setState(res.present ? { kind: "ready", channels: res.channels ?? [] } : { kind: "missing", installUrl: res.installUrl ?? "" });
    } catch (e) {
      setError(errText(e));
    } finally {
      setChecking(false);
    }
  }, [draft.guildId]);

  useEffect(() => {
    void check();
  }, [check]);

  if (!draft.guildId) return <Navigate to="/new" replace />;
  const guild = guilds.find((g) => g.id === draft.guildId);
  const onBack = draft.from ? undefined : () => back("/new");

  if (state.kind === "missing") {
    return (
      <Shell path="/new/channel" onBack={onBack}>
        <ErrorLine error={error} />
        <WizardStepBody
          glyph={discordGlyph}
          title="install the bot"
          description={
            <>
              The bridge bot isn't in <span className="text-foreground">{guild?.name ?? "this server"}</span> yet. It's what
              reads the channel and posts Armada's messages into it, so it has to be invited first.
            </>
          }
        >
          <div className="space-y-3">
            <Button asChild size="lg" className="w-full clip-corner-lg">
              <a href={state.installUrl} target="_blank" rel="noopener noreferrer">
                <DiscordMark /> Install the bot <ExternalLink className="opacity-60" />
              </a>
            </Button>
            <Button variant="secondary" className="w-full clip-corner-lg" disabled={checking} onClick={() => void check()}>
              {checking ? <Loader2 className="animate-spin" /> : <RefreshCw />} I installed it, check again
            </Button>
          </div>
        </WizardStepBody>
      </Shell>
    );
  }

  const target = draft.from ? "/new/pair" : "/new/armada";
  return (
    <Shell path="/new/channel" onBack={onBack}>
      <ErrorLine error={error} />
      <WizardStepBody
        glyph={guild ? <GuildIcon name={guild.name} icon={guild.icon} className="size-14 rounded-2xl text-base" /> : discordGlyph}
        title="pick a channel"
        description={
          draft.from ? (
            <>
              Adding a channel to <span className="text-foreground">{draft.communityName}</span>. The community's stored invite is
              reused, so there's no new link to paste.
            </>
          ) : (
            <>Which channel in <span className="text-foreground">{guild?.name ?? "the server"}</span> should be mirrored?</>
          )
        }
      >
        <div className="space-y-3">
          {state.kind === "loading" ? (
            <div className="flex justify-center py-6">
              <Loader2 className="size-5 animate-spin text-muted-foreground" />
            </div>
          ) : state.channels.length === 0 ? (
            <p className="text-sm text-muted-foreground">The bot can't see any text channels in this server.</p>
          ) : (
            <div className="max-h-[45vh] space-y-1 overflow-y-auto rounded-lg bg-secondary/30 p-1 text-left">
              {state.channels.map((ch) => (
                <button
                  key={ch.id}
                  type="button"
                  onClick={() => update({ channelId: ch.id, channelName: ch.name })}
                  className={`flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-sm transition-colors ${
                    draft.channelId === ch.id ? "bg-primary/15 text-foreground" : "hover:bg-secondary/60"
                  }`}
                >
                  <Hash className="size-4 shrink-0 text-muted-foreground" />
                  <span className="min-w-0 flex-1 truncate text-left">{ch.name}</span>
                  {draft.channelId === ch.id && <Check className="size-4 shrink-0 text-primary" />}
                </button>
              ))}
            </div>
          )}
          <Button
            size="lg"
            className="w-full clip-corner-lg"
            disabled={!draft.channelId || state.kind !== "ready" || (Boolean(draft.from) && !draft.bridgeId)}
            onClick={() => next(target)}
          >
            Continue
          </Button>
        </div>
      </WizardStepBody>
    </Shell>
  );
}

// ── 3. Armada invite ─────────────────────────────────────────────────────────

function ArmadaStep() {
  const { draft, update } = useFlow();
  const { next, back } = useFlowNav();
  const [invite, setInvite] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  if (draft.from) return <Navigate to="/new/pair" replace />;
  if (!draft.guildId) return <Navigate to="/new" replace />;
  if (!draft.channelId) return <Navigate to="/new/channel" replace />;

  async function resolve() {
    setBusy(true);
    setError("");
    try {
      const res = await api<{ bridgeId: string; community: { name: string }; channels: ConcordChannel[] }>("/api/bridges", {
        method: "POST",
        body: JSON.stringify({ inviteUrl: invite.trim() }),
      });
      update({ bridgeId: res.bridgeId, communityName: res.community.name, concordChannels: res.channels, concordChannelId: undefined });
      setInvite("");
      next("/new/pair");
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Shell path="/new/armada" onBack={() => back("/new/channel")}>
      <ErrorLine error={error} />
      <WizardStepBody
        glyph={<Crest className="size-14" />}
        title="connect armada"
        description="Paste an invite link to the Armada community. Mint one just for the bridge, so the community can revoke it on its own later."
      >
        <div className="space-y-3 text-left">
          {draft.bridgeId && draft.communityName && (
            <button
              type="button"
              onClick={() => next("/new/pair")}
              className="flex w-full items-center gap-3 clip-corner-lg bg-primary/15 p-3 text-left transition-colors hover:bg-primary/20"
            >
              <Crest className="size-8 shrink-0" />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm font-medium">{draft.communityName}</span>
                <span className="block text-xs text-muted-foreground">Already connected. Continue with this community</span>
              </span>
              <Check className="size-4 shrink-0 text-primary" />
            </button>
          )}
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (invite.trim() && !busy) void resolve();
            }}
          >
            <div className="relative">
              <Link2 className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                type="url"
                autoFocus={!draft.bridgeId}
                placeholder="https://armada.buzz/invite/naddr1…#…"
                value={invite}
                onChange={(e) => setInvite(e.target.value)}
                className="h-11 pl-9 font-mono text-xs"
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <Button type="submit" size="lg" className="w-full clip-corner-lg" disabled={!invite.trim() || busy}>
              {busy ? <><Loader2 className="animate-spin" /> Resolving the invite…</> : draft.bridgeId ? "Use this invite instead" : "Continue"}
            </Button>
          </form>
          <p className="text-center text-xs text-muted-foreground">
            In Armada, open the community's menu and choose <span className="text-foreground">Invite people</span>.
          </p>
        </div>
      </WizardStepBody>
    </Shell>
  );
}

// ── 4. Pair + consent ────────────────────────────────────────────────────────

function PairStep() {
  const { draft, update, steps } = useFlow();
  const { back } = useFlowNav();
  const navigate = useNavigate();
  const location = useLocation();
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  if (!draft.guildId) return <Navigate to="/new" replace />;
  if (!draft.channelId) return <Navigate to="/new/channel" replace />;
  if (!draft.bridgeId || !draft.concordChannels) return <Navigate to={draft.from ? "/new/channel" : "/new/armada"} replace />;

  async function submit() {
    setBusy(true);
    setError("");
    try {
      await api(`/api/bridges/${draft.bridgeId}/link`, {
        method: "POST",
        body: JSON.stringify({ guildId: draft.guildId, channelId: draft.channelId, concordChannelId: draft.concordChannelId, consent }),
      });
      sessionStorage.removeItem(DRAFT_KEY);
      toast({ title: "Bridge requested", description: "Waiting for an Armada moderator to confirm." });
      navigate(`/bridges/${draft.bridgeId}`, { replace: true });
    } catch (e) {
      setError(errText(e));
      setBusy(false);
    }
  }

  const prev = steps[steps.indexOf(location.pathname) - 1] ?? "/new/channel";
  return (
    <Shell path="/new/pair" onBack={() => back(prev)} wide>
      <ErrorLine error={error} />
      <WizardStepBody
        glyph={<ArrowLeftRight className="size-14 text-primary" />}
        title="pair the channels"
        description={
          <>
            Pick the channel in <span className="text-foreground">{draft.communityName}</span> that{" "}
            <span className="font-mono text-foreground">#{draft.channelName}</span> should mirror.
          </>
        }
      >
        <div className="space-y-5 text-left">
          {draft.concordChannels.length === 0 ? (
            <p className="text-center text-sm text-muted-foreground">This community has no text channels the bridge can see.</p>
          ) : (
            <div className="max-h-[38vh] space-y-1 overflow-y-auto rounded-lg bg-secondary/30 p-1">
              {draft.concordChannels.map((ch) => (
                <button
                  key={ch.idHex}
                  type="button"
                  onClick={() => update({ concordChannelId: ch.idHex })}
                  className={`flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-sm transition-colors ${
                    draft.concordChannelId === ch.idHex ? "bg-primary/15 text-foreground" : "hover:bg-secondary/60"
                  }`}
                >
                  <Hash className="size-4 shrink-0 text-muted-foreground" />
                  <span className="min-w-0 flex-1 truncate text-left font-mono">{ch.name}</span>
                  {draft.concordChannelId === ch.idHex && <Check className="size-4 shrink-0 text-primary" />}
                </button>
              ))}
            </div>
          )}

          <Alert variant="warning">
            <ShieldAlert />
            <AlertDescription className="text-xs leading-relaxed">
              <strong className="font-semibold">This channel leaves end-to-end encryption.</strong> Everything posted in it, from
              either side, is mirrored to Discord's servers in plaintext under Discord's terms and retention. The bridge
              announces itself in the Armada channel.
            </AlertDescription>
          </Alert>

          <label className="flex cursor-pointer items-start gap-2.5">
            <Checkbox checked={consent} onCheckedChange={(v) => setConsent(v === true)} className="mt-0.5" />
            <span className="text-xs leading-relaxed text-muted-foreground">
              I understand the paired channel's messages will no longer be end-to-end encrypted.
            </span>
          </label>

          <Button size="lg" className="w-full clip-corner-lg" disabled={!draft.concordChannelId || !consent || busy} onClick={() => void submit()}>
            {busy ? <><Loader2 className="animate-spin" /> Requesting…</> : "Request the bridge"}
          </Button>
          <p className="text-center text-xs text-muted-foreground">
            Next, a moderator confirms it from inside the Armada channel.
          </p>
        </div>
      </WizardStepBody>
    </Shell>
  );
}
