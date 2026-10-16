import { Check, Link2, Loader2, Plus, Server } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, Navigate, Route, Routes, useNavigate, useSearchParams } from "react-router-dom";

import { api, listBridges, type BridgeSummary } from "@/api";
import { GuildIcon } from "@/components/common";
import { Crest, DiscordMark } from "@/components/brand/marks";
import { PickRow, WizardShell, WizardStepBody, useFlowNav } from "@/components/WizardShell";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useBridges } from "@/hooks";
import type { ArmadaChannel, DiscordChannel, MapState, Preset } from "@/lib/channelMap";
import { errText, plural } from "@/lib/utils";
import { ChannelMapStep, ConfirmStep } from "@/pages/ChannelMapStep";
import { useMe } from "@/session";
import { useNostrLogin } from "@/useNostrLogin";

/**
 * "Bridge a server": one flow for every starting point. Pick the Discord
 * server, then the Armada side (a new community is the server import; an
 * existing one is linked through the channel map), then decide channel by
 * channel what mirrors what, what gets created, and which way history goes.
 *
 * Mirrored to sessionStorage so a reload resumes. Nothing secret is in it:
 * the invite is sealed on the server-side draft (`bridgeId`), and an Armada
 * key lives only in the login hook's memory.
 */
export interface ConnectDraft {
  /** Manage-channels mode: the bridge whose community (and sealed invite) is reused. */
  from?: string;
  guildId?: string;
  bridgeId?: string;
  communityName?: string;
  armada?: ArmadaChannel[];
  canCreateArmada?: boolean;
  approvalUrl?: string;
  /** The Discord side as last read, and the map drawn over both. */
  discordChannels?: DiscordChannel[];
  createInstallUrl?: string;
  plan?: Preset;
  map?: MapState;
  copyHistory?: boolean;
  result?: { status: string; confirmCode?: string; count: number };
}

const DRAFT_KEY = "portal:connect";

function loadDraft(): ConnectDraft {
  try {
    return JSON.parse(sessionStorage.getItem(DRAFT_KEY) ?? "{}") as ConnectDraft;
  } catch {
    return {};
  }
}

export interface ConnectFlow {
  draft: ConnectDraft;
  update: (patch: Partial<ConnectDraft>) => void;
  reset: (to?: ConnectDraft) => void;
  close: () => void;
  login: ReturnType<typeof useNostrLogin>;
  steps: string[];
}

const FlowContext = createContext<ConnectFlow | null>(null);
export const useConnect = () => useContext(FlowContext)!;

const STEPS = ["/connect", "/connect/armada", "/connect/map", "/connect/confirm"];
const FROM_STEPS = ["/connect/map", "/connect/confirm"];

/** What `POST /api/bridges` answers: a draft holding the community's sealed invite. */
interface DraftResponse {
  bridgeId: string;
  community: { name: string };
  channels: ArmadaChannel[];
  canCreateChannels: boolean;
  approvalUrl: string;
}

function draftPatch(res: DraftResponse): Partial<ConnectDraft> {
  return {
    bridgeId: res.bridgeId,
    communityName: res.community.name,
    armada: res.channels,
    canCreateArmada: res.canCreateChannels,
    approvalUrl: res.approvalUrl,
    map: undefined,
    result: undefined,
  };
}

export function Connect() {
  const [draft, setDraft] = useState<ConnectDraft>(loadDraft);
  const [params] = useSearchParams();
  const from = params.get("from");
  const navigate = useNavigate();
  const login = useNostrLogin([]);

  useEffect(() => {
    sessionStorage.setItem(DRAFT_KEY, JSON.stringify(draft));
  }, [draft]);

  const update = useCallback((patch: Partial<ConnectDraft>) => setDraft((d) => ({ ...d, ...patch })), []);
  const reset = useCallback((to: ConnectDraft = {}) => setDraft(to), []);
  const close = useCallback(() => {
    sessionStorage.removeItem(DRAFT_KEY);
    navigate("/", { replace: true });
  }, [navigate]);

  const flow: ConnectFlow = { draft, update, reset, close, login, steps: draft.from ? FROM_STEPS : STEPS };

  // Always a fresh start: StartFromBridge drops the parameter once it has
  // opened the community, so its presence means a new click. Skipping this
  // when a stale draft named the same bridge fell through to the server step,
  // which discarded that draft and asked for the server and community again.
  if (from) {
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
        <Route path="armada" element={<ArmadaStep />} />
        <Route path="map" element={<ChannelMapStep />} />
        <Route path="confirm" element={<ConfirmStep />} />
        <Route path="done" element={<DoneStep />} />
        <Route path="*" element={<Navigate to="/connect" replace />} />
      </Routes>
    </FlowContext.Provider>
  );
}

export function ConnectShell({ path, onBack, children, wide }: { path: string; onBack?: () => void; children: ReactNode; wide?: boolean }) {
  const { steps, close } = useConnect();
  const index = steps.indexOf(path);
  return (
    <WizardShell
      index={Math.max(0, index)}
      total={index < 0 ? 0 : steps.length}
      stepKey={path}
      maxWidth={wide ? "max-w-xl" : "max-w-md"}
      onBack={onBack}
      onClose={close}
    >
      {children}
    </WizardShell>
  );
}

export function ErrorLine({ error }: { error: string }) {
  if (!error) return null;
  return (
    <Alert variant="destructive">
      <AlertDescription>{error}</AlertDescription>
    </Alert>
  );
}

/** `?from=<bridge>`: manage the channels of a community already bridged. */
function StartFromBridge({ from }: { from: string }) {
  const { reset, close } = useConnect();
  const navigate = useNavigate();
  const [error, setError] = useState("");

  useEffect(() => {
    let stale = false;
    void (async () => {
      try {
        const source = (await listBridges()).find((b) => b.bridge_id === from);
        if (!source?.discord_guild_id) throw new Error("That bridge isn't available to copy from.");
        const res = await api<DraftResponse>("/api/bridges", { method: "POST", body: JSON.stringify({ fromBridgeId: from }) });
        if (stale) return;
        reset({ from, guildId: source.discord_guild_id, ...draftPatch(res) });
        navigate("/connect/map", { replace: true });
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
        title={error ? "can't open the community" : "opening the community…"}
        description={error || "Reading both sides so you can see what is linked and what isn't."}
      >
        {!error && <Loader2 className="mx-auto size-5 animate-spin text-muted-foreground" />}
      </WizardStepBody>
    </WizardShell>
  );
}

// ── 1. Discord server ────────────────────────────────────────────────────────

function ServerStep() {
  const { guilds } = useMe();
  const { draft, update, reset } = useConnect();
  const { next } = useFlowNav();
  const [none, setNone] = useState(false);

  // Arriving here plainly after a manage-channels run: that run's state is stale.
  useEffect(() => {
    if (draft.from || draft.result) reset();
  }, [draft.from, draft.result, reset]);

  return (
    <ConnectShell path="/connect">
      <WizardStepBody
        glyph={<DiscordMark className="size-14 text-discord" />}
        title="bridge a server"
        description="Which Discord server?"
      >
        <div className="space-y-3">
          <div className="space-y-1.5">
            {guilds.map((g) => (
              <PickRow
                key={g.id}
                selected={draft.guildId === g.id && !none}
                onClick={() => {
                  setNone(false);
                  if (draft.guildId !== g.id) update({ guildId: g.id });
                }}
              >
                <GuildIcon name={g.name} icon={g.icon} />
                <span className="min-w-0 flex-1 truncate text-sm font-medium">{g.name}</span>
                {draft.guildId === g.id && !none && <Check className="size-4 shrink-0 text-primary" />}
              </PickRow>
            ))}
            <PickRow selected={none} onClick={() => setNone(true)}>
              <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-secondary text-muted-foreground">
                <Plus className="size-4" />
              </span>
              <span className="min-w-0 flex-1 text-sm font-medium">I don't have a Discord server yet</span>
            </PickRow>
          </div>
          {none ? (
            <Alert>
              <AlertDescription className="space-y-3 text-left text-xs leading-relaxed">
                <p>
                  In Discord, click <strong>+</strong> in the server list and make an empty server. The bridge fills it in.
                </p>
                <p>Then sign in again so it shows up here.</p>
                <Button asChild size="sm" variant="secondary" className="clip-corner">
                  <a href="/api/auth/discord">
                    <DiscordMark /> Sign in again
                  </a>
                </Button>
              </AlertDescription>
            </Alert>
          ) : (
            <Button size="lg" className="w-full clip-corner-lg" disabled={!draft.guildId} onClick={() => next("/connect/armada")}>
              Continue
            </Button>
          )}
          <p className="text-xs text-muted-foreground">Only servers you manage are listed.</p>
        </div>
      </WizardStepBody>
    </ConnectShell>
  );
}

// ── 2. Armada side ───────────────────────────────────────────────────────────

interface KnownCommunity {
  id: string;
  name: string;
  source: BridgeSummary;
  channels: number;
}

/** Communities this account already bridges, newest first: their invites are on file. */
function knownCommunities(bridges: BridgeSummary[]): KnownCommunity[] {
  const out = new Map<string, KnownCommunity>();
  for (const b of bridges) {
    if (!b.community_id || b.status === "draft" || b.status === "unlinked") continue;
    const known = out.get(b.community_id);
    if (known) known.channels++;
    else out.set(b.community_id, { id: b.community_id, name: b.community_name ?? "Unnamed community", source: b, channels: 1 });
  }
  return [...out.values()];
}

function ArmadaStep() {
  const { guilds } = useMe();
  const { draft, update } = useConnect();
  const { next, back } = useFlowNav();
  const navigate = useNavigate();
  const { bridges } = useBridges();
  const known = useMemo(() => knownCommunities(bridges ?? []), [bridges]);
  const [invite, setInvite] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  if (!draft.guildId) return <Navigate to="/connect" replace />;
  const guild = guilds.find((g) => g.id === draft.guildId);

  async function open(body: object, key: string) {
    setBusy(key);
    setError("");
    try {
      const res = await api<DraftResponse>("/api/bridges", { method: "POST", body: JSON.stringify(body) });
      update(draftPatch(res));
      setInvite("");
      next("/connect/map");
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy("");
    }
  }

  return (
    <ConnectShell path="/connect/armada" onBack={() => back("/connect")}>
      <ErrorLine error={error} />
      <WizardStepBody
        glyph={<Crest className="size-14" />}
        title="pick the armada side"
        description={<>Bridge <span className="text-foreground">{guild?.name ?? "the server"}</span> with…</>}
      >
        <div className="space-y-5 text-left">
          <PickRow selected={false} onClick={() => navigate(`/import?guild=${draft.guildId}`)}>
            <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-primary/15 text-primary">
              <Server className="size-4" />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block text-sm font-medium">A new community</span>
              <span className="block text-xs text-muted-foreground">Copied from this server. You own it.</span>
            </span>
          </PickRow>

          {known.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-2xs font-semibold uppercase tracking-wider text-muted-foreground">Yours</p>
              {known.map((c) => (
                <PickRow key={c.id} selected={false} onClick={() => void open({ fromBridgeId: c.source.bridge_id }, c.id)}>
                  <Crest className="size-9 shrink-0" />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">{c.name}</span>
                    <span className="block text-xs text-muted-foreground">{plural(c.channels, "channel")} bridged</span>
                  </span>
                  {busy === c.id && <Loader2 className="size-4 animate-spin text-muted-foreground" />}
                </PickRow>
              ))}
            </div>
          )}

          <form
            className="space-y-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (invite.trim() && !busy) void open({ inviteUrl: invite.trim() }, "invite");
            }}
          >
            <p className="text-2xs font-semibold uppercase tracking-wider text-muted-foreground">Another one</p>
            <div className="relative">
              <Link2 className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                type="url"
                placeholder="https://armada.buzz/invite/naddr1…#…"
                value={invite}
                onChange={(e) => setInvite(e.target.value)}
                className="h-11 pl-9 font-mono text-xs"
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <Button type="submit" variant="secondary" className="w-full clip-corner-lg" disabled={!invite.trim() || !!busy}>
              {busy === "invite" ? <><Loader2 className="animate-spin" /> Reading the community…</> : "Use this invite"}
            </Button>
            <p className="text-xs text-muted-foreground">
              Get one in Armada: community menu → <span className="text-foreground">Invite people</span>.
            </p>
          </form>
        </div>
      </WizardStepBody>
    </ConnectShell>
  );
}

// ── 4. Done ──────────────────────────────────────────────────────────────────

function DoneStep() {
  const { draft, close } = useConnect();
  const result = draft.result;
  if (!result) return <Navigate to="/connect" replace />;
  const live = result.status === "active";
  return (
    <ConnectShell path="/connect/done">
      <WizardStepBody
        glyph={<Check className="size-14 text-accent2" />}
        title={live ? "bridged" : "almost there"}
        description={
          live ? (
            <>{plural(result.count, "channel")} now mirror both ways.</>
          ) : (
            <>An Armada moderator sends this in any of the channels:</>
          )
        }
      >
        <div className="space-y-4">
          {!live && result.confirmCode && (
            <code className="mx-auto block w-fit rounded-chrome border border-dashed border-border bg-chrome-deep px-3 py-1.5 font-mono text-sm text-foreground">
              /bridge confirm {result.confirmCode}
            </code>
          )}
          <Button size="lg" className="w-full clip-corner-lg" onClick={close}>
            See your bridges
          </Button>
          <Button asChild variant="ghost" className="w-full">
            <Link to="/connect" replace>
              Bridge another server
            </Link>
          </Button>
        </div>
      </WizardStepBody>
    </ConnectShell>
  );
}
