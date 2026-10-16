import { Check, ChevronDown, ExternalLink, Loader2, Lock, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Navigate, useNavigate } from "react-router-dom";

import { ApiError, api } from "@/api";
import { Crest, DiscordMark } from "@/components/brand/marks";
import { WizardStepBody, useFlowNav } from "@/components/WizardShell";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Switch } from "@/components/ui/switch";
import {
  applyPreset,
  armadaChoices,
  isLinked,
  linkable,
  normalize,
  rows as mapRows,
  suggestPreset,
  toPairs,
  withHistory,
  type ArmadaChannel,
  type DiscordChannel,
  type MapState,
  type Preset,
  type Row,
} from "@/lib/channelMap";
import { cn, errText, plural } from "@/lib/utils";
import { NostrLogin } from "@/NostrLogin";
import { ConnectShell, ErrorLine, useConnect, type ConnectDraft } from "@/pages/Connect";
import { useMe } from "@/session";

interface GuildChannels {
  present: boolean;
  channels?: DiscordChannel[];
  installUrl?: string;
  createInstallUrl?: string;
}

/** NIP-98 HTTP auth: what an approval is signed as (see `approval_signer`). */
const HTTP_AUTH_KIND = 27235;

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Copying history is the point when one side is being filled from the other; when both are busy, it's a choice to make on purpose. */
function fills(plan: Preset) {
  return plan === "toDiscord" || plan === "toArmada";
}

/** Everything the two screens derive from the draft. */
function useMap(draft: ConnectDraft) {
  const discord = useMemo(() => draft.discordChannels ?? [], [draft.discordChannels]);
  const armada = useMemo(() => draft.armada ?? [], [draft.armada]);
  return useMemo(() => {
    if (!draft.map) return null;
    const effective = withHistory(draft.map, discord, armada, Boolean(draft.copyHistory));
    const list = mapRows(effective, discord, armada);
    const linked = list.filter(isLinked);
    return {
      discord,
      armada,
      effective,
      list,
      linked,
      paired: linked.filter((r) => r.discord?.kind === "existing" && r.armada?.kind === "existing").length,
      newDiscord: linked.filter((r) => r.discord?.kind === "create").length,
      newArmada: linked.filter((r) => r.armada?.kind === "create").length,
      historyTo: {
        armada: linked.some((r) => r.history === "discord"),
        discord: linked.some((r) => r.history === "armada"),
      },
    };
  }, [draft.map, draft.copyHistory, discord, armada]);
}

// ── 3. Channels ──────────────────────────────────────────────────────────────

export function ChannelMapStep() {
  const { guilds } = useMe();
  const { draft, update, steps } = useConnect();
  const { next, back } = useFlowNav();
  const [missing, setMissing] = useState<GuildChannels | null>(null);
  const [error, setError] = useState("");
  const [checking, setChecking] = useState(false);
  const canCreateArmada = Boolean(draft.canCreateArmada);
  const map = useMap(draft);

  async function load() {
    if (!draft.guildId) return;
    setChecking(true);
    setError("");
    try {
      const res = await api<GuildChannels>(`/api/guilds/${draft.guildId}/channels`);
      if (!res.present) {
        setMissing(res);
        return;
      }
      setMissing(null);
      const channels = res.channels ?? [];
      const ids = (list?: DiscordChannel[]) => (list ?? []).map((c) => c.id).join(",");
      // Re-plan when Discord changed under the map (a run that failed partway
      // made channels, which are existing channels now, not ones to create).
      if (!draft.map || ids(channels) !== ids(draft.discordChannels)) {
        const plan = suggestPreset(channels, draft.armada ?? [], canCreateArmada);
        update({
          discordChannels: channels,
          createInstallUrl: res.createInstallUrl,
          plan,
          map: applyPreset(plan, channels, draft.armada ?? [], canCreateArmada),
          copyHistory: fills(plan),
        });
      } else {
        update({ discordChannels: channels, createInstallUrl: res.createInstallUrl });
      }
    } catch (e) {
      setError(errText(e));
    } finally {
      setChecking(false);
    }
  }

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft.guildId, draft.bridgeId]);

  if (!draft.guildId) return <Navigate to="/connect" replace />;
  if (!draft.bridgeId) return <Navigate to={draft.from ? "/connect" : "/connect/armada"} replace />;
  const guild = guilds.find((g) => g.id === draft.guildId);
  const onBack = draft.from ? undefined : () => back(steps[steps.indexOf("/connect/map") - 1] ?? "/connect");

  if (missing) {
    return (
      <ConnectShell path="/connect/map" onBack={onBack}>
        <ErrorLine error={error} />
        <WizardStepBody
          glyph={<DiscordMark className="size-14 text-discord" />}
          title="add the bot"
          description={<>The bridge bot isn't in {guild?.name ?? "this server"} yet.</>}
        >
          <div className="space-y-3">
            <Button asChild size="lg" className="w-full clip-corner-lg">
              <a href={missing.createInstallUrl ?? missing.installUrl} target="_blank" rel="noopener noreferrer">
                <DiscordMark /> Add the bot <ExternalLink className="opacity-60" />
              </a>
            </Button>
            <Button variant="secondary" className="w-full clip-corner-lg" disabled={checking} onClick={() => void load()}>
              {checking ? <Loader2 className="animate-spin" /> : <RefreshCw />} Done, check again
            </Button>
          </div>
        </WizardStepBody>
      </ConnectShell>
    );
  }

  if (!map || !draft.map) {
    return (
      <ConnectShell path="/connect/map" onBack={onBack}>
        <ErrorLine error={error} />
        <div className="flex justify-center py-10">
          <Loader2 className="size-5 animate-spin text-muted-foreground" />
        </div>
      </ConnectShell>
    );
  }

  const { discord, armada, list, linked } = map;
  const discordOpen = discord.filter((c) => !c.bridged);
  const armadaOpen = linkable(armada);
  const plan = draft.plan ?? "merge";
  // A choice only when both sides have channels; otherwise the empty side is filled.
  const everything: Preset = fills(plan) ? plan : "merge";
  const choosable = discordOpen.length > 0 && armadaOpen.length > 0;
  const suggestion = applyPreset("merge", discord, armada, canCreateArmada);

  function setMap(m: MapState) {
    update({ map: m });
  }

  function choosePlan(p: Preset) {
    update({ plan: p, map: applyPreset(p, discord, armada, canCreateArmada), copyHistory: fills(p) });
  }

  return (
    <ConnectShell path="/connect/map" onBack={onBack} wide>
      <div className="flex flex-col gap-6">
        <Sides discordName={guild?.name ?? "Discord"} discordCount={discordOpen.length} armadaName={draft.communityName ?? "Armada"} armadaCount={armadaOpen.length} />

        <ErrorLine error={error} />

        {list.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground">Everything here is already bridged.</p>
        ) : (
          <>
            {choosable && (
              <div className="grid grid-cols-2 gap-1 rounded-lg bg-secondary/40 p-1">
                {(
                  [
                    ["pair", "Matching names"],
                    [everything, "Everything"],
                  ] as const
                ).map(([p, label]) => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => choosePlan(p)}
                    aria-pressed={plan === p}
                    className={cn(
                      "rounded-md py-2 text-sm font-medium transition-colors",
                      plan === p ? "bg-primary/20 text-foreground" : "text-muted-foreground hover:text-foreground",
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>
            )}

            <div className="divide-y divide-chrome/60 overflow-hidden rounded-lg bg-secondary/30">
              {list.map((row) => (
                <ChannelRow
                  key={row.key}
                  row={row}
                  map={draft.map!}
                  suggestion={suggestion}
                  armada={armada}
                  canCreateArmada={canCreateArmada}
                  onChange={setMap}
                />
              ))}
            </div>

            <Summary {...map} />

            {linked.length > 0 && (map.linked.some((r) => r.discord?.kind === "existing" || r.armada?.kind === "existing")) && (
              <label className="flex cursor-pointer items-center justify-between gap-4 rounded-lg bg-secondary/30 px-4 py-3">
                <span>
                  <span className="block text-sm font-medium">Copy past messages</span>
                  <span className="block text-xs text-muted-foreground">
                    {draft.copyHistory ? historyLine(map.historyTo) : "Only new messages will be mirrored."}
                  </span>
                </span>
                <Switch checked={Boolean(draft.copyHistory)} onCheckedChange={(on) => update({ copyHistory: on })} />
              </label>
            )}
          </>
        )}

        <Button size="lg" className="w-full clip-corner-lg" disabled={linked.length === 0} onClick={() => next("/connect/confirm")}>
          Continue
        </Button>
      </div>
    </ConnectShell>
  );
}

function historyLine(to: { armada: boolean; discord: boolean }) {
  if (to.armada && to.discord) return "Each side gets the history it's missing.";
  if (to.discord) return "Recent Armada messages get posted in Discord.";
  return "Discord messages show up in Armada at their original times.";
}

function Sides(props: { discordName: string; discordCount: number; armadaName: string; armadaCount: number }) {
  const side = (glyph: ReactNode, name: string, count: number) => (
    <div className="flex min-w-0 flex-1 flex-col items-center gap-1.5 text-center">
      {glyph}
      <span className="w-full truncate text-sm font-medium">{name}</span>
      <span className="text-xs text-muted-foreground">{count === 0 ? "empty" : plural(count, "channel")}</span>
    </div>
  );
  return (
    <div className="flex items-center gap-3">
      {side(<DiscordMark className="size-9 text-discord" />, props.discordName, props.discordCount)}
      <span className="font-mono text-xl text-primary">⇆</span>
      {side(<Crest className="size-9" />, props.armadaName, props.armadaCount)}
    </div>
  );
}

function Summary(props: { paired: number; newDiscord: number; newArmada: number }) {
  const parts = [
    props.paired > 0 && `${props.paired} paired`,
    props.newDiscord > 0 && `${props.newDiscord} new in Discord`,
    props.newArmada > 0 && `${props.newArmada} new in Armada`,
  ].filter(Boolean);
  if (parts.length === 0) return <p className="text-center text-sm text-muted-foreground">Tick the channels to bridge.</p>;
  return <p className="text-center text-sm text-foreground">{parts.join(" · ")}</p>;
}

/**
 * One channel, one line: a tick to include it, its name, and what happens to
 * it. Where there's a real choice of partner, that label is a quiet select.
 */
function ChannelRow(props: {
  row: Row;
  map: MapState;
  suggestion: MapState;
  armada: ArmadaChannel[];
  canCreateArmada: boolean;
  onChange: (m: MapState) => void;
}) {
  const { row, map, suggestion, armada, canCreateArmada, onChange } = props;
  const linked = isLinked(row);

  if (row.key.startsWith("d:")) {
    const id = row.key.slice(2);
    const d = row.discord?.kind === "existing" ? row.discord.channel : undefined;
    const choices = armadaChoices(map, id, armada);
    // Ticking a row back on restores its suggested partner, if no other row has taken it since.
    const suggested = suggestion.discord[id];
    const free = suggested === "create" ? canCreateArmada : choices.some((c) => c.idHex === suggested);
    const fallback = free ? suggested : canCreateArmada ? "create" : choices[0]?.idHex;
    const options: Array<[string, string]> = [
      ...choices.map((c): [string, string] => [c.idHex, d && normalize(c.name) === normalize(d.name) ? "paired" : `with #${c.name}`]),
      ...(canCreateArmada ? [["create", "new in Armada"] as [string, string]] : []),
    ];
    const set = (value: string) => onChange({ ...map, discord: { ...map.discord, [id]: value } });
    const current = row.armada?.kind === "existing" ? row.armada.channel.idHex : row.armada ? "create" : "skip";
    return (
      <RowShell
        checked={linked}
        disabled={!fallback}
        onToggle={(on) => set(on ? fallback! : "skip")}
        name={d?.name ?? ""}
        side="discord"
        hint={!fallback ? "no Armada channel to pair with" : undefined}
      >
        {linked && <Outcome value={current} options={options} onChange={set} />}
      </RowShell>
    );
  }

  const id = row.key.slice(2);
  const name = row.armada?.kind === "existing" ? row.armada.channel.name : "";
  return (
    <RowShell checked={linked} onToggle={(on) => onChange({ ...map, armada: { ...map.armada, [id]: on ? "create" : "skip" } })} name={name} side="armada">
      {linked && <span className="text-xs text-muted-foreground">new in Discord</span>}
    </RowShell>
  );
}

/** A row is marked with the side its channel lives on now. */
function RowShell(props: {
  checked: boolean;
  disabled?: boolean;
  onToggle: (on: boolean) => void;
  name: string;
  side: "discord" | "armada";
  hint?: string;
  children?: ReactNode;
}) {
  return (
    <div className={cn("flex items-center gap-3 px-3 py-2.5", !props.checked && "opacity-55")}>
      <label className="flex min-w-0 flex-1 cursor-pointer items-center gap-3">
        <Checkbox checked={props.checked} disabled={props.disabled} onCheckedChange={(v) => props.onToggle(v === true)} />
        {props.side === "discord" ? (
          <DiscordMark className="size-4 shrink-0 text-discord" aria-label="Discord" />
        ) : (
          <Crest className="size-4 shrink-0" aria-label="Armada" />
        )}
        <span className="truncate text-sm">{props.name}</span>
      </label>
      {props.hint ? <span className="shrink-0 text-xs text-muted-foreground">{props.hint}</span> : props.children}
    </div>
  );
}

/** What happens to a channel, as text; a select only when there's more than one answer. */
function Outcome({ value, options, onChange }: { value: string; options: Array<[string, string]>; onChange: (v: string) => void }) {
  const label = options.find(([v]) => v === value)?.[1] ?? "";
  if (options.length < 2) return <span className="shrink-0 text-xs text-muted-foreground">{label}</span>;
  return (
    <span className="relative shrink-0">
      <select
        aria-label="Pair with"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="cursor-pointer appearance-none rounded bg-transparent py-0.5 pl-1 pr-5 text-right text-xs text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {options.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
      </select>
      <ChevronDown className="pointer-events-none absolute right-0 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
    </span>
  );
}

// ── 4. Confirm ───────────────────────────────────────────────────────────────

export function ConfirmStep() {
  const { draft, update, login } = useConnect();
  const { back } = useFlowNav();
  const navigate = useNavigate();
  const map = useMap(draft);
  const [understood, setUnderstood] = useState(false);
  const [adminNow, setAdminNow] = useState(Boolean(login.pk));
  const [botReady, setBotReady] = useState(false);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [installUrl, setInstallUrl] = useState("");

  if (!draft.bridgeId || !map) return <Navigate to="/connect/map" replace />;
  const needsBot = map.newDiscord > 0 && Boolean(draft.createInstallUrl);
  const signing = adminNow && Boolean(login.pk);

  async function submit() {
    setBusy(signing ? "Signing…" : map!.newDiscord + map!.newArmada > 0 ? "Creating channels…" : "Bridging…");
    setError("");
    setInstallUrl("");
    try {
      const request = JSON.stringify({ guildId: draft.guildId, consent: true, pairs: toPairs(map!.list) });
      const approval =
        signing && draft.approvalUrl
          ? await login.signTemplate({
              kind: HTTP_AUTH_KIND,
              content: "",
              tags: [
                ["u", draft.approvalUrl],
                ["method", "POST"],
                ["payload", await sha256Hex(request)],
              ],
              created_at: Math.floor(Date.now() / 1000),
            })
          : undefined;
      const res = await api<{ status: string; bridgeIds: string[]; confirmCode?: string }>(`/api/bridges/${draft.bridgeId}/link-many`, {
        method: "POST",
        body: JSON.stringify({ request, approval }),
      });
      update({ result: { status: res.status, confirmCode: res.confirmCode, count: res.bridgeIds.length }, bridgeId: undefined, map: undefined });
      navigate("/connect/done", { replace: true });
    } catch (e) {
      const url = e instanceof ApiError ? (e.body as { installUrl?: string } | null)?.installUrl : undefined;
      if (url) setInstallUrl(url);
      setError(errText(e));
      setBusy("");
    }
  }

  const ready = understood && (!needsBot || botReady) && (!adminNow || Boolean(login.pk));

  return (
    <ConnectShell path="/connect/confirm" onBack={() => back("/connect/map")}>
      <WizardStepBody
        glyph={<Check className="size-12 text-primary" />}
        title="ready?"
        description={<>Bridge {plural(map.linked.length, "channel")} with {draft.communityName}.</>}
      >
        <div className="space-y-3 text-left">
          <ErrorLine error={error} />
          {installUrl && (
            <Button asChild variant="secondary" className="w-full clip-corner-lg">
              <a href={installUrl} target="_blank" rel="noopener noreferrer">
                <DiscordMark /> Let the bot create channels <ExternalLink className="opacity-60" />
              </a>
            </Button>
          )}

          {needsBot && (
            <Task done={botReady}>
              <span className="flex-1">
                <span className="block text-sm font-medium">Let the bot create channels</span>
                <a className="text-xs text-primary underline" href={draft.createInstallUrl} target="_blank" rel="noopener noreferrer">
                  Open Discord
                </a>
              </span>
              <Checkbox checked={botReady} onCheckedChange={(v) => setBotReady(v === true)} aria-label="Done" />
            </Task>
          )}

          <Task done={understood}>
            <Lock className="size-4 shrink-0 text-warning" />
            <span className="flex-1 text-sm">Bridged channels aren't end-to-end encrypted. Discord can read them.</span>
            <Checkbox checked={understood} onCheckedChange={(v) => setUnderstood(v === true)} aria-label="Understood" />
          </Task>

          <div className="space-y-2 rounded-lg bg-secondary/30 p-3">
            <span className="block text-sm font-medium">Who approves on Armada?</span>
            <div className="grid grid-cols-2 gap-1 rounded-md bg-secondary/40 p-1">
              {(
                [
                  [false, "A moderator"],
                  [true, "Me, now"],
                ] as const
              ).map(([value, label]) => (
                <button
                  key={label}
                  type="button"
                  onClick={() => setAdminNow(value)}
                  aria-pressed={adminNow === value}
                  className={cn("rounded py-1.5 text-sm", adminNow === value ? "bg-primary/20 text-foreground" : "text-muted-foreground")}
                >
                  {label}
                </button>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">
              {adminNow ? "Log in with an Armada key that can manage channels." : "You'll get a code to send in Armada."}
            </p>
            {adminNow && <NostrLogin login={login} />}
          </div>

          <Button size="lg" className="w-full clip-corner-lg" disabled={!ready || !!busy} onClick={() => void submit()}>
            {busy ? <><Loader2 className="animate-spin" /> {busy}</> : "Bridge"}
          </Button>
        </div>
      </WizardStepBody>
    </ConnectShell>
  );
}

function Task({ done, children }: { done: boolean; children: ReactNode }) {
  return (
    <label className={cn("flex cursor-pointer items-center gap-3 rounded-lg p-3 transition-colors", done ? "bg-accent2/10" : "bg-secondary/30")}>
      {children}
    </label>
  );
}
