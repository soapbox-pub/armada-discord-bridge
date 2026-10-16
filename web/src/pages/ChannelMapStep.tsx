import { ArrowLeftRight, ExternalLink, Hash, Loader2, Plus, RefreshCw, ShieldAlert } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";

import { ApiError, api } from "@/api";
import { SectionLabel } from "@/components/common";
import { DiscordMark } from "@/components/brand/marks";
import { WizardStepBody, useFlowNav } from "@/components/WizardShell";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  applyPreset,
  armadaChoices,
  historyOptions,
  isLinked,
  linkable,
  rows as mapRows,
  suggestPreset,
  toPairs,
  type DiscordChannel,
  type History,
  type MapState,
  type Preset,
  type Row,
} from "@/lib/channelMap";
import { cn, errText, plural } from "@/lib/utils";
import { NostrLogin } from "@/NostrLogin";
import { ConnectShell, ErrorLine, useConnect } from "@/pages/Connect";
import { useMe } from "@/session";

interface GuildChannels {
  present: boolean;
  channels?: DiscordChannel[];
  installUrl?: string;
  createInstallUrl?: string;
}

const PRESETS: Array<{ id: Preset; label: string; hint: string }> = [
  { id: "pair", label: "Pair matches", hint: "Link channels with the same name, nothing else." },
  { id: "toArmada", label: "Discord → Armada", hint: "Bring every Discord channel over, with its history." },
  { id: "toDiscord", label: "Armada → Discord", hint: "Bring every Armada channel over, history into empty channels." },
  { id: "merge", label: "Merge both", hint: "Everything on both sides; Discord history into Armada, Armada history into empty channels." },
];

const HISTORY_LABEL: Record<History, string> = {
  none: "No history",
  discord: "Copy Discord's history",
  armada: "Copy Armada's history",
};

/** NIP-98 HTTP auth: what an approval is signed as (see `approval_signer`). */
const HTTP_AUTH_KIND = 27235;

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const selectClass =
  "h-8 w-full min-w-0 truncate rounded-md border border-transparent bg-secondary/60 px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

export function ChannelMapStep() {
  const { guilds } = useMe();
  const { draft, update, login, steps } = useConnect();
  const { back } = useFlowNav();
  const navigate = useNavigate();
  const [discord, setDiscord] = useState<GuildChannels | null>(null);
  const [map, setMap] = useState<MapState | null>(null);
  const [preset, setPreset] = useState<Preset | null>(null);
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [needsInstall, setNeedsInstall] = useState("");

  const armada = useMemo(() => draft.armada ?? [], [draft.armada]);
  const canCreateArmada = Boolean(draft.canCreateArmada);

  const load = useCallback(async () => {
    if (!draft.guildId) return;
    setError("");
    try {
      setDiscord(await api<GuildChannels>(`/api/guilds/${draft.guildId}/channels`));
    } catch (e) {
      setError(errText(e));
    }
  }, [draft.guildId]);

  useEffect(() => {
    void load();
  }, [load]);

  // A fresh read of Discord re-fills the map: a channel made by a run that
  // failed partway is an existing channel now, not one to create.
  useEffect(() => {
    if (!discord?.present) return;
    const channels = discord.channels ?? [];
    const start = preset ?? suggestPreset(channels, armada, canCreateArmada);
    setPreset(start);
    setMap(applyPreset(start, channels, armada, canCreateArmada));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [discord, armada, canCreateArmada]);

  if (!draft.guildId) return <Navigate to="/connect" replace />;
  if (!draft.bridgeId) return <Navigate to={draft.from ? "/connect" : "/connect/armada"} replace />;
  const guild = guilds.find((g) => g.id === draft.guildId);
  const onBack = draft.from ? undefined : () => back(steps[steps.indexOf("/connect/map") - 1] ?? "/connect");

  if (discord && !discord.present) {
    return (
      <ConnectShell path="/connect/map" onBack={onBack}>
        <ErrorLine error={error} />
        <WizardStepBody
          glyph={<DiscordMark className="size-14 text-discord" />}
          title="install the bot"
          description={
            <>
              The bridge bot isn't in <span className="text-foreground">{guild?.name ?? "this server"}</span> yet. It reads the
              channels and posts Armada's messages into them, so it has to be invited first.
            </>
          }
        >
          <div className="space-y-3">
            <Button asChild size="lg" className="w-full clip-corner-lg">
              <a href={discord.createInstallUrl ?? discord.installUrl} target="_blank" rel="noopener noreferrer">
                <DiscordMark /> Install the bot <ExternalLink className="opacity-60" />
              </a>
            </Button>
            <Button variant="secondary" className="w-full clip-corner-lg" onClick={() => void load()}>
              <RefreshCw /> I installed it, check again
            </Button>
            <p className="text-xs text-muted-foreground">
              This link also lets the bot create channels, for an empty server. Use{" "}
              <a className="underline" href={discord.installUrl} target="_blank" rel="noopener noreferrer">
                the plain one
              </a>{" "}
              if you'd rather it couldn't.
            </p>
          </div>
        </WizardStepBody>
      </ConnectShell>
    );
  }

  if (!discord || !map) {
    return (
      <ConnectShell path="/connect/map" onBack={onBack}>
        <ErrorLine error={error} />
        <div className="flex justify-center py-10">
          <Loader2 className="size-5 animate-spin text-muted-foreground" />
        </div>
      </ConnectShell>
    );
  }

  const channels = discord.channels ?? [];
  const list = mapRows(map, channels, armada);
  const linked = list.filter(isLinked);
  const createsDiscord = linked.filter((r) => r.discord?.kind === "create").length;
  const createsArmada = linked.filter((r) => r.armada?.kind === "create").length;
  const withHistory = linked.filter((r) => r.history !== "none").length;
  const alreadyBridged = channels.filter((c) => c.bridged).length + armada.filter((a) => a.bridged).length;
  const hiddenArmada = armada.filter((a) => !a.bridged && (a.private || a.forum)).length;
  const busyDiscord = channels.filter((c) => !c.bridged && !c.empty).length;

  function choose(p: Preset) {
    setPreset(p);
    setMap(applyPreset(p, channels, armada, canCreateArmada));
  }

  function setDiscordChoice(discordId: string, value: string) {
    setMap((m) => m && { ...m, discord: { ...m.discord, [discordId]: value } });
  }

  function setArmadaChoice(armadaId: string, value: "create" | "skip") {
    setMap((m) => m && { ...m, armada: { ...m.armada, [armadaId]: value } });
  }

  function setHistory(key: string, value: History) {
    setMap((m) => m && { ...m, history: { ...m.history, [key]: value } });
  }

  async function submit() {
    setBusy(login.pk ? "Signing the approval…" : "Linking…");
    setError("");
    setNeedsInstall("");
    try {
      const request = JSON.stringify({ guildId: draft.guildId, consent: true, pairs: toPairs(list) });
      const approval =
        login.pk && draft.approvalUrl
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
      setBusy(createsDiscord + createsArmada > 0 ? "Creating channels and linking…" : "Linking…");
      const res = await api<{ status: string; bridgeIds: string[]; confirmCode?: string }>(`/api/bridges/${draft.bridgeId}/link-many`, {
        method: "POST",
        body: JSON.stringify({ request, approval }),
      });
      update({ result: { status: res.status, confirmCode: res.confirmCode, count: res.bridgeIds.length }, bridgeId: undefined });
      navigate("/connect/done", { replace: true });
    } catch (e) {
      const installUrl = e instanceof ApiError ? (e.body as { installUrl?: string } | null)?.installUrl : undefined;
      if (installUrl) setNeedsInstall(installUrl);
      setError(errText(e));
      setBusy("");
      // Some channels may have been made before the refusal: re-read them.
      void load();
    }
  }

  const blocker = linked.length === 0 ? "Link at least one channel" : !consent ? "Accept the disclosure" : undefined;

  return (
    <ConnectShell path="/connect/map" onBack={onBack} wide>
      <div className="flex flex-col gap-7">
        <div className="flex flex-col items-center gap-3 text-center">
          <ArrowLeftRight className="size-12 text-primary" />
          <div className="space-y-1.5">
            <h1 className="font-mono text-2xl font-bold lowercase tracking-tight">map the channels</h1>
            <p className="text-sm text-muted-foreground">
              <span className="text-foreground">{guild?.name ?? "Discord"}</span>: {plural(channels.length - channels.filter((c) => c.bridged).length, "channel")}
              {busyDiscord < channels.length && <>, {busyDiscord} with messages</>}
              {" · "}
              <span className="text-foreground">{draft.communityName}</span>: {plural(linkable(armada).length, "channel")}
            </p>
          </div>
        </div>

        <ErrorLine error={error} />
        {needsInstall && (
          <Button asChild variant="secondary" className="clip-corner-lg">
            <a href={needsInstall} target="_blank" rel="noopener noreferrer">
              <DiscordMark /> Let the bot create channels <ExternalLink className="opacity-60" />
            </a>
          </Button>
        )}

        <section className="space-y-2 text-left">
          <SectionLabel>Start from</SectionLabel>
          <div className="grid grid-cols-2 gap-1.5">
            {PRESETS.map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => choose(p.id)}
                aria-pressed={preset === p.id}
                className={cn(
                  "clip-corner-lg p-2.5 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring",
                  preset === p.id ? "bg-primary/15" : "bg-secondary/40 hover:bg-secondary/70",
                )}
              >
                <span className="block text-sm font-medium">{p.label}</span>
                <span className="block text-xs leading-snug text-muted-foreground">{p.hint}</span>
              </button>
            ))}
          </div>
          {!canCreateArmada && (
            <p className="text-xs text-muted-foreground">
              The bridge can only create Armada channels in a community it imported for you. Create any missing ones in Armada,
              then reopen this map.
            </p>
          )}
        </section>

        <section className="space-y-2 text-left">
          <SectionLabel>Channels</SectionLabel>
          <div className="overflow-hidden rounded-lg bg-secondary/30">
            <div className="grid grid-cols-[1fr_auto_1fr] items-center gap-2 border-b border-chrome px-3 py-2 text-2xs uppercase tracking-wider text-muted-foreground">
              <span>Discord</span>
              <span className="w-4" />
              <span>Armada</span>
            </div>
            <div className="max-h-[55vh] divide-y divide-chrome/60 overflow-y-auto">
              {list.length === 0 && <p className="p-4 text-center text-sm text-muted-foreground">Nothing left to link.</p>}
              {list.map((row) => (
                <MapRow
                  key={row.key}
                  row={row}
                  choices={row.key.startsWith("d:") ? armadaChoices(map, row.key.slice(2), armada) : []}
                  canCreateArmada={canCreateArmada}
                  onDiscord={setDiscordChoice}
                  onArmada={setArmadaChoice}
                  onHistory={setHistory}
                />
              ))}
            </div>
          </div>
          {(alreadyBridged > 0 || hiddenArmada > 0) && (
            <p className="text-xs text-muted-foreground">
              {alreadyBridged > 0 && <>{plural(alreadyBridged, "channel")} already bridged aren't shown. </>}
              {hiddenArmada > 0 && <>{plural(hiddenArmada, "private or forum channel")} can't be bridged from here.</>}
            </p>
          )}
          <p className="text-xs text-muted-foreground">
            Discord's history brings each channel's newest 10,000 messages into Armada at their original times. Armada's history
            goes only into an empty Discord channel, newest 500, shown as posted today.
          </p>
        </section>

        {(createsDiscord > 0 || createsArmada > 0 || withHistory > 0) && (
          <p className="text-center text-sm text-muted-foreground">
            {plural(linked.length, "channel")} linked
            {createsDiscord > 0 && <> · {createsDiscord} created on Discord</>}
            {createsArmada > 0 && <> · {createsArmada} created on Armada</>}
            {withHistory > 0 && <> · history for {withHistory}</>}
          </p>
        )}

        {createsDiscord > 0 && discord.createInstallUrl && (
          <Alert>
            <AlertDescription className="text-xs leading-relaxed">
              Creating Discord channels needs the bot to hold <strong>Manage Channels</strong>, which it doesn't ask for by default.{" "}
              <a className="text-primary underline" href={discord.createInstallUrl} target="_blank" rel="noopener noreferrer">
                Grant it
              </a>{" "}
              first if you haven't.
            </AlertDescription>
          </Alert>
        )}

        <section className="space-y-2 text-left">
          <SectionLabel>Approve on Armada</SectionLabel>
          <p className="text-xs text-muted-foreground">
            Log in with an Armada key that holds Manage Channels in {draft.communityName} and the bridge goes live at once.
            Otherwise it posts a code in each channel for a moderator to confirm.
          </p>
          <NostrLogin login={login} />
        </section>

        <Alert variant="warning">
          <ShieldAlert />
          <AlertDescription className="text-xs leading-relaxed">
            <strong className="font-semibold">Bridged channels leave end-to-end encryption.</strong> Everything posted in them, from
            either side, is mirrored to Discord's servers in plaintext under Discord's terms and retention. The bridge announces
            itself in each Armada channel.
          </AlertDescription>
        </Alert>

        <label className="flex cursor-pointer items-start gap-2.5 text-left">
          <Checkbox checked={consent} onCheckedChange={(v) => setConsent(v === true)} className="mt-0.5" />
          <span className="text-xs leading-relaxed text-muted-foreground">
            I understand the linked channels' messages will no longer be end-to-end encrypted.
          </span>
        </label>

        <div className="space-y-2">
          <Button size="lg" className="w-full clip-corner-lg" disabled={!!blocker || !!busy} onClick={() => void submit()}>
            {busy ? <><Loader2 className="animate-spin" /> {busy}</> : login.pk ? `Bridge ${plural(linked.length, "channel")}` : `Request ${plural(linked.length, "bridge")}`}
          </Button>
          {blocker && <p className="text-center text-xs text-muted-foreground">{blocker}.</p>}
        </div>
      </div>
    </ConnectShell>
  );
}

function MapRow(props: {
  row: Row;
  choices: ReturnType<typeof armadaChoices>;
  canCreateArmada: boolean;
  onDiscord: (discordId: string, value: string) => void;
  onArmada: (armadaId: string, value: "create" | "skip") => void;
  onHistory: (key: string, value: History) => void;
}) {
  const { row, choices, canCreateArmada } = props;
  const linked = isLinked(row);
  const options = historyOptions(row);
  const fromDiscord = row.key.startsWith("d:");

  const discordCell =
    fromDiscord && row.discord?.kind === "existing" ? (
      <ChannelLabel name={row.discord.channel.name} category={row.discord.channel.category} note={row.discord.channel.empty ? "empty" : undefined} />
    ) : (
      <select
        aria-label="Discord side"
        className={selectClass}
        value={row.discord ? "create" : "skip"}
        onChange={(e) => props.onArmada(row.key.slice(2), e.target.value as "create" | "skip")}
      >
        <option value="skip">Don't bridge</option>
        <option value="create">Create #{row.armada?.kind === "existing" ? row.armada.channel.name : "channel"} on Discord</option>
      </select>
    );

  const armadaCell = fromDiscord ? (
    <select
      aria-label="Armada side"
      className={selectClass}
      value={row.armada?.kind === "existing" ? row.armada.channel.idHex : row.armada ? "create" : "skip"}
      onChange={(e) => props.onDiscord(row.key.slice(2), e.target.value)}
    >
      <option value="skip">Don't bridge</option>
      {canCreateArmada && <option value="create">Create #{row.discord?.kind === "existing" ? row.discord.channel.name : "channel"} on Armada</option>}
      {choices.map((c) => (
        <option key={c.idHex} value={c.idHex}>
          #{c.name}
          {c.category ? ` · ${c.category}` : ""}
        </option>
      ))}
    </select>
  ) : (
    row.armada?.kind === "existing" && <ChannelLabel name={row.armada.channel.name} category={row.armada.channel.category} />
  );

  return (
    <div className={cn("space-y-1.5 px-3 py-2", !linked && "opacity-60")}>
      <div className="grid grid-cols-[1fr_auto_1fr] items-center gap-2">
        <div className="min-w-0">{discordCell}</div>
        {linked ? <ArrowLeftRight className="size-4 text-primary/70" /> : <span className="w-4" />}
        <div className="min-w-0">{armadaCell}</div>
      </div>
      {linked && (row.discord?.kind === "create" || row.armada?.kind === "create") && (
        <p className="flex items-center gap-1 text-2xs text-muted-foreground">
          <Plus className="size-3" /> created by the bridge
          {(row.discord?.kind === "create" ? row.discord.category : row.armada?.kind === "create" ? row.armada.category : null) && <> under its category</>}
        </p>
      )}
      {linked && options.length > 1 && (
        <select
          aria-label="History"
          className={cn(selectClass, "h-7 w-auto bg-transparent text-xs text-muted-foreground")}
          value={row.history}
          onChange={(e) => props.onHistory(row.key, e.target.value as History)}
        >
          {options.map((o) => (
            <option key={o} value={o}>
              {HISTORY_LABEL[o]}
            </option>
          ))}
        </select>
      )}
    </div>
  );
}

function ChannelLabel({ name, category, note }: { name: string; category?: string | null; note?: string }) {
  return (
    <span className="flex min-w-0 items-center gap-1.5 text-sm">
      <Hash className="size-3.5 shrink-0 text-muted-foreground" />
      <span className="truncate">{name}</span>
      {category && <span className="hidden shrink truncate text-2xs text-muted-foreground sm:inline">{category}</span>}
      {note && <span className="shrink-0 text-2xs text-muted-foreground">{note}</span>}
    </span>
  );
}
