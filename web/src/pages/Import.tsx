import { AlertTriangle, Check, ExternalLink, Hash, Loader2, Lock, Plus, RefreshCw, ShieldAlert, Volume2, X } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { Navigate, Route, Routes, useNavigate } from "react-router-dom";
import type { NostrEvent } from "nostr-tools/pure";

import { api } from "@/api";
import type { ImportChannel, ImportPlanView, OwnerSignTemplate } from "@/api";
import { GuildIcon, SectionLabel } from "@/components/common";
import { DiscordMark } from "@/components/brand/marks";
import { PickRow, WizardShell, WizardStepBody, useFlowNav } from "@/components/WizardShell";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { cn, errText, plural } from "@/lib/utils";
import { NostrLogin } from "@/NostrLogin";
import { useMe } from "@/session";
import { useNostrLogin } from "@/useNostrLogin";

/**
 * The import being set up, mirrored to sessionStorage so a reload lands back
 * on the review with the toggles as they were. Nothing secret is in it: the
 * owner's key lives in the login hook's memory and nowhere else (see
 * useNostrLogin), which is also why it is held up here, above the step routes,
 * where moving between steps does not drop it.
 */
interface Draft {
  guildId?: string;
  importId?: string;
  plan?: ImportPlanView;
  defaultRelays?: string[];
  relays?: string[];
  editRelays?: boolean;
}

const DRAFT_KEY = "portal:import";

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
  login: ReturnType<typeof useNostrLogin>;
  close: () => void;
}

const FlowContext = createContext<Flow | null>(null);
const useFlow = () => useContext(FlowContext)!;

const discordGlyph = <DiscordMark className="size-14 text-discord" />;

export function ImportFlow() {
  const [draft, setDraft] = useState<Draft>(loadDraft);
  const login = useNostrLogin([]);
  const navigate = useNavigate();

  useEffect(() => {
    sessionStorage.setItem(DRAFT_KEY, JSON.stringify(draft));
  }, [draft]);

  const update = useCallback((patch: Partial<Draft>) => setDraft((d) => ({ ...d, ...patch })), []);
  const close = useCallback(() => {
    sessionStorage.removeItem(DRAFT_KEY);
    navigate("/", { replace: true });
  }, [navigate]);

  return (
    <FlowContext.Provider value={{ draft, update, login, close }}>
      <Routes>
        <Route index element={<ServerStep />} />
        <Route path="review" element={<ReviewStep />} />
        <Route path="*" element={<Navigate to="/import" replace />} />
      </Routes>
    </FlowContext.Provider>
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

// ── 1. Server (and the bot install, if it's missing) ─────────────────────────

function ServerStep() {
  const { guilds } = useMe();
  const { draft, update, close } = useFlow();
  const { next } = useFlowNav();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [installUrl, setInstallUrl] = useState("");

  async function preview() {
    if (!draft.guildId) return;
    setBusy(true);
    setError("");
    try {
      const res = await api<
        | { present: false; installUrl: string }
        | { present: true; importId: string; plan: ImportPlanView; defaultRelays: string[] }
      >("/api/imports", { method: "POST", body: JSON.stringify({ guildId: draft.guildId }) });
      if (!res.present) {
        setInstallUrl(res.installUrl);
        return;
      }
      setInstallUrl("");
      update({ importId: res.importId, plan: res.plan, defaultRelays: res.defaultRelays, relays: res.defaultRelays, editRelays: false });
      next("/import/review");
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  }

  const guild = guilds.find((g) => g.id === draft.guildId);

  if (installUrl) {
    return (
      <WizardShell index={0} total={2} stepKey="install" onBack={() => setInstallUrl("")} onClose={close}>
        <ErrorLine error={error} />
        <WizardStepBody
          glyph={discordGlyph}
          title="install the bot"
          description={
            <>
              The bridge bot isn't in <span className="text-foreground">{guild?.name ?? "this server"}</span> yet. It reads the
              server's structure for the import and runs any live bridges afterwards.
            </>
          }
        >
          <div className="space-y-3">
            <Button asChild size="lg" className="w-full clip-corner-lg">
              <a href={installUrl} target="_blank" rel="noopener noreferrer">
                <DiscordMark /> Install the bot <ExternalLink className="opacity-60" />
              </a>
            </Button>
            <Button variant="secondary" className="w-full clip-corner-lg" disabled={busy} onClick={() => void preview()}>
              {busy ? <Loader2 className="animate-spin" /> : <RefreshCw />} I installed it, check again
            </Button>
          </div>
        </WizardStepBody>
      </WizardShell>
    );
  }

  return (
    <WizardShell index={0} total={2} stepKey="server" onClose={close}>
      <ErrorLine error={error} />
      <WizardStepBody
        glyph={discordGlyph}
        title="import a server"
        description="The whole server becomes a brand-new Armada community that you own: its channels, roles and custom emoji, with optional live bridges and message history."
      >
        <div className="space-y-3">
          {guilds.length === 0 && <p className="text-sm text-muted-foreground">No servers found where you hold Manage Server.</p>}
          <div className="space-y-1.5">
            {guilds.map((g) => (
              <PickRow key={g.id} selected={draft.guildId === g.id} onClick={() => update({ guildId: g.id })}>
                <GuildIcon name={g.name} icon={g.icon} />
                <span className="min-w-0 flex-1 truncate text-sm font-medium">{g.name}</span>
                {draft.guildId === g.id && <Check className="size-4 shrink-0 text-primary" />}
              </PickRow>
            ))}
          </div>
          <Button size="lg" className="w-full clip-corner-lg" disabled={!draft.guildId || busy} onClick={() => void preview()}>
            {busy ? <><Loader2 className="animate-spin" /> Reading the server…</> : "Continue"}
          </Button>
          <p className="text-xs text-muted-foreground">Only servers where you hold Manage Server are listed.</p>
        </div>
      </WizardStepBody>
    </WizardShell>
  );
}

// ── 2. Review, sign, confirm ─────────────────────────────────────────────────

function ReviewStep() {
  const { draft, update, login, close } = useFlow();
  const { back } = useFlowNav();
  const navigate = useNavigate();
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [signingStep, setSigningStep] = useState("");
  const [error, setError] = useState("");
  const [newRelay, setNewRelay] = useState("");

  const plan = draft.plan;
  const relays = draft.relays ?? [];

  const groups = useMemo(() => {
    const out: Array<{ category?: string; channels: ImportChannel[] }> = [];
    for (const c of plan?.channels ?? []) {
      const last = out[out.length - 1];
      if (last && last.category === c.category) last.channels.push(c);
      else out.push({ category: c.category, channels: [c] });
    }
    return out;
  }, [plan]);

  if (!plan || !draft.importId) return <Navigate to="/import" replace />;

  const selected = plan.channels.filter((c) => c.selected);
  const bridged = selected.filter((c) => c.bridge);
  const privateBridged = bridged.some((c) => c.private);
  const missingWebhook = bridged.filter((c) => c.botMissingWebhook);
  const newRelayValid = /^wss?:\/\/\S+$/.test(newRelay.trim()) && !relays.includes(newRelay.trim());

  function setChannels(map: (c: ImportChannel) => ImportChannel) {
    update({ plan: { ...plan!, channels: plan!.channels.map(map) } });
  }

  // Each flag implies the one above: history needs a bridge, a bridge needs the channel.
  function toggle(discordId: string, field: "selected" | "bridge" | "history") {
    setChannels((c) => {
      if (c.discordId !== discordId) return c;
      if (field === "selected") {
        const on = !c.selected;
        return { ...c, selected: on, bridge: on && c.bridge, history: on && c.history };
      }
      if (field === "bridge") {
        const on = !c.bridge;
        return { ...c, bridge: on, history: on && c.history };
      }
      return { ...c, history: !c.history };
    });
  }

  function addRelay() {
    if (!newRelayValid) return;
    update({ relays: [...relays, newRelay.trim()] });
    setNewRelay("");
  }

  async function start() {
    if (!login.pk) return;
    setBusy(true);
    setError("");
    try {
      setSigningStep("Preparing the community…");
      const prep = await api<{ ownerPk: string; templates: OwnerSignTemplate[] }>(`/api/imports/${draft.importId}/prepare`, {
        method: "POST",
        body: JSON.stringify({
          ownerNpub: login.pk,
          relays: draft.editRelays ? relays : undefined,
          channels: plan!.channels.map((c) => ({ discordId: c.discordId, selected: c.selected, bridge: c.bridge, history: c.history })),
        }),
      });
      const signed: NostrEvent[] = [];
      for (let i = 0; i < prep.templates.length; i++) {
        setSigningStep(`Signing as owner (${i + 1} of ${prep.templates.length})…`);
        signed.push(await login.signTemplate(prep.templates[i].template));
      }
      setSigningStep("Starting the import…");
      await api(`/api/imports/${draft.importId}/confirm`, { method: "POST", body: JSON.stringify({ signedEvents: signed }) });
      const id = draft.importId!;
      sessionStorage.removeItem(DRAFT_KEY);
      navigate(`/imports/${id}`, { replace: true, state: { fresh: true } });
    } catch (e) {
      setSigningStep("");
      setError(errText(e));
      setBusy(false);
    }
  }

  const blocker = !login.pk
    ? "Log in with your Armada key first"
    : selected.length === 0
      ? "Pick at least one channel"
      : relays.length === 0
        ? "Add at least one relay"
        : undefined;

  return (
    <WizardShell index={1} total={2} stepKey="review" maxWidth="max-w-xl" onBack={() => back("/import")} onClose={close}>
      <div className="flex flex-col gap-7">
        <div className="flex flex-col items-center gap-3 text-center">
          {plan.guild.iconUrl ? (
            <img src={plan.guild.iconUrl} alt="" className="size-14 rounded-2xl" referrerPolicy="no-referrer" />
          ) : (
            discordGlyph
          )}
          <div className="space-y-1.5">
            <h1 className="font-mono text-2xl font-bold lowercase tracking-tight">{plan.communityName}</h1>
            <p className="text-sm text-muted-foreground">
              {plural(selected.length, "channel")} · {bridged.length} live-bridged · {plural(plan.roles.length, "role")}
              {plan.emojis.length > 0 && <> · {plural(plan.emojis.length, "emoji", "emoji")}</>}
            </p>
          </div>
        </div>

        <ErrorLine error={error} />

        <Section title="Your Armada account" hint="The new community is owned by this key, like any community you create in Armada.">
          <NostrLogin login={login} />
        </Section>

        <Section
          title="Channels"
          action={
            <span className="flex gap-3 text-xs">
              <button type="button" className="text-muted-foreground hover:text-foreground" onClick={() => setChannels((c) => ({ ...c, selected: true }))}>
                All
              </button>
              <button
                type="button"
                className="text-muted-foreground hover:text-foreground"
                onClick={() => setChannels((c) => ({ ...c, selected: false, bridge: false, history: false }))}
              >
                None
              </button>
            </span>
          }
        >
          <div className="overflow-hidden rounded-lg bg-secondary/30">
            <div className="flex items-center gap-2 border-b border-chrome px-3 py-2 text-2xs uppercase tracking-wider text-muted-foreground">
              <span className="flex-1">Channel</span>
              <span className="w-12 text-center">Bridge</span>
              <span className="w-12 text-center">History</span>
            </div>
            <div className="max-h-[50vh] overflow-y-auto p-1">
              {groups.map((g, i) => (
                <div key={`${g.category ?? ""}-${i}`}>
                  {g.category && (
                    <div className="px-2 pb-1 pt-3 text-2xs font-semibold uppercase tracking-wider text-muted-foreground/80">{g.category}</div>
                  )}
                  {g.channels.map((c) => (
                    <ChannelRow key={c.discordId} channel={c} onToggle={(f) => toggle(c.discordId, f)} />
                  ))}
                </div>
              ))}
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            Bridged channels keep mirroring both ways after the import. History brings over each one's newest 10,000
            messages with their original times and authors.
          </p>
          {plan.channels.some((c) => c.private) && (
            <p className="text-xs text-muted-foreground">
              <Lock className="mr-1 inline size-3" />
              Gated channels import as private: key-gated, and invisible to members without the role. Only you get the key
              at first; you share it from Armada.
            </p>
          )}
        </Section>

        {missingWebhook.length > 0 && (
          <Alert variant="warning">
            <AlertTriangle />
            <AlertDescription className="text-xs leading-relaxed">
              The bot can't manage webhooks in {missingWebhook.map((c) => `#${c.name}`).join(", ")}, so Armada messages won't
              reach Discord there. Give the bot <strong>Manage Webhooks</strong> on those channels in Discord before importing.
            </AlertDescription>
          </Alert>
        )}

        {privateBridged && (
          <Alert variant="destructive">
            <Lock />
            <AlertDescription className="text-xs leading-relaxed">
              You're mirroring a private channel. Its key is handed to the bridge's own identity so it can read the room, and
              everything posted there is copied to Discord in plaintext: a gated room on this side is an ordinary Discord
              channel on the other. You can revoke the bridge's access from the channel's role in Armada at any time; doing so
              rotates the key, and the bridge stays silent on that channel until you re-grant it.
            </AlertDescription>
          </Alert>
        )}

        {plan.roles.length > 0 && (
          <Section title="Roles">
            <div className="flex flex-wrap gap-1.5">
              {plan.roles.map((r) => (
                <span
                  key={r.discordId}
                  title={r.dropped.length > 0 ? `Loses ${r.dropped.join(", ")}` : undefined}
                  className="inline-flex items-center gap-1 rounded-chrome bg-secondary/60 px-2 py-1 text-xs"
                >
                  {r.name}
                  {r.dropped.length > 0 && <AlertTriangle className="size-3 text-warning/80" />}
                </span>
              ))}
            </div>
            {plan.roles.some((r) => r.dropped.length > 0) && (
              <p className="text-xs text-muted-foreground">
                <AlertTriangle className="mr-1 inline size-3 text-warning/80" />
                Some Discord permissions have no Armada equivalent. Hover a role to see what it loses.
              </p>
            )}
          </Section>
        )}

        {plan.skipped.length > 0 && (
          <Section title="Not imported">
            <ul className="space-y-1 text-xs text-muted-foreground">
              {plan.skipped.map((s, i) => (
                <li key={i}>
                  <span className="text-foreground/80">{s.name}</span>: {s.reason}
                </li>
              ))}
            </ul>
          </Section>
        )}

        <Section
          title="Relays"
          action={
            !draft.editRelays ? (
              <button type="button" className="text-xs text-muted-foreground hover:text-foreground" onClick={() => update({ editRelays: true })}>
                Change
              </button>
            ) : (
              <button
                type="button"
                className="text-xs text-muted-foreground hover:text-foreground"
                onClick={() => {
                  update({ relays: draft.defaultRelays ?? [], editRelays: false });
                  setNewRelay("");
                }}
              >
                Reset to the standard set
              </button>
            )
          }
        >
          <div className="space-y-1 rounded-lg bg-secondary/30 p-2">
            {relays.map((r) => (
              <div key={r} className="flex items-center gap-2 px-1">
                <span className="size-1.5 shrink-0 rounded-full bg-accent2/70" />
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground">{r}</span>
                {draft.editRelays && (
                  <button
                    type="button"
                    aria-label={`Remove ${r}`}
                    className="grid size-6 place-items-center rounded text-muted-foreground hover:text-destructive"
                    onClick={() => update({ relays: relays.filter((x) => x !== r) })}
                  >
                    <X className="size-3.5" />
                  </button>
                )}
              </div>
            ))}
            {relays.length === 0 && <p className="px-1 text-xs text-destructive">No relays. Add at least one.</p>}
          </div>
          {draft.editRelays && (
            <div className="flex gap-2">
              <Input
                value={newRelay}
                onChange={(e) => setNewRelay(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    addRelay();
                  }
                }}
                placeholder="wss://relay.example.com"
                className="h-9 font-mono text-xs"
                autoComplete="off"
                spellCheck={false}
              />
              <Button type="button" variant="secondary" size="icon" className="size-9 shrink-0" aria-label="Add relay" disabled={!newRelayValid} onClick={addRelay}>
                <Plus />
              </Button>
            </div>
          )}
        </Section>

        <Alert variant="warning">
          <ShieldAlert />
          <AlertDescription className="text-xs leading-relaxed">
            You'll sign the community's founding events with your key, here in your browser; it never reaches the portal. The
            bridge keeps an Admin role to run the import and the live bridges, and you can revoke it from Armada at any time.{" "}
            <strong className="font-semibold">Bridged channels leave end-to-end encryption:</strong> their messages are mirrored
            to Discord in plaintext. The import runs once and can't be undone from here.
          </AlertDescription>
        </Alert>

        <label className="flex cursor-pointer items-start gap-2.5">
          <Checkbox checked={consent} onCheckedChange={(v) => setConsent(v === true)} className="mt-0.5" />
          <span className="text-xs leading-relaxed text-muted-foreground">
            I understand that I own this community, and that bridged channels are not end-to-end encrypted.
          </span>
        </label>

        <div className="space-y-2">
          <Button size="lg" className="w-full clip-corner-lg" disabled={!!blocker || !consent || busy} onClick={() => void start()}>
            {signingStep ? <><Loader2 className="animate-spin" /> {signingStep}</> : "Import the server"}
          </Button>
          {blocker && <p className="text-center text-xs text-muted-foreground">{blocker}.</p>}
        </div>
      </div>
    </WizardShell>
  );
}

function Section({ title, hint, action, children }: { title: string; hint?: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="space-y-2 text-left">
      <div className="flex items-baseline justify-between gap-3">
        <SectionLabel>{title}</SectionLabel>
        {action}
      </div>
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
      {children}
    </section>
  );
}

function ChannelRow({ channel: c, onToggle }: { channel: ImportChannel; onToggle: (f: "selected" | "bridge" | "history") => void }) {
  const Icon = c.private ? Lock : c.kind === "voice" ? Volume2 : Hash;
  return (
    <div className={cn("flex items-center gap-2 rounded-md px-2 py-1.5 hover:bg-secondary/50", !c.selected && "opacity-60")}>
      <label className="flex min-w-0 flex-1 cursor-pointer items-center gap-2">
        <Checkbox checked={c.selected} onCheckedChange={() => onToggle("selected")} />
        <Icon className="size-3.5 shrink-0 text-muted-foreground" />
        <span className="truncate text-sm">{c.name}</span>
        {c.kind === "voice" && <span className="shrink-0 text-2xs text-muted-foreground">voice</span>}
        {c.bridge && c.botMissingWebhook && (
          <span title="The bot lacks Manage Webhooks here" className="shrink-0">
            <AlertTriangle className="size-3.5 text-warning" />
          </span>
        )}
      </label>
      <span className="grid w-12 place-items-center">
        {c.bridgeable ? (
          <Checkbox aria-label={`Bridge #${c.name} live`} checked={c.bridge} disabled={!c.selected} onCheckedChange={() => onToggle("bridge")} />
        ) : (
          <span className="text-muted-foreground/40">—</span>
        )}
      </span>
      <span className="grid w-12 place-items-center">
        {c.bridgeable ? (
          <Checkbox aria-label={`Import #${c.name} history`} checked={c.history} disabled={!c.selected || !c.bridge} onCheckedChange={() => onToggle("history")} />
        ) : (
          <span className="text-muted-foreground/40">—</span>
        )}
      </span>
    </div>
  );
}
