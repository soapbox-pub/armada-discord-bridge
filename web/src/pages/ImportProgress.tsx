import { AlertTriangle, ArrowRight, Check, ExternalLink, History, Loader2, RotateCw } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";

import { api, type ImportStatus } from "@/api";
import { CopyButton, SectionLabel } from "@/components/common";
import { DiscordMark } from "@/components/brand/marks";
import { WizardShell, WizardStepBody } from "@/components/WizardShell";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { toast } from "@/components/ui/toaster";
import { cn, errText, plural } from "@/lib/utils";

const RUNNING: ImportStatus["status"][] = ["minting", "publishing", "wiring", "history"];

/**
 * An import's progress and result, read from the server, so it survives a
 * reload and can be revisited. The pipeline runs server-side; closing this
 * page doesn't stop it.
 */
export function ImportProgress() {
  const { id } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const [status, setStatus] = useState<ImportStatus | null>(null);
  const [loadError, setLoadError] = useState("");
  const [actionError, setActionError] = useState("");
  const [poll, setPoll] = useState(0);

  useEffect(() => {
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const res = await api<ImportStatus>(`/api/imports/${id}`);
        if (stop) return;
        setStatus(res);
        setLoadError("");
        if (!RUNNING.includes(res.status) && res.status !== "awaiting_sigs") return;
      } catch (e) {
        // A 404 is final; anything else is likely a portal restart, so keep polling.
        if (!stop && /not found/i.test(errText(e))) {
          setLoadError("This import doesn't exist, or it belongs to another Discord account.");
          return;
        }
      }
      if (!stop) timer = setTimeout(() => void tick(), 2000);
    };
    void tick();
    return () => {
      stop = true;
      clearTimeout(timer);
    };
  }, [id, poll]);

  // Open the finished community in Armada, once, and only when this visit
  // watched it finish: revisiting a done import shouldn't pop a tab. A popup
  // blocker may eat it; the button covers that.
  const sawRunning = useRef(Boolean((location.state as { fresh?: boolean } | null)?.fresh));
  const opened = useRef(false);
  useEffect(() => {
    if (!status) return;
    if (status.status !== "done") {
      sawRunning.current = true;
      return;
    }
    if (sawRunning.current && status.inviteUrl && !opened.current) {
      opened.current = true;
      window.open(status.inviteUrl, "_blank", "noopener");
    }
  }, [status]);

  async function act(path: "retry" | "rerun-history") {
    setActionError("");
    try {
      await api(`/api/imports/${id}/${path}`, { method: "POST" });
      if (path === "rerun-history") toast({ title: "History re-import started", description: "Messages appear in Armada as they publish." });
      setStatus((s) => (s ? { ...s, status: path === "retry" ? "publishing" : "history", statusDetail: null } : s));
      setPoll((n) => n + 1);
    } catch (e) {
      setActionError(errText(e));
    }
  }

  const close = () => navigate("/", { replace: true });

  if (loadError) {
    return (
      <WizardShell index={0} total={0} stepKey="missing" onClose={close}>
        <WizardStepBody glyph={<AlertTriangle className="size-14 text-destructive" />} title="import not found" description={loadError}>
          <Button asChild size="lg" className="w-full clip-corner-lg">
            <Link to="/import">Start an import</Link>
          </Button>
        </WizardStepBody>
      </WizardShell>
    );
  }

  if (!status) {
    return (
      <WizardShell index={0} total={0} stepKey="loading" onClose={close}>
        <div className="flex justify-center">
          <Loader2 className="size-6 animate-spin text-muted-foreground" />
        </div>
      </WizardShell>
    );
  }

  const plan = status.plan;
  const selected = plan.channels.filter((c) => c.selected);
  const bridged = selected.filter((c) => c.bridge);
  const published = selected.filter((c) => c.publishedAt).length;
  const wired = plan.channels.filter((c) => c.bridgeId).length;
  const rolesDone = plan.roles.filter((r) => r.publishedAt).length;
  const historyCount = plan.channels.reduce((n, c) => n + (c.historyImported ?? 0), 0);
  const wantsHistory = selected.some((c) => c.bridge && c.history);
  const skippedBridges = plan.channels.filter((c) => c.bridgeSkipped);

  if (status.status === "previewed" || status.status === "awaiting_sigs") {
    return (
      <WizardShell index={0} total={0} stepKey="unstarted" onClose={close}>
        <WizardStepBody
          glyph={<DiscordMark className="size-14 text-discord" />}
          title="not started yet"
          description={`The import of ${plan.communityName} was reviewed but never signed, so nothing has been created.`}
        >
          <Button asChild size="lg" className="w-full clip-corner-lg">
            <Link to="/import">Start over</Link>
          </Button>
        </WizardStepBody>
      </WizardShell>
    );
  }

  if (status.status === "done") {
    const bits = [
      plural(published, "channel"),
      wired > 0 ? `${wired} live ${wired === 1 ? "bridge" : "bridges"}` : null,
      historyCount > 0 ? `${historyCount.toLocaleString()} history messages` : null,
      plan.emojis.length > 0 ? plural(plan.emojis.length, "custom emoji", "custom emoji") : null,
    ].filter(Boolean);
    return (
      <WizardShell index={0} total={0} stepKey="done" onClose={close}>
        <WizardStepBody
          glyph={
            <span className="grid size-16 place-items-center rounded-full bg-accent2/10 wake-glow">
              <Check className="size-9 animate-success-pop text-accent2" />
            </span>
          }
          title={`${plan.communityName} is live`}
          description={`${bits.join(", ")}, owned by your key.`}
        >
          <div className="space-y-4 text-left">
            {actionError && (
              <Alert variant="destructive">
                <AlertDescription>{actionError}</AlertDescription>
              </Alert>
            )}
            {status.inviteUrl && (
              <>
                <Button asChild size="lg" className="w-full clip-corner-lg">
                  <a href={status.inviteUrl} target="_blank" rel="noreferrer">
                    Open your community in Armada <ExternalLink className="opacity-60" />
                  </a>
                </Button>
                <div className="flex items-center gap-2 rounded-lg bg-secondary/40 py-1 pl-3 pr-1">
                  <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground">{status.inviteUrl}</span>
                  <CopyButton value={status.inviteUrl} label="Copy invite link" />
                </div>
              </>
            )}
            <Button asChild variant="secondary" className="w-full clip-corner-lg">
              <Link to="/">
                Go to your bridges <ArrowRight />
              </Link>
            </Button>
            {wantsHistory && (
              <Button variant="ghost" className="w-full text-muted-foreground" onClick={() => void act("rerun-history")}>
                <History /> Re-run history import
              </Button>
            )}
            {skippedBridges.length > 0 && (
              <Box title="Bridges not wired">
                {skippedBridges.map((c) => (
                  <p key={c.discordId} className="text-xs text-muted-foreground">
                    <span className="text-foreground/80">#{c.name}</span>: {c.bridgeSkipped}
                  </p>
                ))}
              </Box>
            )}
            {plan.skipped.length > 0 && (
              <Box title="Not imported">
                {plan.skipped.map((s, i) => (
                  <p key={i} className="text-xs text-muted-foreground">
                    <span className="text-foreground/80">{s.name}</span>: {s.reason}
                  </p>
                ))}
              </Box>
            )}
          </div>
        </WizardStepBody>
      </WizardShell>
    );
  }

  const failed = status.status === "failed";
  const minted = Boolean(plan.checkpoints?.communityIdHex);
  const stages: Array<{ label: string; value: string; state: StageState; progress?: number }> = [
    { label: "Community", value: minted ? "minted, owned by your key" : "minting…", state: minted ? "done" : "active" },
    {
      label: "Channels",
      value: `${published} / ${selected.length}`,
      state: stage(published, selected.length, minted),
      progress: selected.length ? published / selected.length : 1,
    },
    { label: "Roles", value: `${rolesDone} / ${plan.roles.length}`, state: stage(rolesDone, plan.roles.length, minted) },
  ];
  if (bridged.length > 0) {
    stages.push({
      label: "Live bridges",
      value: `${wired} / ${bridged.length}`,
      state: stage(wired + skippedBridges.length, bridged.length, published === selected.length),
    });
  }
  if (wantsHistory) {
    stages.push({ label: "History", value: `${historyCount.toLocaleString()} messages`, state: status.status === "history" ? "active" : "waiting" });
  }
  // A failure stops the pipeline at one stage; the ones after it never began.
  if (failed) {
    const at = stages.findIndex((s) => s.state !== "done");
    stages.forEach((s, i) => {
      if (s.state !== "done") s.state = i === at ? "stopped" : "waiting";
    });
  }

  return (
    <WizardShell index={0} total={0} stepKey="progress" onClose={close}>
      <WizardStepBody
        glyph={failed ? <AlertTriangle className="size-14 text-destructive" /> : <Loader2 className="size-14 animate-spin text-discord" />}
        title={failed ? "import stopped" : `importing ${plan.communityName}`}
        description={
          failed
            ? "The import stopped partway. Nothing is lost, and retrying picks up where it left off."
            : "Minting the community, publishing channels and roles, then wiring the live bridges. A big server takes a few minutes; you can close this page and come back."
        }
      >
        <div className="space-y-3 text-left">
          <ol className="space-y-1 rounded-lg bg-secondary/40 p-3">
            {stages.map((s) => (
              <Stage key={s.label} {...s} />
            ))}
          </ol>
          <p className="text-center font-mono text-xs text-muted-foreground">status: {status.status}</p>
          {failed && (
            <>
              {(status.statusDetail || actionError) && (
                <Alert variant="destructive">
                  <AlertDescription className="text-xs">{actionError || status.statusDetail}</AlertDescription>
                </Alert>
              )}
              <Button size="lg" className="w-full clip-corner-lg" onClick={() => void act("retry")}>
                <RotateCw /> Retry from where it stopped
              </Button>
            </>
          )}
        </div>
      </WizardStepBody>
    </WizardShell>
  );
}

type StageState = "done" | "active" | "waiting" | "stopped";

function stage(done: number, total: number, started: boolean): StageState {
  if (total > 0 && done >= total) return "done";
  if (total === 0 && started) return "done";
  return started ? "active" : "waiting";
}

function Stage({ state, label, value, progress }: { state: StageState; label: string; value: string; progress?: number }) {
  return (
    <li className="space-y-1.5 px-1 py-1.5">
      <div className="flex items-center gap-2.5">
        <span className="grid size-4 shrink-0 place-items-center">
          {state === "done" && <Check className="size-4 text-accent2" />}
          {state === "active" && <Loader2 className="size-3.5 animate-spin text-primary" />}
          {state === "waiting" && <span className="size-1.5 rounded-full bg-muted-foreground/40" />}
          {state === "stopped" && <span className="size-1.5 rounded-full bg-destructive" />}
        </span>
        <span className={cn("flex-1 text-sm", state === "waiting" && "text-muted-foreground")}>{label}</span>
        <span className="font-mono text-xs text-muted-foreground">{value}</span>
      </div>
      {progress !== undefined && state === "active" && (
        <div className="ml-[1.625rem] h-0.5 overflow-hidden rounded-full bg-muted">
          <div className="h-full bg-primary transition-all duration-500" style={{ width: `${Math.round(progress * 100)}%` }} />
        </div>
      )}
    </li>
  );
}

function Box({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="space-y-1 rounded-lg bg-secondary/40 p-3">
      <SectionLabel>{title}</SectionLabel>
      {children}
    </div>
  );
}
