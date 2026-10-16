import { ArrowLeft, Check, History, Loader2, Pause, Play, Plus, Unlink } from "lucide-react";
import * as nip19 from "nostr-tools/nip19";
import { useEffect, useState, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { api, type BridgeSummary } from "@/api";
import { ChannelName, CopyButton, SectionLabel, StatusPill } from "@/components/common";
import { DiscordMark } from "@/components/brand/marks";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { toast } from "@/components/ui/toaster";
import { useBridges } from "@/hooks";
import { errText } from "@/lib/utils";

function npubOf(hex?: string): string | undefined {
  if (!hex || !/^[0-9a-f]{64}$/i.test(hex)) return undefined;
  return nip19.npubEncode(hex.toLowerCase());
}

function short(s: string, head = 12, tail = 6) {
  return s.length > head + tail + 1 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s;
}

export function BridgeDetail() {
  const { id } = useParams();
  const { bridges, error, reload } = useBridges();
  const bridge = bridges?.find((b) => b.bridge_id === id);

  if (error && !bridges) {
    return (
      <Alert variant="destructive">
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }
  if (!bridges) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="size-4 animate-spin" /> Loading…
      </div>
    );
  }
  if (!bridge) {
    return (
      <div className="flex flex-col items-center gap-4 py-16 text-center">
        <h1 className="font-mono text-2xl font-bold lowercase tracking-tight">bridge not found</h1>
        <p className="text-sm text-muted-foreground">It may have been unlinked, or it belongs to another Discord account.</p>
        <Button asChild variant="secondary" className="clip-corner-lg">
          <Link to="/"><ArrowLeft /> All bridges</Link>
        </Button>
      </div>
    );
  }
  return <BridgeView bridge={bridge} reload={reload} />;
}

function BridgeView({ bridge: b, reload }: { bridge: BridgeSummary; reload: () => Promise<void> }) {
  const navigate = useNavigate();
  const [busy, setBusy] = useState<"" | "pause" | "resume" | "unlink" | "history">("");
  const npub = npubOf(b.primary_pk);
  const count = Number(b.bridged_count) || 0;

  async function act(action: "pause" | "resume" | "unlink") {
    setBusy(action);
    try {
      await api(`/api/bridges/${b.bridge_id}/${action}`, { method: "POST" });
      if (action === "unlink") {
        toast({ title: "Bridge unlinked", description: `#${b.discord_channel_name ?? "channel"} is no longer mirrored.` });
        navigate("/", { replace: true });
        return;
      }
      toast({ title: action === "pause" ? "Bridge paused" : "Bridge resumed" });
      await reload();
    } catch (e) {
      toast({ title: `Couldn't ${action} the bridge`, description: errText(e), variant: "destructive" });
    } finally {
      setBusy("");
    }
  }

  async function rerunHistory() {
    setBusy("history");
    try {
      await api(`/api/communities/${b.community_id}/rerun-history`, { method: "POST" });
      toast({ title: "History re-import started", description: "Messages appear in Armada as they publish." });
    } catch (e) {
      toast({ title: "Couldn't re-run the history import", description: errText(e), variant: "destructive" });
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="space-y-8">
      <Link to="/" className="inline-flex items-center gap-1.5 text-sm text-muted-foreground transition-colors hover:text-foreground">
        <ArrowLeft className="size-4" /> All bridges
      </Link>

      <header className="space-y-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <SectionLabel>{b.community_name ?? "Armada community"}</SectionLabel>
          <StatusPill status={b.status} live={b.live} />
        </div>
        <h1 className="flex flex-wrap items-center gap-x-3 gap-y-1 text-2xl font-bold tracking-tight sm:text-3xl">
          <span className="flex min-w-0 items-center gap-2">
            <DiscordMark className="size-6 shrink-0 text-discord" />
            <ChannelName name={b.discord_channel_name} />
          </span>
          <span className="font-normal text-primary">⇆</span>
          <ChannelName name={b.concord_channel_name} className="font-mono" />
        </h1>
        <p className="text-sm text-muted-foreground">
          {b.discord_guild_name ?? "Discord server"} on Discord, {b.community_name ?? "your community"} on Armada
          {count > 0 && <> · {count.toLocaleString()} messages bridged</>}
        </p>
      </header>

      {b.status === "pending_confirm" && <AwaitingConfirm bridge={b} onActive={reload} />}

      {b.status === "severed" && (
        <Alert variant="destructive">
          <AlertTitle>The bridge stopped</AlertTitle>
          <AlertDescription className="space-y-3">
            <p>{b.status_detail ?? "It lost access to one side. Fix the cause, then resume it."}</p>
            <Button size="sm" className="clip-corner" disabled={!!busy} onClick={() => void act("resume")}>
              {busy === "resume" ? <Loader2 className="animate-spin" /> : <Play />} Resume
            </Button>
          </AlertDescription>
        </Alert>
      )}

      {b.status === "paused" && (
        <Alert>
          <AlertDescription className="flex flex-wrap items-center justify-between gap-3">
            <span className="text-muted-foreground">Paused. Nothing is mirrored in either direction until you resume.</span>
            <Button size="sm" className="clip-corner" disabled={!!busy} onClick={() => void act("resume")}>
              {busy === "resume" ? <Loader2 className="animate-spin" /> : <Play />} Resume
            </Button>
          </AlertDescription>
        </Alert>
      )}

      <section className="space-y-2">
        <SectionLabel>Details</SectionLabel>
        <dl className="divide-y divide-chrome overflow-hidden rounded-lg border border-chrome bg-card text-sm">
          <Row label="Discord channel" value={b.discord_channel_id} display={b.discord_channel_id} />
          <Row label="Armada channel" value={b.concord_channel_id} display={b.concord_channel_id && short(b.concord_channel_id)} />
          <Row
            label="Bridge identity"
            hint="The bridge's own Armada account. Moderators can look it up by this npub."
            value={npub}
            display={npub && short(npub, 14, 8)}
          />
          {b.created_at && <Row label="Created" display={new Date(b.created_at).toLocaleString()} />}
          {b.status_detail && b.status !== "severed" && <Row label="Last status" display={b.status_detail} mono={false} />}
        </dl>
      </section>

      <section className="space-y-2">
        <SectionLabel>Manage</SectionLabel>
        <div className="flex flex-wrap gap-2">
          {b.status === "active" && (
            <Button variant="secondary" className="clip-corner-lg" disabled={!!busy} onClick={() => void act("pause")}>
              {busy === "pause" ? <Loader2 className="animate-spin" /> : <Pause />} Pause
            </Button>
          )}
          {b.community_id && b.discord_guild_id && (
            <Button asChild variant="secondary" className="clip-corner-lg">
              <Link to={`/connect?from=${b.bridge_id}`}><Plus /> Manage channels</Link>
            </Button>
          )}
          {b.community_id && (
            <Button variant="secondary" className="clip-corner-lg" disabled={!!busy} onClick={() => void rerunHistory()}>
              {busy === "history" ? <Loader2 className="animate-spin" /> : <History />} Re-run history import
            </Button>
          )}
        </div>
      </section>

      <section className="space-y-2">
        <SectionLabel className="text-destructive/80">Danger zone</SectionLabel>
        <div className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-destructive/30 bg-destructive/5 p-4">
          <div className="max-w-md space-y-1">
            <div className="text-sm font-medium">Unlink this bridge</div>
            <p className="text-xs leading-relaxed text-muted-foreground">
              Stops mirroring for good and destroys the bridge's keys. Its bridged identities can't be recovered.
            </p>
          </div>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="destructive" className="clip-corner-lg" disabled={!!busy}>
                {busy === "unlink" ? <Loader2 className="animate-spin" /> : <Unlink />} Unlink
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>unlink this bridge?</AlertDialogTitle>
                <AlertDialogDescription>
                  #{b.discord_channel_name} and #{b.concord_channel_name} stop mirroring. The bridge's keys are
                  destroyed, and the bridged identities can't be recovered. Messages already copied stay where they are.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Keep it</AlertDialogCancel>
                <AlertDialogAction destructive onClick={() => void act("unlink")}>Unlink</AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      </section>
    </div>
  );
}

function Row(props: { label: string; hint?: string; value?: string; display?: ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-center gap-4 px-4 py-3">
      <dt className="w-28 shrink-0 sm:w-36 text-muted-foreground" title={props.hint}>{props.label}</dt>
      <dd className={`min-w-0 flex-1 truncate ${props.mono === false ? "" : "font-mono text-xs"}`}>{props.display ?? "—"}</dd>
      {props.value && <CopyButton value={props.value} label={`Copy ${props.label.toLowerCase()}`} />}
    </div>
  );
}

/**
 * The bridge is requested but not yet enabled on the Armada side. Follows the
 * status live, so the page flips the moment a moderator confirms.
 */
function AwaitingConfirm({ bridge: b, onActive }: { bridge: BridgeSummary; onActive: () => Promise<void> }) {
  const [status, setStatus] = useState(b.status);

  useEffect(() => {
    const source = new EventSource(`/api/bridges/${b.bridge_id}/events`);
    source.onmessage = (event) => {
      const data = JSON.parse(event.data as string) as { status: string };
      setStatus(data.status);
      if (data.status !== "pending_confirm") {
        source.close();
        if (data.status === "active") toast({ title: "Bridge confirmed", description: "Messages now flow both ways." });
        void onActive();
      }
    };
    return () => source.close();
  }, [b.bridge_id, onActive]);

  if (status === "active") {
    return (
      <div className="flex items-center gap-3 rounded-lg border border-accent2/40 bg-accent2/5 p-4 text-sm">
        <Check className="size-5 animate-success-pop text-accent2" />
        Confirmed. Messages now flow both ways.
      </div>
    );
  }

  return (
    <div className="animate-pending-glow space-y-4 rounded-lg border border-primary/40 bg-primary/5 p-5">
      <div className="flex items-center gap-2">
        <Loader2 className="size-4 animate-spin text-primary" />
        <span className="font-mono text-sm font-bold lowercase tracking-tight text-primary">waiting for armada to confirm</span>
      </div>
      <ol className="space-y-2 text-sm leading-relaxed text-muted-foreground">
        <li className="flex gap-3">
          <span className="font-mono text-primary">1</span>
          <span>
            The bridge posted a confirmation request in <span className="font-mono text-foreground">#{b.concord_channel_name}</span> on Armada.
          </span>
        </li>
        <li className="flex gap-3">
          <span className="font-mono text-primary">2</span>
          <span>
            Any member there with <span className="text-foreground">Manage Channels</span> replies with the code from that message:
            <code className="mt-1.5 block w-fit rounded-chrome border border-dashed border-border bg-chrome-deep px-2.5 py-1 font-mono text-xs text-foreground">
              /bridge confirm &lt;code&gt;
            </code>
          </span>
        </li>
        <li className="flex gap-3">
          <span className="font-mono text-primary">3</span>
          <span>This page updates on its own when they do. You can leave and come back.</span>
        </li>
      </ol>
    </div>
  );
}
