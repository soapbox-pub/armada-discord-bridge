import { ArrowLeftRight, ChevronRight, History, MoreHorizontal, Plus, ServerCog } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";

import { api, type BridgeSummary } from "@/api";
import { ChannelName, StatusPill } from "@/components/common";
import { DiscordMark } from "@/components/brand/marks";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { toast } from "@/components/ui/toaster";
import { useBridges } from "@/hooks";
import { cn, errText, plural } from "@/lib/utils";

interface Community {
  key: string;
  name: string;
  guildName?: string;
  /** A bridge to copy the community (and its sealed invite) from. */
  source?: BridgeSummary;
  bridges: BridgeSummary[];
}

/**
 * One card per Armada community. Drafts are left out: they are what an
 * abandoned wizard leaves behind, carry no channel yet, and there is nothing
 * to do with one but start over.
 */
function groupByCommunity(bridges: BridgeSummary[]): Community[] {
  const groups = new Map<string, Community>();
  for (const b of bridges) {
    if (b.status === "draft") continue;
    const key = b.community_id ?? b.bridge_id;
    let g = groups.get(key);
    if (!g) {
      g = { key, name: b.community_name ?? "Unnamed community", guildName: b.discord_guild_name, bridges: [] };
      groups.set(key, g);
    }
    g.bridges.push(b);
    if (!g.source && b.community_id && b.discord_guild_id) g.source = b;
    g.guildName ??= b.discord_guild_name;
  }
  return [...groups.values()];
}

export function Dashboard() {
  const { bridges, error } = useBridges();
  const communities = bridges ? groupByCommunity(bridges) : null;
  const total = communities?.reduce((n, c) => n + c.bridges.length, 0) ?? 0;

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="space-y-1">
          <h1 className="font-mono text-3xl font-bold lowercase tracking-tight">bridges</h1>
          <p className="text-sm text-muted-foreground">
            {communities === null
              ? "Loading…"
              : total === 0
                ? "Nothing bridged yet."
                : `${plural(total, "channel")} across ${plural(communities.length, "community", "communities")}.`}
          </p>
        </div>
        {total > 0 && (
          <div className="flex gap-2">
            <Button asChild variant="secondary" className="clip-corner-lg">
              <Link to="/import"><ServerCog /> Import a server</Link>
            </Button>
            <Button asChild className="clip-corner-lg">
              <Link to="/new"><Plus /> New bridge</Link>
            </Button>
          </div>
        )}
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {communities === null && !error && <DashboardSkeleton />}

      {communities !== null && total === 0 && <EmptyState />}

      {communities?.map((c) => <CommunityCard key={c.key} community={c} />)}
    </div>
  );
}

function EmptyState() {
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <StartCard
        to="/new"
        icon={<ArrowLeftRight className="size-5" />}
        title="bridge a channel"
        body="Pair one Discord channel with a channel in an Armada community you're already in. Messages flow both ways."
        cta="New bridge"
      />
      <StartCard
        to="/import"
        icon={<DiscordMark className="size-5" />}
        title="import a server"
        body="Turn a whole Discord server into a new Armada community you own: channels, roles, emoji and history."
        cta="Import a server"
      />
    </div>
  );
}

function StartCard(props: { to: string; icon: React.ReactNode; title: string; body: string; cta: string }) {
  return (
    <Link
      to={props.to}
      className="group flex flex-col gap-3 clip-hairline-lg p-5 [--fill:var(--card)] [--fill-hover:var(--secondary)] focus-visible:outline-none focus-visible:[--edge:var(--ring)]"
    >
      <span className="grid size-10 place-items-center clip-corner bg-primary/15 text-primary">{props.icon}</span>
      <span className="font-mono text-lg font-bold lowercase tracking-tight">{props.title}</span>
      <span className="text-sm leading-relaxed text-muted-foreground">{props.body}</span>
      <span className="mt-auto inline-flex items-center gap-1 pt-2 text-sm font-medium text-primary">
        {props.cta}
        <ChevronRight className="size-4 transition-transform group-hover:translate-x-0.5" />
      </span>
    </Link>
  );
}

function CommunityCard({ community }: { community: Community }) {
  const navigate = useNavigate();
  const live = community.bridges.filter((b) => b.status === "active").length;

  async function rerunHistory(communityId: string) {
    try {
      await api(`/api/communities/${communityId}/rerun-history`, { method: "POST" });
      toast({ title: "History re-import started", description: "Messages appear in Armada as they publish." });
    } catch (e) {
      toast({ title: "Couldn't re-run the history import", description: errText(e), variant: "destructive" });
    }
  }

  return (
    <section className="overflow-hidden rounded-lg border border-chrome bg-card">
      <header className="flex items-center gap-3 border-b border-chrome bg-chrome/60 px-4 py-3">
        <div className="min-w-0 flex-1">
          <h2 className="truncate font-semibold">{community.name}</h2>
          <p className="truncate text-xs text-muted-foreground">
            {community.guildName ? <>Discord: {community.guildName} · </> : null}
            {live} of {plural(community.bridges.length, "channel")} live
          </p>
        </div>
        {community.source && (
          <>
            <Button
              variant="ghost"
              size="sm"
              className="text-muted-foreground hover:text-foreground"
              onClick={() => navigate(`/new?from=${community.source!.bridge_id}`)}
            >
              <Plus /> <span className="hidden sm:inline">Add channel</span>
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="size-9 text-muted-foreground hover:text-foreground" aria-label="More">
                  <MoreHorizontal />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onSelect={() => void rerunHistory(community.source!.community_id!)}>
                  <History /> Re-run history import
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </>
        )}
      </header>
      <ul className="divide-y divide-chrome">
        {community.bridges.map((b) => (
          <li key={b.bridge_id}>
            <BridgeRow bridge={b} />
          </li>
        ))}
      </ul>
    </section>
  );
}

function BridgeRow({ bridge: b }: { bridge: BridgeSummary }) {
  const count = Number(b.bridged_count) || 0;
  return (
    <Link
      to={`/bridges/${b.bridge_id}`}
      className="gutter-tick group flex items-center gap-3 px-4 py-3 transition-colors hover:bg-secondary/40 focus-visible:bg-secondary/40 focus-visible:outline-none"
    >
      <div className="flex min-w-0 flex-1 flex-col gap-1 sm:flex-row sm:items-center sm:gap-2">
        <span className="flex min-w-0 items-center gap-1.5 text-sm">
          <DiscordMark className="size-3.5 shrink-0 text-discord" />
          <ChannelName name={b.discord_channel_name} />
        </span>
        <ArrowLeftRight className="hidden size-3.5 shrink-0 text-primary/70 sm:block" />
        <span className="flex min-w-0 items-center gap-1.5 font-mono text-sm">
          <span className="sm:hidden text-primary/70">⇆</span>
          <ChannelName name={b.concord_channel_name} />
        </span>
      </div>
      <span className="hidden font-mono text-xs text-muted-foreground sm:block">{count.toLocaleString()} msgs</span>
      <StatusPill status={b.status} live={b.live} className="justify-end sm:w-32" />
      <ChevronRight className="size-4 shrink-0 text-muted-foreground/50 transition-transform group-hover:translate-x-0.5 group-hover:text-muted-foreground" />
    </Link>
  );
}

function DashboardSkeleton() {
  return (
    <div className="overflow-hidden rounded-lg border border-chrome bg-card">
      <div className="h-[60px] border-b border-chrome bg-chrome/60" />
      {[0, 1, 2].map((i) => (
        <div key={i} className={cn("flex items-center gap-3 px-4 py-4", i > 0 && "border-t border-chrome")}>
          <div className="h-3 w-24 animate-pulse rounded bg-muted" />
          <div className="h-3 w-24 animate-pulse rounded bg-muted" />
          <div className="ml-auto h-3 w-16 animate-pulse rounded bg-muted" />
        </div>
      ))}
    </div>
  );
}
