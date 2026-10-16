import { Check, Copy } from "lucide-react";
import { useState, type ReactNode } from "react";

import type { BridgeStatus } from "@/api";
import { cn } from "@/lib/utils";

const STATUS: Record<string, { label: string; dot: string; text: string }> = {
  active: { label: "live", dot: "bg-accent2 shadow-[0_0_8px_hsl(var(--accent2)/0.8)]", text: "text-accent2" },
  pending_confirm: { label: "awaiting confirm", dot: "bg-primary animate-pulse", text: "text-primary" },
  paused: { label: "paused", dot: "bg-muted-foreground", text: "text-muted-foreground" },
  severed: { label: "severed", dot: "bg-destructive", text: "text-destructive" },
  draft: { label: "draft", dot: "bg-muted-foreground/50", text: "text-muted-foreground" },
};

/**
 * A bridge's state as an LED. Cyan is the wake: a live bridge is the one
 * place it burns. An active bridge the manager isn't running right now gets a
 * hollow LED rather than a lie.
 */
export function StatusPill({ status, live, className }: { status: BridgeStatus; live?: boolean; className?: string }) {
  const s = STATUS[status] ?? { label: status.replace(/_/g, " "), dot: "bg-muted-foreground", text: "text-muted-foreground" };
  const idle = status === "active" && live === false;
  return (
    <span
      className={cn("inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap font-mono text-xs lowercase", s.text, className)}
      title={idle ? "Active, but not connected right now" : undefined}
    >
      <span className={cn("size-1.5 rounded-full", idle ? "border border-accent2 bg-transparent shadow-none" : s.dot)} />
      {idle ? "connecting" : s.label}
    </span>
  );
}

export function CopyButton({ value, label = "Copy", className }: { value: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={cn(
        "inline-grid size-7 shrink-0 place-items-center rounded-md text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground",
        className,
      )}
      onClick={() => {
        void navigator.clipboard.writeText(value).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1400);
        });
      }}
    >
      {copied ? <Check className="size-3.5 text-accent2" /> : <Copy className="size-3.5" />}
    </button>
  );
}

export function GuildIcon({ name, icon, className }: { name: string; icon?: string; className?: string }) {
  if (icon) return <img src={icon} alt="" referrerPolicy="no-referrer" className={cn("size-9 shrink-0 rounded-full object-cover", className)} />;
  return (
    <span className={cn("grid size-9 shrink-0 place-items-center rounded-full bg-muted font-mono text-xs lowercase", className)}>
      {name.slice(0, 2)}
    </span>
  );
}

/** Armada's small uppercase section label. */
export function SectionLabel({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={cn("text-xs font-semibold uppercase tracking-wider text-muted-foreground", className)}>{children}</span>
  );
}

/** `#name`, with the hash dimmed the way both clients draw it. */
export function ChannelName({ name, className }: { name?: string; className?: string }) {
  return (
    <span className={cn("min-w-0 truncate", className)}>
      <span className="mr-0.5 text-muted-foreground/70">#</span>
      {name ?? "unknown"}
    </span>
  );
}
