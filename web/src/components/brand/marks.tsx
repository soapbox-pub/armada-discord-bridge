import { cn } from "@/lib/utils";

/* Path data shared verbatim with armada's public/logo.svg and ArmadaCrest. */
const SAIL =
  "M64 4.225l-39.97 88.5h17.13l2.31-5.2 2.76-6.22-2.22-1.43-1.42-12.84h9.99l4.89-11.01L64 41.335l11.42 25.7h9.99l-1.43 12.84-2.22 1.43 2.77 6.22 2.31 5.2h17.13z";
const CARET =
  "M76.84 79.165c-.15 0-.31-.05-.44-.15l-12.41-9.65-12.41 9.65c-.31.24-.76.19-1-.13a.706.706 0 0 1 .13-1l12.85-9.99c.26-.2.62-.2.88 0l12.85 9.99a.715.715 0 0 1-.43 1.28z";
const WAVES = [
  "M95.4 104.865H32.59c-1.18 0-2.14-.96-2.14-2.14s.96-2.14 2.14-2.14H95.4c1.18 0 2.14.96 2.14 2.14s-.96 2.14-2.14 2.14z",
  "M83.98 115.565H44.01a1.43 1.43 0 1 1 0-2.86h39.97a1.43 1.43 0 1 1 0 2.86z",
  "M73.99 123.775H54.01a1.071 1.071 0 0 1 0-2.14h19.98a1.071 1.071 0 0 1 0 2.14z",
];

/** The Armada mark, flat. For chrome: the top bar, the footer. */
export function Crest({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 128 128" fill="none" aria-hidden="true" className={className}>
      <g fill="hsl(var(--accent2))">
        {WAVES.map((d) => <path key={d} d={d} />)}
      </g>
      <path d={SAIL} fill="hsl(var(--primary))" />
      <path d={CARET} fill="hsl(var(--primary))" fillOpacity={0.85} />
    </svg>
  );
}

/**
 * The mark drawn in, as armada's ArmadaCrest: a hairline pen traces the sail,
 * the fill floods in behind it, one halo pass, and the waves sweep open. Every
 * element's static state is its resting state, so reduced motion lands on
 * the finished mark.
 */
export function AnimatedCrest({ size = 132, className }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 128 128"
      fill="none"
      role="img"
      aria-label="Armada"
      className={cn("relative drop-shadow-[0_8px_24px_hsl(var(--primary)/0.25)]", className)}
    >
      <g fill="hsl(var(--accent2))">
        {WAVES.map((d, i) => (
          <g
            key={d}
            className="animate-[armada-wake_6s_ease-in-out_infinite]"
            style={{ transformOrigin: "64px 0", animationDelay: `${0.9 + i * 0.6}s` }}
          >
            <path
              d={d}
              className="animate-[armada-sweep_0.52s_cubic-bezier(0.22,1,0.36,1)_both]"
              style={{ transformOrigin: "64px 0", animationDelay: `${i * 0.07}s` }}
            />
          </g>
        ))}
      </g>
      <path
        d={SAIL}
        fill="hsl(var(--primary))"
        className="animate-[armada-sheen_0.9s_ease-in-out_both]"
        style={{ opacity: 0, filter: "drop-shadow(0 0 10px hsl(var(--primary) / 0.6))", animationDelay: "0.64s" }}
      />
      <path d={SAIL} fill="hsl(var(--primary))" className="animate-[armada-ink_0.42s_ease-out_both]" style={{ animationDelay: "0.4s" }} />
      <path
        d={SAIL}
        pathLength={1}
        fill="none"
        stroke="hsl(var(--primary))"
        strokeWidth={2}
        strokeLinecap="round"
        strokeLinejoin="round"
        className="animate-[armada-trace_0.78s_cubic-bezier(0.65,0,0.35,1)_both]"
        style={{ opacity: 0, strokeDasharray: 1, animationDelay: "0.08s" }}
      />
      <path d={CARET} fill="hsl(var(--primary))" fillOpacity={0.85} className="animate-[armada-ink_0.32s_ease-out_0.86s_both]" />
    </svg>
  );
}

/* Discord's Clyde mark (simple-icons path). */
export function DiscordMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" className={className}>
      <path d="M20.317 4.3698a19.7913 19.7913 0 00-4.8851-1.5152.0741.0741 0 00-.0785.0371c-.211.3753-.4447.8648-.6083 1.2495-1.8447-.2762-3.68-.2762-5.4868 0-.1636-.3933-.4058-.8742-.6177-1.2495a.077.077 0 00-.0785-.037 19.7363 19.7363 0 00-4.8852 1.515.0699.0699 0 00-.0321.0277C.5334 9.0458-.319 13.5799.0992 18.0578a.0824.0824 0 00.0312.0561c2.0528 1.5076 4.0413 2.4228 5.9929 3.0294a.0777.0777 0 00.0842-.0276c.4616-.6304.8731-1.2952 1.226-1.9942a.076.076 0 00-.0416-.1057c-.6528-.2476-1.2743-.5495-1.8722-.8923a.077.077 0 01-.0076-.1277c.1258-.0943.2517-.1923.3718-.2914a.0743.0743 0 01.0776-.0105c3.9278 1.7933 8.18 1.7933 12.0614 0a.0739.0739 0 01.0785.0095c.1202.099.246.1981.3728.2924a.077.077 0 01-.0066.1276 12.2986 12.2986 0 01-1.873.8914.0766.0766 0 00-.0407.1067c.3604.698.7719 1.3628 1.225 1.9932a.076.076 0 00.0842.0286c1.961-.6067 3.9495-1.5219 6.0023-3.0294a.077.077 0 00.0313-.0552c.5004-5.177-.8382-9.6739-3.5485-13.6604a.061.061 0 00-.0312-.0286zM8.02 15.3312c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9555-2.4189 2.157-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.9555 2.4189-2.1569 2.4189zm7.9748 0c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9554-2.4189 2.1569-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.946 2.4189-2.1568 2.4189Z" />
    </svg>
  );
}

/** "armada ⇆ discord", the portal's wordmark: Armada's mono lowercase. */
export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={cn("font-mono font-bold lowercase tracking-tight", className)}>
      armada<span className="mx-[0.3em] font-normal text-primary">⇆</span>discord
    </span>
  );
}
