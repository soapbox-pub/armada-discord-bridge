import { ArrowLeft, X } from "lucide-react";
import { useCallback, useEffect, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import { AsciiSea } from "@/components/brand/AsciiSea";
import { cn } from "@/lib/utils";

/** Marks a history entry as pushed by a wizard step, so Back can pop it. */
interface FlowState {
  inFlow?: boolean;
}

/**
 * Step navigation for a wizard whose steps are routes. `next` pushes, so the
 * browser's Back button walks back through the steps; `back` pops when the
 * previous step is the entry below this one, and otherwise (a reload, a
 * pasted link) replaces, so it never steps out of the wizard to wherever the
 * visitor was before.
 */
export function useFlowNav() {
  const navigate = useNavigate();
  const location = useLocation();
  const inFlow = Boolean((location.state as FlowState | null)?.inFlow);
  return {
    next: useCallback((to: string) => navigate(to, { state: { inFlow: true } satisfies FlowState }), [navigate]),
    back: useCallback(
      (to: string) => (inFlow ? navigate(-1) : navigate(to, { replace: true })),
      [inFlow, navigate],
    ),
    exit: useCallback((to = "/") => navigate(to, { replace: true }), [navigate]),
  };
}

/**
 * Full-screen wizard chrome, after armada's onboarding WizardShell: progress
 * bar, back and close, one centered column that slides in per step.
 * `stepKey` must differ per step so the column remounts and the animation
 * replays.
 */
export function WizardShell({
  index,
  total,
  stepKey,
  maxWidth = "max-w-md",
  onBack,
  onClose,
  children,
}: {
  index: number;
  /** Number of steps. `0` means single-screen: no progress bar. */
  total: number;
  stepKey: string;
  maxWidth?: "max-w-sm" | "max-w-md" | "max-w-xl";
  onBack?: () => void;
  onClose?: () => void;
  children: ReactNode;
}) {
  useEffect(() => {
    if (!onClose) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !document.querySelector("[role=alertdialog]")) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Each step starts at the top, like the page it is.
  useEffect(() => {
    document.getElementById("wizard-scroll")?.scrollTo(0, 0);
  }, [stepKey]);

  const pct = total > 0 ? ((index + 1) / total) * 100 : 100;
  return (
    <div className="fixed inset-0 flex flex-col bg-background">
      <AsciiSea />

      {total > 0 && (
        <div className="relative z-10 h-1 shrink-0 bg-muted" role="progressbar" aria-valuemin={1} aria-valuemax={total} aria-valuenow={index + 1}>
          <div className="h-full bg-primary transition-all duration-500 ease-out" style={{ width: `${pct}%` }} />
        </div>
      )}

      <div className="relative z-20 flex shrink-0 items-center justify-between px-2 pt-2">
        {onBack ? (
          <IconButton label="Back" onClick={onBack}><ArrowLeft className="size-5" /></IconButton>
        ) : (
          <div className="size-9" />
        )}
        {total > 0 && (
          <span className="font-mono text-xs text-muted-foreground">
            {index + 1} / {total}
          </span>
        )}
        {onClose ? (
          <IconButton label="Close" onClick={onClose}><X className="size-5" /></IconButton>
        ) : (
          <div className="size-9" />
        )}
      </div>

      {/* Stable gutter so a step growing past the viewport doesn't shift the column sideways. */}
      <div id="wizard-scroll" className="relative z-10 flex-1 overflow-y-auto [scrollbar-gutter:stable]">
        <div
          key={stepKey}
          className={cn(
            "relative mx-auto flex min-h-full w-full flex-col justify-center gap-8 px-6 pb-12 pt-6",
            "animate-in fade-in slide-in-from-right-4 duration-300",
            maxWidth,
          )}
        >
          {/* Calm water under the column: a long step (the import review)
              reaches down into the sea, and its translucent surfaces would
              otherwise sit on top of the swell. Feathered so the edge reads as
              a wake, not a box. */}
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-y-0 -inset-x-10 -z-10 bg-background [mask-image:linear-gradient(to_right,transparent,black_2.5rem,black_calc(100%-2.5rem),transparent)]"
          />
          {children}
        </div>
      </div>
    </div>
  );
}

function IconButton({ label, onClick, children }: { label: string; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      className="grid size-9 place-items-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      {children}
    </button>
  );
}

/** Common step body: glyph, heading, paragraph, actions. */
export function WizardStepBody({
  glyph,
  title,
  description,
  children,
}: {
  glyph: ReactNode;
  title: string;
  description: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-8 text-center">
      {glyph}
      <div className="space-y-2.5">
        <h1 className="font-mono text-2xl font-bold lowercase tracking-tight text-foreground">{title}</h1>
        <div className="text-sm leading-relaxed text-muted-foreground">{description}</div>
      </div>
      <div className="w-full">{children}</div>
    </div>
  );
}

/** A selectable row in a wizard list (servers, channels). */
export function PickRow({
  selected,
  onClick,
  children,
}: {
  selected: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={selected}
      className={cn(
        "flex w-full items-center gap-3 clip-corner-lg p-2.5 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring",
        selected ? "bg-primary/15 text-foreground" : "bg-secondary/40 hover:bg-secondary/70",
      )}
    >
      {children}
    </button>
  );
}
