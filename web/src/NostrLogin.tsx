import { KeyRound, Loader2, LogIn, Puzzle } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import type { useNostrLogin } from "./useNostrLogin";

/** The login card (disconnected) or account chip (connected), after armada's LoginDialog. */
export function NostrLogin(props: { login: ReturnType<typeof useNostrLogin> }) {
  const { login } = props;

  if (login.pk) {
    return (
      <div className="flex items-center gap-3 clip-corner-lg bg-secondary/50 p-3">
        {login.profile.picture ? (
          <img className="size-10 shrink-0 rounded-full object-cover" src={login.profile.picture} alt="" referrerPolicy="no-referrer" />
        ) : (
          <span className="grid size-10 shrink-0 place-items-center clip-corner bg-primary/15 text-primary">
            <KeyRound className="size-5" />
          </span>
        )}
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-medium">
            {login.profile.name ?? "Logged in"}
            <span className="font-normal text-muted-foreground"> · {login.method === "extension" ? "extension" : "your key"}</span>
          </div>
          <div className="truncate font-mono text-xs text-muted-foreground">{login.npub}</div>
        </div>
        <Button variant="ghost" size="sm" className="shrink-0 text-muted-foreground" onClick={login.disconnect}>
          Log out
        </Button>
      </div>
    );
  }

  const hasExtension = typeof window !== "undefined" && Boolean(window.nostr);
  return (
    <div className="space-y-4 clip-corner-lg bg-card p-5">
      <div className="flex items-center gap-3">
        <span className="grid size-10 shrink-0 place-items-center clip-corner bg-primary/15 text-primary">
          <LogIn className="size-5" />
        </span>
        <div>
          <div className="font-mono text-base font-bold lowercase tracking-tight">log in with nostr</div>
          <p className="text-xs text-muted-foreground">
            New here?{" "}
            <a href="https://armada.buzz" target="_blank" rel="noreferrer" className="font-medium text-primary hover:underline">
              Create an account
            </a>
          </p>
        </div>
      </div>

      {hasExtension && (
        <>
          <Button className="h-11 w-full clip-corner-lg" disabled={login.loggingIn} onClick={() => void login.connectExtension()}>
            {login.loggingIn ? <Loader2 className="animate-spin" /> : <Puzzle />}
            {login.loggingIn ? "Logging in…" : "Log in with extension"}
          </Button>
          <div className="flex items-center gap-3">
            <span className="h-px flex-1 bg-[hsl(var(--chrome-divider))]" />
            <span className="text-[0.7rem] uppercase tracking-widest text-muted-foreground">or</span>
            <span className="h-px flex-1 bg-[hsl(var(--chrome-divider))]" />
          </div>
        </>
      )}

      <form
        className="space-y-2"
        onSubmit={(e) => {
          e.preventDefault();
          login.unlockNsec();
        }}
      >
        <div className="flex gap-2">
          <Input
            type="password"
            placeholder="nsec1…"
            autoComplete="off"
            spellCheck={false}
            value={login.nsec}
            onChange={(e) => {
              login.setNsec(e.target.value);
              if (login.loginError) login.setLoginError("");
            }}
            className={cn("h-11 font-mono text-xs", login.loginError && "border-destructive")}
          />
          <Button
            type="submit"
            variant={hasExtension ? "secondary" : "default"}
            className="h-11 shrink-0 clip-corner-lg"
            disabled={!login.nsec.trim() || login.loggingIn}
          >
            Log in
          </Button>
        </div>
        {login.loginError && <p className="text-xs text-destructive">{login.loginError}</p>}
        <p className="text-xs leading-relaxed text-muted-foreground">
          Your key signs here, in this tab, and is never sent to the portal or saved to disk.
        </p>
      </form>
    </div>
  );
}
