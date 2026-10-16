import { ChevronDown, LogOut, ShieldOff } from "lucide-react";
import { useState } from "react";
import { Link, Outlet } from "react-router-dom";

import { Crest, Wordmark } from "@/components/brand/marks";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { toast } from "@/components/ui/toaster";
import { errText } from "@/lib/utils";
import { useMe, useSession } from "@/session";

/** Signed-in chrome: the hull bar on top, content, and the footer. */
export function AppShell() {
  return (
    <div className="flex min-h-screen flex-col">
      <TopBar />
      <main className="mx-auto w-full max-w-3xl flex-1 px-4 pb-16 pt-8 sm:px-6 sm:pt-10">
        <Outlet />
      </main>
      <Footer />
    </div>
  );
}

function TopBar() {
  return (
    <header className="sticky top-0 z-40 border-b border-chrome bg-chrome/90 backdrop-blur supports-[backdrop-filter]:bg-chrome/75">
      <div className="mx-auto flex h-12 max-w-3xl items-center justify-between gap-3 px-4 sm:px-6">
        <Link
          to="/"
          className="flex items-center gap-2 rounded-md text-foreground transition-opacity hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <Crest className="size-6" />
          <Wordmark className="text-sm" />
          <span className="hidden font-mono text-xs text-muted-foreground sm:inline">/ bridge portal</span>
        </Link>
        <AccountMenu />
      </div>
    </header>
  );
}

function AccountMenu() {
  const { user } = useMe();
  const { signOut, signOutEverywhere } = useSession();
  const [confirmAll, setConfirmAll] = useState(false);

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger className="flex items-center gap-2 rounded-md py-1 pl-1 pr-1.5 text-sm transition-colors hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring data-[state=open]:bg-secondary">
          {user.avatarUrl ? (
            <img src={user.avatarUrl} alt="" referrerPolicy="no-referrer" className="size-7 rounded-full object-cover" />
          ) : (
            <span className="grid size-7 place-items-center rounded-full bg-muted font-mono text-xs lowercase">
              {user.username.slice(0, 2)}
            </span>
          )}
          <span className="hidden max-w-[10rem] truncate sm:inline">{user.username}</span>
          <ChevronDown className="size-3.5 text-muted-foreground" />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuLabel className="font-normal">
            <div className="text-xs text-muted-foreground">Signed in with Discord as</div>
            <div className="truncate font-medium">{user.username}</div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => void signOut().catch((e) => toast({ title: "Couldn't sign out", description: errText(e), variant: "destructive" }))}>
            <LogOut /> Sign out
          </DropdownMenuItem>
          <DropdownMenuItem destructive onSelect={() => setConfirmAll(true)}>
            <ShieldOff /> Sign out everywhere
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <AlertDialog open={confirmAll} onOpenChange={setConfirmAll}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>sign out everywhere?</AlertDialogTitle>
            <AlertDialogDescription>
              Ends every portal session for this Discord account, on every device, including
              this one and any Armada app that connected through the portal. Your bridges keep
              running.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              destructive
              onClick={() =>
                void signOutEverywhere()
                  .then((n) => toast({ title: "Signed out everywhere", description: `${n} ${n === 1 ? "session" : "sessions"} ended.` }))
                  .catch((e) => toast({ title: "Couldn't sign out", description: errText(e), variant: "destructive" }))
              }
            >
              Sign out everywhere
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

const SOURCE_URL =
  "https://gitworkshop.dev/npub1jvnpg4c6ljadf5t6ry0w9q0rnm4mksde87kglkrc993z46c39axsgq89sc/armada-discord-bridge";

export function Footer() {
  return (
    <footer className="border-t border-chrome bg-chrome">
      <div className="mx-auto flex max-w-3xl flex-wrap items-center justify-between gap-x-6 gap-y-3 px-4 py-5 sm:px-6">
        <div className="flex items-center gap-2 text-muted-foreground">
          <Crest className="size-4 opacity-70" />
          <Wordmark className="text-xs font-medium" />
        </div>
        <nav className="flex flex-wrap items-center gap-x-5 gap-y-2 font-mono text-xs lowercase tracking-wide text-muted-foreground/70">
          <a href="https://armada.buzz" target="_blank" rel="noreferrer" className="transition-colors hover:text-foreground">armada.buzz</a>
          <a href="https://soapbox.pub/armada" target="_blank" rel="noreferrer" className="transition-colors hover:text-foreground">about armada</a>
          <a href={SOURCE_URL} target="_blank" rel="noreferrer" className="transition-colors hover:text-foreground">source code</a>
          <a href="https://soapbox.pub" target="_blank" rel="noreferrer" className="transition-colors hover:text-foreground">soapbox</a>
        </nav>
      </div>
    </footer>
  );
}
