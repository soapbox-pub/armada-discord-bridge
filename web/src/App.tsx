import { ArrowLeft } from "lucide-react";
import { Link, Route, Routes } from "react-router-dom";

import { AppShell } from "@/components/AppShell";
import { Crest } from "@/components/brand/marks";
import { Button } from "@/components/ui/button";
import { BridgeDetail } from "@/pages/BridgeDetail";
import { Dashboard } from "@/pages/Dashboard";
import { ImportFlow } from "@/pages/Import";
import { ImportProgress } from "@/pages/ImportProgress";
import { Landing } from "@/pages/Landing";
import { NewBridge } from "@/pages/NewBridge";
import { useSession } from "@/session";

/**
 * Routes, behind one gate: signed out, every path shows the landing page (the
 * session parks the path and returns to it after sign-in). The server falls
 * back to index.html for any non-API path, so each of these survives a reload.
 *
 *   /                 dashboard: bridges, grouped by community
 *   /bridges/:id      one bridge: status, live confirm, pause, unlink
 *   /new[/channel|/armada|/pair][?from=<bridge>]   bridge a channel
 *   /import[/review]  import a server (Armada links here)
 *   /imports/:id      an import's progress and result
 */
export function App() {
  const { me } = useSession();

  if (!me) {
    return (
      <div className="grid min-h-screen place-items-center">
        <Crest className="size-12 animate-pulse" />
      </div>
    );
  }
  if (!me.user) return <Landing />;

  return (
    <Routes>
      <Route path="new/*" element={<NewBridge />} />
      <Route path="import/*" element={<ImportFlow />} />
      <Route path="imports/:id" element={<ImportProgress />} />
      <Route element={<AppShell />}>
        <Route index element={<Dashboard />} />
        <Route path="bridges/:id" element={<BridgeDetail />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}

function NotFound() {
  return (
    <div className="flex flex-col items-center gap-4 py-16 text-center">
      <p className="font-mono text-sm text-primary">
        <span className="text-accent2">$ </span>404
      </p>
      <h1 className="font-mono text-2xl font-bold lowercase tracking-tight">nothing moored here</h1>
      <p className="text-sm text-muted-foreground">That page doesn't exist.</p>
      <Button asChild variant="secondary" className="clip-corner-lg">
        <Link to="/"><ArrowLeft /> All bridges</Link>
      </Button>
    </div>
  );
}
