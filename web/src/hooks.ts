import { useCallback, useEffect, useState } from "react";

import { listBridges, type BridgeSummary } from "@/api";
import { errText } from "@/lib/utils";

export function useBridges() {
  const [bridges, setBridges] = useState<BridgeSummary[] | null>(null);
  const [error, setError] = useState("");

  const reload = useCallback(async () => {
    try {
      setBridges(await listBridges());
      setError("");
    } catch (e) {
      setError(errText(e));
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  return { bridges, error, reload };
}
