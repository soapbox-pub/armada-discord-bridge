-- One-shot welcome marker: the bridge announcement must survive process
-- restarts, so the fact it was sent lives on the row, not in memory.
ALTER TABLE bridges ADD COLUMN announced_at timestamptz;

-- Every bridge that ever reached routing has already announced itself;
-- without this backfill each would greet its channels once more on the
-- next restart.
UPDATE bridges SET announced_at = now()
  WHERE status NOT IN ('draft', 'pending_confirm');
