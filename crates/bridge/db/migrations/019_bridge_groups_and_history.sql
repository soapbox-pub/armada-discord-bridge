-- Channels linked together, one live bridge per Armada channel, and history
-- for any bridge.
--
-- `link_group`: the channel map links many channels in one request, under one
-- confirm code. A `/bridge confirm <code>` in any of them approves the group;
-- each channel's request names all the others, so a moderator is never
-- approving a channel they were not shown.
--
-- `history`: a copy of past messages requested for this bridge, and how far it
-- got. Until now only the server importer could backfill, and only into the
-- community it minted:
--   {"direction": "discord" | "armada", "state": "pending" | "running" | "done" | "failed",
--    "imported": <n>, "cursor": "<last copied id>", "detail": "<why it failed>"}
--
-- One live bridge per Armada channel: a Concord channel bridged to two Discord
-- channels mirrors each of them into the other through it, which nobody asks
-- for and the channel map would have no way to show. As in 017, demote the
-- later duplicates to 'paused' before indexing rather than deleting anything.

ALTER TABLE bridges ADD COLUMN IF NOT EXISTS link_group uuid;
ALTER TABLE bridges ADD COLUMN IF NOT EXISTS history jsonb NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS bridges_by_link_group ON bridges (link_group) WHERE link_group IS NOT NULL;

WITH ranked AS (
  SELECT bridge_id,
         row_number() OVER (PARTITION BY community_id, concord_channel_id
                            ORDER BY created_at, bridge_id) AS rn
    FROM bridges
   WHERE status IN ('pending_confirm', 'active')
     AND community_id IS NOT NULL
     AND concord_channel_id IS NOT NULL
)
UPDATE bridges b
   SET status = 'paused',
       status_detail = 'paused by migration 019: another bridge already mirrors this Armada channel',
       updated_at = now()
  FROM ranked r
 WHERE b.bridge_id = r.bridge_id
   AND r.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS bridges_one_per_concord_channel
  ON bridges (community_id, concord_channel_id)
  WHERE status IN ('pending_confirm', 'active') AND community_id IS NOT NULL AND concord_channel_id IS NOT NULL;
