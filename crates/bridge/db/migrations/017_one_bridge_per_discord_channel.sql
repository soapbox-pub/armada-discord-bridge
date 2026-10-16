-- One live bridge per Discord channel, enforced by the database.
--
-- `POST /api/bridges/:id/link` proves the caller holds Manage Server in the
-- guild it names, but a channel id is not a claim about the guild it lives in.
-- The route now checks that the channel is actually one of that guild's, and
-- this index is the backstop for the race two concurrent links would otherwise
-- win together: one shared bot serves every tenant and BridgeManager routes on
-- the channel id alone (`byDiscordChannel`, last writer wins), so a second
-- live row for one channel is enough to redirect a channel's traffic.
--
-- Demote before indexing: migrations run inside a transaction at boot, so a
-- duplicate that predates this file would abort the migration and take the
-- portal down with it. Losers become 'paused', which is reversible and which
-- `init()` does not resume -- the operator can inspect and re-resume the right
-- one rather than having the schema pick a winner destructively. The incumbent
-- (earliest created) keeps the channel; bridge_id breaks a created_at tie so
-- the choice is deterministic.

WITH ranked AS (
  SELECT bridge_id,
         row_number() OVER (PARTITION BY discord_channel_id
                            ORDER BY created_at, bridge_id) AS rn
    FROM bridges
   WHERE status IN ('pending_confirm', 'active')
     AND discord_channel_id IS NOT NULL
)
UPDATE bridges b
   SET status = 'paused',
       status_detail = 'paused by migration 017: another bridge already mirrors this Discord channel',
       updated_at = now()
  FROM ranked r
 WHERE b.bridge_id = r.bridge_id
   AND r.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS bridges_one_per_discord_channel
  ON bridges (discord_channel_id)
  WHERE status IN ('pending_confirm', 'active') AND discord_channel_id IS NOT NULL;

-- Superseded: the unique index above covers the same column and predicate.
DROP INDEX IF EXISTS bridges_by_discord_channel;
