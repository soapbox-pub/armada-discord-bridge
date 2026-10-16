-- History-import progress, apart from the plan.
--
-- The importer checkpointed every 20 messages by rewriting `plan`, which
-- holds the whole guild's channel list (up to ~150KB). That is a full copy of
-- the plan per checkpoint, in the table and in the WAL, for a two-field
-- change. Checkpoints now go here instead, keyed by Discord channel id:
--   {"<discordId>": {"imported": <n>, "cursor": "<last message id>"}}
-- An UPDATE that leaves `plan` alone keeps its TOASTed value as is.
--
-- Entries here are newer than the plan's `historyImported`/`historyCursor`
-- for their channel, and readers overlay them. Every write of `plan` folds
-- them in and resets this to '{}', so the plan is never older than it.

ALTER TABLE imports ADD COLUMN IF NOT EXISTS history_progress jsonb NOT NULL DEFAULT '{}';
