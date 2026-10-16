-- Reaction mappings: one row per bridged kind 7 rumor, so reaction removal
-- can find its counterpart in either direction. Discord-origin rows key on
-- (message, user, emoji); concord-origin rows on the rumor id.
CREATE TABLE IF NOT EXISTS reaction_mappings (
  tenant_id          text NOT NULL DEFAULT 'default',
  rumor_id           text NOT NULL,
  discord_message_id text NOT NULL,
  emoji              text NOT NULL,
  origin             text NOT NULL CHECK (origin IN ('discord', 'concord')),
  author_ref         text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, rumor_id)
);

CREATE INDEX IF NOT EXISTS reaction_mappings_by_discord
  ON reaction_mappings (tenant_id, discord_message_id, author_ref, emoji);
