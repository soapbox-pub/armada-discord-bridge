-- /claim codes: the bot command mints a one-time code bound to the invoking
-- (community, discord user); the portal consumes it on first use, so the
-- person claiming the npub is provably the same Discord account that asked.

CREATE TABLE IF NOT EXISTS claim_codes (
  tenant_id        text NOT NULL DEFAULT 'default',
  code             text PRIMARY KEY,
  community_id     text NOT NULL,
  discord_guild_id text NOT NULL,
  discord_user_id  text NOT NULL,
  expires_at       timestamptz NOT NULL DEFAULT (now() + interval '30 minutes'),
  consumed_at      timestamptz
);

CREATE INDEX IF NOT EXISTS claim_codes_lookup ON claim_codes (community_id, discord_user_id);
