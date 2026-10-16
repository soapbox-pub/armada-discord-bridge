-- One puppet master secret per (Armada community, Discord guild) pairing, so
-- every channel bridged between the same server and community derives ONE
-- npub per Discord user. Sealed with the portal KMS key like bridges.*_sealed.
CREATE TABLE IF NOT EXISTS guild_community_secrets (
  community_id         text NOT NULL,
  discord_guild_id     text NOT NULL,
  master_secret_sealed bytea NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (community_id, discord_guild_id)
);
