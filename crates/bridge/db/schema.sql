-- Bridge schema v1.
-- Multi-tenant from day one: every table carries tenant_id so the hosted
-- portal needs no migration. The single-tenant deployment uses
-- tenant_id = 'default'.

-- Join material (community_root, channel keys, epochs) deliberately does NOT
-- live here: the env-provisioned bridge takes it from env, and the portal
-- keeps its own sealed under bridges.*_sealed.
CREATE TABLE IF NOT EXISTS communities (
  tenant_id      text NOT NULL DEFAULT 'default',
  community_id   text NOT NULL,             -- lowercase hex, self-certifying
  relays         text[] NOT NULL,
  name           text,
  joined_at      timestamptz NOT NULL DEFAULT now(),
  -- Set when the bridge is cut off: 'banned' | 'refounded' | 'dissolved'.
  severed_reason text,
  PRIMARY KEY (tenant_id, community_id)
);

CREATE TABLE IF NOT EXISTS channel_links (
  tenant_id          text NOT NULL DEFAULT 'default',
  discord_guild_id   text NOT NULL,
  discord_channel_id text NOT NULL,
  -- No webhook credentials here on purpose: the adapter creates its webhook
  -- from the bot token at runtime and caches it in memory.
  community_id       text NOT NULL,
  concord_channel_id text NOT NULL,          -- lowercase hex channel id
  enabled            boolean NOT NULL DEFAULT false,  -- flips on in-channel confirm
  options            jsonb NOT NULL DEFAULT '{}',     -- attachments/reactions/edits toggles
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, discord_channel_id, concord_channel_id),
  FOREIGN KEY (tenant_id, community_id) REFERENCES communities (tenant_id, community_id)
);

-- One row per bridged message pair; split Discord messages produce several
-- rows sharing one rumor id (part_index orders them).
CREATE TABLE IF NOT EXISTS messages (
  tenant_id          text NOT NULL DEFAULT 'default',
  discord_message_id text NOT NULL,
  discord_channel_id text NOT NULL,
  concord_rumor_id   text NOT NULL,          -- lowercase hex rumor id
  concord_channel_id text NOT NULL,
  community_id       text NOT NULL,
  -- 'discord' when a Discord user authored it (puppet on the Concord side),
  -- 'concord' when a Concord member authored it (webhook on the Discord side).
  origin             text NOT NULL CHECK (origin IN ('discord', 'concord')),
  author_ref         text NOT NULL,          -- discord user id or concord npub hex
  part_index         int  NOT NULL DEFAULT 0,
  created_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, discord_message_id, part_index)
);

CREATE INDEX IF NOT EXISTS messages_by_rumor
  ON messages (tenant_id, concord_rumor_id);
CREATE INDEX IF NOT EXISTS messages_by_discord_channel
  ON messages (tenant_id, discord_channel_id, created_at DESC);

-- Relay/backfill cursors so restarts resume instead of re-reading history.
CREATE TABLE IF NOT EXISTS cursors (
  tenant_id    text NOT NULL DEFAULT 'default',
  community_id text NOT NULL,
  stream_pk    text NOT NULL,                -- derived stream pubkey (plane address)
  relay_url    text NOT NULL,
  last_seen_at bigint NOT NULL DEFAULT 0,    -- unix seconds of newest processed wrap
  PRIMARY KEY (tenant_id, community_id, stream_pk, relay_url)
);

-- Exactly-one-worker-per-community lease, for a multi-worker data plane.
CREATE TABLE IF NOT EXISTS leases (
  tenant_id    text NOT NULL DEFAULT 'default',
  community_id text NOT NULL,
  worker_id    text NOT NULL,
  expires_at   timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, community_id)
);
