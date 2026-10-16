-- Portal control plane: accounts arrive via
-- Discord OAuth (no separate users table; the session carries the identity),
-- bridges own their sealed per-bridge secrets.

CREATE TABLE IF NOT EXISTS portal_sessions (
  sid        text PRIMARY KEY,
  data       jsonb NOT NULL DEFAULT '{}',
  expires_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS bridges (
  tenant_id            text NOT NULL DEFAULT 'default',
  bridge_id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_discord_id     text NOT NULL,
  status               text NOT NULL DEFAULT 'draft'
                       CHECK (status IN ('draft','pending_confirm','active','paused','severed','unlinked')),
  status_detail        text,
  -- Sealed with the portal KMS key (AES-256-GCM); never stored plaintext.
  invite_url_sealed    bytea,
  master_secret_sealed bytea,
  primary_sk_sealed    bytea,
  primary_pk           text,
  community_id         text,
  community_name       text,
  discord_guild_id     text,
  discord_channel_id   text,
  concord_channel_id   text,
  confirm_code         text,
  options              jsonb NOT NULL DEFAULT '{}',
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS bridges_by_owner ON bridges (owner_discord_id, created_at DESC);
CREATE INDEX IF NOT EXISTS bridges_by_discord_channel ON bridges (discord_channel_id) WHERE status IN ('pending_confirm','active');
