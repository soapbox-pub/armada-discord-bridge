-- Server import: one row per import run. The
-- plan jsonb is both the preview shown to the user and the pipeline's
-- checkpoint ledger, so a crashed import resumes instead of duplicating.
-- Secrets (community owner key, invite URL, link signer) are sealed with the
-- portal KMS key, same treatment as the bridges table.

CREATE TABLE IF NOT EXISTS imports (
  tenant_id             text NOT NULL DEFAULT 'default',
  import_id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_discord_id      text NOT NULL,
  discord_guild_id      text NOT NULL,
  discord_guild_name    text,
  status                text NOT NULL DEFAULT 'previewed'
                        CHECK (status IN ('previewed','minting','publishing','wiring','done','failed')),
  status_detail         text,
  plan                  jsonb NOT NULL,
  -- The custodial community owner secret key (hex, sealed). The community's
  -- root of trust; ownership is baked into the community_id and cannot move.
  owner_sk_sealed       bytea,
  -- Community identity + access secrets minted at genesis (JSON, sealed):
  -- { owner_salt, community_root, root_epoch }.
  community_sealed      bytea,
  community_id          text,
  -- The shareable public invite minted at the end of the import.
  invite_url_sealed     bytea,
  link_signer_sk_sealed bytea,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS imports_by_owner ON imports (owner_discord_id, created_at DESC);
