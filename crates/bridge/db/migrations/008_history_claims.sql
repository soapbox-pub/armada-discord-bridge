-- History backfill: the import pipeline gains
-- a 'history' phase after wiring; claims link a Discord user to their Armada
-- key (levels: profile link, role grants, key handover).

ALTER TABLE imports DROP CONSTRAINT IF EXISTS imports_status_check;
ALTER TABLE imports ADD CONSTRAINT imports_status_check
  CHECK (status IN ('previewed','awaiting_sigs','minting','publishing','wiring','history','done','failed'));

CREATE TABLE IF NOT EXISTS claims (
  tenant_id        text NOT NULL DEFAULT 'default',
  claim_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  community_id     text NOT NULL,
  discord_guild_id text NOT NULL,
  discord_user_id  text NOT NULL,
  npub             text NOT NULL,             -- claimed Armada pubkey, lowercase hex
  -- Which levels ran: profile link, imported-role grants, key handover.
  linked           boolean NOT NULL DEFAULT false,
  roles_granted    text[] NOT NULL DEFAULT '{}',
  key_revealed     boolean NOT NULL DEFAULT false,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, community_id, discord_user_id)
);
