-- Bot-command claims: a Discord user posts /claim in any bridged channel,
-- gets a claim link; the signed npub connects their Armada account.
-- The session carries the claim context; it expires with the session itself.

ALTER TABLE claims ADD COLUMN IF NOT EXISTS community_name text;
