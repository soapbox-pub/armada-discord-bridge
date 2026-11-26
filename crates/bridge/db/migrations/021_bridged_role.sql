-- The Role every Discord member of a (community, server) pairing is given on
-- Armada (`/bridge role`): NULL takes a plain Role named "Discord" or
-- "Bridged" if there is one, '' gives none, otherwise a role id. Kept on the
-- pairing's row because a puppet's identity is the pairing's.
ALTER TABLE guild_community_secrets ADD COLUMN IF NOT EXISTS bridged_role text;
