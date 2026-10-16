-- Secrets at rest: nothing in the database is usable on its own.
--
-- Key material was already sealed (bridges.*_sealed, guild_community_secrets,
-- imports.*_sealed). What was not: the session id, which IS the bearer
-- credential; the Discord OAuth token riding in the session jsonb; and the
-- one-time /claim codes. This closes those three, which bounds a
-- database-only compromise — a backup, a replica, a dump, a shared console —
-- to data that needs PORTAL_SEAL_KEY to mean anything.

-- Session ids: the column now holds sha256(token). Existing rows rehash in
-- place, so nobody is logged out. (Raw ids are 48 hex chars, hashes 64.)
UPDATE portal_sessions SET sid = encode(sha256(convert_to(sid, 'UTF8')), 'hex')
  WHERE sid ~ '^[0-9a-f]{48}$';

-- The popup handoff: the token sealed for the nonce poller to collect, so the
-- postMessage and polling legs of that flow hand out the same session.
-- Cleared on collection; expires with the row otherwise.
ALTER TABLE portal_sessions ADD COLUMN IF NOT EXISTS handoff_sealed bytea;

-- Plaintext Discord OAuth bearers, dropped rather than converted: SQL has no
-- way to seal them. Sessions stay valid and the token re-seals on the next
-- login; a claim made in the meantime degrades to "no roles granted", the
-- same way a stale OAuth scope already does.
UPDATE portal_sessions SET data = data - 'accessToken' WHERE data ? 'accessToken';

-- Claim codes are stored as a keyed digest now. The plaintext ones cannot be
-- converted and expire within 30 minutes regardless; anyone mid-claim runs
-- /claim again.
DELETE FROM claim_codes;

-- Webhook credentials were never actually written here — the Discord adapter
-- creates its webhook at runtime from the bot token and caches the object in
-- memory. Drop the columns so nobody starts filling them in.
ALTER TABLE channel_links DROP COLUMN IF EXISTS webhook_id;
ALTER TABLE channel_links DROP COLUMN IF EXISTS webhook_token;

-- communities.sealed_keys promised sealing that never happened: the
-- env-provisioned bridge carries its key material in env and wrote an empty
-- blob here on every upsert.
ALTER TABLE communities DROP COLUMN IF EXISTS sealed_keys;
