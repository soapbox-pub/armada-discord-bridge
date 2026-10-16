-- The /claim feature is gone: no route mints a code, no route spends one, and
-- the bot answers /claim by saying so.
--
-- claim_codes was pure in-flight state -- one row per outstanding code, dead
-- 30 minutes after it was minted -- so it goes with the feature. It is already
-- empty in production: 013 wiped it when codes became keyed digests, and
-- nothing has run /claim since.
DROP TABLE IF EXISTS claim_codes;

-- `claims` STAYS, deliberately, though nothing reads it any more.
--
-- It is the only record of which npubs were handed a puppet's secret key
-- (`key_revealed`), and that fact outlives the feature: those bridged
-- identities are shared-custody from here on, and no amount of deleting code
-- takes a key back out of somebody's hands. It is also the only record of
-- which Armada roles were granted to whom by the claim path. Dropping the
-- table would destroy the answer to "who holds what, and since when" while
-- changing nothing about the situation it describes.
--
-- Archival from now on: no writer, no reader. If it is ever dropped, do it
-- deliberately and after exporting, not as a tidy-up.
COMMENT ON TABLE claims IS
  'Archival: the retired /claim feature. No writer, no reader. Records which npubs hold a puppet secret key (key_revealed) and which roles were granted.';
