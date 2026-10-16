-- Display names for both sides of a link, so the dashboard can say
-- "#general <-> #spam and testing" instead of raw snowflakes and hex.
-- The manager rewrites them on every bridge start, so renames heal on
-- the next boot and pre-existing rows backfill themselves.
ALTER TABLE bridges ADD COLUMN IF NOT EXISTS discord_channel_name text;
ALTER TABLE bridges ADD COLUMN IF NOT EXISTS concord_channel_name text;
