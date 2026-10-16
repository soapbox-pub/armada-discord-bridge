-- Discord server (guild) display name for dashboard cards; owners managing
-- several servers need to tell links apart. Refreshed on every bridge start.
ALTER TABLE bridges ADD COLUMN IF NOT EXISTS discord_guild_name text;
