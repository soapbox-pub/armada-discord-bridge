-- One-shot marker for the "bot is missing Manage Webhooks" alert: the notice
-- (in-channel on both sides, plus this row's status_detail) must fire once per
-- bridge, not on every mirrored message nor again after a restart.
ALTER TABLE bridges ADD COLUMN perm_alerted_at timestamptz;
