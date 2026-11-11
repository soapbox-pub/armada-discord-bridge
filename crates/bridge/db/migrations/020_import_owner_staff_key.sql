-- When the owner of an imported community signed the Grant that hands them
-- its staff write key (CORD-04 §3), and the portal saw it land.
--
-- A column of its own, not a plan checkpoint: the owner delivers it from the
-- browser whenever they like, often while the pipeline is still backfilling
-- history, and the pipeline rewrites `plan` wholesale from its in-memory copy,
-- so a checkpoint written beside it would be silently undone.

ALTER TABLE imports ADD COLUMN IF NOT EXISTS owner_staff_key_at timestamptz;
