-- The popup handoff now waits for a confirmation click in the callback page
-- before the nonce poll can collect the session token, because the nonce
-- itself is chosen by whoever composed the auth-start URL and so proves
-- nothing about who ran the login.
--
-- The click spends a one-time token that exists only in that page, looked up
-- here by its SHA-256. Partial and short-lived, like the other two mid-flight
-- lookups in 014: a session carries claimApproval only between the callback
-- and the click.

CREATE INDEX IF NOT EXISTS portal_sessions_claim_approval
  ON portal_sessions ((data->>'claimApproval'))
  WHERE data ? 'claimApproval';
