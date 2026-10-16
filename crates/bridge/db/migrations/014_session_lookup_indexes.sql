-- The OAuth callback and the popup poller find a session by a value buried in
-- the jsonb, which meant a sequential scan of portal_sessions on every login.
-- The table is one anyone can grow: hitting /api/auth/discord inserts a
-- pre-auth row, and nothing swept the expired ones until now.
--
-- Partial, because only a handful of rows are ever mid-flight: a session
-- carries oauthState until its callback lands and claimNonce until the opener
-- collects the token.

CREATE INDEX IF NOT EXISTS portal_sessions_oauth_state
  ON portal_sessions ((data->>'oauthState'))
  WHERE data ? 'oauthState';

CREATE INDEX IF NOT EXISTS portal_sessions_claim_nonce
  ON portal_sessions ((data->>'claimNonce'))
  WHERE data ? 'claimNonce';

-- Sweeping runs hourly and wants the expired rows, not all of them.
CREATE INDEX IF NOT EXISTS portal_sessions_expires_at ON portal_sessions (expires_at);
