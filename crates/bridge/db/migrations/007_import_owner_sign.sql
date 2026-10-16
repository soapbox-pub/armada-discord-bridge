-- Owner-signed imports: the community owner is the user's real Nostr key,
-- and the pipeline pauses at 'awaiting_sigs' while the browser signs the
-- genesis seals. 'minting' stays for any historical rows.

ALTER TABLE imports DROP CONSTRAINT IF EXISTS imports_status_check;
ALTER TABLE imports ADD CONSTRAINT imports_status_check
  CHECK (status IN ('previewed','awaiting_sigs','minting','publishing','wiring','done','failed'));
