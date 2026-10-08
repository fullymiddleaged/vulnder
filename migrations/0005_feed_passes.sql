-- Feed passes: a browser's allowance of new stacks an hour (src/lib/pass.ts).
-- The id is random and travels only in an HttpOnly cookie; nothing here links
-- it to an IP. `stacks` holds keyed hashes (HMAC with a key derived from a
-- Worker secret), so the table alone can't confirm a guessed stack. Rows are
-- deleted a day after they are made, by the daily maintenance.
CREATE TABLE feed_passes (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  -- When this hour's allowance started (the first new stack); NULL until then.
  window_start TEXT,
  -- JSON array of the stack hashes used in this window.
  stacks TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX feed_passes_created_at ON feed_passes (created_at);

-- Rollback: DROP TABLE feed_passes;
