-- Daily usage counters for metered work (free-text parsing calls Workers AI).
-- A client is identified by a SHA-256 hash of its IP and a random salt that
-- changes every UTC day; the salt for past days is deleted with their counters,
-- so stored hashes can't be linked across days or back to an IP afterwards.
CREATE TABLE usage_counters (
  -- UTC date, YYYY-MM-DD.
  day TEXT NOT NULL,
  -- What is metered, e.g. 'parse'.
  bucket TEXT NOT NULL,
  -- Salted client hash, or '*' for the total across all clients.
  subject TEXT NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (day, bucket, subject)
);
