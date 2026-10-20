-- events.type gains 'exploitation_reported': CISA's SSVC assessment newly
-- reports active exploitation of a CVE that isn't on KEV (src/ingest/merge.ts).
-- 0001 limited type with a CHECK, which SQLite can't alter, so the table is
-- rebuilt without it; the EventType union in merge.ts is the list now.
--
-- Cost: about 3 row writes per stored event (the row and two indexes). On a
-- full deployment that's around 115,000, more than Workers Free allows in a
-- day, so on Free apply it on a day of its own. Until it's applied, ingest's
-- INSERT OR IGNORE skips the new event rows; the CVE still shows, since its
-- last_event_at moves either way.
CREATE TABLE events_new (
  id INTEGER PRIMARY KEY,
  vuln_id TEXT NOT NULL,
  type TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  dedupe_key TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '{}',
  UNIQUE (vuln_id, type, dedupe_key)
);
INSERT INTO events_new (id, vuln_id, type, occurred_at, dedupe_key, detail)
  SELECT id, vuln_id, type, occurred_at, dedupe_key, detail FROM events;
DROP TABLE events;
ALTER TABLE events_new RENAME TO events;
CREATE INDEX events_occurred_at ON events (occurred_at);

-- Rollback: DELETE FROM events WHERE type = 'exploitation_reported', then
-- rebuild the same way with 0001's CHECK.
