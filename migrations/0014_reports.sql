-- Write-ups of a CVE by trusted sources (src/ingest/reporters.ts: Huntress,
-- Rapid7, watchTowr, CERT-EU, NCSC UK), read from their RSS feeds each hour
-- (src/ingest/reports.ts). They go into exploits, which the feed already reads
-- by CVE ID, as source = the reporter's id and kind = 'report', with url the
-- post. published_at is the post's date (YYYY-MM-DD); ranking counts a source
-- from then (src/match/priority.ts). title is the post's title as plain text,
-- at most 200 characters, shown on the result as the source's own words.
-- Metasploit and Nuclei rows leave both null.
-- Coverage is never evidence of exploitation: only CISA KEV and CISA's
-- reports of active exploitation are.
--
-- Adding nullable columns rewrites nothing. Apply it before deploying the
-- code that reads it.
ALTER TABLE exploits ADD COLUMN published_at TEXT;
ALTER TABLE exploits ADD COLUMN title TEXT;

-- Rollback: DELETE FROM exploits WHERE kind IN ('report', 'urgent'); ALTER TABLE exploits DROP COLUMN title; ALTER TABLE exploits DROP COLUMN published_at;
