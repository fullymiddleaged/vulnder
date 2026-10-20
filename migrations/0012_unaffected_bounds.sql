-- What a CVE record says a version is NOT affected by, kept per affected row
-- so a match can read it without the ranges (src/match/versions.ts):
-- unaffected_below is X in an unaffected "0" lessThan X entry (where the bug
-- was introduced), unaffected_from is X in an unaffected X lessThanOrEqual "*"
-- entry (where it was fixed for good). A product named with a version ("the
-- Linux kernel 6.8") drops only the matches these rule out.
--
-- Apply before deploying the code that writes them. Adding nullable columns
-- rewrites nothing; the backfill updates only rows whose ranges have an
-- unaffected entry (7,323 on the October 2026 local backfill, 6,108 of them
-- the kernel's), reading the table once.
ALTER TABLE affected ADD COLUMN unaffected_below TEXT;
ALTER TABLE affected ADD COLUMN unaffected_from TEXT;
UPDATE affected SET
  unaffected_below = (
    SELECT json_extract(value, '$.lessThan') FROM json_each(affected.ranges)
    WHERE json_extract(value, '$.status') = 'unaffected' AND COALESCE(json_extract(value, '$.versionType'), '') != 'git'
      AND json_extract(value, '$.version') = '0' AND json_type(value, '$.lessThan') = 'text'
    ORDER BY key LIMIT 1
  ),
  unaffected_from = (
    SELECT json_extract(value, '$.version') FROM json_each(affected.ranges)
    WHERE json_extract(value, '$.status') = 'unaffected' AND COALESCE(json_extract(value, '$.versionType'), '') != 'git'
      AND json_type(value, '$.version') = 'text' AND json_extract(value, '$.lessThanOrEqual') = '*'
    ORDER BY key LIMIT 1
  )
WHERE ranges LIKE '%unaffected%';

-- Rollback: ALTER TABLE affected DROP COLUMN unaffected_below; ALTER TABLE affected DROP COLUMN unaffected_from;
