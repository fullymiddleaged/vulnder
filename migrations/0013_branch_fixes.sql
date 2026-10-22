-- Fixed versions for records fixed on several release branches (PHP's
-- 8.2.* < 8.2.35, 8.3.* < 8.3.36, ...), which ingest used to leave with none.
-- Ingest now keeps each branch's fix, joined with ", " in fixed_version, when
-- every affected range's lessThan is its branch plus one more number
-- (src/match/versions.ts fixedVersionOf); this backfills rows stored before
-- that, by the same rule. A match shows the fix on the version's branch.
--
-- It writes no events, so no "fix released" entries for old fixes. It only
-- touches rows with no fixed version and a lessThan in their ranges: 793 of
-- 131,961 on the October 2026 local backfill (Splunk, the kernel's semver
-- ranges, MongoDB, Wireshark, OpenSSL, PHP...). Fields are read through each
-- entry's path, so an entry that isn't an object reads as null, not an error.
UPDATE affected SET fixed_version = (
  SELECT replace(group_concat(DISTINCT lt), ',', ', ') FROM (
    SELECT lt FROM (
      SELECT key,
        json_extract(affected.ranges, fullkey || '.status') AS status,
        json_extract(affected.ranges, fullkey || '.versionType') AS vt,
        CASE WHEN json_type(affected.ranges, fullkey || '.lessThan') = 'text' THEN json_extract(affected.ranges, fullkey || '.lessThan') END AS lt
      FROM json_each(affected.ranges)
    )
    WHERE status = 'affected' AND COALESCE(vt, '') != 'git' AND lt != '' AND instr(lt, '*') = 0
    ORDER BY key
  )
)
WHERE fixed_version IS NULL AND ranges LIKE '%lessThan%'
  AND (
    SELECT count(DISTINCT lt) FROM (
      SELECT json_extract(affected.ranges, fullkey || '.status') AS status,
        json_extract(affected.ranges, fullkey || '.versionType') AS vt,
        CASE WHEN json_type(affected.ranges, fullkey || '.lessThan') = 'text' THEN json_extract(affected.ranges, fullkey || '.lessThan') END AS lt
      FROM json_each(affected.ranges)
    )
    WHERE status = 'affected' AND COALESCE(vt, '') != 'git' AND lt != '' AND instr(lt, '*') = 0
  ) BETWEEN 2 AND 8
  AND NOT EXISTS (
    -- a: the start with its last number (or ".*" wildcard's "*") dropped; b: the start itself, then a dot.
    SELECT 1 FROM (
      SELECT lt,
        CASE WHEN v IS NULL THEN '' WHEN v LIKE '%.*' THEN substr(v, 1, length(v) - 1) ELSE rtrim(v, '0123456789') END AS a,
        COALESCE(v || '.', '') AS b
      FROM (
        SELECT json_extract(affected.ranges, fullkey || '.status') AS status,
          json_extract(affected.ranges, fullkey || '.versionType') AS vt,
          CASE WHEN json_type(affected.ranges, fullkey || '.lessThan') = 'text' THEN json_extract(affected.ranges, fullkey || '.lessThan') END AS lt,
          CASE WHEN json_type(affected.ranges, fullkey || '.version') = 'text' THEN json_extract(affected.ranges, fullkey || '.version') END AS v
        FROM json_each(affected.ranges)
      )
      WHERE status = 'affected' AND COALESCE(vt, '') != 'git' AND lt != '' AND instr(lt, '*') = 0
    )
    WHERE instr(lt, ',') > 0 OR NOT (
      (length(a) > 1 AND substr(a, -1) = '.' AND substr(lt, 1, length(a)) = a AND length(lt) > length(a) AND rtrim(substr(lt, length(a) + 1), '0123456789') = '')
      OR (length(b) > 1 AND substr(lt, 1, length(b)) = b AND length(lt) > length(b) AND rtrim(substr(lt, length(b) + 1), '0123456789') = '')
    )
  );
