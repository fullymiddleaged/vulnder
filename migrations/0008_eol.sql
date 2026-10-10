-- Vendor support dates, for out-of-support findings (src/match/support.ts).
--
-- eol_releases: release lines of the endoflife.date products mapped in
-- src/stack/eol.ts, refreshed daily (src/ingest/eol.ts). `release` is the
-- release name through normalizeKey ("2012-r2" is "2012_r2"). Dates are
-- YYYY-MM-DD; a NULL eol_from with is_eol = 1 means support ended on a date
-- endoflife.date doesn't give. eoes_from is when paid extended support (ESU,
-- ELS, LTSS, Ubuntu Pro) ends, NULL when there is none. The feed reads it by
-- slug, which the primary key serves.
CREATE TABLE eol_releases (
  slug TEXT NOT NULL,
  release TEXT NOT NULL,
  label TEXT,
  release_date TEXT,
  eol_from TEXT,
  is_eol INTEGER NOT NULL DEFAULT 0,
  eoes_from TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (slug, release)
) WITHOUT ROWID;

-- eol_cve: per product key, its most recent CVE and whether the CNA tagged that
-- record "unsupported-when-assigned" (the product is out of vendor support).
-- Written only for tagged CVEs, and updated by later untagged ones, so it holds
-- the products some vendor has called unsupported. It outlives CVE pruning:
-- an end-of-life router stays flagged after its CVE leaves the window. Read and
-- written by key, which the primary key serves.
CREATE TABLE eol_cve (
  key TEXT PRIMARY KEY,
  last_cve TEXT NOT NULL,
  last_published TEXT NOT NULL,
  tagged INTEGER NOT NULL
) WITHOUT ROWID;

-- Rollback: DROP TABLE eol_cve; DROP TABLE eol_releases;
