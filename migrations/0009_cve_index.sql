-- cve_index: one slim row per CVE ID ever assigned, historic and current, so a
-- pasted list of CVEs (a scanner's report) can be ranked whatever their age.
-- vulns keeps only the window and the safety net; this keeps what ranking
-- needs for everything else (src/ingest/cve-index.ts). Separate from vulns:
-- the prune never touches it, and its writes ride beside ingest's, never in
-- the same batch.
--
-- state is 'published' or 'rejected'. replaced_by is a JSON array of the CVE
-- IDs a rejection points to ("duplicate of CVE-…", "ConsultIDs: …"), NULL
-- otherwise. product is the first affected product's key (vendor/product),
-- product_label its display name. Each source writes only its own columns:
-- CVE records the first group, KEV the kev_ ones, the daily EPSS file the
-- epss_ ones. Read and written by ID, which the primary key serves.
CREATE TABLE cve_index (
  id TEXT PRIMARY KEY,
  state TEXT NOT NULL DEFAULT 'published',
  replaced_by TEXT,
  published_at TEXT,
  title TEXT,
  product TEXT,
  product_label TEXT,
  cvss_score REAL,
  cvss_vector TEXT,
  severity_label TEXT,
  ssvc TEXT,
  kev_added_at TEXT,
  kev_ransomware INTEGER NOT NULL DEFAULT 0,
  kev_due_date TEXT,
  kev_required_action TEXT,
  epss REAL,
  epss_percentile REAL,
  epss_date TEXT
) WITHOUT ROWID;

-- Rollback: DROP TABLE cve_index;
