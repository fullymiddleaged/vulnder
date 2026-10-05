-- Vulnder initial schema.
-- Timestamps are ISO 8601 UTC strings. JSON columns hold JSON text.

-- One row per vulnerability, keyed by CVE ID where one exists, otherwise by the
-- GHSA ID. Other identifiers live in `aliases` (and the aliases table).
CREATE TABLE vulns (
  id TEXT PRIMARY KEY,
  aliases TEXT NOT NULL DEFAULT '[]',
  title TEXT,
  summary TEXT,
  published_at TEXT,
  modified_at TEXT,
  cvss_score REAL,
  cvss_vector TEXT,
  cwe TEXT NOT NULL DEFAULT '[]',
  epss REAL,
  epss_percentile REAL,
  -- Score date of the EPSS value held here.
  epss_date TEXT,
  -- EPSS value at the last epss_crossed event, or the lowest value seen since.
  -- A rise of 0.10 or more above it is an event.
  epss_baseline REAL,
  kev_added_at TEXT,
  kev_ransomware INTEGER NOT NULL DEFAULT 0,
  kev_due_date TEXT,
  kev_required_action TEXT,
  -- CISA ADP (or CNA) SSVC decision points: {exploitation, automatable, technicalImpact}.
  ssvc TEXT,
  -- [{url, tags}]. Named refs because REFERENCES is an SQL keyword.
  refs TEXT NOT NULL DEFAULT '[]',
  -- Bit flags: 1 = CVE record, 2 = GitHub advisory, 4 = KEV, 8 = EPSS.
  source_flags INTEGER NOT NULL DEFAULT 0,
  -- Which source set each merged field: {"title": "cve", ...}. Higher-ranked
  -- sources overwrite lower-ranked ones, never the reverse.
  provenance TEXT NOT NULL DEFAULT '{}',
  last_event_at TEXT,
  updated_at TEXT NOT NULL
);
CREATE INDEX vulns_published_at ON vulns (published_at);
CREATE INDEX vulns_last_event_at ON vulns (last_event_at);
CREATE INDEX vulns_kev_added_at ON vulns (kev_added_at);
CREATE INDEX vulns_epss ON vulns (epss);

-- Every non-primary identifier (GHSA, PYSEC, GO, RUSTSEC, ...) mapped to its vuln.
CREATE TABLE aliases (
  alias TEXT PRIMARY KEY,
  vuln_id TEXT NOT NULL
);
CREATE INDEX aliases_vuln_id ON aliases (vuln_id);

-- What a vuln affects. `source` says which feed supplied the row, so each feed
-- can replace its own rows without touching the others.
-- Package rows: ecosystem uses OSV names (npm, PyPI, crates.io, Go, Maven, ...),
-- package_name is normalised for that ecosystem.
-- Product rows: vendor and product are normalised keys (lowercase, underscores,
-- CPE-style); label keeps the original wording for display.
CREATE TABLE affected (
  id INTEGER PRIMARY KEY,
  vuln_id TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('cve', 'ghsa', 'kev')),
  kind TEXT NOT NULL CHECK (kind IN ('package', 'product')),
  ecosystem TEXT,
  package_name TEXT,
  vendor TEXT,
  product TEXT,
  label TEXT,
  ranges TEXT NOT NULL DEFAULT '[]',
  fixed_version TEXT
);
CREATE INDEX affected_vuln_source ON affected (vuln_id, source);
CREATE INDEX affected_package ON affected (ecosystem, package_name);
CREATE INDEX affected_product ON affected (vendor, product);

-- Change events, recorded as ingest detects them.
-- dedupe_key makes re-processing idempotent: '' for once-per-vuln events, the
-- score date for epss_crossed, the package and fixed version for fix_released.
CREATE TABLE events (
  id INTEGER PRIMARY KEY,
  vuln_id TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('published', 'kev_added', 'epss_crossed', 'fix_released')),
  occurred_at TEXT NOT NULL,
  dedupe_key TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '{}',
  UNIQUE (vuln_id, type, dedupe_key)
);
CREATE INDEX events_occurred_at ON events (occurred_at);

-- Every distinct package and vendor/product seen, for resolving free text.
-- key is 'npm:next' for packages and 'cisco/ios_xe' for products.
-- count is the number of retained vulns that affect it (recomputed daily);
-- rows are kept at count 0 when their vulns are pruned.
CREATE TABLE catalog (
  kind TEXT NOT NULL CHECK (kind IN ('package', 'product')),
  key TEXT NOT NULL,
  ecosystem TEXT,
  name TEXT,
  vendor TEXT,
  product TEXT,
  normalized TEXT NOT NULL,
  label TEXT,
  aliases TEXT NOT NULL DEFAULT '[]',
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (kind, key)
);
CREATE INDEX catalog_normalized ON catalog (normalized);

-- Cursors, per-source run status and the data version counter.
CREATE TABLE meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
