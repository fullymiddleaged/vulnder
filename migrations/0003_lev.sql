-- NIST CSWP 41 LEV ("likely exploited vulnerabilities"), kept as a running sum
-- so it needs no EPSS history: ln of the chance of no exploitation on every day
-- before epss_date, each day counting EPSS/30 (LEV2). The days since epss_date
-- are added when read (src/lib/lev.ts). Rollback: ALTER TABLE vulns DROP COLUMN lev_log.
ALTER TABLE vulns ADD COLUMN lev_log REAL NOT NULL DEFAULT 0;
