-- Families: CVEs in the same product whose descriptions are nearly the same
-- (src/ingest/families.ts). Ingest embeds each vuln's text
-- once and either joins it to a family whose leader is similar enough or makes
-- it the leader of a new one. family_id is NULL until then, and the leader's
-- own id after.
ALTER TABLE vulns ADD COLUMN family_id TEXT;
CREATE INDEX vulns_family ON vulns (family_id);
-- Work still to do, newest first. Rows leave the index once assigned, so it stays small.
CREATE INDEX vulns_unassigned ON vulns (published_at) WHERE family_id IS NULL;

-- Only leaders' vectors are kept, once per block they compare in. A block is a
-- package or product key, plus the title's first words when the key is big
-- (Windows, the Linux kernel), so a lookup reads tens of rows, not thousands.
-- vector: 256 dimensions, int8, base64.
CREATE TABLE families (
  block TEXT NOT NULL,
  leader TEXT NOT NULL,
  vector TEXT NOT NULL,
  PRIMARY KEY (block, leader)
);
CREATE INDEX families_leader ON families (leader);

-- Rollback: DROP TABLE families; DROP INDEX vulns_unassigned; DROP INDEX vulns_family;
-- ALTER TABLE vulns DROP COLUMN family_id;
