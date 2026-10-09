-- A source's word for severity ("critical", "high", …) when it gives one:
-- GitHub's advisory severity, or a CNA's textual severity in the CVE record.
-- Used only when there is no CVSS score, so an unscored critical isn't left in Track.
ALTER TABLE vulns ADD COLUMN severity_label TEXT;
