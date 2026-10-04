/** How long ingest keeps a vulnerability after its last publication or event. */
export const RETENTION_DAYS = 90;

/** EPSS at or above this is the "Likely" tier, and crossing it upward is an event. */
export const EPSS_HIGH = 0.1;

/** An EPSS rise of at least this much since the baseline is an event. */
export const EPSS_RISE = 0.1;

/** Sent on every outbound request, as GitHub's API requires. */
export const USER_AGENT = 'vulnture-ingest';

/** GitHub REST API version. 2026-03-10 also exists; 2022-11-28 is the one the parsers were recorded against. */
export const GITHUB_API_VERSION = '2022-11-28';

/** A source counts as stale when its last successful run is older than this. */
export const STALE_AFTER_HOURS: Record<string, number> = {
  cve: 6,
  ghsa: 6,
  kev: 6,
  epss: 48,
};
