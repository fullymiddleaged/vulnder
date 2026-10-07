/** How long ingest keeps a vulnerability after its last publication or event. */
export const RETENTION_DAYS = 90;

/** EPSS at or above this is the "Likely" tier, and crossing it upward is an event. */
export const EPSS_HIGH = 0.1;

/**
 * NIST LEV at or above this counts like high EPSS (Attend). LEV grows with the
 * days a score was held, so a steady 10% EPSS reaches it in about two months,
 * and a CVE that was hot for a few weeks and then cooled can keep it.
 */
export const LEV_HIGH = 0.2;

/** An EPSS rise of at least this much since the baseline is an event. */
export const EPSS_RISE = 0.1;

/** Sent on every outbound request, as GitHub's API requires. */
export const USER_AGENT = 'vulnder-ingest';

/** GitHub REST API version. 2026-03-10 also exists; 2022-11-28 is the one the parsers were recorded against. */
export const GITHUB_API_VERSION = '2022-11-28';

/** A source counts as stale when its last successful run is older than this. */
export const STALE_AFTER_HOURS: Record<string, number> = {
  cve: 6,
  ghsa: 6,
  kev: 6,
  epss: 48,
};
