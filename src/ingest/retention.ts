import { EPSS_HIGH, KEEP_CVSS, KEEP_DAYS, LEV_HIGH } from '../config';
import { windowStart } from '../lib/time';

/**
 * The safety net. Most CVEs are kept for RETENTION_DAYS after they're
 * published or last change; these are kept, and shown whatever time window is
 * picked, for KEEP_DAYS:
 * - added to CISA KEV in that time, or published in it and reported by CISA
 *   as actively exploited;
 * - published in that time with EPSS of 10% or more, a NIST LEV estimate of
 *   20% or more, or CVSS 9.9 or more.
 * An unpatched exploited bug from six months ago is exactly what shouldn't
 * drop out of view. The predicate and its SQL twin (KEEP_SQL) must agree:
 * test/retention.test.ts checks them against each other.
 */

export interface Keepable {
  publishedAt: string | null;
  kevAddedAt: string | null;
  /** CISA's SSVC exploitation answer, as stored. */
  exploitation: string | null;
  cvssScore: number | null;
  epss: number | null;
  /** The stored LEV sum (src/lib/lev.ts); 0 when there's no history. */
  levLog: number;
}

/** ln(1 − LEV_HIGH): a stored LEV sum at or below this is a LEV of LEV_HIGH or more. */
const LEV_LOG_HIGH = Math.log1p(-LEV_HIGH);
const EPSILON = 1e-9;

export function keepStart(now: Date): string {
  return windowStart(now, KEEP_DAYS);
}

export function keptLonger(v: Keepable, start: string): boolean {
  if (v.kevAddedAt !== null && v.kevAddedAt >= start) return true;
  if (v.publishedAt === null || v.publishedAt < start) return false;
  return (
    v.exploitation?.toLowerCase() === 'active' ||
    (v.cvssScore !== null && v.cvssScore >= KEEP_CVSS - EPSILON) ||
    (v.epss !== null && v.epss >= EPSS_HIGH - EPSILON) ||
    v.levLog <= LEV_LOG_HIGH + EPSILON
  );
}

/**
 * keptLonger() in SQL over a `vulns` row, with `?2` the start of the KEEP_DAYS
 * window. Its thresholds are bound as KEEP_PARAMS, after the start.
 */
export const KEEP_SQL = `(
  COALESCE(kev_added_at, '') >= ?2
  OR (COALESCE(published_at, '') >= ?2 AND (
    lower(COALESCE(json_extract(ssvc, '$.exploitation'), '')) = 'active'
    OR COALESCE(cvss_score, 0) >= ?3
    OR COALESCE(epss, 0) >= ?4
    OR lev_log <= ?5
  ))
)`;
export const KEEP_PARAMS = [KEEP_CVSS - EPSILON, EPSS_HIGH - EPSILON, LEV_LOG_HIGH + EPSILON] as const;
