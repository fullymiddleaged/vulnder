/**
 * NIST CSWP 41 LEV2: the chance a CVE has been exploited at least once, from
 * its daily EPSS scores, LEV = 1 − Π (1 − epss_d / 30). EPSS predicts the next
 * 30 days, so each day carries a thirtieth of it.
 *
 * Vulnder keeps no EPSS history, only the value held since `epss_date` (ingest
 * rewrites it only when it moves meaningfully). So the product is kept as a
 * running sum of logs, `lev_log`, covering every day before `epss_date`; the
 * days since are added here. History starts when Vulnder first saw a score, so
 * this is a lower bound, as NIST's own LEV is.
 */

const DAY_MS = 86_400_000;

/** ln of the chance of no exploitation over `days` days at a steady EPSS score. */
export function levTerm(epss: number, days: number): number {
  if (!(days > 0)) return 0;
  const p = Number.isFinite(epss) ? Math.min(1, Math.max(0, epss)) : 0;
  return days * Math.log1p(-p / 30);
}

/** Whole days from one date to another ('YYYY-MM-DD' or ISO), never negative. */
export function daysBetween(from: string, to: string): number {
  const a = Date.parse(`${from.slice(0, 10)}T00:00:00Z`);
  const b = Date.parse(`${to.slice(0, 10)}T00:00:00Z`);
  if (Number.isNaN(a) || Number.isNaN(b)) return 0;
  return Math.max(0, Math.round((b - a) / DAY_MS));
}

/** LEV today, from the stored sum and the score held since `epssDate` (that day included). */
export function lev(levLog: number, epss: number | null, epssDate: string | null, now: Date): number | null {
  if (epss === null || !epssDate) return levLog < 0 ? 1 - Math.exp(levLog) : null;
  const held = daysBetween(epssDate, now.toISOString()) + 1;
  return 1 - Math.exp(levLog + levTerm(epss, held));
}
