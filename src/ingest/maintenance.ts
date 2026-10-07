import { RETENTION_DAYS } from '../config';
import { windowStart } from '../lib/time';
import { stmt, type Statement } from './store';

/**
 * Daily housekeeping, as one batch:
 * - prune vulns outside the retention window: published before it and no event
 *   inside it (an old CVE that lands on KEV this week stays);
 * - drop events older than the window, and orphaned rows (family leaders too:
 *   their members keep the family id, but nothing new can join);
 * - recount catalog entries, writing only rows whose count changed.
 */
export function maintenanceStatements(now: Date): Statement[] {
  const cutoff = windowStart(now, RETENTION_DAYS);
  const stale = `SELECT id FROM vulns
    WHERE (published_at IS NULL OR published_at < ?1)
      AND (last_event_at IS NULL OR last_event_at < ?1)
      AND (kev_added_at IS NULL OR kev_added_at < ?1)`;
  return [
    stmt(`DELETE FROM families WHERE leader IN (${stale})`, cutoff),
    stmt(`DELETE FROM affected WHERE vuln_id IN (${stale})`, cutoff),
    stmt(`DELETE FROM events WHERE vuln_id IN (${stale})`, cutoff),
    stmt(`DELETE FROM aliases WHERE vuln_id IN (${stale})`, cutoff),
    stmt(`DELETE FROM vulns WHERE id IN (${stale})`, cutoff),
    stmt('DELETE FROM events WHERE occurred_at < ?', cutoff),
    stmt(`UPDATE catalog SET count = c.n
      FROM (
        SELECT 'package' AS kind, ecosystem || ':' || package_name AS key, COUNT(DISTINCT vuln_id) AS n
          FROM affected WHERE kind = 'package' AND ecosystem IS NOT NULL AND package_name IS NOT NULL
          GROUP BY ecosystem, package_name
        UNION ALL
        SELECT 'product', vendor || '/' || product, COUNT(DISTINCT vuln_id)
          FROM affected WHERE kind = 'product' AND vendor IS NOT NULL AND product IS NOT NULL
          GROUP BY vendor, product
      ) AS c
      WHERE catalog.kind = c.kind AND catalog.key = c.key AND catalog.count != c.n`),
    stmt(`UPDATE catalog SET count = 0
      WHERE count != 0 AND (
        (kind = 'package' AND NOT EXISTS (SELECT 1 FROM affected a
          WHERE a.ecosystem = catalog.ecosystem AND a.package_name = catalog.name AND a.kind = 'package'))
        OR (kind = 'product' AND NOT EXISTS (SELECT 1 FROM affected a
          WHERE a.vendor = catalog.vendor AND a.product = catalog.product AND a.kind = 'product')))`),
  ];
}
