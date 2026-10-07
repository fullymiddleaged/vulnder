import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { AFFECTED_KEYS_SQL, CATALOG_COUNTS_SQL, LEADERS_SQL, UNASSIGNED_SQL } from '../src/ingest/families';
import { AFFECTED_PACKAGES_SQL, AFFECTED_PRODUCTS_SQL, EXPLOITED_IN_FAMILIES_SQL, eventsSinceSql, vulnsInWindowSql } from '../src/match/match';
import { KNOWN_KEYS_SQL, PREFIX_SQL, VENDOR_SQL } from '../src/resolve/catalog';
import { HEALTH_META_SQL } from '../src/routes/health';

/**
 * D1 bills every row a query reads, and a full scan reads the whole table on
 * every request (one health check counting four tables read 170,000 rows). So
 * every query on a request path must search an index: its plan may scan only
 * the json_each list of keys it was given.
 */
async function scans(sql: string, params: unknown[]): Promise<string[]> {
  const { results } = await env.DB.prepare(`EXPLAIN QUERY PLAN ${sql}`)
    .bind(...params)
    .all<{ detail: string }>();
  return results.map((r) => r.detail).filter((d) => /^SCAN /.test(d) && !/^SCAN (json_each|j)\b/.test(d));
}

const SINCE = '2026-09-01T00:00:00.000Z';

describe('request-path query plans', () => {
  it.each([
    ['health', HEALTH_META_SQL, ['["status:cve","data_version"]']],
    ['catalog prefix', PREFIX_SQL, ['[["cis","cit"]]', 4000]],
    ['catalog vendor', VENDOR_SQL, ['["cisco"]', 4000]],
    ['catalog keys', KNOWN_KEYS_SQL, ['["npm:next","cisco/ios_xe"]']],
    ['affected packages', AFFECTED_PACKAGES_SQL, ['[["npm","next"]]']],
    ['affected products', AFFECTED_PRODUCTS_SQL, ['[["cisco","ios_xe"]]']],
    ['vulns in window', vulnsInWindowSql(SINCE), ['["CVE-2026-0001"]']],
    ['events since', eventsSinceSql(SINCE), ['["CVE-2026-0001"]']],
    ['exploited family members', EXPLOITED_IN_FAMILIES_SQL, ['["CVE-2026-0001"]']],
    // Ingest's family stage, run every hour.
    ['family leaders', LEADERS_SQL, ['["package:npm:n8n"]']],
    ['family affected keys', AFFECTED_KEYS_SQL, ['["CVE-2026-0001"]']],
    ['family catalog counts', CATALOG_COUNTS_SQL, ['["npm:n8n"]']],
  ] as const)('%s searches an index', async (_name, sql, params) => {
    expect(await scans(sql, [...params])).toEqual([]);
  });

  it('walks only the small unassigned-families index for family work', async () => {
    const { results } = await env.DB.prepare(`EXPLAIN QUERY PLAN ${UNASSIGNED_SQL}`).bind(50).all<{ detail: string }>();
    expect(results.map((r) => r.detail)).toEqual(['SCAN vulns USING INDEX vulns_unassigned']);
  });

  it('flags the full scans this guards against', async () => {
    expect(await scans('SELECT (SELECT COUNT(*) FROM vulns) AS vulns, (SELECT COUNT(*) FROM catalog) AS catalog', [])).not.toEqual([]);
    expect(
      await scans(
        `SELECT DISTINCT c.kind, c.key, c.ecosystem, c.name, c.vendor, c.product, c.normalized, c.label, c.count
         FROM json_each(?) j
         JOIN catalog c ON c.normalized >= json_extract(j.value, '$[0]') AND c.normalized < json_extract(j.value, '$[1]')
         LIMIT 4000`,
        ['[["cis","cit"]]'],
      ),
    ).not.toEqual([]);
  });
});
