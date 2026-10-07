import { env } from 'cloudflare:workers';
import { describe, expect, it } from 'vitest';
import { AFFECTED_PACKAGES_SQL, AFFECTED_PRODUCTS_SQL, eventsSinceSql, vulnsInWindowSql } from '../src/match/match';
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
  ] as const)('%s searches an index', async (_name, sql, params) => {
    expect(await scans(sql, [...params])).toEqual([]);
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
