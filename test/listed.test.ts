import { env } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { app } from '../src/index';
import { applyPatches } from '../src/ingest/apply';
import { CVE_INDEX_BY_ID_SQL } from '../src/ingest/cve-index';
import { bumpDataVersionStatement } from '../src/ingest/meta';
import { matchStack } from '../src/match/match';
import { productItem, type IndexRow } from '../src/match/listed';
import type { OsvClient } from '../src/match/osv';
import { MAX_CVE_ITEMS, parseStack, serializeStack } from '../src/stack/format';
import { resetDb, store } from './helpers/db';

const NOW = new Date();
const daysAgo = (n: number) => new Date(NOW.getTime() - n * 86_400_000).toISOString();
const noOsv: OsvClient = { affecting: async () => new Map() };

/** Rows straight into cve_index, as ingest and the backfill leave them. */
async function index(rows: (Partial<IndexRow> & { id: string })[]): Promise<void> {
  await env.DB.batch(
    rows.map((r) => {
      const cols = Object.keys(r);
      return env.DB.prepare(`INSERT INTO cve_index (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`).bind(...cols.map((c) => r[c as keyof IndexRow] ?? null));
    }),
  );
}

let versionBase = Date.now() * 100 + 50;

beforeEach(async () => {
  await resetDb();
  // In vulns (the window): a PostgreSQL CVE from 20 days ago, also in the index as every CVE is.
  await applyPatches(
    store(),
    [
      {
        source: 'cve',
        id: 'CVE-2026-1003',
        aliases: [],
        fields: { title: 'PostgreSQL privilege escalation', publishedAt: daysAgo(20), cvssScore: 8.8 },
        affected: [{ kind: 'product', vendor: 'postgresql', product: 'postgresql', ranges: [], fixedVersion: null }],
      },
    ],
    { now: NOW, windowStart: daysAgo(90), epssEvents: true },
  );
  await index([
    { id: 'CVE-2026-1003', published_at: daysAgo(20), title: 'PostgreSQL privilege escalation', product: 'postgresql/postgresql', product_label: 'PostgreSQL', cvss_score: 8.8 },
    // Old and on KEV: only the index has it.
    { id: 'CVE-2014-0160', published_at: '2014-04-07T22:55:00.000Z', title: 'Heartbleed', product: 'openssl/openssl', product_label: 'OpenSSL', cvss_score: 7.5, kev_added_at: '2022-05-04', epss: 0.94 },
    // CVSS 10, never exploited as far as anyone knows.
    { id: 'CVE-2015-1000', published_at: '2015-06-01T00:00:00.000Z', title: 'Widget RCE', product: 'npm:widget', product_label: 'widget', cvss_score: 10, epss: 0.001 },
    // Rejected as a duplicate of CVE-2018-1001; rejected with nothing named.
    { id: 'CVE-2018-1000', state: 'rejected', replaced_by: '["CVE-2018-1001"]' },
    { id: 'CVE-2018-1001', published_at: '2018-03-01T00:00:00.000Z', title: 'The real one', cvss_score: 6.1 },
    { id: 'CVE-2019-1000', state: 'rejected' },
  ]);
  await store().batch([bumpDataVersionStatement(NOW)]);
  versionBase += 100;
  await env.DB.prepare("UPDATE meta SET value = ? WHERE key = 'data_version'").bind(String(versionBase)).run();
});
afterEach(() => vi.restoreAllMocks());

const LIST = 'cve:2026-1003,cve:2014-0160,cve:2015-1000,cve:2018-1000,cve:2019-1000,cve:2099-99999';

describe('matchStack with listed CVEs', () => {
  it('ranks every listed CVE whatever its age, evidence first, and accounts for the rest', async () => {
    const res = await matchStack(store(), parseStack(LIST), { now: NOW, days: 30, osv: noOsv });
    expect(res.results.map((r) => [r.id, r.confidence, r.match, r.beforeWindow])).toEqual([
      ['CVE-2014-0160', 'listed', 'exact', true],
      ['CVE-2015-1000', 'listed', 'exact', true],
      ['CVE-2026-1003', 'listed', 'exact', false],
      ['CVE-2018-1001', 'listed', 'exact', true],
    ]);
    // KEV outranks a CVSS 10 with nothing else.
    expect(res.results[0]!.priority).toBe('act');
    expect(['attend', 'watch', 'track']).toContain(res.results[1]!.priority);
    expect(res.results[2]!.matched).toEqual(['cve:2026-1003']);
    // The replacement wasn't listed: it's ranked in its duplicate's place, matching no item.
    expect(res.results[3]!.matched).toEqual([]);
    expect(res.results[3]!.replaces).toEqual(['CVE-2018-1000']);
    expect(res.results[0]!.replaces).toBeUndefined();
    expect(res.listed).toEqual({
      rejected: [
        { id: 'CVE-2018-1000', replacedBy: ['CVE-2018-1001'] },
        { id: 'CVE-2019-1000', replacedBy: [] },
      ],
      notFound: ['CVE-2099-99999'],
    });
    expect(res.watching).toEqual([]);
  });

  it('groups listed CVEs in Fix first by product, or on their own', async () => {
    const res = await matchStack(store(), parseStack(LIST), { now: NOW, days: 30, osv: noOsv });
    expect(res.fixFirst.map((f) => [f.item, f.listed, f.label ?? null, f.vulns])).toEqual([
      ['p:openssl/openssl', true, 'OpenSSL', ['CVE-2014-0160']],
      ['npm:widget', true, 'widget', ['CVE-2015-1000']],
      ['p:postgresql/postgresql', true, 'PostgreSQL', ['CVE-2026-1003']],
      ['cve:2018-1001', true, null, ['CVE-2018-1001']],
    ]);
  });

  it('keeps one result for a CVE both a component and the list match', async () => {
    const res = await matchStack(store(), parseStack('?p:postgresql/postgresql@16,cve:2026-1003'), { now: NOW, days: 30, osv: noOsv });
    expect(res.results).toHaveLength(1);
    expect(res.results[0]).toMatchObject({ id: 'CVE-2026-1003', confidence: 'product_match', match: 'exact', matched: ['?p:postgresql/postgresql@16', 'cve:2026-1003'] });
    expect(res.watching).toEqual([]);
    // In Fix first it counts once under the stack item, which is not a listed group.
    expect(res.fixFirst.map((f) => [f.item, f.listed ?? false])).toEqual([
      ['?p:postgresql/postgresql@16', false],
      ['p:postgresql/postgresql', true],
    ]);
  });

  it('marks a listed replacement as replacing its duplicate', async () => {
    const res = await matchStack(store(), parseStack('cve:2018-1000,cve:2018-1001'), { now: NOW, days: 30, osv: noOsv });
    expect(res.results.map((r) => [r.id, r.matched, r.replaces])).toEqual([['CVE-2018-1001', ['cve:2018-1001'], ['CVE-2018-1000']]]);
  });

  it('ranks an old high-severity CVE with nothing else known as overdue', async () => {
    // Shaped like CVE-2025-41450: CVSS 8.2, assessed once by CISA on publication, EPSS low and flat.
    await index([
      {
        id: 'CVE-2025-41450',
        published_at: '2025-05-08T09:41:20.881Z',
        title: 'Authentication bypass in Danfoss AK-SM 8xxA',
        product: 'danfoss/ak-sm_8xxa_series',
        cvss_score: 8.2,
        cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:H',
        ssvc: JSON.stringify({ exploitation: 'none', automatable: 'no', technicalImpact: 'partial' }),
        epss: 0.0035,
        epss_date: daysAgo(1).slice(0, 10),
      },
    ]);
    const [r] = (await matchStack(store(), parseStack('cve:2025-41450'), { now: NOW, days: 30, osv: noOsv })).results;
    expect(r).toMatchObject({ id: 'CVE-2025-41450', priority: 'attend', respondWithinHours: 168 });
    expect(r!.why.decisive).toEqual({ kind: 'context', text: expect.stringMatching(/^Public for \d+ (months|years) at CVSS 8\.0 or more: a fix is overdue$/) });
  });

  it('never reads cve_index for a stack without listed CVEs', async () => {
    const sql: string[] = [];
    const spy = store();
    const all = spy.all.bind(spy);
    spy.all = ((s: string, p?: unknown[]) => (sql.push(s), all(s, p))) as typeof spy.all;
    await matchStack(spy, parseStack('p:postgresql/postgresql'), { now: NOW, days: 30, osv: noOsv });
    expect(sql.some((s) => s.includes('cve_index'))).toBe(false);
    expect(sql).not.toContain(CVE_INDEX_BY_ID_SQL);
  });

  it(`reads a list of ${MAX_CVE_ITEMS} CVEs in a few queries`, async () => {
    await env.DB.prepare(
      `WITH RECURSIVE i(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM i WHERE x < ?)
       INSERT INTO cve_index (id, published_at, cvss_score) SELECT printf('CVE-2020-%05d', 10000 + x), '2020-01-01', 5 FROM i`,
    ).bind(MAX_CVE_ITEMS).run();
    const items = Array.from({ length: MAX_CVE_ITEMS }, (_, i) => ({ kind: 'cve' as const, id: `CVE-2020-${10001 + i}` }));
    const counting = store();
    const all = counting.all.bind(counting);
    let queries = 0;
    counting.all = ((s: string, p?: unknown[]) => (queries++, all(s, p))) as typeof counting.all;
    const res = await matchStack(counting, parseStack(serializeStack(items)), { now: NOW, days: 30, osv: noOsv });
    expect(res.results).toHaveLength(MAX_CVE_ITEMS);
    // vulns and cve_index, one chunk each; nothing rejected, no families.
    expect(queries).toBe(2);
  });
});

describe('productItem', () => {
  it('turns index product keys into stack items', () => {
    expect(productItem('openssl/openssl', ' OpenSSL ')).toEqual({ item: 'p:openssl/openssl', label: 'OpenSSL' });
    expect(productItem('PyPI:Django', null)).toEqual({ item: 'pypi:django', label: null });
    expect(productItem('npm:@angular/core', 'Angular')).toEqual({ item: 'npm:@angular/core', label: 'Angular' });
    expect(productItem('Maven:org.apache.logging.log4j:log4j-core', null)?.item).toBe('maven:org.apache.logging.log4j:log4j-core');
    for (const bad of [null, '', 'noslash', '/x']) expect(productItem(bad, 'x'), String(bad)).toBeNull();
  });
});

describe('GET /api/feed with listed CVEs', () => {
  it('serves the list, with its rejected and unknown IDs, as JSON, Atom and a badge', async () => {
    const q = `s=${encodeURIComponent(LIST)}`;
    const res = await app.request(`/api/feed?${q}`, {}, env);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { results: { id: string }[]; listed: unknown; summary: { exploited: number } };
    expect(body.results.map((r) => r.id)).toEqual(['CVE-2014-0160', 'CVE-2015-1000', 'CVE-2026-1003', 'CVE-2018-1001']);
    expect(body.listed).toEqual({ rejected: [{ id: 'CVE-2018-1000', replacedBy: ['CVE-2018-1001'] }, { id: 'CVE-2019-1000', replacedBy: [] }], notFound: ['CVE-2099-99999'] });
    expect(body.summary.exploited).toBe(1);

    expect((await app.request(`/feed.xml?${q}`, {}, env)).status).toBe(200);
    const badge = await app.request(`/badge.svg?${q}`, {}, env);
    expect(await badge.text()).toContain('aria-label="1 known-exploited CVE"');
  });

  it('leaves listed out of a feed without listed CVEs', async () => {
    const body = (await (await app.request(`/api/feed?s=${encodeURIComponent('p:postgresql/postgresql')}`, {}, env)).json()) as Record<string, unknown>;
    expect('listed' in body).toBe(false);
  });

  it('puts a list of 1,000 CVEs behind the heavy limiter', async () => {
    const heavy = vi.fn(async () => ({ success: false }));
    const limited = { ...env, FEED_LIMITER: { limit: async () => ({ success: true }) } as unknown as RateLimit, FEED_HEAVY_LIMITER: { limit: heavy } as unknown as RateLimit };
    const list = (n: number) => serializeStack(Array.from({ length: n }, (_, i) => ({ kind: 'cve' as const, id: `CVE-2021-${10000 + i}` })));
    expect((await app.request(`/api/feed?s=${encodeURIComponent(list(999))}`, {}, limited)).status).toBe(200);
    expect(heavy).not.toHaveBeenCalled();
    expect((await app.request(`/api/feed?s=${encodeURIComponent(list(1000))}`, {}, limited)).status).toBe(429);
  });
});
